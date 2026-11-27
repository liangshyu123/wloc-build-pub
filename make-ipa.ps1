<#
.SYNOPSIS
  wloc 一键出未签名 IPA（Windows 上跑，借 GitHub Actions 的 macOS runner 编）。

.DESCRIPTION
  它做完整条链路，你只需要贴一次 GitHub token：
    1. 校验 token、定位账号
    2. 仓库不存在就建（私有），存在就直接用
    3. 把同目录的工程（含 .github/workflows/build-ipa.yml）推到 main
    4. 触发 build-ipa 工作流
    5. 轮询构建，实时打印到哪一步了
    6. 成功后自动下载 artifact 并解出 wloc-ipa.ipa 放到桌面
    7. 失败就把出错步骤和日志尾巴打出来

.PARAMETER Token
  GitHub PAT。需要 repo + workflow 权限（classic 就勾 repo 和 workflow；
  fine-grained 给 Contents:Read/Write + Actions:Read/Write + Workflows:Write）。
  也可以先设环境变量 GITHUB_TOKEN。

.PARAMETER Repo
  目标仓库，格式 owner/name。省略则用 token 所属账号下的 wloc-build。

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\make-ipa.ps1 -Token ghp_xxxxxxxx

.NOTES
  Windows 上没有任何办法本地编 iOS（Swift/iOS SDK 只在 macOS 的 Xcode 里），
  这个脚本就是把「借云 Mac」这一步也自动化掉。
#>
[CmdletBinding()]
param(
    [string]$Token = $env:GITHUB_TOKEN,
    [string]$Repo,
    [string]$SrcDir,
    [string]$Branch = 'main',
    [int]$TimeoutMinutes = 90
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'   # Win10 上 IWR 的进度条会拖慢十倍
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

$Api = 'https://api.github.com'
$WorkflowFile = 'build-ipa.yml'
$ArtifactName = 'wloc-ipa'

function Say($msg, $color = 'Gray') { Write-Host $msg -ForegroundColor $color }
function Step($msg) { Write-Host ""; Write-Host "==> $msg" -ForegroundColor Cyan }
function Die($msg) { Write-Host "✗ $msg" -ForegroundColor Red; exit 1 }

function Invoke-Gh {
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$Method = 'GET',
        $Body,
        [switch]$Raw
    )
    $h = @{
        Authorization          = "Bearer $Token"
        Accept                 = 'application/vnd.github+json'
        'X-GitHub-Api-Version' = '2022-11-28'
        'User-Agent'           = 'wloc-make-ipa'
    }
    $req = @{
        Uri         = if ($Path -like 'http*') { $Path } else { "$Api$Path" }
        Method      = $Method
        Headers     = $h
        ErrorAction = 'Stop'
    }
    if ($Body -ne $null) {
        $req.Body = ($Body | ConvertTo-Json -Depth 20 -Compress)
        $req.ContentType = 'application/json; charset=utf-8'
    }
    try {
        return Invoke-RestMethod @req
    } catch {
        $detail = ''
        try {
            $r = $_.Exception.Response
            if ($r) {
                $sr = New-Object System.IO.StreamReader($r.GetResponseStream())
                $detail = $sr.ReadToEnd()
            }
        } catch { }
        throw "GitHub API $Method $Path 失败：$($_.Exception.Message)`n$detail"
    }
}

# ---------------------------------------------------------------- 0. token
Step '0/6 校验 token'
if (-not $Token) {
    Say '没有 token。到 https://github.com/settings/tokens 建一个（勾 repo + workflow），然后：' 'Yellow'
    Say '  powershell -ExecutionPolicy Bypass -File .\make-ipa.ps1 -Token ghp_xxx' 'Yellow'
    Say '或者先 setx GITHUB_TOKEN ghp_xxx 再重开窗口跑本脚本。' 'Yellow'
    exit 2
}
if (-not $SrcDir) {
    if ($PSScriptRoot) { $SrcDir = $PSScriptRoot }
    elseif ($MyInvocation.MyCommand.Path) { $SrcDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
    else { $SrcDir = (Get-Location).Path }
}
Say "源目录：$SrcDir" 'DarkGray'
$me = Invoke-Gh '/user'
$owner = $me.login
if (-not $Repo) { $Repo = "$owner/wloc-build" }
Say "账号：$owner    仓库：$Repo" 'Green'
if (-not (Test-Path (Join-Path $SrcDir $WorkflowFile)) -and -not (Test-Path (Join-Path $SrcDir ".github\workflows\$WorkflowFile"))) {
    Die "源目录 $SrcDir 里找不到 .github\workflows\$WorkflowFile —— 请在解压后的仓库目录里运行本脚本。"
}

# ---------------------------------------------------------------- 1. 仓库
Step '1/6 准备仓库'
$repoExists = $true
try { $repoInfo = Invoke-Gh "/repos/$Repo" } catch { $repoExists = $false }
if (-not $repoExists) {
    Say "仓库不存在，创建私有仓库 $Repo"
    $name = ($Repo -split '/')[-1]
    $repoInfo = Invoke-Gh '/user/repos' -Method POST -Body @{
        name        = $name
        private     = $true
        description = 'wloc hardened build (unsigned IPA via GitHub Actions)'
        auto_init   = $false
    }
} else {
    Say "仓库已存在（private=$($repoInfo.private)）"
}
$defaultBranch = $repoInfo.default_branch
if (-not $defaultBranch) { $defaultBranch = $Branch }
# 空仓库时 default_branch 可能是 master，统一推到我们指定的分支后再把默认分支改过来
$Branch = if ($defaultBranch -and $defaultBranch -ne '') { $defaultBranch } else { $Branch }
Say "推送分支：$Branch"

# ---------------------------------------------------------------- 2. push
Step '2/6 推送工程到 GitHub'
$git = 'C:\Program Files\Git\cmd\git.exe'
if (-not (Test-Path $git)) { $git = 'git' }
$remote = "https://x-access-token:$Token@github.com/$Repo.git"

Push-Location $SrcDir
$prevEap = $ErrorActionPreference
$ErrorActionPreference = 'Continue'   # 原生命令写 stderr 时，Stop 模式下 PS 5.1 会当成异常中断
try {
    if (-not (Test-Path (Join-Path $SrcDir '.git'))) {
        & $git init -q 2>&1 | Out-Null
        & $git checkout -q -b $Branch 2>&1 | Out-Null
    }
    & $git -c user.name=$owner -c user.email="$owner@users.noreply.github.com" add -A 2>&1 | Out-Null
    # .gitignore 把 Podfile.lock 也忽略了；锁文件必须一起推，否则 CI 上 pod install
    # 可能解析到别的版本，编译行为就和本地不一致了。
    if (Test-Path (Join-Path $SrcDir 'Podfile.lock')) {
        & $git -c user.name=$owner -c user.email="$owner@users.noreply.github.com" add -f Podfile.lock 2>&1 | Out-Null
    }
    $dirty = & $git status --porcelain 2>&1
    if ($dirty) {
        & $git -c user.name=$owner -c user.email="$owner@users.noreply.github.com" `
            commit -q -m "wloc: hardened build ($(Get-Date -Format 'yyyy-MM-dd HH:mm'))" 2>&1 | Out-Null
        Say "已提交 $(($dirty | Measure-Object).Count) 个变更"
    } else {
        Say '工作区干净，跳过提交'
    }
    & $git remote remove origin 2>&1 | Out-Null
    & $git remote add origin $remote 2>&1 | Out-Null
    & $git push -u origin "HEAD:refs/heads/$Branch" --force 2>&1 | ForEach-Object { Say "  $_" 'DarkGray' }
    $pushCode = $LASTEXITCODE
} finally {
    Pop-Location
    $ErrorActionPreference = $prevEap
    & $git remote set-url origin "https://github.com/$Repo.git" 2>&1 | Out-Null
}
if ($pushCode -ne 0) { Die 'git push 失败。检查 token 是否有 repo 写权限，或仓库名是否写错。' }
Say '推送完成' 'Green'

# ---------------------------------------------------------------- 3. 触发
Step '3/6 触发 build-ipa 工作流'
$before = (Get-Date).ToUniversalTime().AddMinutes(-1)
try {
    Invoke-Gh "/repos/$Repo/actions/workflows/$WorkflowFile/dispatches" -Method POST -Body @{ ref = $Branch } | Out-Null
} catch {
    Die "触发失败：$($_.Exception.Message)`n（首次推送后 GitHub 需要几秒才识别新工作流，稍等重跑本脚本即可）"
}
Say '已触发，等 runner 接活…'

# ---------------------------------------------------------------- 4. 等 run
Step '4/6 等待构建'
$run = $null
$deadline = (Get-Date).AddMinutes($TimeoutMinutes)
$spin = 0
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 10
    $spin++
    try {
        $runs = Invoke-Gh "/repos/$Repo/actions/runs?per_page=10&event=workflow_dispatch"
    } catch { continue }
    $cand = $runs.workflow_runs | Where-Object {
        $_.path -like "*$WorkflowFile" -and (([datetime]$_.created_at).ToUniversalTime() -ge $before)
    } | Sort-Object { [datetime]$_.created_at } -Descending | Select-Object -First 1
    if (-not $cand) {
        if ($spin % 6 -eq 0) { Say "  …还在等（$([int]((Get-Date)-$before).TotalMinutes) 分钟）" 'DarkGray' }
        continue
    }
    $run = $cand
    if ($run.status -eq 'completed') { break }
    try {
        $jobs = Invoke-Gh "/repos/$Repo/actions/runs/$($run.id)/jobs"
        $cur = $jobs.jobs | ForEach-Object {
            $s = $_.steps | Where-Object { $_.status -eq 'in_progress' } | Select-Object -First 1
            if ($s) { "$($_.name) → $($s.name)" } else { "$($_.name) → $($_.status)" }
        } -join ' | '
        Say "  [$($run.status)] $cur" 'DarkGray'
    } catch {
        Say "  [$($run.status)]" 'DarkGray'
    }
}

if (-not $run) { Die "等了 $TimeoutMinutes 分钟没拿到 run。去 Actions 页面看队列：https://github.com/$Repo/actions" }
if ($run.status -ne 'completed') { Die "超时（$($run.status)）。macos-13 排队慢是常态，去这里挂着看：$($run.html_url)" }

Say "构建结论：$($run.conclusion)" $(if ($run.conclusion -eq 'success') { 'Green' } else { 'Red' })

# ---------------------------------------------------------------- 5. 失败诊断 / 6. 下载
if ($run.conclusion -ne 'success') {
    Step '构建失败，抓日志'
    Say "运行页：$($run.html_url)" 'Yellow'
    try {
        $jobs = Invoke-Gh "/repos/$Repo/actions/runs/$($run.id)/jobs"
        foreach ($j in $jobs.jobs) {
            foreach ($s in $j.steps) {
                if ($s.conclusion -and $s.conclusion -ne 'success' -and $s.conclusion -ne 'skipped') {
                    Say "  失败步骤：$($j.name) → $($s.name) ($($s.conclusion))" 'Red'
                }
            }
        }
        $tmp = Join-Path $env:TEMP "wloc-logs-$($run.id).zip"
        $h = @{ Authorization = "Bearer $Token"; 'User-Agent' = 'wloc-make-ipa'; Accept = 'application/vnd.github+json' }
        Invoke-WebRequest -Uri "$Api/repos/$Repo/actions/runs/$($run.id)/logs" -Headers $h -OutFile $tmp -MaximumRedirection 5
        $dir = Join-Path $env:TEMP "wloc-logs-$($run.id)"
        if (Test-Path $dir) { Remove-Item $dir -Recurse -Force }
        Expand-Archive -Path $tmp -DestinationPath $dir -Force
        $hits = Select-String -Path (Join-Path $dir '*.txt') -Pattern 'error:|cannot be found|BUILD FAILED|The following build commands failed|unknown option|No such file' -ErrorAction SilentlyContinue
        if ($hits) {
            Say '' ; Say '--- 关键报错 ---' 'Yellow'
            $hits | Select-Object -First 25 | ForEach-Object { Say "  $($_.Filename):$($_.LineNumber)  $($_.Line.Trim())" 'DarkYellow' }
        }
        Say '' ; Say '--- 日志尾部 ---' 'Yellow'
        Get-ChildItem $dir -Filter *.txt -Recurse | ForEach-Object {
            Say "  [$(Split-Path $_.Name -Leaf)]" 'DarkGray'
            Get-Content $_.FullName -Tail 25 | ForEach-Object { Say "    $_" 'DarkGray' }
        }
    } catch {
        Say "日志下载失败（$($_.Exception.Message)），直接看运行页。" 'Yellow'
    }
    exit 1
}

Step '5/6 下载 IPA'
$arts = Invoke-Gh "/repos/$Repo/actions/runs/$($run.id)/artifacts"
$art = $arts.artifacts | Where-Object { $_.name -eq $ArtifactName } | Select-Object -First 1
if (-not $art) { $art = $arts.artifacts | Select-Object -First 1 }
if (-not $art) { Die '这次运行没有 artifact。' }
Say "artifact：$($art.name)  $([math]::Round($art.size_in_bytes/1MB,2)) MB"

$zip = Join-Path $env:TEMP "wloc-ipa-artifact.zip"
$h = @{ Authorization = "Bearer $Token"; 'User-Agent' = 'wloc-make-ipa'; Accept = 'application/vnd.github+json' }
Invoke-WebRequest -Uri "$Api/repos/$Repo/actions/artifacts/$($art.id)/zip" -Headers $h -OutFile $zip -MaximumRedirection 5

$ex = Join-Path $env:TEMP "wloc-ipa-artifact"
if (Test-Path $ex) { Remove-Item $ex -Recurse -Force }
Expand-Archive -Path $zip -DestinationPath $ex -Force
$ipa = Get-ChildItem $ex -Filter *.ipa -Recurse | Select-Object -First 1
if (-not $ipa) { Die "解压后没有 .ipa，看看：$ex" }

$desktop = [Environment]::GetFolderPath('Desktop')
$dest = Join-Path $desktop $ipa.Name
Copy-Item $ipa.FullName $dest -Force
Say "IPA 已放到桌面：$dest" 'Green'
Say ("大小：" + [math]::Round((Get-Item $dest).Length / 1MB, 2) + " MB")

# ---------------------------------------------------------------- 快速自检
Step '6/6 解包自检'
Add-Type -AssemblyName System.IO.Compression.FileSystem
$z = [System.IO.Compression.ZipFile]::OpenRead($dest)
try {
    $names = $z.Entries | ForEach-Object { $_.FullName }
    $app = $names | Where-Object { $_ -match '^Payload/[^/]+\.app/Info\.plist$' } | Select-Object -First 1
    Say ("结构：" + $(if ($app) { 'Payload/*.app ✓' } else { '✗ 不是标准 ipa' })) $(if ($app) { 'Green' } else { 'Red' })
    Say ("隧道扩展：" + $(if ($names -match 'PlugIns/[^/]+\.appex/Info\.plist') { '✓ 有' } else { '✗ 缺（VPN 用不了）' })) $(if ($names -match 'PlugIns/[^/]+\.appex/Info\.plist') { 'Green' } else { 'Red' })
    Say ("代理 p12：" + $(if ($names -match 'AppWLocProxy\.p12$') { '✓ 有' } else { '✗ 缺' })) $(if ($names -match 'AppWLocProxy\.p12$') { 'Green' } else { 'Red' })
    Say ("根证书：" + $(if ($names -match 'AppWLocRootCA\.cer$') { '✓ 有' } else { '✗ 缺' })) $(if ($names -match 'AppWLocRootCA\.cer$') { 'Green' } else { 'Red' })
} finally { $z.Dispose() }

Say ''
Say '装法：' 'Cyan'
Say '  TrollStore（iOS 14~17 且设备支持）→ 直接导入，隧道可用（entitlements 已用 ldid 写入）'
Say '  Sideloadly / AltStore → 能用地图，但没有 App Group / NetworkExtension，VPN 隧道失效，7 天到期'
Say ''
Say '首启应弹「软件 · 卡密验证」；不输卡密点地图无反应。'
