<#
.SYNOPSIS
    v0.6.0-beta - Windows 应急响应场景聚合分析脚本（攻击时间线 + ATT&CK 映射）

.DESCRIPTION
    v0.5-scenario 重点修复之前版本的几个问题：
    1. 不再把 cmd.exe / powershell.exe 这类系统工具仅凭进程名列为风险。
    2. 不再把大量 DWM / UMFD / SYSTEM 的普通 4648、4672 事件刷进重点关注项。
    3. 不再把 Microsoft Windows 内置计划任务、Defender 常规任务大量误报。
    4. 对 RDP 暴力破解、SMB/NTLM 爆破、挖矿、可疑持久化进行「场景聚合判断」。
    5. 新增 RDP 相关事件 1149 / 21 / 24 / 25 关联分析。
    6. 新增危险监听端口聚合扫描，重点关注 3389 / 445 / 5985 / 5986。
    7. 新增可疑启动项检查，重点识别 AppData / Public / Temp 下的 bat、ps1、vbs、exe 持久化。
    8. HTML 报告内置离线文件 Hash 计算器，可在浏览器本地选择文件计算 SHA-1/SHA-256/SHA-384/SHA-512，并输出大写/小写 Hash。
    9. 新增挖矿配置追踪增强：资源异常、服务、计划任务、启动项命中的可疑目录会自动进入矿池/钱包配置扫描队列。
    10. 保留 PowerShell 独立 Hash 计算模式，支持单文件、多文件、目录递归和大小写 Hash 输出。
    11. 增加登录失败明细，即使 4625 没有来源 IP，也会按用户/工作站/登录类型聚合。
    12. 增加挖矿配置按 Value 聚合展示，减少相同矿池/钱包在多个文件中重复刷屏。
    13. 区分疑似活动中挖矿与疑似挖矿残留/历史痕迹。
    14. 新增攻击时间线：将登录失败、RDP、PowerShell、服务、计划任务、启动项、挖矿配置等线索按时间/证据链排序。
    15. 新增 MITRE ATT&CK 映射：自动将常见行为映射到 T1110、T1059.001、T1543.003、T1053.005、T1547.001、T1496 等技术。

.NOTES
    本工具只做蓝队应急响应辅助取证与线索整理，不做查杀，不替代 D盾、河马、EDR、杀毒软件等专业工具。
    请仅在合法授权环境中使用。
#>

param(
    # 默认扫描最近 7 天；如果需要长周期历史排查，可使用 -Days 1000 这类参数覆盖。
    [int]$Days = 7,

    # 重点关注窗口默认最近 3 天。历史长周期扫描时，旧事件仍会进入统计/明细，但不会刷进重点关注项。
    [int]$FocusDays = 3,

    [datetime]$StartTime,

    [datetime]$EndTime,

    [string]$OutputDir = "",

    [string]$LogFolder = "",

    [switch]$AllowNonAdmin,

    [switch]$ExportDetails,

    [switch]$NoHash,

    [int]$CpuSampleSeconds = 3,

    [double]$CpuHighPercent = 30,

    [double]$MemoryHighMB = 1024,

    [double]$MemoryHighPercent = 25,

    # 文件 Hash 独立计算模式：支持单文件/多文件/目录，输出大小写 Hash
    [string[]]$HashFile = @(),

    [string]$HashFolder = "",

    [switch]$HashRecurse,

    [switch]$HashOnly,

    [ValidateSet("MD5","SHA1","SHA256","SHA384","SHA512")]
    [string[]]$HashAlgorithm = @("MD5","SHA1","SHA256")
)

$Version = "v0.7.1-beta"
$ScriptName = "WinIR-Helper.ps1"

# =========================================================
# 基础函数
# =========================================================

function Write-Info { param([string]$Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Message) Write-Host "[+] $Message" -ForegroundColor Green }
function Write-Warn { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }

function Test-IsAdmin {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch { return $false }
}

function Safe-String {
    param($Value)
    if ($null -eq $Value) { return "" }
    return ([string]$Value).Trim()
}

function HtmlEncode {
    param($Value)
    if ($null -eq $Value) { return "" }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}


function Add-Finding {
    param(
        [string]$Level,
        [string]$Category,
        [string]$Title,
        [string]$Evidence,
        [string]$Suggestion
    )

    $script:Findings.Add([PSCustomObject]@{
        Level      = $Level
        Category   = $Category
        Title      = $Title
        Evidence   = $Evidence
        Suggestion = $Suggestion
    }) | Out-Null
}

function Add-Scenario {
    param(
        [string]$Level,
        [string]$Scenario,
        [string]$Conclusion,
        [string]$Evidence,
        [string]$Suggestion
    )

    $script:Scenarios.Add([PSCustomObject]@{
        Level      = $Level
        Scenario   = $Scenario
        Conclusion = $Conclusion
        Evidence   = $Evidence
        Suggestion = $Suggestion
    }) | Out-Null
}

function Get-SHA256Safe {
    param([string]$Path)

    if ($NoHash) { return "" }

    try {
        if (Test-Path $Path -PathType Leaf) {
            return (Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop).Hash
        }
    }
    catch {}
    return ""
}

function Test-PrivateIP {
    param([string]$IP)

    if ([string]::IsNullOrWhiteSpace($IP)) { return $true }
    $ip2 = $IP.Trim()

    if ($ip2 -in @("-","0.0.0.0","::","::1","127.0.0.1","localhost")) { return $true }
    if ($ip2 -match "^10\.") { return $true }
    if ($ip2 -match "^192\.168\.") { return $true }
    if ($ip2 -match "^172\.(1[6-9]|2[0-9]|3[0-1])\.") { return $true }
    if ($ip2 -match "^169\.254\.") { return $true }

    return $false
}

function Get-TimeWindow {
    if (-not $PSBoundParameters.ContainsKey("EndTime") -or $EndTime -eq [datetime]::MinValue) {
        $script:EndTime = Get-Date
    }
    else {
        $script:EndTime = $EndTime
    }

    if ($Days -le 0) { $script:Days = 7 } else { $script:Days = [Math]::Abs($Days) }
    if ($FocusDays -le 0) { $script:FocusDays = 3 } else { $script:FocusDays = [Math]::Abs($FocusDays) }

    if (-not $PSBoundParameters.ContainsKey("StartTime") -or $StartTime -eq [datetime]::MinValue) {
        $script:StartTime = $script:EndTime.AddDays(-1 * $script:Days)
    }
    else {
        $script:StartTime = $StartTime
    }

    $focusStart = $script:EndTime.AddDays(-1 * $script:FocusDays)
    if ($focusStart -lt $script:StartTime) {
        $script:FocusStartTime = $script:StartTime
    }
    else {
        $script:FocusStartTime = $focusStart
    }
}

function Test-IsInFocusWindow {
    param([datetime]$Time)
    if ($null -eq $Time -or $Time -eq [datetime]::MinValue) { return $false }
    return ($Time -ge $script:FocusStartTime -and $Time -le $script:EndTime)
}

function Ensure-OutputDir {
    if ([string]::IsNullOrWhiteSpace($OutputDir)) {
        $base = Join-Path (Get-Location) ("WinIR_Output_" + (Get-Date -Format "yyyyMMdd_HHmmss"))
    }
    else {
        $base = $OutputDir
    }

    New-Item -Path $base -ItemType Directory -Force | Out-Null
    $script:OutputDir = (Resolve-Path $base).Path
    $script:DetailDir = Join-Path $script:OutputDir "details"

    if ($ExportDetails) {
        New-Item -Path $script:DetailDir -ItemType Directory -Force | Out-Null
    }
}

function Export-DetailCsv {
    param(
        [string]$Name,
        [object]$Data
    )

    if (-not $ExportDetails) { return }

    $path = Join-Path $script:DetailDir $Name
    try {
        $rows = @()
        if ($null -ne $Data) {
            foreach ($item in $Data) {
                $rows += $item
            }
        }

        if ($rows.Count -eq 0) {
            $rows = @(
                [PSCustomObject]@{
                    Note = "本次扫描未发现对应明细。"
                }
            )
        }

        $rows | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    }
    catch {
        Write-Warn "导出明细失败：$Name"
    }
}

function ConvertTo-HtmlTable {
    param(
        [object]$Data,
        [int]$MaxRows = 50
    )

    $safeData = @()
    if ($null -ne $Data) {
        foreach ($item in $Data) {
            $safeData += $item
        }
    }

    if ($safeData.Count -eq 0) {
        return "<p class='empty'>暂无数据</p>"
    }

    $rows = @($safeData | Select-Object -First $MaxRows)
    $props = $rows[0].PSObject.Properties.Name

    $html = "<table><thead><tr>"
    foreach ($p in $props) {
        $html += "<th>$(HtmlEncode $p)</th>"
    }
    $html += "</tr></thead><tbody>"

    foreach ($r in $rows) {
        $html += "<tr>"
        foreach ($p in $props) {
            $v = $r.$p
            if ($p -eq "Level") {
                $class = "badge-watch"
                if ($v -eq "高危") { $class = "badge-high" }
                elseif ($v -eq "中危") { $class = "badge-mid" }
                $html += "<td><span class='badge $class'>$(HtmlEncode $v)</span></td>"
            }
            else {
                $html += "<td>$(HtmlEncode $v)</td>"
            }
        }
        $html += "</tr>"
    }

    $html += "</tbody></table>"
    return $html
}

# =========================================================
# 事件解析函数
# =========================================================

function Get-EventDataValue {
    param(
        [xml]$Xml,
        [string]$Name
    )

    try {
        $node = $Xml.Event.EventData.Data | Where-Object { $_.Name -eq $Name } | Select-Object -First 1
        if ($null -eq $node) { return "" }
        return Safe-String $node.'#text'
    }
    catch { return "" }
}

function Get-EventDataByIndex {
    param(
        [xml]$Xml,
        [int]$Index
    )

    try {
        $data = @($Xml.Event.EventData.Data)
        if ($data.Count -gt $Index) {
            return Safe-String $data[$Index].'#text'
        }
    }
    catch {}
    return ""
}

function Get-EventMessageValue {
    param(
        [string]$Message,
        [string]$FieldName
    )

    if ([string]::IsNullOrWhiteSpace($Message)) { return "" }

    $pattern = [regex]::Escape($FieldName) + ":\s*(.+)"
    if ($Message -match $pattern) {
        return ($matches[1]).Trim()
    }
    return ""
}

function Get-LogonTypeDesc {
    param([string]$LogonType)

    switch ($LogonType) {
        "2"  { return "2-本地交互登录/控制台" }
        "3"  { return "3-网络登录/SMB、NTLM 或 RDP-NLA 认证阶段" }
        "4"  { return "4-批处理登录" }
        "5"  { return "5-服务登录" }
        "7"  { return "7-解锁登录" }
        "8"  { return "8-网络明文登录" }
        "9"  { return "9-新凭据登录/RunAs 或横向移动线索" }
        "10" { return "10-远程交互登录/RDP" }
        "11" { return "11-缓存交互登录" }
        default {
            if ([string]::IsNullOrWhiteSpace($LogonType)) { return "未知" }
            return "$LogonType-未知类型"
        }
    }
}

function Test-IsNoiseUser {
    param([string]$User)

    if ([string]::IsNullOrWhiteSpace($User)) { return $true }

    $u = $User.Trim()
    if ($u -in @("-","SYSTEM","LOCAL SERVICE","NETWORK SERVICE")) { return $true }
    if ($u -match "^DWM-\d+$") { return $true }
    if ($u -match "^UMFD-\d+$") { return $true }

    return $false
}

function Test-IsSelfToolText {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }

    # v0.6.5-hotfix：修复自噪音正则字符串引号导致的 PowerShell 解析错误。
    # v0.6.2：过滤 WinIR 自身运行和报告生成造成的 4103/4104 噪音。
    # 只影响 PowerShell 事件展示与时间线，不影响进程、服务、计划任务、启动项和挖矿配置扫描。
    if ($Text -match '(?i)WinIR-Helper|WinIR_Output_|重点关注项\.csv|WinIR_Report\.html|WinIR_Summary\.txt|SuspiciousCmdRegex|MiningProcRegex|Cmdletization|Microsoft\.PowerShell\.Cmdletization|ConvertTo-HtmlTable|miningConfigForHtml|MiningCandidate|MiningConfigsGrouped|AttackTimeline|AttackTechnique|EvidenceChain|FailedByIP|failedDetailsForHtml|Get-DangerousPortInfo|ResourceAnomalies|resourceAbnormal|Export-DetailCsv|离线文件 Hash 计算器|Write-Ok\s+["'']?分析完成|分析完成！|优先查看：|\$ReportPath|\$SummaryPath|\$ScenarioPath|\$FindingPath|Set-Content\s+-Path\s+\$ReportPath|Start-Process\s+\$ReportPath|WinIR_Offline_File_Hash|hashCalcBtn|hashResultWrap') {
        return $true
    }

    return $false
}

function Test-IsAdminExecutionPolicyOnly {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }

    # v0.6.3：单独 Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
    # 常见于管理员临时运行应急脚本。保留为关注项，但不再当作强攻击执行证据。
    $normalized = ($Text -replace "\s+", " ").Trim()

    if ($normalized -match "(?i)Set-ExecutionPolicy\s+-Scope\s+Process\s+-ExecutionPolicy\s+Bypass" -and
        $normalized -notmatch "(?i)downloadstring|downloadfile|frombase64string|-enc|-encodedcommand|invoke-expression|\biex\b|new-object\s+net\.webclient|certutil|bitsadmin|schtasks\s+/create|net\s+user|add-localgroupmember|set-mppreference|disableantispyware|http://|https://|stratum|xmrig|miner|c3pool") {
        return $true
    }

    return $false
}

function Get-EventsById {
    param(
        [string]$LogName,
        [int[]]$Ids
    )

    $all = @()

    if (-not [string]::IsNullOrWhiteSpace($LogFolder) -and (Test-Path $LogFolder)) {
        $evtxFiles = Get-ChildItem -Path $LogFolder -Recurse -File -Filter "*.evtx" -ErrorAction SilentlyContinue

        foreach ($file in $evtxFiles) {
            try {
                $events = Get-WinEvent -FilterHashtable @{
                    Path = $file.FullName
                    Id   = $Ids
                } -ErrorAction Stop

                foreach ($evt in $events) {
                    if ($evt.TimeCreated -ge $StartTime -and $evt.TimeCreated -le $EndTime) {
                        $all += $evt
                    }
                }
            }
            catch {}
        }
    }
    else {
        try {
            $events = Get-WinEvent -FilterHashtable @{
                LogName   = $LogName
                Id        = $Ids
                StartTime = $StartTime
                EndTime   = $EndTime
            } -ErrorAction Stop

            $all += $events
        }
        catch {}
    }

    return $all
}

# =========================================================
# 进程与端口辅助函数
# =========================================================

function Get-TotalPhysicalMemoryMB {
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        return [Math]::Round($cs.TotalPhysicalMemory / 1MB, 2)
    }
    catch { return 0 }
}

function Get-ProcessMemoryMB {
    param([int]$ProcessId)

    try {
        $p = Get-Process -Id $ProcessId -ErrorAction Stop
        return [Math]::Round($p.WorkingSet64 / 1MB, 2)
    }
    catch { return 0 }
}

function Get-ProcessCpuPercentMap {
    param([int]$SampleSeconds = 3)

    $result = @{}

    try {
        if ($SampleSeconds -lt 1) { $SampleSeconds = 1 }

        $cores = [Environment]::ProcessorCount
        if ($cores -le 0) { $cores = 1 }

        $first = @{}
        Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
            try { $first[$_.Id] = $_.TotalProcessorTime.TotalSeconds } catch {}
        }

        Start-Sleep -Seconds $SampleSeconds

        Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                if ($first.ContainsKey($_.Id)) {
                    $delta = $_.TotalProcessorTime.TotalSeconds - $first[$_.Id]
                    $percent = ($delta / $SampleSeconds / $cores) * 100
                    if ($percent -lt 0) { $percent = 0 }
                    $result[$_.Id] = [Math]::Round($percent, 2)
                }
            }
            catch {}
        }
    }
    catch {}

    return $result
}

function Get-DangerousPortInfo {
    param([int]$Port)

    $map = @{
        21    = "FTP，明文传输风险"
        22    = "SSH，远程管理端口"
        23    = "Telnet，明文远程登录高风险"
        135   = "RPC，Windows 横向移动常见相关端口"
        139   = "NetBIOS，Windows 文件共享相关端口"
        445   = "SMB，Windows 文件共享/爆破/横向移动重点端口"
        1433  = "MSSQL 数据库"
        3306  = "MySQL 数据库"
        3389  = "RDP 远程桌面，高危暴露端口"
        5432  = "PostgreSQL 数据库"
        5900  = "VNC 远程控制"
        5985  = "WinRM HTTP，Windows 远程管理"
        5986  = "WinRM HTTPS，Windows 远程管理"
        6379  = "Redis 数据库"
        7001  = "WebLogic 常见端口"
        8080  = "常见 Web/代理/管理端口"
        9200  = "Elasticsearch"
        11211 = "Memcached"
        27017 = "MongoDB"
    }

    if ($map.ContainsKey($Port)) { return $map[$Port] }
    return ""
}

function Extract-ExecutablePath {
    param([string]$Command)

    if ([string]::IsNullOrWhiteSpace($Command)) { return "" }

    $c = $Command.Trim()

    if ($c -match '^\s*"([^"]+)"') {
        return $matches[1]
    }

    if ($c -match '^([A-Za-z]:\\[^\s]+)') {
        return $matches[1]
    }

    return $c.Split(" ")[0]
}

function Test-IsBuiltinTask {
    param(
        [string]$TaskPath,
        [string]$Actions
    )

    $text = "$TaskPath $Actions"

    # v0.6.6：OneDrive 用户启动任务精细白名单。
    # Get-ScheduledTask 的 TaskPath 通常只是 "\"，任务名不一定在 TaskPath 中，所以这里精确匹配官方 Action 路径。
    # 伪装 OneDrive 名称但 Action 指向 wscript/mshta/powershell/ProgramData 的任务不会被放过。
    if ($Actions -match '(?i)^"?C:\\Users\\[^\\]+\\AppData\\Local\\Microsoft\\OneDrive\\[^\\]+\\OneDriveLauncher\.exe"?\s+/startInstances\s*$') {
        return $true
    }
    if ($Actions -match '(?i)^"?C:\\Users\\[^\\]+\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive\.exe"?\s+/(background|startup|startInstances)\b') {
        return $true
    }
    if ($TaskPath -match "(?i)^\\OneDrive Startup Task-" -and
        $Actions -match "(?i)\\AppData\\Local\\Microsoft\\OneDrive\\[^\\]+\\OneDriveLauncher\.exe\b|\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive\.exe\b") {
        return $true
    }

    # v0.6.2：先处理高置信系统任务白名单，避免 Defender / NetTrace 这类系统任务因 ProgramData 或 vbs 被误报。
    # 注意：这里是精确白名单，不会放过伪装在 Microsoft\Windows 下、但 Action 指向可疑目录或脚本链的任务。
    if ($TaskPath -match "(?i)^\\Microsoft\\Windows\\Windows Defender\\" -and
        $Actions -match "(?i)\\ProgramData\\Microsoft\\Windows Defender\\platform\\[^\\]+\\MpCmdRun\.exe\b") {
        return $true
    }

    if ($TaskPath -match "(?i)^\\Microsoft\\Windows\\NetTrace\\" -and
        $Actions -match "(?i)%windir%\\system32\\gatherNetworkInfo\.vbs\b|\\Windows\\system32\\gatherNetworkInfo\.vbs\b") {
        return $true
    }

    # v0.6.1+：不要只因为任务挂在 \Microsoft\Windows 下就直接白名单。
    # 真实攻击/挖矿常把任务伪装到 UpdateOrchestrator、WDI、Application Experience 等目录下。
    # 只要 Action 指向 ProgramData/AppData/Temp/Public/Downloads，或使用 powershell/wscript/mshta/bat/hta 等可疑执行链，必须继续分析。
    $actionLooksSuspicious = $false
    if ($Actions -match "(?i)\\ProgramData\\|\\Users\\[^\\]+\\AppData\\|\\Users\\Public\\|\\Windows\\Temp\\|\\Temp\\|\\Downloads\\") { $actionLooksSuspicious = $true }
    if ($Actions -match "(?i)\.(ps1|vbs|js|jse|wsf|hta|bat|cmd|scr)\b|powershell(\.exe)?|wscript(\.exe)?|cscript(\.exe)?|mshta(\.exe)?|-ExecutionPolicy|Bypass|WindowStyle\s+Hidden|-enc|-encodedcommand|stratum|xmrig|miner|c3pool") { $actionLooksSuspicious = $true }

    if ($actionLooksSuspicious) {
        return $false
    }

    if ($TaskPath -match "^\\Microsoft\\Windows\\") {
        if ($text -match "(?i)Windows Defender|Workplace Join|Application Experience|ApplicationData|AppxDeploymentClient|Autochk|DiskDiagnostic|NetTrace|GatherNetworkInfo|PLA|Server Manager|SharedPC|Software Inventory Logging|StateRepository|Time Zone|Windows Filtering Platform|WindowsUpdate|Shell|Registry|Bluetooth|CloudExperienceHost|Defrag|Diagnosis|Maps|MemoryDiagnostic|MobilePC|Power Efficiency Diagnostics|Ras|Servicing|Setup|Speech|TextServicesFramework|Time Synchronization|UpdateOrchestrator|WDI|WOF") {
            return $true
        }
    }

    if ($text -match "(?i)WpsUpdate|Kingsoft|ksolaunch\.exe|WPS Office") {
        return $true
    }

    return $false
}


function Test-IsTrustedServiceEvent {
    param(
        [string]$ServiceName,
        [string]$ImagePath
    )

    $text = "$ServiceName $ImagePath"

    if ($text -match "(?i)Microsoft Defender|MpDefenderCoreService|MpKsl|MicrosoftEdgeElevationService|Intel\(R\)|VMware VMCI|WPS Office Cloud Service|Printer Extensions|Kingsoft|KslD|Windows Defender") {
        return $true
    }

    # v0.6.3：Microsoft Update Health Tools 是 Windows 更新健康组件，避免作为新服务关注项刷屏。
    # 只对白名单路径降噪；如果同名服务出现在 ProgramData/AppData/Temp 等可疑路径，仍会进入后续风险判断。
    if ($ServiceName -match "(?i)^Microsoft Update Health Service$" -and
        $ImagePath -match "(?i)^`"?C:\\Program Files\\Microsoft Update Health Tools\\uhssvc\.exe`"?$") {
        return $true
    }

    # v0.6.6：Microsoft PC Manager Service 精细白名单。
    # 只对白名单 WindowsApps 路径降噪；同名服务若出现在 ProgramData/AppData/Temp，仍按可疑处理。
    if ($ServiceName -match "(?i)^Microsoft PC Manager Service$" -and
        $ImagePath -match "(?i)^`"?C:\\Program Files\\WindowsApps\\Microsoft\.MicrosoftPCManager_[^\\]+\\PCManager\\MSPCManagerService\.exe`"?$") {
        return $true
    }

    return $false
}


function Test-IsCoreWindowsProcess {
    param(
        [string]$Name,
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }

    $coreNames = @(
        "System Idle Process","System","Registry","smss.exe","csrss.exe","wininit.exe",
        "winlogon.exe","services.exe","lsass.exe","svchost.exe","fontdrvhost.exe",
        "WUDFHost.exe","spoolsv.exe","dwm.exe","sihost.exe","ctfmon.exe","taskhostw.exe",
        "AggregatorHost.exe","conhost.exe","unsecapp.exe","WmiPrvSE.exe"
    )

    if ($Name -notin $coreNames) { return $false }

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $true
    }

    if ($Path -match "(?i)^C:\\Windows\\System32\\|^C:\\Windows\\system32\\|^C:\\Windows\\SysWOW64\\") {
        return $true
    }

    return $false
}

function Test-IsTrustedVendorCommand {
    param([string]$Command)

    if ([string]::IsNullOrWhiteSpace($Command)) { return $false }

    $c = $Command.Trim()

    # 常见可信厂商 / 常驻项降噪。这里只对白名单命令做降级，不代表完全安全。
    if ($c -match "(?i)\\Kingsoft\\WPS Office\\|ksolaunch\.exe|photolaunch\.exe|WPS Office|\\Oray\\SunLogin\\|SunloginClient\.exe|sunlogin_guard\.exe|SecurityHealthSystray\.exe|AzureArcSysTray\.exe|HipsTray\.exe") {
        return $true
    }

    # OneDrive 默认启动项与升级清理 RunOnce 在干净 Windows 中很常见，避免刷屏。
    if ($c -match '(?i)\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive\.exe"?\s+/background') {
        return $true
    }
    if ($c -match '(?i)^"?C:\\Users\\[^\\]+\\AppData\\Local\\Microsoft\\OneDrive\\[^\\]+\\OneDriveLauncher\.exe"?\s+/startInstances\s*$') {
        return $true
    }
    if ($c -match '(?i)\\Windows\\system32\\cmd\.exe\s+/q\s+/c\s+(del|rmdir).+\\AppData\\Local\\Microsoft\\OneDrive\\') {
        return $true
    }
    if ($c -match '(?i)\\AppData\\Local\\Microsoft\\OneDrive\\(Update|StandaloneUpdater)\\OneDriveSetup\.exe') {
        return $true
    }
    if ($c -match '(?i)\\AppData\\Local\\Microsoft\\OneDrive\\[^\\]+\\OneDriveLauncher\.exe\b|\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive\.exe\b') {
        return $true
    }

    return $false
}


function Test-IsKnownPublicNetworkNoise {
    param(
        [string]$ProcessName,
        [string]$ProcessPath
    )

    $name = Safe-String $ProcessName
    $path = Safe-String $ProcessPath
    $text = "$name $path"

    # 常见 Windows / Microsoft 组件公网连接，默认从'公网连接明细'中降噪。
    # 这里只影响网络连接展示，不影响可疑进程、启动项、服务和挖矿配置判断。
    if ($text -match '(?i)MsMpEng\.exe|MpDefenderCoreService\.exe|SecurityHealthService\.exe|SearchApp\.exe|SkypeApp\.exe|OneDrive\.exe|MicrosoftEdge|msedge\.exe') {
        return $true
    }

    if ($path -match '(?i)^C:\\Windows\\SystemApps\\|^C:\\Program Files\\WindowsApps\\|^C:\\Program Files \(x86\)\\Microsoft\\|^C:\\Program Files\\Microsoft\\') {
        return $true
    }

    # svchost 公网连接在 Windows Update / Defender / 系统服务中较常见，默认降噪；
    # 若进程位于可疑目录或命令行可疑，会在资源异常模块中体现。
    if ($name -match '(?i)^svchost\.exe$' -and $path -match '(?i)^C:\\Windows\\') {
        return $true
    }

    return $false
}

function Test-IsScriptOrDangerPersistence {
    param([string]$Command)

    if ([string]::IsNullOrWhiteSpace($Command)) { return $false }

    if ($Command -match "(?i)\.(bat|cmd|ps1|vbs|js|jse|wsf|scr|hta)\b") { return $true }
    if ($Command -match "(?i)-enc|-encodedcommand|downloadstring|downloadfile|iex\s|invoke-expression|certutil.*-urlcache|bitsadmin|mshta|regsvr32.*scrobj|rundll32.*javascript|net\s+user|net\s+localgroup|add-localgroupmember|xmrig|miner|c3pool|stratum|monero") { return $true }

    return $false
}

function Get-ResourceTitle {
    param(
        [string]$Tags,
        [string]$RiskLevel
    )

    if ($Tags -match "挖矿|矿池|c3pool|xmrig|WinRing0") {
        return "发现疑似挖矿进程"
    }

    if ($Tags -match "CPU占用|内存占用") {
        return "发现资源占用异常进程"
    }

    return "发现可疑进程线索"
}

function Add-MiningCandidateDir {
    param(
        [System.Collections.Generic.List[string]]$List,
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return }

    try {
        $pathMatches = [regex]::Matches($Value, '[A-Za-z]:\\[^"''\s<>|]+')
        foreach ($m in $pathMatches) {
            $p = $m.Value.Trim().TrimEnd(',', ';', ')', ']')
            if ([string]::IsNullOrWhiteSpace($p)) { continue }

            $dir = ""
            if (Test-Path $p -PathType Container) {
                $dir = (Resolve-Path $p).Path
            }
            elseif (Test-Path $p -PathType Leaf) {
                $dir = Split-Path -Path (Resolve-Path $p).Path -Parent
            }
            else {
                # 文件可能已不存在，仍尝试从路径推断目录
                if ($p -match '\\') {
                    $dir = Split-Path -Path $p -Parent
                }
            }

            if (-not [string]::IsNullOrWhiteSpace($dir) -and (Test-Path $dir -PathType Container)) {
                # v0.6.2：候选目录进入队列前先做边界检查，避免把 C:\ProgramData\Microsoft\Windows、
                # Windows Defender 平台目录等过宽/系统目录拉进挖矿配置扫描。
                if (-not (Test-IsSafeMiningExpansionDir -Dir $dir)) { continue }

                if (-not $List.Contains($dir)) {
                    $List.Add($dir) | Out-Null
                }
            }
        }
    }
    catch {}
}

function Get-ShortContext {
    param(
        [string]$Text,
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Text) -or [string]::IsNullOrWhiteSpace($Value)) {
        return ""
    }

    try {
        $idx = $Text.IndexOf($Value)
        if ($idx -lt 0) { return "" }
        $start = [Math]::Max(0, $idx - 60)
        $len = [Math]::Min(220, $Text.Length - $start)
        return ($Text.Substring($start, $len) -replace "`r|`n", " ")
    }
    catch { return "" }
}

function Add-MiningConfigHit {
    param(
        [System.Collections.Generic.List[object]]$List,
        [string]$Type,
        [string]$Value,
        [string]$FilePath,
        [string]$SourceDir,
        [string]$Context,
        [string]$Confidence
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return }
    $cleanValue = $Value.Trim().Trim('"', "'", ',', ';')
    if ([string]::IsNullOrWhiteSpace($cleanValue)) { return }

    # 去重：同一个文件、同一值只保留一次，避免同一矿池同时以'矿池地址'和'矿池地址候选'重复出现。
    foreach ($x in $List) {
        if ($x.Value -eq $cleanValue -and $x.FilePath -eq $FilePath) {
            return
        }
    }

    $List.Add([PSCustomObject]@{
        Type       = $Type
        Value      = $cleanValue
        FilePath   = $FilePath
        SourceDir  = $SourceDir
        Confidence = $Confidence
        Context    = $Context
    }) | Out-Null
}


function Get-WinIRNormalizedIocValue {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return "" }
    $v = $Value.Trim().Trim('"', "'", ',', ';', ')', ']')

    # 去掉尾部路径中常见脚本/二进制下载文件名，仅用于归一化 host:port，不改变原始展示。
    try {
        if ($v -match '(?i)^(?:stratum\+(?:tcp|ssl)|ssl|tcp|http|https)://([^/\s"''<>;,]+)') {
            return $Matches[1].ToLower()
        }
        if ($v -match '(?i)^([a-z0-9][a-z0-9._-]+\.[a-z0-9.-]+:[0-9]{2,5})$') {
            return $Matches[1].ToLower()
        }
    } catch {}

    return $v.ToLower()
}

function Get-WinIRIocType {
    param(
        [string]$Value,
        [string]$Context
    )

    $v = Safe-String $Value
    $ctx = Safe-String $Context

    if ($v -match '(?i)^https?://') {
        # http(s) 默认不作为矿池，作为下载/投放 URL。后续如出现真实矿池 API，可人工研判。
        return "下载/投放URL候选"
    }

    if ($v -match '(?i)^stratum\+') { return "矿池地址" }

    if ($v -match '(?i)^(ssl|tcp)://') { return "矿池地址候选" }

    if ($ctx -match '(?i)downloadstring|downloadfile|certutil|bitsadmin|urlcache|curl|wget|invoke-webrequest|iwr|http://' -and
        $v -match '(?i)\.(exe|dll|ps1|bat|cmd|vbs|hta|js|jse|scr)(\b|$)') {
        return "下载/投放URL候选"
    }

    if ($v -match '(?i)pool|xmr|miner|relay|gateway|node|cdn|cache|sync|:[0-9]{2,5}') {
        return "矿池地址候选"
    }

    return "IOC候选"
}

function Add-WinIRIocHit {
    param(
        [System.Collections.Generic.List[object]]$List,
        [string]$Value,
        [string]$FilePath,
        [string]$SourceDir,
        [string]$Context,
        [string]$Confidence
    )

    $typ = Get-WinIRIocType -Value $Value -Context $Context
    Add-MiningConfigHit -List $List -Type $typ -Value $Value -FilePath $FilePath -SourceDir $SourceDir -Context $Context -Confidence $Confidence
}


function Add-MiningHitsFromText {
    param(
        [System.Collections.Generic.List[object]]$List,
        [string]$Text,
        [string]$FilePath,
        [string]$SourceDir
    )

    if ([string]::IsNullOrWhiteSpace($Text)) { return }

    # v0.6.4：更通用的矿池/钱包/矿工标识提取。
    # 目的：覆盖 ssl://、tcp://、http(s)://、key=value、.ini、.db、.bak、无扩展配置、ADS 等边缘情况。
    # 注意：该函数只在候选目录内执行，不做全盘扫描，降低误报与性能风险。

    foreach ($m in [regex]::Matches($Text, '(?i)\b((?:stratum\+(?:tcp|ssl)|ssl|tcp|http|https)://[a-z0-9][a-z0-9._-]+(?::[0-9]{2,5})?(?:/[^\s"''<>;,)]*)?)')) {
        $v = $m.Groups[1].Value.Trim().Trim('"', "'", ',', ';', ')', ']')
        if ([string]::IsNullOrWhiteSpace($v)) { continue }

        # http(s) 太容易误报，必须带矿池/中继/网关/节点/端口等上下文特征。
        if ($v -match '(?i)^https?://' -and $v -notmatch '(?i)pool|xmr|miner|stratum|relay|gateway|node|cdn|cache|wallet|:[0-9]{2,5}|lab\.invalid') {
            continue
        }

        $ctx = Get-ShortContext -Text $Text -Value $v
        $confidence = if ($v -match '(?i)^stratum\+|lab\.invalid|pool|xmr|miner|relay|gateway|node|:[0-9]{2,5}|\.(exe|dll|ps1|bat|cmd|vbs|hta|js)$') { "高" } else { "中" }

        Add-WinIRIocHit -List $List -Value $v -FilePath $FilePath -SourceDir $SourceDir -Context $ctx -Confidence $confidence
    }

    # key=value / key: value / JSON 字段。覆盖 pool_primary、pool_backup、endpoint、fallback、remote、mirror_endpoint 等。
    foreach ($m in [regex]::Matches($Text, '(?im)(?:"?(pool(?:_[a-z0-9-]+)?|url|endpoint|fallback|remote|primary|backup|server|host|proxy|mirror_endpoint)"?\s*[:=]\s*"?)([^"''#;\r\n,]+)')) {
        $v = $m.Groups[2].Value.Trim().Trim('"', "'", ',', ';')
        if ([string]::IsNullOrWhiteSpace($v)) { continue }

        if ($v -match '(?i)stratum|ssl://|tcp://|pool|xmr|miner|relay|gateway|node|cdn|cache|lab\.invalid|:[0-9]{2,5}') {
            $ctx = Get-ShortContext -Text $Text -Value $v
            $confidence = if ($v -match '(?i)^stratum\+|ssl://|tcp://|relay|gateway|node|pool|lab\.invalid|:[0-9]{2,5}|\.(exe|dll|ps1|bat|cmd|vbs|hta|js)$') { "高" } else { "中" }
            Add-WinIRIocHit -List $List -Value $v -FilePath $FilePath -SourceDir $SourceDir -Context $ctx -Confidence $confidence
        }
    }

    # 兜底 host:port：只在候选目录内抓取带 pool/xmr/relay/gateway/node/cdn/cache/sync 等上下文的 host:port。
    foreach ($m in [regex]::Matches($Text, '(?i)\b([a-z0-9][a-z0-9._-]*(?:pool|xmr|miner|relay|gateway|node|cdn|cache|sync)[a-z0-9._-]*\.[a-z0-9.-]+:[0-9]{2,5})\b')) {
        $v = $m.Groups[1].Value.Trim().Trim('"', "'", ',', ';', ')', ']')
        Add-MiningConfigHit -List $List -Type "矿池地址候选" -Value $v -FilePath $FilePath -SourceDir $SourceDir -Context (Get-ShortContext -Text $Text -Value $v) -Confidence "中"
    }

    # 钱包/矿工账号/Token 候选。真实 XMR 钱包仍由原有高置信规则处理，这里补足实验/配置中的长标识。
    foreach ($m in [regex]::Matches($Text, '(?im)(?:"?(user|wallet|account|worker|worker_id|mirror_wallet|token)"?\s*[:=]\s*"?|--user\s+|-u\s+)([A-Za-z0-9_.+\-]{24,220})')) {
        $v = $m.Groups[2].Value.Trim().Trim('"', "'", ',', ';')
        if ([string]::IsNullOrWhiteSpace($v)) { continue }
        if ($v -match '^(true|false|null|none|default)$') { continue }

        $typ = "钱包地址候选"
        $conf = "中"
        if ($v -match '^[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}$') { $typ = "钱包地址"; $conf = "高" }

        Add-MiningConfigHit -List $List -Type $typ -Value $v -FilePath $FilePath -SourceDir $SourceDir -Context (Get-ShortContext -Text $Text -Value $v) -Confidence $conf
    }
}



function Test-IsSafeMiningExpansionDir {
    param([string]$Dir)

    if ([string]::IsNullOrWhiteSpace($Dir)) { return $false }

    try {
        $d = $Dir.Trim().TrimEnd('\')
        if ([string]::IsNullOrWhiteSpace($d)) { return $false }

        # 不扫描过宽目录，避免全盘慢扫和误报
        $blockedExact = @(
            'C:',
            'C:\',
            'C:\Windows',
            'C:\Windows\System32',
            'C:\ProgramData',
            'C:\ProgramData\Microsoft',
            'C:\ProgramData\Microsoft\Windows',
            'C:\Program Files',
            'C:\Program Files (x86)',
            'C:\Users'
        )
        foreach ($b in $blockedExact) {
            if ($d.Equals($b, [System.StringComparison]::OrdinalIgnoreCase)) { return $false }
        }

        if ($d -match '(?i)^C:\\ProgramData\\Microsoft\\Windows Defender(\\|$)') { return $false }
        if ($d -match '(?i)^C:\\ProgramData\\Microsoft\\Windows\\Start Menu(\\|$)') { return $false }
        if ($d -match '^C:\\Users\\[^\\]+$') { return $false }
        if ($d -match '^C:\\Users\\[^\\]+\\AppData$') { return $false }
        if ($d -match '^C:\\Users\\[^\\]+\\AppData\\Local$') { return $false }
        if ($d -match '^C:\\Users\\[^\\]+\\AppData\\Roaming$') { return $false }
        if ($d -match '^C:\\Users\\[^\\]+\\AppData\\Local\\Microsoft$') { return $false }
        if ($d -match '^C:\\Users\\[^\\]+\\AppData\\Roaming\\Microsoft$') { return $false }

        # 允许 C:\ProgramData\某个具体子目录，例如 C:\ProgramData\WinIRLabV2
        if ($d -match '^C:\\ProgramData\\[^\\]+$') { return $true }

        # v0.6.4：允许 Public 下具体子目录作为候选镜像目录，但不允许 C:\Users\Public 根目录。
        if ($d -match '^C:\\Users\\Public\\[^\\]+$') { return $true }
        if ($d -match '^C:\\Users\\Public\\[^\\]+\\[^\\]+') { return $true }

        # v0.6.1：允许从可疑证据命中的 ProgramData 深层目录向上扩展到具体父目录，例如 Runtime/.telemetry -> UpdateHealth。
        # 仍然禁止 C:\ProgramData、C:\ProgramData\Microsoft 这类过宽目录。
        if ($d -match '^C:\\ProgramData\\[^\\]+\\[^\\]+') { return $true }

        # 允许 Public、Temp、Downloads 下的具体子目录
        if ($d -match '^C:\\Users\\Public\\[^\\]+$') { return $true }
        if ($d -match '^C:\\Windows\\Temp\\[^\\]+$') { return $true }
        if ($d -match '^C:\\Users\\[^\\]+\\Downloads\\[^\\]+$') { return $true }

        # 允许 AppData 下的非 Microsoft 具体应用目录，避免把 OneDrive/系统组件扩大扫描
        if ($d -match '^C:\\Users\\[^\\]+\\AppData\\(Local|Roaming)\\(?!Microsoft\\b)[^\\]+$') { return $true }

        return $false
    }
    catch { return $false }
}

function Test-IsSuspiciousPersistencePath {
    param([string]$PathOrCommand)

    if ([string]::IsNullOrWhiteSpace($PathOrCommand)) { return $false }

    if ($PathOrCommand -match "(?i)\\Users\\[^\\]+\\AppData\\|\\Users\\Public\\|\\Windows\\Temp\\|\\Temp\\|\\ProgramData\\|\\Downloads\\") {
        return $true
    }

    if ($PathOrCommand -match "(?i)\.(bat|cmd|ps1|vbs|js|jse|wsf|scr|hta)\b") {
        return $true
    }

    return $false
}


function Format-FileSize {
    param([Int64]$Bytes)

    if ($Bytes -ge 1GB) { return ("{0:N2} GB" -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ("{0:N2} MB" -f ($Bytes / 1MB)) }
    if ($Bytes -ge 1KB) { return ("{0:N2} KB" -f ($Bytes / 1KB)) }
    return "$Bytes B"
}

function Add-HashTarget {
    param(
        [System.Collections.Generic.List[string]]$Targets,
        [string]$InputPath
    )

    if ([string]::IsNullOrWhiteSpace($InputPath)) { return }

    $p = $InputPath.Trim().Trim('"', "'")
    if ([string]::IsNullOrWhiteSpace($p)) { return }

    try {
        $resolvedItems = @(Resolve-Path -Path $p -ErrorAction Stop)
        foreach ($ri in $resolvedItems) {
            $full = $ri.Path
            if (Test-Path $full -PathType Leaf) {
                if (-not $Targets.Contains($full)) { $Targets.Add($full) | Out-Null }
            }
        }
    }
    catch {
        Write-Warn "Hash 目标不存在或无法访问：$InputPath"
    }
}

function Invoke-HashCalculator {
    Write-Info "进入独立文件 Hash 计算模式..."

    Ensure-OutputDir

    $targets = New-Object System.Collections.Generic.List[string]

    foreach ($hf in $HashFile) {
        if ([string]::IsNullOrWhiteSpace($hf)) { continue }

        # 支持用户用分号分隔多个路径，也支持拖入带引号路径。
        foreach ($part in ($hf -split ';')) {
            Add-HashTarget -Targets $targets -InputPath $part
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($HashFolder)) {
        $folder = $HashFolder.Trim().Trim('"', "'")
        if (Test-Path $folder -PathType Container) {
            try {
                $gciParams = @{
                    Path        = $folder
                    File        = $true
                    ErrorAction = 'SilentlyContinue'
                }
                if ($HashRecurse) { $gciParams['Recurse'] = $true }

                foreach ($f in (Get-ChildItem @gciParams)) {
                    if (-not $targets.Contains($f.FullName)) { $targets.Add($f.FullName) | Out-Null }
                }
            }
            catch {
                Write-Warn "读取目录失败：$folder"
            }
        }
        else {
            Write-Warn "HashFolder 不是有效目录：$HashFolder"
        }
    }

    if ($HashOnly -and $targets.Count -eq 0) {
        Write-Host ""
        Write-Host "请粘贴或拖入要计算 Hash 的文件路径。" -ForegroundColor Cyan
        Write-Host "多个文件可以用英文分号 ; 分隔。直接回车结束。" -ForegroundColor DarkCyan
        $line = Read-Host "文件路径"
        if (-not [string]::IsNullOrWhiteSpace($line)) {
            foreach ($part in ($line -split ';')) {
                Add-HashTarget -Targets $targets -InputPath $part
            }
        }
    }

    if ($targets.Count -eq 0) {
        Write-Warn "未提供任何有效文件，Hash 计算结束。"
        return
    }

    $results = New-Object System.Collections.Generic.List[object]

    foreach ($file in $targets) {
        try {
            $item = Get-Item -Path $file -ErrorAction Stop
            foreach ($algo in $HashAlgorithm) {
                try {
                    $hash = (Get-FileHash -Path $item.FullName -Algorithm $algo -ErrorAction Stop).Hash
                    $results.Add([PSCustomObject]@{
                        FileName      = $item.Name
                        FullPath      = $item.FullName
                        SizeBytes     = $item.Length
                        SizeReadable  = Format-FileSize -Bytes $item.Length
                        CreationTime  = $item.CreationTime
                        LastWriteTime = $item.LastWriteTime
                        Algorithm     = $algo
                        HashUpper     = $hash.ToUpper()
                        HashLower     = $hash.ToLower()
                    }) | Out-Null
                }
                catch {
                    Write-Warn "计算失败：$($item.FullName) / $algo"
                }
            }
        }
        catch {
            Write-Warn "无法读取文件：$file"
        }
    }

    if ($results.Count -eq 0) {
        Write-Warn "没有成功生成 Hash 结果。"
        return
    }

    $csvPath = Join-Path $script:OutputDir "文件Hash计算结果.csv"
    $txtPath = Join-Path $script:OutputDir "文件Hash计算结果.txt"

    try {
        $results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    }
    catch {
        Write-Warn "导出 CSV 失败：$csvPath"
    }

    try {
        $lines = New-Object System.Collections.Generic.List[string]
        $lines.Add("WinIR-Helper $Version 文件 Hash 计算结果") | Out-Null
        $lines.Add("生成时间：$(Get-Date)") | Out-Null
        $lines.Add("文件数量：$($targets.Count)") | Out-Null
        $lines.Add("") | Out-Null

        foreach ($r in $results) {
            $lines.Add("文件名：$($r.FileName)") | Out-Null
            $lines.Add("路径：$($r.FullPath)") | Out-Null
            $lines.Add("大小：$($r.SizeReadable) ($($r.SizeBytes) bytes)") | Out-Null
            $lines.Add("算法：$($r.Algorithm)") | Out-Null
            $lines.Add("Hash 大写：$($r.HashUpper)") | Out-Null
            $lines.Add("hash 小写：$($r.HashLower)") | Out-Null
            $lines.Add("创建时间：$($r.CreationTime)") | Out-Null
            $lines.Add("修改时间：$($r.LastWriteTime)") | Out-Null
            $lines.Add("-" * 80) | Out-Null
        }

        $lines | Out-File -FilePath $txtPath -Encoding UTF8
    }
    catch {
        Write-Warn "导出 TXT 失败：$txtPath"
    }

    Write-Host ""
    Write-Ok "Hash 计算完成。"
    Write-Host "CSV：$csvPath"
    Write-Host "TXT：$txtPath"
    Write-Host ""
    $results | Format-Table FileName, Algorithm, SizeReadable, HashUpper -AutoSize
}


# =========================================================
# 独立文件 Hash 计算模式
# =========================================================

if ($HashOnly -or $HashFile.Count -gt 0 -or -not [string]::IsNullOrWhiteSpace($HashFolder)) {
    Invoke-HashCalculator
    return
}

# =========================================================
# 初始化
# =========================================================

$IsAdmin = Test-IsAdmin

if (-not $IsAdmin -and -not $AllowNonAdmin) {
    Write-Warn "当前 PowerShell 不是管理员权限，部分日志和系统信息可能无法读取。"
    Write-Warn "建议右键 PowerShell，选择「以管理员身份运行」。"
    Write-Warn "如确实要继续，可运行：.\$ScriptName -AllowNonAdmin"
    exit
}

Get-TimeWindow
Ensure-OutputDir

$Findings = New-Object System.Collections.Generic.List[object]
$Scenarios = New-Object System.Collections.Generic.List[object]

Write-Host ""
Write-Host "=============================================" -ForegroundColor DarkCyan
Write-Host " WinIR-Helper $Version" -ForegroundColor Green
Write-Host " 攻击场景聚合分析版" -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor DarkCyan
Write-Host "扫描范围：$StartTime ~ $EndTime"
Write-Host "重点排查：$FocusStartTime ~ $EndTime"
Write-Host "输出目录：$OutputDir"
Write-Host "详细 CSV：$($ExportDetails.IsPresent)"
Write-Host ""

# =========================================================
# 模块 1：Windows 安全事件
# =========================================================

Write-Info "正在分析 Windows 安全事件..."

$SecurityEventIds = @(4624,4625,4634,4648,4672,4720,4726,4732,4698,1102)
$SecurityEventsRaw = Get-EventsById -LogName "Security" -Ids $SecurityEventIds
$SecurityEvents = @()

foreach ($evt in $SecurityEventsRaw) {
    try {
        [xml]$xml = $evt.ToXml()
        $msg = $evt.Message

        $subjectUser = Get-EventDataValue -Xml $xml -Name "SubjectUserName"
        $targetUser  = Get-EventDataValue -Xml $xml -Name "TargetUserName"
        $memberName  = Get-EventDataValue -Xml $xml -Name "MemberName"
        $targetSid   = Get-EventDataValue -Xml $xml -Name "TargetSid"
        $memberSid   = Get-EventDataValue -Xml $xml -Name "MemberSid"
        $ip          = Get-EventDataValue -Xml $xml -Name "IpAddress"
        $port        = Get-EventDataValue -Xml $xml -Name "IpPort"
        $logonType   = Get-EventDataValue -Xml $xml -Name "LogonType"
        $status      = Get-EventDataValue -Xml $xml -Name "Status"
        $subStatus   = Get-EventDataValue -Xml $xml -Name "SubStatus"
        $authPackage = Get-EventDataValue -Xml $xml -Name "AuthenticationPackageName"
        $targetDomain = Get-EventDataValue -Xml $xml -Name "TargetDomainName"
        $workstation  = Get-EventDataValue -Xml $xml -Name "WorkstationName"
        if (-not $workstation) { $workstation = Get-EventDataValue -Xml $xml -Name "Workstation" }

        if ([string]::IsNullOrWhiteSpace($targetUser)) { $targetUser = $subjectUser }

        $failureReason = ""
        if ($evt.Id -eq 4625) {
            $failureReason = Get-EventMessageValue -Message $msg -FieldName "Failure Reason"
        }

        $eventType = switch ($evt.Id) {
            4624 { "登录成功" }
            4625 { "登录失败" }
            4634 { "账户注销" }
            4648 { "显式凭据登录" }
            4672 { "特权登录" }
            4720 { "创建用户" }
            4726 { "删除用户" }
            4732 { "加入本地组" }
            4698 { "创建计划任务" }
            1102 { "安全日志被清除" }
            default { "安全事件" }
        }

        $SecurityEvents += [PSCustomObject]@{
            TimeCreated   = $evt.TimeCreated
            EventID       = $evt.Id
            EventType     = $eventType
            RecordID      = $evt.RecordId
            Computer      = $evt.MachineName
            SubjectUser   = $subjectUser
            TargetUser    = $targetUser
            TargetDomain  = $targetDomain
            WorkstationName = $workstation
            MemberName    = $memberName
            TargetSid     = $targetSid
            MemberSid     = $memberSid
            LogonType     = $logonType
            LogonTypeDesc = Get-LogonTypeDesc -LogonType $logonType
            SourceIP      = $ip
            SourcePort    = $port
            FailureReason = $failureReason
            Status        = $status
            SubStatus     = $subStatus
            AuthPackage   = $authPackage
        }
    }
    catch {}
}

$SecuritySummary = $SecurityEvents |
    Group-Object EventID, EventType |
    Sort-Object Count -Descending |
    ForEach-Object {
        $first = $_.Group | Select-Object -First 1
        [PSCustomObject]@{
            EventID   = $first.EventID
            EventType = $first.EventType
            Count     = $_.Count
        }
    }

Export-DetailCsv -Name "安全事件明细.csv" -Data $SecurityEvents
Export-DetailCsv -Name "安全事件统计.csv" -Data $SecuritySummary

# 登录失败与成功
$FailedLogons = $SecurityEvents | Where-Object { $_.EventID -eq 4625 }
$SuccessfulLogons = $SecurityEvents | Where-Object { $_.EventID -eq 4624 }

# 4625 有时没有标准来源 IP，尤其是本机 IPC$、本地服务或部分虚拟机测试场景。
# 因此除 IP Top 外，额外生成登录失败明细与'来源/用户/类型'聚合，避免用户误以为没有失败登录。
$FailedLogonDetails = @()
foreach ($f in ($FailedLogons | Sort-Object TimeCreated)) {
    $srcIp = Safe-String $f.SourceIP
    $workstationName = Safe-String $f.WorkstationName
    $srcDisplay = ""

    if ($srcIp -and $srcIp -notin @("-","127.0.0.1","::1")) {
        $srcDisplay = "IP:$srcIp"
    }
    elseif ($workstationName -and $workstationName -ne "-") {
        $srcDisplay = "Workstation:$workstationName"
    }
    elseif ($srcIp -in @("127.0.0.1","::1")) {
        $srcDisplay = "Localhost:$srcIp"
    }
    else {
        $srcDisplay = "NoSourceIP"
    }

    $FailedLogonDetails += [PSCustomObject]@{
        TimeCreated     = $f.TimeCreated
        Source          = $srcDisplay
        SourceIP        = $f.SourceIP
        WorkstationName = $f.WorkstationName
        TargetUser      = $f.TargetUser
        TargetDomain    = $f.TargetDomain
        LogonType       = $f.LogonType
        LogonTypeDesc   = $f.LogonTypeDesc
        SourcePort      = $f.SourcePort
        FailureReason   = $f.FailureReason
        Status          = $f.Status
        SubStatus       = $f.SubStatus
        AuthPackage     = $f.AuthPackage
        RecordID        = $f.RecordID
    }
}

$FailedByIdentity = $FailedLogonDetails |
    Group-Object Source,TargetUser,LogonTypeDesc |
    Sort-Object Count -Descending |
    ForEach-Object {
        $items = $_.Group | Sort-Object TimeCreated
        $first = $items | Select-Object -First 1
        $last  = $items | Select-Object -Last 1
        [PSCustomObject]@{
            Source          = $first.Source
            FailedCount     = $_.Count
            AttackStartTime = $first.TimeCreated
            LastFailTime    = $last.TimeCreated
            DurationMinutes = [Math]::Round((New-TimeSpan -Start $first.TimeCreated -End $last.TimeCreated).TotalMinutes, 2)
            TargetUser      = $first.TargetUser
            TargetDomain    = $first.TargetDomain
            LogonTypeDesc   = $first.LogonTypeDesc
            FailureReasons  = (($items.FailureReason | Where-Object { $_ } | Sort-Object -Unique) -join ";")
            StatusCodes     = (($items.Status | Where-Object { $_ } | Sort-Object -Unique) -join ";")
            Workstations    = (($items.WorkstationName | Where-Object { $_ } | Sort-Object -Unique) -join ";")
            Note            = if ($first.Source -eq "NoSourceIP") { "4625 未解析到来源 IP，建议结合 WorkstationName、LogonType 和安全日志原文复核。" } else { "" }
        }
    }

$FailedByIP = $FailedLogons |
    Where-Object { $_.SourceIP -and $_.SourceIP -ne "-" -and $_.SourceIP -ne "::1" -and $_.SourceIP -ne "127.0.0.1" } |
    Group-Object SourceIP |
    Sort-Object Count -Descending |
    ForEach-Object {
        $currentIP = $_.Name
        $items = $_.Group | Sort-Object TimeCreated
        $firstFail = $items | Select-Object -First 1
        $lastFail  = $items | Select-Object -Last 1

        $ports = $items.SourcePort | Where-Object { $_ -match "^\d+$" } | ForEach-Object { [int]$_ }
        $minPort = ""
        $maxPort = ""
        if ($ports.Count -gt 0) {
            $minPort = ($ports | Measure-Object -Minimum).Minimum
            $maxPort = ($ports | Measure-Object -Maximum).Maximum
        }

        $topMethod = ($items | Group-Object LogonTypeDesc | Sort-Object Count -Descending | Select-Object -First 1).Name

        $successAfter = $SuccessfulLogons |
            Where-Object { $_.SourceIP -eq $currentIP -and $_.TimeCreated -ge $firstFail.TimeCreated } |
            Sort-Object TimeCreated |
            Select-Object -First 1

        [PSCustomObject]@{
            SourceIP          = $currentIP
            FailedCount       = $_.Count
            AttackStartTime   = $firstFail.TimeCreated
            LastFailTime      = $lastFail.TimeCreated
            DurationMinutes   = [Math]::Round((New-TimeSpan -Start $firstFail.TimeCreated -End $lastFail.TimeCreated).TotalMinutes, 2)
            TargetUsers       = (($items.TargetUser | Where-Object { $_ } | Sort-Object -Unique) -join ";")
            TargetUserCount   = ($items.TargetUser | Where-Object { $_ } | Sort-Object -Unique).Count
            MainLogonMethod   = $topMethod
            LogonMethods      = (($items.LogonTypeDesc | Where-Object { $_ } | Sort-Object -Unique) -join ";")
            SourcePortRange   = if ($minPort -ne "" -and $maxPort -ne "") { "$minPort-$maxPort" } else { "" }
            Reasons           = (($items.FailureReason | Where-Object { $_ } | Sort-Object -Unique) -join ";")
            FirstSuccessTime  = if ($successAfter) { $successAfter.TimeCreated } else { "" }
            FirstSuccessUser  = if ($successAfter) { $successAfter.TargetUser } else { "" }
            FirstSuccessType  = if ($successAfter) { $successAfter.LogonTypeDesc } else { "" }
            AttackJudgement   = if ($successAfter) { "失败后出现同源登录成功，疑似爆破成功，需要重点复核" } else { "仅发现失败登录，疑似爆破尝试" }
        }
    }

Export-DetailCsv -Name "登录失败来源IP统计.csv" -Data $FailedByIP
Export-DetailCsv -Name "登录失败明细.csv" -Data $FailedLogonDetails
Export-DetailCsv -Name "登录失败按来源用户聚合.csv" -Data $FailedByIdentity

# 减少 4648 / 4672 噪音，只保留有实际意义的事件
foreach ($evt in ($SecurityEvents | Where-Object { $_.EventID -in @(1102,4720,4726,4732,4698,4648,4672) })) {
    # 重点关注项默认只展示最近 FocusDays 天内的安全事件，避免 -Days 1000 时历史事件刷屏。
    if (-not (Test-IsInFocusWindow -Time $evt.TimeCreated)) { continue }

    if ($evt.EventID -eq 4672) {
        if (Test-IsNoiseUser -User $evt.TargetUser) { continue }
        if ([string]::IsNullOrWhiteSpace($evt.SourceIP) -or $evt.SourceIP -eq "-") { continue }
    }

    if ($evt.EventID -eq 4648) {
        if (Test-IsNoiseUser -User $evt.TargetUser) { continue }
        if ($evt.SourceIP -in @("-","127.0.0.1","::1")) { continue }
    }

    if ($evt.EventID -eq 4720) {
        if ($evt.TargetUser -in @("WDAGUtilityAccount","DefaultAccount")) { continue }
    }

    if ($evt.EventID -eq 4732) {
        # 只将管理员组 / 远程桌面组变更放入重点关注；Users / IIS_IUSRS 这类普通组不刷屏
        if ($evt.TargetUser -notmatch "(?i)Administrators|Remote Desktop Users|管理员|远程桌面用户") {
            continue
        }
    }

    $level = switch ($evt.EventID) {
        1102 { "高危" }
        4720 { "高危" }
        4732 { "高危" }
        4726 { "中危" }
        4698 { "中危" }
        4648 { "关注" }
        4672 { "关注" }
        default { "关注" }
    }

    $detail = "时间=$($evt.TimeCreated)，EventID=$($evt.EventID)，用户=$($evt.TargetUser)"
    if ($evt.MemberName) { $detail += "，成员=$($evt.MemberName)" }
    if ($evt.SubjectUser) { $detail += "，操作者=$($evt.SubjectUser)" }
    if ($evt.SourceIP) { $detail += "，来源IP=$($evt.SourceIP)" }

    Add-Finding -Level $level -Category "Windows 安全事件" -Title $evt.EventType `
        -Evidence $detail `
        -Suggestion "结合事件上下文、登录来源、管理员组成员、计划任务和服务安装记录进行人工复核。"
}

# =========================================================
# 模块 2：RDP 事件
# =========================================================

Write-Info "正在分析 RDP 相关事件..."

$RdpEvents = @()

$rdpRaw1 = Get-EventsById -LogName "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" -Ids @(1149)
$rdpRaw2 = Get-EventsById -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" -Ids @(21,24,25)

foreach ($evt in @($rdpRaw1 + $rdpRaw2)) {
    try {
        [xml]$xml = $evt.ToXml()
        $msg = $evt.Message

        $user = Get-EventDataValue -Xml $xml -Name "User"
        if (-not $user) { $user = Get-EventDataByIndex -Xml $xml -Index 0 }

        $domain = Get-EventDataValue -Xml $xml -Name "Domain"
        if (-not $domain) { $domain = Get-EventDataByIndex -Xml $xml -Index 1 }

        $addr = Get-EventDataValue -Xml $xml -Name "Address"
        if (-not $addr) { $addr = Get-EventDataValue -Xml $xml -Name "ClientAddress" }
        if (-not $addr) { $addr = Get-EventDataByIndex -Xml $xml -Index 2 }

        if ($msg -match "(\d{1,3}\.){3}\d{1,3}") {
            $addr = $matches[0]
        }

        $desc = switch ($evt.Id) {
            1149 { "RDP_Auth_Success" }
            21   { "RDP_Connect_Success" }
            24   { "RDP_Disconnect" }
            25   { "RDP_Reconnect_Success" }
            default { "RDP_Event" }
        }

        $RdpEvents += [PSCustomObject]@{
            TimeCreated = $evt.TimeCreated
            EventID     = $evt.Id
            UserName    = $user
            Domain      = $domain
            Address     = $addr
            Description = $desc
            Message     = $msg
        }
    }
    catch {}
}

Export-DetailCsv -Name "RDP事件.csv" -Data $RdpEvents

# =========================================================
# 模块 3：服务安装 7045
# =========================================================

Write-Info "正在分析服务安装事件 7045..."

$ServiceEvents = @()
$raw7045 = Get-EventsById -LogName "System" -Ids @(7045)

foreach ($evt in $raw7045) {
    try {
        [xml]$xml = $evt.ToXml()
        $serviceName = Get-EventDataValue -Xml $xml -Name "ServiceName"
        $imagePath   = Get-EventDataValue -Xml $xml -Name "ImagePath"
        $accountName = Get-EventDataValue -Xml $xml -Name "AccountName"

        if (-not $serviceName) { $serviceName = Get-EventMessageValue -Message $evt.Message -FieldName "Service Name" }
        if (-not $imagePath)   { $imagePath   = Get-EventMessageValue -Message $evt.Message -FieldName "Service File Name" }

        $riskLevel = "关注"
        $riskReason = "新服务安装，需要确认来源"

        if (Test-IsTrustedServiceEvent -ServiceName $serviceName -ImagePath $imagePath) {
            $riskLevel = "正常"
            $riskReason = "常见系统/厂商服务，默认不进入重点关注项"
        }
        elseif ("$serviceName $imagePath" -match "(?i)c3pool|xmrig|miner|WinRing0|nssm|monero|stratum") {
            $riskLevel = "高危"
            $riskReason = "服务名或路径命中挖矿/驱动/服务持久化特征"
        }
        elseif (Test-IsSuspiciousPersistencePath -PathOrCommand $imagePath) {
            $riskLevel = "高危"
            $riskReason = "服务路径位于用户目录/临时目录/可疑路径"
        }
        elseif ($serviceName -match "^[a-z]{6,12}$" -and $imagePath -match "(?i)\\system32\\drivers\\.*\.sys") {
            $riskLevel = "中危"
            $riskReason = "随机命名驱动服务，需要复核签名与来源"
        }

        $item = [PSCustomObject]@{
            Level       = $riskLevel
            TimeCreated = $evt.TimeCreated
            ServiceName = $serviceName
            ImagePath   = $imagePath
            AccountName = $accountName
            Reason      = $riskReason
        }

        $ServiceEvents += $item

        if ($riskLevel -ne "正常") {
            Add-Finding -Level $riskLevel -Category "服务安装" -Title "发现服务安装线索" `
                -Evidence "时间=$($item.TimeCreated)，服务=$($item.ServiceName)，路径=$($item.ImagePath)，原因=$($item.Reason)" `
                -Suggestion "重点检查服务文件签名、Hash、创建时间、是否由计划任务/脚本安装。若与挖矿目录或 nssm 相关，应优先处置。"
        }
    }
    catch {}
}

Export-DetailCsv -Name "7045_服务安装事件.csv" -Data $ServiceEvents

# =========================================================
# 模块 4：账户、管理员组、远程桌面组、隐藏账户
# =========================================================

Write-Info "正在检查本地用户、管理员组、远程桌面用户组与隐藏账户..."

function Test-AccountNameInMembers {
    param(
        [string]$AccountName,
        [object[]]$Members
    )

    if ([string]::IsNullOrWhiteSpace($AccountName)) { return $false }

    $escaped = [regex]::Escape($AccountName)
    foreach ($m in $Members) {
        $n = [string]$m.Name
        if ($n -match "(?i)(^|\\)$escaped$") { return $true }
        if ($n -ieq $AccountName) { return $true }
    }

    return $false
}

function Get-AccountRid {
    param([object]$Sid)
    try {
        $s = [string]$Sid
        if ($s -match '-(\d+)$') { return [int]$Matches[1] }
    } catch {}
    return $null
}

$CurrentUserName = [Environment]::UserName

$LocalUsers = @()
try {
    $LocalUsers = Get-LocalUser -ErrorAction Stop | ForEach-Object {
        [PSCustomObject]@{
            Name                   = $_.Name
            Enabled                = $_.Enabled
            SID                    = $_.SID
            RID                    = Get-AccountRid -Sid $_.SID
            LastLogon              = $_.LastLogon
            PasswordLastSet        = $_.PasswordLastSet
            PasswordExpires        = $_.PasswordExpires
            PasswordRequired       = $_.PasswordRequired
            PasswordNeverExpires   = $_.PasswordNeverExpires
            UserMayChangePassword = $_.UserMayChangePassword
            AccountExpires         = $_.AccountExpires
            Description            = $_.Description
        }
    }
}
catch {}

$AdminMembers = @()
foreach ($g in @("Administrators","管理员")) {
    try {
        $AdminMembers = Get-LocalGroupMember -Group $g -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                Group           = $g
                Name            = $_.Name
                ObjectClass     = $_.ObjectClass
                PrincipalSource = $_.PrincipalSource
                SID             = $_.SID
            }
        }
        if ($AdminMembers.Count -gt 0) { break }
    }
    catch {}
}

$RdpMembers = @()
foreach ($g in @("Remote Desktop Users","远程桌面用户")) {
    try {
        $RdpMembers = Get-LocalGroupMember -Group $g -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                Group           = $g
                Name            = $_.Name
                ObjectClass     = $_.ObjectClass
                PrincipalSource = $_.PrincipalSource
                SID             = $_.SID
            }
        }
        if ($RdpMembers.Count -gt 0) { break }
    }
    catch {}
}

$HiddenAccounts = @()
try {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
    if (Test-Path $regPath) {
        $props = Get-ItemProperty -Path $regPath
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -notmatch "^PS") {
                $HiddenAccounts += [PSCustomObject]@{
                    Account  = $p.Name
                    Value    = $p.Value
                    RegPath  = $regPath
                    Meaning  = if ([int]$p.Value -eq 0) { "隐藏登录界面账户" } else { "显示/非隐藏或异常值，需复核" }
                }

                Add-Finding -Level "高危" -Category "账户检查" -Title "发现 Winlogon 隐藏账户注册表项" `
                    -Evidence "账户=$($p.Name)，值=$($p.Value)，路径=$regPath" `
                    -Suggestion "确认该账户是否为攻击者隐藏账户；检查管理员组、远程桌面用户组、登录日志与创建账户事件。"
            }
        }
    }
}
catch {}

$AccountSecurityEvents = $SecurityEvents |
    Where-Object { $_.EventID -in @(4720,4722,4723,4724,4725,4726,4728,4732,4738,4739,4740,4648,4672,1102) } |
    Sort-Object TimeCreated |
    Select-Object TimeCreated,EventID,EventType,SubjectUser,TargetUser,MemberName,TargetDomain,TargetSid,MemberSid,LogonTypeDesc,SourceIP,WorkstationName,Status,SubStatus

$SuspiciousUsers = @()
foreach ($u in $LocalUsers) {
    $reasons = New-Object System.Collections.Generic.List[string]
    $score = 0

    $isHidden = $false
    foreach ($h in $HiddenAccounts) {
        if ($h.Account -ieq $u.Name) { $isHidden = $true; break }
    }

    $isAdmin = Test-AccountNameInMembers -AccountName $u.Name -Members $AdminMembers
    $isRdp   = Test-AccountNameInMembers -AccountName $u.Name -Members $RdpMembers
    $isCurrentUser = ($u.Name -ieq $CurrentUserName)
    $rid = Get-AccountRid -Sid $u.SID
    $isBuiltInAdministrator = ($rid -eq 500 -or $u.Name -match '(?i)^administrator$')
    $isBuiltInGuestOrSystem = ($rid -in @(501,503,504) -or $u.Name -match '(?i)^(Guest|DefaultAccount|WDAGUtilityAccount)$')
    $suspiciousName = ($u.Name -match '(?i)(hack|hacker|backdoor|shadow|shell|support|backup|svc_|admin\d+|system\d+|\$$)')

    # v0.6.8：本地管理员组成员本身不是恶意。Might 这种当前用户属于管理员组属于正常场景，只在'管理员组成员'表展示。
    # 只有和隐藏账户、可疑命名、远程桌面组、异常密码策略等组合出现时，才进入'可疑本地账户'。
    if ($suspiciousName) {
        $reasons.Add("用户名命中可疑模式") | Out-Null
        $score += 3
    }

    if ($isHidden) {
        $reasons.Add("存在 Winlogon SpecialAccounts\\UserList 隐藏账户项") | Out-Null
        $score += 6
    }

    if ($isRdp -and -not $isCurrentUser) {
        $reasons.Add("属于远程桌面用户组") | Out-Null
        $score += 3
    }

    if ($isAdmin -and ($suspiciousName -or $isHidden -or $isRdp)) {
        $reasons.Add("可疑账户同时属于本地管理员组") | Out-Null
        $score += 4
    }

    if ($isBuiltInAdministrator -and $u.Enabled -eq $true) {
        $reasons.Add("内置 Administrator 账户已启用") | Out-Null
        $score += 2
    }

    if ($u.Enabled -eq $true -and $u.PasswordNeverExpires -eq $true -and ($suspiciousName -or $isHidden -or $isRdp -or ($isAdmin -and -not $isCurrentUser -and -not $isBuiltInAdministrator))) {
        $reasons.Add("可疑账户启用且密码永不过期") | Out-Null
        $score += 1
    }

    if ($u.Enabled -eq $true -and $u.UserMayChangePassword -eq $false -and ($suspiciousName -or $isHidden -or $isRdp)) {
        $reasons.Add("可疑账户启用且用户不可改密码") | Out-Null
        $score += 1
    }

    # 过滤常见内置/正常账户：
    # 1. 禁用的内置 Administrator 不进入可疑账户；
    # 2. 当前登录用户仅因管理员组或描述为空不进入可疑账户；
    # 3. Guest / DefaultAccount / WDAGUtilityAccount 等系统账户不因内置属性进入可疑账户。
    if ($isBuiltInAdministrator -and $u.Enabled -eq $false -and -not $isHidden) {
        $reasons.Clear()
        $score = 0
    }

    if ($isCurrentUser -and -not $isHidden -and -not $suspiciousName -and -not $isRdp) {
        $reasons.Clear()
        $score = 0
    }

    if ($isBuiltInGuestOrSystem -and -not $isHidden -and -not $suspiciousName) {
        $reasons.Clear()
        $score = 0
    }

    if ($reasons.Count -gt 0) {
        $level = if ($isHidden -or ($isAdmin -and $suspiciousName)) { "高危" }
                 elseif ($isRdp -or $score -ge 4) { "中危" }
                 else { "关注" }

        $SuspiciousUsers += [PSCustomObject]@{
            Level                  = $level
            Name                   = $u.Name
            Enabled                = $u.Enabled
            Score                  = $score
            Reasons                = ($reasons -join ";")
            IsHidden               = $isHidden
            IsAdmin                = $isAdmin
            IsRemoteDesktopUser    = $isRdp
            IsCurrentUser          = $isCurrentUser
            IsBuiltIn              = ($isBuiltInAdministrator -or $isBuiltInGuestOrSystem)
            LastLogon              = $u.LastLogon
            PasswordLastSet        = $u.PasswordLastSet
            PasswordNeverExpires   = $u.PasswordNeverExpires
            UserMayChangePassword = $u.UserMayChangePassword
            Description            = $u.Description
            SID                    = $u.SID
        }

        Add-Finding -Level $level -Category "账户检查" -Title "发现可疑本地账户 / 权限组合" `
            -Evidence "用户=$($u.Name)，评分=$score，原因=$($reasons -join ';')，隐藏=$isHidden，管理员组=$isAdmin，远程桌面组=$isRdp，当前用户=$isCurrentUser，最近登录=$($u.LastLogon)，描述=$($u.Description)" `
            -Suggestion "确认账户来源、创建时间、所属组、最近登录和业务归属。若为未知账户且属于管理员或远程桌面用户组，应优先禁用、留证并复核创建事件。"
    }
}

# v0.6.8：如果 SpecialAccounts\UserList 中存在账户名，但 Get-LocalUser 未枚举到，也要作为'隐藏账户残留/幽灵项'单独进入可疑账户表。
foreach ($h in $HiddenAccounts) {
    $exists = $false
    foreach ($u in $LocalUsers) {
        if ($u.Name -ieq $h.Account) { $exists = $true; break }
    }

    if (-not $exists) {
        $SuspiciousUsers += [PSCustomObject]@{
            Level                  = "高危"
            Name                   = $h.Account
            Enabled                = "Unknown"
            Score                  = 6
            Reasons                = "Winlogon 隐藏账户注册表项存在，但 Get-LocalUser 未枚举到账户；可能是残留项、创建失败或异常隐藏痕迹"
            IsHidden               = $true
            IsAdmin                = "Unknown"
            IsRemoteDesktopUser    = "Unknown"
            IsCurrentUser          = $false
            IsBuiltIn              = $false
            LastLogon              = ""
            PasswordLastSet        = ""
            PasswordNeverExpires   = ""
            UserMayChangePassword = ""
            Description            = ""
            SID                    = ""
        }

        Add-Finding -Level "高危" -Category "账户检查" -Title "发现隐藏账户注册表残留 / 未枚举账户" `
            -Evidence "账户=$($h.Account)，路径=$($h.RegPath)，Get-LocalUser 未枚举到该账户" `
            -Suggestion "复核该隐藏账户是否已被删除但注册表残留，或是否存在异常隐藏/枚举绕过情况；建议导出注册表项并检查 SAM、事件日志和管理员组变化。"
    }
}

Export-DetailCsv -Name "本地用户.csv" -Data $LocalUsers
Export-DetailCsv -Name "管理员组成员.csv" -Data $AdminMembers
Export-DetailCsv -Name "远程桌面用户组成员.csv" -Data $RdpMembers
Export-DetailCsv -Name "Winlogon隐藏账户.csv" -Data $HiddenAccounts
Export-DetailCsv -Name "可疑本地账户.csv" -Data $SuspiciousUsers
Export-DetailCsv -Name "账户相关安全事件.csv" -Data $AccountSecurityEvents

# =========================================================
# 模块 5：计划任务、启动项
# =========================================================

Write-Info "正在检查计划任务与启动项..."

$SuspiciousPathRegex = "(?i)\\Users\\[^\\]+\\AppData\\|\\Users\\Public\\|\\Windows\\Temp\\|\\Temp\\|\\ProgramData\\|\\Downloads\\"
$DangerCommandRegex  = "(?i)-enc|-encodedcommand|frombase64string|downloadstring|downloadfile|iex\s|invoke-expression|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b|new-object\s+net\.webclient|certutil.*-urlcache|bitsadmin|mshta|regsvr32.*scrobj|rundll32.*javascript|schtasks\s+/create|net\s+user|net\s+localgroup|add-localgroupmember|set-mppreference|disableantispyware|bypass|hidden|nop|http://|https://|xmrig|miner|c3pool|stratum|monero"

$Tasks = @()
try {
    $Tasks = Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
        $actions = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join " || "
        [PSCustomObject]@{
            TaskName = $_.TaskName
            TaskPath = $_.TaskPath
            State    = $_.State
            Author   = $_.Author
            Actions  = $actions
        }
    }
}
catch {}

$SuspiciousTasks = @()
foreach ($t in $Tasks) {
    if (Test-IsBuiltinTask -TaskPath $t.TaskPath -Actions $t.Actions) { continue }

    $reason = @()
    if ($t.Actions -match $DangerCommandRegex) { $reason += "命令行动作可疑" }
    if (Test-IsSuspiciousPersistencePath -PathOrCommand $t.Actions) { $reason += "执行路径位于可疑目录或脚本类型" }
    if ("$($t.TaskPath)$($t.TaskName)" -match "(?i)^\\Microsoft\\Windows\\(UpdateOrchestrator|WDI|Application Experience)\\" -and
        $t.TaskName -notmatch "(?i)^(Schedule Scan|Schedule Retry Scan|USO_UxBroker|Reboot|Refresh Settings|Maintenance Install|PcaPatchDbTask|ProgramDataUpdater|Microsoft Compatibility Appraiser)$") {
        $reason += "任务伪装在 Microsoft\\Windows 系统路径下但名称/动作需要复核"
    }

    if ($reason.Count -gt 0) {
        $level = if ($t.Actions -match "(?i)xmrig|miner|c3pool|net\s+user|add-localgroupmember|downloadstring|-enc|-encodedcommand") { "高危" } else { "中危" }
        if ($reason -contains "任务伪装在 Microsoft\\Windows 系统路径下但名称/动作需要复核" -and $t.Actions -match "(?i)\\ProgramData\\|powershell|wscript|cscript|mshta|\.(ps1|vbs|hta|bat|cmd)\b") { $level = "中危" }

        $obj = [PSCustomObject]@{
            Level    = $level
            TaskName = "$($t.TaskPath)$($t.TaskName)"
            State    = $t.State
            Actions  = $t.Actions
            Reason   = ($reason -join ";")
        }

        $SuspiciousTasks += $obj

        Add-Finding -Level $level -Category "计划任务" -Title "发现可疑计划任务" `
            -Evidence "任务=$($obj.TaskName)，动作=$($obj.Actions)，原因=$($obj.Reason)" `
            -Suggestion "检查任务创建时间、执行文件签名、Hash、是否与挖矿/后门/下载执行有关。"
    }
}

Export-DetailCsv -Name "可疑计划任务.csv" -Data $SuspiciousTasks

$StartupItems = @()
try {
    $startupRegPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    )

    foreach ($rp in $startupRegPaths) {
        if (Test-Path $rp) {
            $props = Get-ItemProperty -Path $rp
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -notmatch "^PS") {
                    $cmd = [string]$p.Value
                    $exe = Extract-ExecutablePath -Command $cmd
                    $sigStatus = ""
                    try {
                        if (Test-Path $exe -PathType Leaf) {
                            $sigStatus = (Get-AuthenticodeSignature -FilePath $exe -ErrorAction SilentlyContinue).Status
                        }
                    }
                    catch {}

                    $StartupItems += [PSCustomObject]@{
                        Location  = $rp
                        Name      = $p.Name
                        Command   = $cmd
                        FilePath  = $exe
                        Signature = $sigStatus
                    }
                }
            }
        }
    }

    $startupFolders = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    )

    foreach ($sf in $startupFolders) {
        if (Test-Path $sf) {
            Get-ChildItem -Path $sf -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '(?i)^desktop\.ini$' } | ForEach-Object {
                $cmd = $_.FullName
                $filePath = $_.FullName
                $sigStatus = ""

                # v0.6.4：解析 Startup 目录中的 .lnk 快捷方式。
                # 攻击者经常用快捷方式隐藏真实 TargetPath + Arguments；原来只看到 .lnk 文件本身，容易漏掉 wscript/mshta/powershell 等动作。
                if ($_.Extension -match '(?i)^\.lnk$') {
                    try {
                        $shell = New-Object -ComObject WScript.Shell
                        $shortcut = $shell.CreateShortcut($_.FullName)
                        $target = [string]$shortcut.TargetPath
                        $args = [string]$shortcut.Arguments
                        if (-not [string]::IsNullOrWhiteSpace($target)) {
                            $cmd = ($target + " " + $args).Trim()
                            $filePath = $target
                        }
                    } catch {}
                }

                try {
                    if (Test-Path $filePath -PathType Leaf) {
                        $sigStatus = (Get-AuthenticodeSignature -FilePath $filePath -ErrorAction SilentlyContinue).Status
                    }
                } catch {}

                $StartupItems += [PSCustomObject]@{
                    Location  = $sf
                    Name      = $_.Name
                    Command   = $cmd
                    FilePath  = $filePath
                    Signature = $sigStatus
                }
            }
        }
    }
}
catch {}

$SuspiciousStartup = @()
foreach ($s in $StartupItems) {
    if ($s.Name -match '(?i)^desktop\.ini$') { continue }
    $reason = @()
    $isTrustedVendor = Test-IsTrustedVendorCommand -Command $s.Command
    $isDangerScriptOrCommand = Test-IsScriptOrDangerPersistence -Command $s.Command

    $isSuspiciousPath = Test-IsSuspiciousPersistencePath -PathOrCommand $s.Command

    # v0.5.2 调整：持久化启动项只要落在 ProgramData / Public / Temp / Downloads / AppData 等高风险位置，
    # 即使文件带有效签名也进入关注。真实攻击中常见'复制系统签名程序到可写目录后持久化'的伪装方式。
    if ($isSuspiciousPath -and (-not $isTrustedVendor)) {
        $reason += "启动项执行路径位于可疑目录"
        if ([string]::IsNullOrWhiteSpace($s.Signature) -or $s.Signature -ne "Valid") {
            $reason += "启动项位于可疑目录且缺少可信签名"
        }
    }

    if ($isDangerScriptOrCommand) {
        $reason += "启动项命令命中危险脚本或命令特征"
    }

    if ($s.Signature -and $s.Signature -notin @("Valid","NotSigned") -and (-not $isTrustedVendor)) {
        $reason += "签名状态异常：$($s.Signature)"
    }

    if ($reason.Count -gt 0) {
        $level = if ($s.Command -match "(?i)\.(bat|cmd|ps1|vbs|js|hta)\b|wscript(\.exe)?|cscript(\.exe)?|mshta(\.exe)?|powershell(\.exe)?|xmrig|miner|c3pool|stratum|monero|downloadstring|-enc|-encodedcommand") { "高危" } else { "中危" }

        $obj = [PSCustomObject]@{
            Level     = $level
            Location  = $s.Location
            Name      = $s.Name
            Command   = $s.Command
            FilePath  = $s.FilePath
            Signature = $s.Signature
            Reason    = ($reason -join ";")
        }

        $SuspiciousStartup += $obj

        Add-Finding -Level $level -Category "启动项" -Title "发现可疑启动项持久化" `
            -Evidence "位置=$($obj.Location)，名称=$($obj.Name)，命令=$($obj.Command)，签名=$($obj.Signature)，原因=$($obj.Reason)" `
            -Suggestion "重点检查 AppData/Public/Temp/ProgramData 下的 bat、ps1、vbs、exe 启动项；确认是否为后门或挖矿持久化。"
    }
}

Export-DetailCsv -Name "启动项.csv" -Data $StartupItems
Export-DetailCsv -Name "可疑启动项.csv" -Data $SuspiciousStartup

# =========================================================
# 模块 6：进程、网络、危险端口、资源异常
# =========================================================

Write-Info "正在检查进程、网络连接与资源异常..."
Write-Info "正在采样进程 CPU，占用约 $CpuSampleSeconds 秒..."

$CpuPercentMap = Get-ProcessCpuPercentMap -SampleSeconds $CpuSampleSeconds
$TotalMemoryMB = Get-TotalPhysicalMemoryMB

$MiningProcRegex = "(?i)xmrig|xmr-stak|monero|stratum|cryptonight|nanominer|cpuminer|minerd|miner|c3pool"
$SensitiveToolRegex = "(?i)^(powershell\.exe|pwsh\.exe|cmd\.exe|certutil\.exe|bitsadmin\.exe|mshta\.exe|rundll32\.exe|regsvr32\.exe|wscript\.exe|cscript\.exe|wmic\.exe|curl\.exe|wget\.exe|nc\.exe|ncat\.exe)$"

$Processes = @()
try {
    $cimProcs = Get-CimInstance Win32_Process -ErrorAction Stop
    foreach ($p in $cimProcs) {
        $path = Safe-String $p.ExecutablePath
        $cmd  = Safe-String $p.CommandLine
        $memMB = Get-ProcessMemoryMB -ProcessId $p.ProcessId
        $memPercent = 0
        if ($TotalMemoryMB -gt 0) { $memPercent = [Math]::Round(($memMB / $TotalMemoryMB) * 100, 2) }

        $cpuPercent = 0
        if ($CpuPercentMap.ContainsKey([int]$p.ProcessId)) { $cpuPercent = $CpuPercentMap[[int]$p.ProcessId] }

        $riskReasons = @()
        if ("$($p.Name) $path $cmd" -match $MiningProcRegex) { $riskReasons += "命中挖矿相关命名/路径/命令特征" }
        if ($cmd -match $DangerCommandRegex -and -not (Test-IsSelfToolText $cmd)) { $riskReasons += "命令行命中危险特征" }
        if ($path -match $SuspiciousPathRegex) { $riskReasons += "进程位于可疑路径" }
        if ($cpuPercent -ge $CpuHighPercent) { $riskReasons += "CPU占用异常" }
        if ($memMB -ge $MemoryHighMB -or $memPercent -ge $MemoryHighPercent) { $riskReasons += "内存占用异常" }

        $Processes += [PSCustomObject]@{
            ProcessId       = $p.ProcessId
            ParentProcessId = $p.ParentProcessId
            Name            = $p.Name
            ExecutablePath  = $path
            CommandLine     = $cmd
            CpuPercent      = $cpuPercent
            MemoryMB        = $memMB
            MemoryPercent   = $memPercent
            PublicConnections = 0
            SHA256          = Get-SHA256Safe -Path $path
            RiskReasons     = ($riskReasons -join ";")
        }
    }
}
catch {}

$NetConns = @()
try {
    $tcp = Get-NetTCPConnection -ErrorAction Stop | Where-Object { $_.State -in @("Established","Listen","SynSent","CloseWait") }

    foreach ($c in $tcp) {
        $proc = $Processes | Where-Object { $_.ProcessId -eq $c.OwningProcess } | Select-Object -First 1
        $remote = Safe-String $c.RemoteAddress
        $isPublic = $false

        if ($remote -and -not (Test-PrivateIP $remote)) {
            $isPublic = $true
        }

        $NetConns += [PSCustomObject]@{
            LocalAddress  = $c.LocalAddress
            LocalPort     = $c.LocalPort
            RemoteAddress = $c.RemoteAddress
            RemotePort    = $c.RemotePort
            State         = $c.State
            ProcessId     = $c.OwningProcess
            ProcessName   = $proc.Name
            ProcessPath   = $proc.ExecutablePath
            IsPublicIP    = $isPublic
        }
    }
}
catch {}

$publicByPid = @{}
foreach ($n in ($NetConns | Where-Object { $_.IsPublicIP -eq $true })) {
    $procIdKey = [int]$n.ProcessId
    if (-not $publicByPid.ContainsKey($procIdKey)) { $publicByPid[$procIdKey] = 0 }
    $publicByPid[$procIdKey] += 1
}

$ResourceAnomalies = @()
foreach ($proc in $Processes) {
    $procIdKey = [int]$proc.ProcessId
    $publicCount = 0
    if ($publicByPid.ContainsKey($procIdKey)) { $publicCount = $publicByPid[$procIdKey] }
    $proc.PublicConnections = $publicCount

    $score = 0
    $tags = @()

    $isCoreWindowsProcess = Test-IsCoreWindowsProcess -Name $proc.Name -Path $proc.ExecutablePath
    $hasMiningFeature = ("$($proc.Name) $($proc.ExecutablePath) $($proc.CommandLine)" -match $MiningProcRegex)
    $hasDangerCommand = ($proc.CommandLine -match $DangerCommandRegex -and -not (Test-IsSelfToolText $proc.CommandLine))
    $hasSuspiciousPath = ($proc.ExecutablePath -match $SuspiciousPathRegex)
    $isKnownPublicNoise = Test-IsKnownPublicNetworkNoise -ProcessName $proc.Name -ProcessPath $proc.ExecutablePath
    $isTrustedVendorCommand = Test-IsTrustedVendorCommand -Command "$($proc.ExecutablePath) $($proc.CommandLine)"

    # v0.6.5：OneDrive / Edge / Defender 等常见组件如果只是 AppData 路径 + 公网连接，
    # 且没有资源压力、危险命令或挖矿特征，则不进入资源异常。
    if (($isKnownPublicNoise -or $isTrustedVendorCommand) -and
        -not ($hasMiningFeature -or $hasDangerCommand) -and
        $proc.CpuPercent -lt $CpuHighPercent -and
        $proc.MemoryMB -lt $MemoryHighMB -and
        $proc.MemoryPercent -lt $MemoryHighPercent) {
        continue
    }

    if ($proc.CpuPercent -ge 70) { $score += 4; $tags += "CPU占用极高" }
    elseif ($proc.CpuPercent -ge $CpuHighPercent) { $score += 2; $tags += "CPU占用偏高" }

    if ($proc.MemoryPercent -ge 40 -or $proc.MemoryMB -ge 2048) { $score += 3; $tags += "内存占用极高" }
    elseif ($proc.MemoryPercent -ge $MemoryHighPercent -or $proc.MemoryMB -ge $MemoryHighMB) { $score += 2; $tags += "内存占用偏高" }

    # 公网连接只作为辅助证据，不再单独触发资源异常。
    if ($publicCount -ge 20) { $score += 2; $tags += "公网连接很多" }
    elseif ($publicCount -ge 5 -and ($hasMiningFeature -or $hasDangerCommand -or $hasSuspiciousPath)) { $score += 1; $tags += "存在多个公网连接" }

    if ($hasSuspiciousPath) { $score += 2; $tags += "位于高风险目录" }
    if ($hasMiningFeature) { $score += 4; $tags += "命中挖矿命名/路径特征" }
    if ($hasDangerCommand) { $score += 2; $tags += "命令行可疑" }

    # 过滤低资源、系统核心进程、仅公网连接造成的噪音。
    $hasResourcePressure = ($proc.CpuPercent -ge $CpuHighPercent -or $proc.MemoryMB -ge $MemoryHighMB -or $proc.MemoryPercent -ge $MemoryHighPercent)
    $hasRealSuspiciousEvidence = ($hasMiningFeature -or $hasDangerCommand -or $hasSuspiciousPath -or $hasResourcePressure)

    if (-not $hasRealSuspiciousEvidence) { continue }
    if ($isCoreWindowsProcess -and -not ($hasResourcePressure -or $hasDangerCommand -or $hasMiningFeature)) { continue }
    if ($score -lt 3) { continue }

    $level = if ($score -ge 7) { "高危" } elseif ($score -ge 4) { "中危" } else { "关注" }
    $tagText = ($tags -join ";")
    $title = Get-ResourceTitle -Tags $tagText -RiskLevel $level

    $ResourceAnomalies += [PSCustomObject]@{
        Level             = $level
        Score             = $score
        ProcessId         = $proc.ProcessId
        Name              = $proc.Name
        CpuPercent        = $proc.CpuPercent
        MemoryMB          = $proc.MemoryMB
        MemoryPercent     = $proc.MemoryPercent
        PublicConnections = $publicCount
        Tags              = $tagText
        ExecutablePath    = $proc.ExecutablePath
        CommandLine       = $proc.CommandLine
        SHA256            = $proc.SHA256
    }

    Add-Finding -Level $level -Category "资源异常" -Title $title `
        -Evidence "PID=$($proc.ProcessId)，进程=$($proc.Name)，CPU=$($proc.CpuPercent)%，内存=$($proc.MemoryMB)MB($($proc.MemoryPercent)%)，公网连接=$publicCount，评分=$score，标签=$tagText，路径=$($proc.ExecutablePath)" `
        -Suggestion "资源异常不等于一定是挖矿。请结合 CPU/内存持续占用、外联地址、进程路径、计划任务/服务/启动项和文件 Hash 进行研判。"
}

$DangerPorts = @()
try {
    $listens = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue

    $groups = $listens | Group-Object LocalPort
    foreach ($g in $groups) {
        $port = [int]$g.Name
        $info = Get-DangerousPortInfo -Port $port
        if (-not $info) { continue }

        $items = @($g.Group)
        $addrs = (($items.LocalAddress | Sort-Object -Unique) -join ";")
        $first = $items | Select-Object -First 1
        $proc = $Processes | Where-Object { $_.ProcessId -eq $first.OwningProcess } | Select-Object -First 1

        $level = "关注"
        if ($port -in @(3389,445,5985,5986,6379,9200,27017,3306,1433,23)) { $level = "高危" }
        elseif ($port -in @(21,22,135,139,5900,11211,7001,8080)) { $level = "中危" }

        $DangerPorts += [PSCustomObject]@{
            Level        = $level
            LocalPort    = $port
            LocalAddress = $addrs
            ServiceRisk  = $info
            ProcessId    = $first.OwningProcess
            ProcessName  = $proc.Name
            ProcessPath  = $proc.ExecutablePath
        }

        Add-Finding -Level $level -Category "危险端口" -Title "发现危险监听端口" `
            -Evidence "本地监听端口=$port，监听地址=$addrs，说明=$info，进程=$($proc.Name)" `
            -Suggestion "监听不代表公网可访问。请结合 Windows 防火墙、云安全组、路由/NAT 策略确认是否对外暴露。"
    }
}
catch {}

Export-DetailCsv -Name "进程明细.csv" -Data $Processes
Export-DetailCsv -Name "网络连接.csv" -Data $NetConns
Export-DetailCsv -Name "资源异常进程.csv" -Data $ResourceAnomalies
Export-DetailCsv -Name "危险监听端口.csv" -Data $DangerPorts

# =========================================================
# 模块 7：挖矿配置提取
# =========================================================

Write-Info "正在提取挖矿配置文件中的矿池和钱包线索..."

$MiningCandidateDirs = New-Object System.Collections.Generic.List[string]

# 1. 从已经命中的资源异常/服务/计划任务/启动项中提取目录
#    v0.5.2 关键改进：不再只信 xmrig/miner 等关键词。
#    只要进程、服务、计划任务或启动项已经被判为可疑，就将其所在目录加入轻量扫描队列，
#    再从目录内提取 stratum / pool / wallet / user 等配置证据。
$MiningCandidateSources = New-Object System.Collections.Generic.List[object]

function Add-MiningCandidateFromEvidence {
    param(
        [string]$SourceType,
        [string]$EvidenceName,
        [string]$Value,
        [string]$Reason
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return }

    $beforeCount = $MiningCandidateDirs.Count
    Add-MiningCandidateDir -List $MiningCandidateDirs -Value $Value
    $afterCount = $MiningCandidateDirs.Count

    $MiningCandidateSources.Add([PSCustomObject]@{
        SourceType   = $SourceType
        EvidenceName = $EvidenceName
        Value        = $Value
        Reason       = $Reason
        AddedDir     = if ($afterCount -gt $beforeCount) { "Yes" } else { "MaybeExistingOrInvalid" }
    }) | Out-Null
}

foreach ($r in $ResourceAnomalies) {
    $resourceText = "$($r.Name) $($r.ExecutablePath) $($r.CommandLine) $($r.Tags)"
    $shouldTrace = $false
    $traceReason = @()

    if ($resourceText -match "(?i)xmrig|miner|c3pool|monero|stratum|WinRing0|nssm") { $shouldTrace = $true; $traceReason += "命中挖矿/驱动/服务特征" }
    if ($r.Score -ge 4 -and $r.ExecutablePath -match $SuspiciousPathRegex) { $shouldTrace = $true; $traceReason += "资源异常且位于可疑目录" }
    if ($r.CpuPercent -ge $CpuHighPercent -and $r.ExecutablePath -match $SuspiciousPathRegex) { $shouldTrace = $true; $traceReason += "高 CPU 且位于可疑目录" }
    if ($r.PublicConnections -ge 1 -and $r.ExecutablePath -match $SuspiciousPathRegex) { $shouldTrace = $true; $traceReason += "可疑目录进程存在公网连接" }
    if ($r.CommandLine -match "(?i)--config\s+|\s-c\s+|/config\s+|config\.json|\.conf\b") { $shouldTrace = $true; $traceReason += "命令行疑似指定配置文件" }

    if ($shouldTrace) {
        Add-MiningCandidateFromEvidence -SourceType "资源异常进程" -EvidenceName $r.Name -Value $r.ExecutablePath -Reason ($traceReason -join ";")
        Add-MiningCandidateFromEvidence -SourceType "资源异常进程命令行" -EvidenceName $r.Name -Value $r.CommandLine -Reason ($traceReason -join ";")
    }
}

foreach ($s in $ServiceEvents) {
    if ($s.Level -eq "正常") { continue }
    $serviceText = "$($s.ServiceName) $($s.ImagePath) $($s.Reason)"
    $shouldTrace = $false
    $traceReason = @()

    if ($serviceText -match "(?i)xmrig|miner|c3pool|monero|stratum|WinRing0|nssm") { $shouldTrace = $true; $traceReason += "服务命中挖矿/驱动/持久化特征" }
    if (Test-IsSuspiciousPersistencePath -PathOrCommand $s.ImagePath) { $shouldTrace = $true; $traceReason += "服务路径位于可疑目录" }
    if ($s.Reason -match "可疑路径|用户目录|临时目录|挖矿|持久化") { $shouldTrace = $true; $traceReason += "服务安装原因可疑" }
    if ($s.ImagePath -match "(?i)--config\s+|\s-c\s+|/config\s+|config\.json|\.conf\b") { $shouldTrace = $true; $traceReason += "服务命令疑似指定配置文件" }

    if ($shouldTrace) {
        Add-MiningCandidateFromEvidence -SourceType "服务安装" -EvidenceName $s.ServiceName -Value $s.ImagePath -Reason ($traceReason -join ";")
    }
}

foreach ($t in $SuspiciousTasks) {
    Add-MiningCandidateFromEvidence -SourceType "可疑计划任务" -EvidenceName $t.TaskName -Value $t.Actions -Reason $t.Reason
}

foreach ($s in $SuspiciousStartup) {
    Add-MiningCandidateFromEvidence -SourceType "可疑启动项" -EvidenceName $s.Name -Value $s.Command -Reason $s.Reason
}

# 对全部启动项做一次轻量补充：如果持久化命令本身位于可疑目录，但由于签名/厂商规则没有进入重点关注，也加入候选目录池。
foreach ($s in $StartupItems) {
    if ((Test-IsSuspiciousPersistencePath -PathOrCommand $s.Command) -and (-not (Test-IsTrustedVendorCommand -Command $s.Command))) {
        Add-MiningCandidateFromEvidence -SourceType "启动项补充" -EvidenceName $s.Name -Value $s.Command -Reason "启动项命令位于可疑目录，加入配置扫描候选"
    }
}


# 1.5. 候选目录向上轻量扩展：
# 如果命中的是 C:\ProgramData\WinIRLabV2\Runtime 这类子目录，配置文件可能放在兄弟目录 Cache / Conf / Logs 中。
# 因此只在安全边界内补充父目录，例如 C:\ProgramData\WinIRLabV2；禁止补充 C:\ProgramData、C:\Windows 等过宽目录。
try {
    $currentDirs = @($MiningCandidateDirs)
    foreach ($dir in $currentDirs) {
        if ([string]::IsNullOrWhiteSpace($dir)) { continue }
        if (-not (Test-Path $dir -PathType Container)) { continue }

        $parent = Split-Path -Path $dir -Parent
        if ((Test-IsSafeMiningExpansionDir -Dir $parent) -and (Test-Path $parent -PathType Container)) {
            if (-not $MiningCandidateDirs.Contains($parent)) {
                $MiningCandidateDirs.Add($parent) | Out-Null
                $MiningCandidateSources.Add([PSCustomObject]@{
                    SourceType   = "候选父目录补充"
                    EvidenceName = (Split-Path -Path $dir -Leaf)
                    Value        = $dir
                    Reason       = "可疑文件位于子目录，补充扫描安全范围内父目录以发现兄弟目录中的配置/日志"
                    AddedDir     = "Yes"
                }) | Out-Null
            }
        }
    }
}
catch {}


# 1.6. 兄弟目录定向补充：
# 如果只命中 Runtime 或 .telemetry，配置常在同级 Cache/Config/Conf/Data/Logs 中。
# 这里仅补充少量高价值目录名，不做全盘搜索。
try {
    $siblingNames = @('Cache','Config','Conf','Configs','Data','Logs','Log','Profile','Profiles','Runtime','Scripts','.telemetry')
    $baseDirsForSibling = @($MiningCandidateDirs)
    foreach ($dir in $baseDirsForSibling) {
        if ([string]::IsNullOrWhiteSpace($dir)) { continue }
        if (-not (Test-Path $dir -PathType Container)) { continue }

        $parent = Split-Path -Path $dir -Parent
        if (-not (Test-IsSafeMiningExpansionDir -Dir $parent)) { continue }

        foreach ($sn in $siblingNames) {
            $sib = Join-Path $parent $sn
            if ((Test-Path $sib -PathType Container) -and (-not $MiningCandidateDirs.Contains($sib))) {
                $MiningCandidateDirs.Add($sib) | Out-Null
                $MiningCandidateSources.Add([PSCustomObject]@{
                    SourceType   = "候选兄弟目录补充"
                    EvidenceName = $sn
                    Value        = $sib
                    Reason       = "可疑目录存在同级高价值配置目录，补充扫描以发现隐藏配置/日志"
                    AddedDir     = "Yes"
                }) | Out-Null
            }
        }
    }
}
catch {}

# 2. 补充常见挖矿目录候选，不做大范围全盘扫描，避免太慢
try {
    $commonRoots = @("C:\Users", "C:\ProgramData", "C:\Windows\Temp")
    foreach ($root in $commonRoots) {
        if (Test-Path $root -PathType Container) {
            Get-ChildItem -Path $root -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
                if ($_.Name -match "(?i)c3pool|xmrig|miner|xmr|monero") {
                    if (-not $MiningCandidateDirs.Contains($_.FullName)) {
                        $MiningCandidateDirs.Add($_.FullName) | Out-Null
                    }
                    $MiningCandidateSources.Add([PSCustomObject]@{
                        SourceType   = "常见挖矿目录名"
                        EvidenceName = $_.Name
                        Value        = $_.FullName
                        Reason       = "目录名命中挖矿关键词"
                        AddedDir     = "Yes"
                    }) | Out-Null
                }
            }
        }
    }
}
catch {}

# v0.6.4：补充 Public/Libraries 下的可疑镜像目录。
# 不扫描整个 Public，只挑选目录名带 WinIRLab/miner/xmr/cache/update/runtime 等可疑上下文的具体目录。
try {
    $publicRoots = @("C:\Users\Public", "C:\Users\Public\Libraries", "C:\Users\Public\Documents")
    foreach ($root in $publicRoots) {
        if (Test-Path $root -PathType Container) {
            Get-ChildItem -Path $root -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
                if ($_.Name -match "(?i)winirlab|xmrig|miner|xmr|monero|cache|update|runtime|telemetry") {
                    if (Test-IsSafeMiningExpansionDir -Dir $_.FullName) {
                        if (-not $MiningCandidateDirs.Contains($_.FullName)) {
                            $MiningCandidateDirs.Add($_.FullName) | Out-Null
                        }
                        $MiningCandidateSources.Add([PSCustomObject]@{
                            SourceType   = "Public可疑镜像目录"
                            EvidenceName = $_.Name
                            Value        = $_.FullName
                            Reason       = "Public/Libraries 下目录名带可疑缓存/挖矿上下文，加入轻量配置扫描"
                            AddedDir     = "Yes"
                        }) | Out-Null
                    }
                }
            }
        }
    }
}
catch {}

$MiningConfigs = New-Object System.Collections.Generic.List[object]
$MiningConfigFiles = @()
# v0.6.6：ADS 备用数据流显式结果。即使 IOC 与普通文件重复，也单独导出并进入关注项。
$AdsFindings = @()
$MiningTextExt = @(".json", ".conf", ".config", ".txt", ".bat", ".cmd", ".ps1", ".ini", ".yml", ".yaml", ".xml", ".db", ".bak", ".log", ".dat", "")

foreach ($dir in $MiningCandidateDirs) {
    if (-not (Test-Path $dir -PathType Container)) { continue }

    try {
        $files = Get-ChildItem -Path $dir -Recurse -File -Force -ErrorAction SilentlyContinue |
            Where-Object {
                $ext = $_.Extension.ToLower()
                $_.Length -gt 0 -and $_.Length -lt 2MB -and (
                    ($MiningTextExt -contains $ext) -or
                    [string]::IsNullOrWhiteSpace($ext) -or
                    $_.Name -match '(?i)config|state|profile|route|policy|wallet|pool|runtime|cache|worker|endpoint'
                )
            } |
            Sort-Object @{Expression={ if ($_.Name -match '(?i)config|runtime|profile|pool|wallet|fallback|remote|log') { 0 } else { 1 } }}, LastWriteTime -Descending |
            Select-Object -First 160

        foreach ($f in $files) {
            $MiningConfigFiles += [PSCustomObject]@{
                SourceDir     = $dir
                FilePath      = $f.FullName
                Length        = $f.Length
                LastWriteTime = $f.LastWriteTime
            }

            $content = ""
            try { $content = Get-Content -Path $f.FullName -Raw -ErrorAction Stop } catch { continue }
            if ([string]::IsNullOrWhiteSpace($content)) { continue }

            # v0.6.4：先做通用协议/字段扫描，再走原有高置信专项规则。
            Add-MiningHitsFromText -List $MiningConfigs -Text $content -FilePath $f.FullName -SourceDir $dir

            # v0.6.6：轻量扫描 NTFS Alternate Data Stream（ADS），并显式输出 ADS 证据。
            # 只扫描已经进入候选文件列表的小文件，避免全盘 ADS 扫描造成性能和误报问题。
            try {
                $streams = Get-Item -Path $f.FullName -Stream * -ErrorAction SilentlyContinue |
                    Where-Object { $_.Stream -and $_.Length -gt 0 -and $_.Length -lt 2MB }

                foreach ($st in $streams) {
                    $streamName = [string]$st.Stream
                    if ([string]::IsNullOrWhiteSpace($streamName)) { continue }

                    if ($streamName -eq '$DATA' -or $streamName -eq ':$DATA') { continue }
                    $streamNameClean = ($streamName -replace ':\$DATA$','')
                    if ([string]::IsNullOrWhiteSpace($streamNameClean) -or $streamNameClean -eq '$DATA') { continue }

                    $adsContent = ""
                    try { $adsContent = Get-Content -Path $f.FullName -Stream $streamNameClean -Raw -ErrorAction Stop } catch { $adsContent = "" }

                    if (-not [string]::IsNullOrWhiteSpace($adsContent)) {
                        $adsPath = "$($f.FullName):$streamNameClean"
                        $adsFlat = ($adsContent -replace '\s+', ' ')
                        $adsLooksInteresting = $adsFlat -match '(?i)stratum|ssl://|tcp://|https?://|wallet|worker|token|pool|relay|gateway|node|lab\.invalid|fake_src_ip|source_ip'

                        $MiningConfigFiles += [PSCustomObject]@{
                            SourceDir     = $dir
                            FilePath      = $adsPath
                            Length        = $st.Length
                            LastWriteTime = $f.LastWriteTime
                        }

                        Add-MiningHitsFromText -List $MiningConfigs -Text $adsContent -FilePath $adsPath -SourceDir $dir

                        if ($adsLooksInteresting) {
                            $AdsFindings += [PSCustomObject]@{
                                HostFile      = $f.FullName
                                StreamName    = $streamNameClean
                                AdsPath       = $adsPath
                                Length        = $st.Length
                                LastWriteTime = $f.LastWriteTime
                                SourceDir     = $dir
                                Context       = $adsFlat.Substring(0, [Math]::Min(260, $adsFlat.Length))
                                Note          = "候选目录文件存在 ADS 备用数据流，且流内容命中 IOC/认证/配置上下文关键词"
                            }
                        }
                    }
                }
            } catch {}

            # 如果脚本/批处理里引用了同一安全父目录下的配置/日志文件，补充读取该文件。
            # 这用于识别：服务/计划任务 -> loader.ps1 -> Cache\runtime-profile.json 这种真实常见布局。
            try {
                foreach ($pm in [regex]::Matches($content, '[A-Za-z]:\\[^"''<>|\r\n]+\.(json|conf|config|txt|log|ini|yml|yaml|xml|ps1|bat|cmd|db|bak|dat)')) {
                    $refPath = $pm.Value.Trim().Trim('"', "'", ',', ';')
                    if ((Test-Path $refPath -PathType Leaf)) {
                        $refFile = Get-Item -Path $refPath -ErrorAction SilentlyContinue
                        if ($null -ne $refFile -and $refFile.Length -gt 0 -and $refFile.Length -lt 2MB -and ($MiningTextExt -contains $refFile.Extension.ToLower())) {
                            $refDir = Split-Path -Path $refFile.FullName -Parent
                            $sameSafeParent = $false
                            try {
                                $parentA = Split-Path -Path $dir -Parent
                                $parentB = Split-Path -Path $refDir -Parent
                                if ($parentA -eq $parentB -or $dir -eq $parentB -or $refDir.StartsWith($dir, [System.StringComparison]::OrdinalIgnoreCase)) { $sameSafeParent = $true }
                                if (Test-IsSafeMiningExpansionDir -Dir $parentB) { $sameSafeParent = $true }
                            } catch {}

                            if ($sameSafeParent) {
                                $MiningConfigFiles += [PSCustomObject]@{
                                    SourceDir     = $dir
                                    FilePath      = $refFile.FullName
                                    Length        = $refFile.Length
                                    LastWriteTime = $refFile.LastWriteTime
                                }

                                $refContent = ""
                                try { $refContent = Get-Content -Path $refFile.FullName -Raw -ErrorAction Stop } catch { $refContent = "" }
                                if (-not [string]::IsNullOrWhiteSpace($refContent)) {
                                    Add-MiningHitsFromText -List $MiningConfigs -Text $refContent -FilePath $refFile.FullName -SourceDir $refDir

                                    foreach ($sm in [regex]::Matches($refContent, '(?i)stratum\+(tcp|ssl)://[^\s"''<>]+')) {
                                        Add-MiningConfigHit -List $MiningConfigs -Type "矿池地址" -Value $sm.Value -FilePath $refFile.FullName -SourceDir $refDir -Context (Get-ShortContext -Text $refContent -Value $sm.Value) -Confidence "高"
                                    }
                                    foreach ($um in [regex]::Matches($refContent, '(?i)"(url|endpoint|fallback|remote)"\s*:\s*"([^"]+)"|(?im)^\s*(endpoint|fallback|remote)\s*=\s*([^\r\n#]+)')) {
                                        $v = if ($um.Groups[2].Success) { $um.Groups[2].Value } else { $um.Groups[4].Value }
                                        $v = $v.Trim().Trim('"', "'", ',', ';')
                                        if ($v -match '(?i)stratum|pool|relay|gateway|:[0-9]{2,5}') {
                                            Add-MiningConfigHit -List $MiningConfigs -Type "矿池地址候选" -Value $v -FilePath $refFile.FullName -SourceDir $refDir -Context (Get-ShortContext -Text $refContent -Value $v) -Confidence "中"
                                        }
                                    }
                                    foreach ($wm in [regex]::Matches($refContent, '(?i)("user"\s*:\s*"|"wallet"\s*:\s*"|"account"\s*:\s*"|account\s*=\s*|wallet\s*=\s*|token\s*=\s*)([A-Za-z0-9_.+\-]{32,180})')) {
                                        $wv = $wm.Groups[2].Value.Trim().Trim('"', "'", ',', ';')
                                        if ($wv -notmatch '^(true|false|null)$') {
                                            Add-MiningConfigHit -List $MiningConfigs -Type "钱包地址候选" -Value $wv -FilePath $refFile.FullName -SourceDir $refDir -Context (Get-ShortContext -Text $refContent -Value $wv) -Confidence "中"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch {}

            # 矿池地址：stratum 协议最可靠
            foreach ($m in [regex]::Matches($content, '(?i)stratum\+(tcp|ssl)://[^\s"''<>]+')) {
                Add-MiningConfigHit -List $MiningConfigs -Type "矿池地址" -Value $m.Value -FilePath $f.FullName -SourceDir $dir -Context (Get-ShortContext -Text $content -Value $m.Value) -Confidence "高"
            }

            # JSON / 配置中的 url / endpoint / fallback / remote 字段
            foreach ($m in [regex]::Matches($content, '(?i)"(url|endpoint|fallback|remote)"\s*:\s*"([^"]+)"')) {
                $v = $m.Groups[2].Value
                if ($v -match '(?i)stratum|pool|relay|gateway|:[0-9]{2,5}') {
                    $hitType = if ($v -match '(?i)^stratum\+') { "矿池地址" } else { "矿池地址候选" }
                    Add-MiningConfigHit -List $MiningConfigs -Type $hitType -Value $v -FilePath $f.FullName -SourceDir $dir -Context (Get-ShortContext -Text $content -Value $v) -Confidence "高"
                }
            }

            # 命令行 -o / --url 指定矿池
            foreach ($m in [regex]::Matches($content, '(?i)(--url|-o)\s+([^\s"'']+)')) {
                $v = $m.Groups[2].Value
                if ($v -match '(?i)stratum|pool|:[0-9]{2,5}') {
                    Add-MiningConfigHit -List $MiningConfigs -Type "矿池地址" -Value $v -FilePath $f.FullName -SourceDir $dir -Context (Get-ShortContext -Text $content -Value $v) -Confidence "高"
                }
            }

            # pool 域名/IP:端口 兜底提取
            foreach ($m in [regex]::Matches($content, '(?i)([a-z0-9.-]*pool[a-z0-9.-]*|[a-z0-9.-]*xmr[a-z0-9.-]*)\.[a-z]{2,}:[0-9]{2,5}')) {
                Add-MiningConfigHit -List $MiningConfigs -Type "矿池地址候选" -Value $m.Value -FilePath $f.FullName -SourceDir $dir -Context (Get-ShortContext -Text $content -Value $m.Value) -Confidence "中"
            }

            # XMR 钱包地址常见格式：95 个 Base58 字符，以 4 或 8 开头
            foreach ($m in [regex]::Matches($content, '\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b')) {
                Add-MiningConfigHit -List $MiningConfigs -Type "钱包地址" -Value $m.Value -FilePath $f.FullName -SourceDir $dir -Context (Get-ShortContext -Text $content -Value $m.Value) -Confidence "高"
            }

            # user / wallet / account / token / -u 后面的长字符串，作为钱包或矿工用户名候选
            foreach ($m in [regex]::Matches($content, '(?i)("user"\s*:\s*"|"wallet"\s*:\s*"|"account"\s*:\s*"|account\s*=\s*|wallet\s*=\s*|token\s*=\s*|--user\s+|-u\s+)([A-Za-z0-9_.+\-]{32,180})')) {
                $v = $m.Groups[2].Value
                if ($v -notmatch '^(true|false|null)$') {
                    $typ = "钱包地址候选"
                    $conf = "中"
                    if ($v -match '^[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}$') { $typ = "钱包地址"; $conf = "高" }
                    Add-MiningConfigHit -List $MiningConfigs -Type $typ -Value $v -FilePath $f.FullName -SourceDir $dir -Context (Get-ShortContext -Text $content -Value $v) -Confidence $conf
                }
            }
        }
    }
    catch {}
}

$MiningConfigsArrayRaw = @()
foreach ($mc in $MiningConfigs) {
    $MiningConfigsArrayRaw += $mc
}

# v0.6.5：IOC 归一化去重。
# 如果已经存在带协议的 ssl://host:port、tcp://host:port、stratum+tcp://host:port，
# 就不再重复展示同一 host:port 裸值；URL 下载项也从矿池中拆分出来。
$protocolHostPorts = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($mc in $MiningConfigsArrayRaw) {
    $norm = Get-WinIRNormalizedIocValue -Value $mc.Value
    if ($mc.Value -match '(?i)^(?:stratum\+(?:tcp|ssl)|ssl|tcp)://' -and -not [string]::IsNullOrWhiteSpace($norm)) {
        [void]$protocolHostPorts.Add($norm)
    }
}

$MiningConfigsArray = @()
foreach ($mc in $MiningConfigsArrayRaw) {
    $norm = Get-WinIRNormalizedIocValue -Value $mc.Value

    if ($mc.Value -notmatch '(?i)://' -and $protocolHostPorts.Contains($norm)) {
        continue
    }

    # http(s) 下载/投放 URL 不算矿池，但仍作为 IOC 输出。
    if ($mc.Value -match '(?i)^https?://' -and $mc.Type -match '矿池') {
        $mc.Type = "下载/投放URL候选"
    }

    $MiningConfigsArray += $mc
}

$MiningConfigsGroupedArray = @()
foreach ($g in ($MiningConfigsArray | Where-Object { $_.Value } | Group-Object Value)) {
    $items = @($g.Group)
    $first = $items | Select-Object -First 1
    $types = (($items.Type | Where-Object { $_ } | Sort-Object -Unique) -join ";")
    $sourceFiles = (($items.FilePath | Where-Object { $_ } | Sort-Object -Unique) -join "`n")
    $sourceDirs = (($items.SourceDir | Where-Object { $_ } | Sort-Object -Unique) -join "`n")
    $confidence = if (@($items | Where-Object { $_.Confidence -eq "高" }).Count -gt 0) { "高" } else { "中" }

    $MiningConfigsGroupedArray += [PSCustomObject]@{
        Type       = $types
        Value      = $g.Name
        Confidence = $confidence
        HitCount   = $items.Count
        SourceFiles = $sourceFiles
        SourceDirs  = $sourceDirs
        Context     = $first.Context
    }
}

$MiningCandidateSourcesArray = @()
foreach ($src in $MiningCandidateSources) { $MiningCandidateSourcesArray += $src }

Export-DetailCsv -Name "挖矿配置扫描目录来源.csv" -Data $MiningCandidateSourcesArray
Export-DetailCsv -Name "挖矿配置文件候选.csv" -Data $MiningConfigFiles
Export-DetailCsv -Name "挖矿配置提取.csv" -Data $MiningConfigsArray
Export-DetailCsv -Name "挖矿配置按Value聚合.csv" -Data $MiningConfigsGroupedArray
Export-DetailCsv -Name "ADS备用数据流线索.csv" -Data $AdsFindings

if ($AdsFindings.Count -gt 0) {
    $adsPreview = (($AdsFindings | Select-Object -First 5 | ForEach-Object { $_.AdsPath }) -join "`n")
    Add-Finding -Level "中危" -Category "ADS" -Title "候选目录中发现可疑 ADS 备用数据流" `
        -Evidence "ADS数量=$($AdsFindings.Count)，示例=$adsPreview" `
        -Suggestion "ADS 可能被用于隐藏配置或脚本片段。建议使用 Get-Item -Stream *、Get-Content -Stream、Sysinternals streams.exe 复核，并结合文件 Hash/时间线判断是否需要隔离。"
}

# v0.6.4：候选目录内的自定义认证失败日志关联。
# 真实 Windows Security 4625 的来源 IP 仍以系统日志为准；这里用于补充应用/代理/实验日志中的 src/client_ip/fake_src_ip 线索。
$CustomAuthLogHits = @()
try {
    foreach ($dir in $MiningCandidateDirs) {
        if (-not (Test-Path $dir -PathType Container)) { continue }

        $logFiles = Get-ChildItem -Path $dir -Recurse -File -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Length -gt 0 -and $_.Length -lt 2MB -and ($_.Extension.ToLower() -in @(".log",".txt",".conf",".ini",".db","")) } |
            Select-Object -First 80

        foreach ($lf in $logFiles) {
            $logText = ""
            try { $logText = Get-Content -Path $lf.FullName -Raw -ErrorAction Stop } catch { $logText = "" }
            if ([string]::IsNullOrWhiteSpace($logText)) { continue }
            if ($logText -notmatch "(?i)fail|failed|brute|auth|login|rdp|smb|4625") { continue }

            foreach ($m in [regex]::Matches($logText, '(?i)\b(?:fake_src_ip|src|source_ip|client_ip|remote_ip)\s*=\s*((?:\d{1,3}\.){3}\d{1,3})\b')) {
                $ip = $m.Groups[1].Value
                $CustomAuthLogHits += [PSCustomObject]@{
                    SourceFile = $lf.FullName
                    SourceDir  = $dir
                    SourceIP   = $ip
                    Context    = (Get-ShortContext -Text $logText -Value $ip)
                    Note       = "自定义/应用日志中的来源 IP 线索；需与 Windows Security 4625、网络设备或真实远程登录场景交叉验证"
                }
            }
        }
    }
} catch {}

Export-DetailCsv -Name "自定义认证日志IP线索.csv" -Data $CustomAuthLogHits

if ($CustomAuthLogHits.Count -gt 0) {
    $ipPreview = (($CustomAuthLogHits.SourceIP | Sort-Object -Unique | Select-Object -First 10) -join ";")
    Add-Finding -Level "关注" -Category "认证日志" -Title "候选目录中发现自定义认证失败来源 IP 线索" `
        -Evidence "IP线索=$ipPreview，命中文件数=$(@($CustomAuthLogHits.SourceFile | Sort-Object -Unique).Count)" `
        -Suggestion "这类 IP 来自应用/实验/代理日志，不等同于 Windows Security 4625 的真实 Source IP；请结合真实远程登录、网关、防火墙或双机测试验证。"
}

if ($MiningConfigsGroupedArray.Count -gt 0) {
    $poolCount = @($MiningConfigsGroupedArray | Where-Object { $_.Type -match "矿池" }).Count
    $walletCount = @($MiningConfigsGroupedArray | Where-Object { $_.Type -match "钱包" }).Count
    $urlCount = @($MiningConfigsGroupedArray | Where-Object { $_.Type -match "下载/投放URL" }).Count

    Add-Finding -Level "高危" -Category "挖矿配置" -Title "发现矿池、钱包或投放 URL 配置线索" `
        -Evidence "矿池线索=$poolCount，钱包线索=$walletCount，投放URL线索=$urlCount，候选目录=$($MiningCandidateDirs -join ';')" `
        -Suggestion "优先打开配置文件确认矿池地址、钱包地址和启动脚本；结合进程、服务、计划任务判断挖矿程序如何启动。"
}

# =========================================================
# 模块 7：PowerShell 痕迹
# =========================================================

Write-Info "正在检查 PowerShell 高危痕迹..."

$PowerShellFindings = @()
$psEvents = Get-EventsById -LogName "Microsoft-Windows-PowerShell/Operational" -Ids @(4103,4104)

foreach ($evt in $psEvents) {
    $msg = $evt.Message
    if (Test-IsSelfToolText $msg) { continue }

    if ($msg -match $DangerCommandRegex) {
        $psLevel = "中危"
        $psReason = "命中 PowerShell 高危命令特征"
        $psSuggestion = "重点检查是否存在下载执行、编码命令、绕过策略、禁用防护、创建账户或添加管理员行为。"

        if (Test-IsAdminExecutionPolicyOnly $msg) {
            $psLevel = "关注"
            $psReason = "仅发现当前进程级 ExecutionPolicy Bypass，可能是管理员临时运行脚本"
            $psSuggestion = "若该记录与管理员运行 WinIR/测试脚本时间一致，可作为低优先级关注；若出现在未知时间段或伴随下载执行、编码命令、账户变更，应升级复核。"
        }

        $PowerShellFindings += [PSCustomObject]@{
            Level       = $psLevel
            TimeCreated = $evt.TimeCreated
            EventID     = $evt.Id
            RecordID    = $evt.RecordId
            Reason      = $psReason
            Summary     = $msg.Substring(0, [Math]::Min(400, $msg.Length))
        }

        Add-Finding -Level $psLevel -Category "PowerShell" -Title "PowerShell 事件日志命中高危命令特征" `
            -Evidence "时间=$($evt.TimeCreated)，EventID=$($evt.Id)，原因=$psReason，摘要=$($msg.Substring(0, [Math]::Min(300, $msg.Length)))" `
            -Suggestion $psSuggestion
    }
}

Export-DetailCsv -Name "PowerShell高危痕迹.csv" -Data $PowerShellFindings

# =========================================================
# 场景聚合判断
# =========================================================

if ($null -eq $MiningConfigsArray) {
    $MiningConfigsArray = @()
}

Write-Info "正在进行攻击场景聚合判断..."

$RdpListening = @($DangerPorts | Where-Object { $_.LocalPort -eq 3389 }).Count -gt 0
$SmbListening = @($DangerPorts | Where-Object { $_.LocalPort -eq 445 }).Count -gt 0

foreach ($ipItem in ($FailedByIP | Where-Object { $_.LastFailTime -ge $FocusStartTime })) {
    $relatedRdp = @($RdpEvents | Where-Object { $_.Address -eq $ipItem.SourceIP })
    $hasRdpEvents = $relatedRdp.Count -gt 0
    $hasSuccess = -not [string]::IsNullOrWhiteSpace([string]$ipItem.FirstSuccessTime)

    if ($ipItem.FailedCount -ge 5 -and ($RdpListening -or $hasRdpEvents -or $ipItem.FirstSuccessType -match "RDP|10-")) {
        $level = if ($hasSuccess -or $hasRdpEvents) { "高危" } else { "中危" }

        Add-Scenario -Level $level -Scenario "疑似 RDP 暴力破解 / 远程桌面攻击" `
            -Conclusion "来源 IP $($ipItem.SourceIP) 存在多次登录失败，且本机监听 3389 或存在 RDP 相关事件。" `
            -Evidence "疑似开始时间=$($ipItem.AttackStartTime)，失败次数=$($ipItem.FailedCount)，目标账户=$($ipItem.TargetUsers)，登录方式=$($ipItem.MainLogonMethod)，首次成功=$($ipItem.FirstSuccessTime)，RDP事件数=$($relatedRdp.Count)" `
            -Suggestion "优先复核 3389 是否对外开放、该 IP 是否出现 1149/21/25 RDP 成功事件、是否存在后续创建账户/加入组/服务安装行为。"
    }
    elseif ($ipItem.FailedCount -ge 5 -and $SmbListening -and $ipItem.MainLogonMethod -match "3-") {
        Add-Scenario -Level "中危" -Scenario "疑似 SMB / NTLM 网络登录爆破" `
            -Conclusion "来源 IP $($ipItem.SourceIP) 存在多次 LogonType 3 登录失败，且本机监听 445。" `
            -Evidence "疑似开始时间=$($ipItem.AttackStartTime)，失败次数=$($ipItem.FailedCount)，目标账户=$($ipItem.TargetUsers)，端口范围=$($ipItem.SourcePortRange)" `
            -Suggestion "检查 SMB 是否对外暴露，确认该 IP 是否有后续登录成功、横向移动或文件共享访问行为。"
    }
}


foreach ($failGroup in ($FailedByIdentity | Where-Object { $_.LastFailTime -ge $FocusStartTime -and $_.FailedCount -ge 5 })) {
    if ($failGroup.Source -match '^IP:') { continue }

    Add-Scenario -Level "中危" -Scenario "疑似登录失败集中发生（无标准来源 IP）" `
        -Conclusion "发现多次 4625 登录失败，但事件未解析到标准远程 IP，可能是本机/内网/IPC$ 失败登录或日志字段缺失。" `
        -Evidence "来源=$($failGroup.Source)，失败次数=$($failGroup.FailedCount)，目标账户=$($failGroup.TargetUser)，登录方式=$($failGroup.LogonTypeDesc)，开始=$($failGroup.AttackStartTime)，结束=$($failGroup.LastFailTime)" `
        -Suggestion "建议查看登录失败明细，结合 WorkstationName、LogonType、Status/SubStatus 与原始安全日志确认是否为爆破或测试行为。"
}

$activeMinerProcessEvidence = @($ResourceAnomalies | Where-Object {
    ($_.CpuPercent -ge $CpuHighPercent -or $_.Tags -match "CPU占用") -and
    ("$($_.Name) $($_.ExecutablePath) $($_.Tags) $($_.CommandLine)" -match "(?i)xmrig|miner|c3pool|monero|stratum|WinRing0|ProgramData|AppData|Temp|Public|ExecutionPolicy|WindowStyle Hidden")
})
$minerServiceEvidence = @($ServiceEvents | Where-Object { "$($_.ServiceName) $($_.ImagePath)" -match "(?i)c3pool|xmrig|miner|WinRing0|nssm|monero|stratum|ProgramData|AppData|Temp|Public|ExecutionPolicy" })
$minerConfigEvidence = @($MiningConfigsGroupedArray | Where-Object { "$($_.Type) $($_.Value)" -match "(?i)矿池|钱包|stratum|pool|tcp://" })
$minerPersistenceEvidence = @($SuspiciousStartup) + @($SuspiciousTasks) + @($minerServiceEvidence)
$minerEvidence = @($activeMinerProcessEvidence) + @($minerServiceEvidence) + @($minerConfigEvidence)

if (@($activeMinerProcessEvidence).Count -gt 0 -and @($minerConfigEvidence).Count -gt 0) {
    Add-Scenario -Level "高危" -Scenario "疑似活动中挖矿 / 资源滥用" `
        -Conclusion "当前存在资源异常进程，并发现矿池/钱包配置及持久化线索，倾向于活动中挖矿或资源滥用。" `
        -Evidence "活动进程数=$(@($activeMinerProcessEvidence).Count)，配置线索数=$(@($minerConfigEvidence).Count)，持久化线索数=$(@($minerPersistenceEvidence).Count)；示例=$((@($minerConfigEvidence) | Select-Object -First 1 | Out-String).Trim())" `
        -Suggestion "优先确认高 CPU 进程的路径、Hash、父进程和启动来源；立即复核服务/计划任务/启动项与矿池配置文件。"
}
elseif (@($minerConfigEvidence).Count -gt 0 -and @($minerPersistenceEvidence).Count -gt 0) {
    Add-Scenario -Level "高危" -Scenario "疑似挖矿残留 / 历史痕迹" `
        -Conclusion "当前未发现持续资源异常进程，但存在矿池/钱包配置和持久化线索，倾向于挖矿残留或历史投放痕迹。" `
        -Evidence "配置线索数=$(@($minerConfigEvidence).Count)，持久化线索数=$(@($minerPersistenceEvidence).Count)；示例=$((@($minerConfigEvidence) | Select-Object -First 1 | Out-String).Trim())" `
        -Suggestion "建议检查对应文件是否仍存在、服务/任务/启动项是否仍启用，并结合文件时间线判断是否已被清理或处于休眠状态。"
}
elseif (@($minerEvidence).Count -gt 0) {
    Add-Scenario -Level "中危" -Scenario "疑似挖矿相关线索" `
        -Conclusion "发现部分挖矿相关线索，但当前证据链不足以区分活动中挖矿或历史残留。" `
        -Evidence "相关线索数量=$(@($minerEvidence).Count)；示例=$((@($minerEvidence) | Select-Object -First 1 | Out-String).Trim())" `
        -Suggestion "建议继续结合进程、服务、计划任务、启动项、矿池/钱包配置和文件 Hash 进行人工复核。"
}

$persistenceEvidence = @()
$persistenceEvidence += @($SuspiciousStartup)
$persistenceEvidence += @($SuspiciousTasks)
$persistenceEvidence += @($ServiceEvents | Where-Object { $_.Level -in @("高危","中危") })

if (@($persistenceEvidence).Count -gt 0) {
    Add-Scenario -Level "中危" -Scenario "疑似持久化行为" `
        -Conclusion "发现启动项、计划任务或服务安装相关持久化线索。" `
        -Evidence "相关线索数量=$(@($persistenceEvidence).Count)" `
        -Suggestion "重点复核 AppData/Public/Temp/ProgramData 目录下的启动项、可疑服务、计划任务和 nssm/脚本启动方式。"
}

$accountEvidence = @($SecurityEvents | Where-Object { $_.TimeCreated -ge $FocusStartTime -and $_.EventID -in @(4720,4732) -and $_.TargetUser -match "(?i)Administrators|Remote Desktop Users|管理员|远程桌面用户|hack|test|support|admin" })
if (@($accountEvidence).Count -gt 0) {
    Add-Scenario -Level "高危" -Scenario "疑似账户权限变更" `
        -Conclusion "发现创建用户或加入敏感本地组的事件。" `
        -Evidence "相关线索数量=$(@($accountEvidence).Count)" `
        -Suggestion "核查新增账户、组成员变化、操作者账户和变化时间是否与攻击时间线重合。"
}

# 如果没有任何场景结论，给出正常提示
if ($Scenarios.Count -eq 0) {
    Add-Scenario -Level "正常" -Scenario "未形成明确攻击场景" `
        -Conclusion "当前规则未聚合出明确攻击场景。" `
        -Evidence "未发现满足阈值的 RDP/SMB 爆破、挖矿、持久化或账户变更组合。" `
        -Suggestion "这不代表系统绝对安全，建议结合业务背景、EDR/杀软告警和人工分析继续复核。"
}

# 如果没有重点关注项，给出正常提示
if ($Findings.Count -eq 0) {
    Add-Finding -Level "正常" -Category "总体" -Title "当前规则未发现重点关注项" `
        -Evidence "在本次时间范围内，当前规则未命中高危、中危或关注项。" `
        -Suggestion "这不代表系统绝对安全，建议结合业务背景和人工分析继续复核。"
}


# =========================================================
# 模块 8：攻击时间线与 ATT&CK 映射（v0.6.0-beta）
# =========================================================

Write-Info "正在构建攻击时间线与 ATT&CK 映射..."

$AttackTimeline = New-Object System.Collections.Generic.List[object]
$AttackTechniqueRaw = New-Object System.Collections.Generic.List[object]
$script:TimelineCounter = 0

function Add-AttackTimelineEvent {
    param(
        [datetime]$TimeCreated,
        [string]$Phase,
        [string]$Action,
        [string]$Level,
        [string]$EvidenceType,
        [string]$Source,
        [string]$Target,
        [string]$TechniqueId,
        [string]$TechniqueName,
        [string]$Tactic,
        [string]$Evidence,
        [string]$Suggestion
    )

    if ($null -eq $TimeCreated -or $TimeCreated -eq [datetime]::MinValue) {
        $TimeCreated = $EndTime
    }

    $script:TimelineCounter += 1
    $evidenceId = "TL-{0:D3}" -f $script:TimelineCounter

    $AttackTimeline.Add([PSCustomObject]@{
        EvidenceId    = $evidenceId
        TimeCreated   = $TimeCreated
        Phase         = $Phase
        Action        = $Action
        Level         = $Level
        EvidenceType  = $EvidenceType
        Source        = $Source
        Target        = $Target
        TechniqueId   = $TechniqueId
        TechniqueName = $TechniqueName
        Tactic        = $Tactic
        Evidence      = $Evidence
        Suggestion    = $Suggestion
    }) | Out-Null

    if ($TechniqueId) {
        $AttackTechniqueRaw.Add([PSCustomObject]@{
            EvidenceId    = $evidenceId
            Tactic        = $Tactic
            TechniqueId   = $TechniqueId
            TechniqueName = $TechniqueName
            Action        = $Action
            Level         = $Level
            Evidence      = $Evidence
            Suggestion    = $Suggestion
        }) | Out-Null
    }
}

function Get-FirstExistingFileTime {
    param([string]$SourceFiles)
    try {
        foreach ($line in (($SourceFiles -split "`n") | Where-Object { $_ })) {
            $candidate = ([string]$line).Trim()
            if ($candidate -and (Test-Path $candidate)) {
                return (Get-Item $candidate -Force).LastWriteTime
            }
        }
    } catch {}
    return $EndTime
}

# 1) 登录失败 / 爆破线索
$recentFailedLogonsForTimeline = @($FailedLogonDetails | Where-Object { $_.TimeCreated -ge $FocusStartTime })
if ($recentFailedLogonsForTimeline.Count -ge 5) {
    $firstFail = $recentFailedLogonsForTimeline | Sort-Object TimeCreated | Select-Object -First 1
    $lastFail  = $recentFailedLogonsForTimeline | Sort-Object TimeCreated | Select-Object -Last 1
    $targets = (($recentFailedLogonsForTimeline.TargetUser | Where-Object { $_ } | Sort-Object -Unique) -join ";")
    $sources = (($recentFailedLogonsForTimeline.Source | Where-Object { $_ } | Sort-Object -Unique) -join ";")

    Add-AttackTimelineEvent -TimeCreated $firstFail.TimeCreated `
        -Phase "凭证攻击" `
        -Action "多次登录失败 / 疑似口令猜测" `
        -Level "中危" `
        -EvidenceType "Security 4625" `
        -Source $sources `
        -Target $targets `
        -TechniqueId "T1110" `
        -TechniqueName "Brute Force" `
        -Tactic "Credential Access" `
        -Evidence "最近重点窗口内发现 $($recentFailedLogonsForTimeline.Count) 次登录失败，开始=$($firstFail.TimeCreated)，结束=$($lastFail.TimeCreated)，目标账户=$targets" `
        -Suggestion "结合来源 IP/WorkstationName、LogonType、Status/SubStatus 判断是否为 SMB/RDP/NLA 爆破或本机测试。"
}

foreach ($ipItem in ($FailedByIP | Where-Object { $_.FailedCount -ge 5 -and $_.LastFailTime -ge $FocusStartTime })) {
    Add-AttackTimelineEvent -TimeCreated $ipItem.AttackStartTime `
        -Phase "凭证攻击" `
        -Action "来源 IP 多次登录失败" `
        -Level "中危" `
        -EvidenceType "Security 4625 聚合" `
        -Source $ipItem.SourceIP `
        -Target $ipItem.TargetUsers `
        -TechniqueId "T1110" `
        -TechniqueName "Brute Force" `
        -Tactic "Credential Access" `
        -Evidence "失败次数=$($ipItem.FailedCount)，目标账户=$($ipItem.TargetUsers)，登录方式=$($ipItem.MainLogonMethod)，首次成功=$($ipItem.FirstSuccessTime)" `
        -Suggestion "若失败后出现同源成功登录，应优先复核该账户和后续行为。"
}

# 1.4) ADS 备用数据流隐藏配置线索
if ($AdsFindings.Count -gt 0) {
    $adsPreview = (($AdsFindings | Select-Object -First 5 | ForEach-Object { $_.AdsPath }) -join ";")
    Add-AttackTimelineEvent -TimeCreated $EndTime `
        -Phase "防御规避" `
        -Action "候选文件存在可疑 ADS 备用数据流" `
        -Level "中危" `
        -EvidenceType "ADS" `
        -Source "NTFS Alternate Data Stream" `
        -Target $adsPreview `
        -TechniqueId "T1564.004" `
        -TechniqueName "NTFS File Attributes" `
        -Tactic "Defense Evasion" `
        -Evidence "ADS数量=$($AdsFindings.Count)，示例=$adsPreview" `
        -Suggestion "复核 ADS 内容是否包含隐藏配置、投放 URL、钱包/矿池或脚本片段；必要时导出宿主文件和 ADS 内容留证。"
}

# 1.5) 自定义认证日志 IP 线索
if ($CustomAuthLogHits.Count -gt 0) {
    $ipPreview = (($CustomAuthLogHits.SourceIP | Sort-Object -Unique | Select-Object -First 8) -join ";")
    Add-AttackTimelineEvent -TimeCreated $EndTime `
        -Phase "凭证攻击" `
        -Action "自定义认证日志出现来源 IP 线索" `
        -Level "关注" `
        -EvidenceType "Custom Auth Log" `
        -Source "候选目录日志" `
        -Target $ipPreview `
        -TechniqueId "T1110" `
        -TechniqueName "Brute Force" `
        -Tactic "Credential Access" `
        -Evidence "自定义/应用日志中发现来源 IP 线索：$ipPreview；注意这不等同于 Windows Security 4625 真实来源 IP。" `
        -Suggestion "用于辅助复核；真实危险 IP 仍建议通过双机登录失败、网关、防火墙或 Security 4625 事件验证。"
}

# 2) RDP 远程服务行为
foreach ($rdp in ($RdpEvents | Where-Object { $_.TimeCreated -ge $FocusStartTime } | Sort-Object TimeCreated | Select-Object -First 30)) {
    Add-AttackTimelineEvent -TimeCreated $rdp.TimeCreated `
        -Phase "远程访问" `
        -Action "RDP 相关会话事件" `
        -Level "关注" `
        -EvidenceType "TerminalServices" `
        -Source $rdp.Address `
        -Target $rdp.UserName `
        -TechniqueId "T1021.001" `
        -TechniqueName "Remote Desktop Protocol" `
        -Tactic "Lateral Movement" `
        -Evidence "EventID=$($rdp.EventID)，描述=$($rdp.Description)，用户=$($rdp.UserName)，来源=$($rdp.Address)" `
        -Suggestion "与 4624/4625、1149、21/24/25、3389 监听和后续持久化行为进行时间线关联。"
}

# 3) PowerShell 执行痕迹
foreach ($ps in ($PowerShellFindings | Where-Object { $_.TimeCreated -ge $FocusStartTime } | Sort-Object TimeCreated | Select-Object -First 30)) {
    $psLevelForTimeline = if ($ps.Level) { $ps.Level } else { "中危" }
    $psAction = if ($psLevelForTimeline -eq "关注") { "PowerShell 管理/测试操作特征" } else { "PowerShell 高危命令特征" }

    Add-AttackTimelineEvent -TimeCreated $ps.TimeCreated `
        -Phase "执行" `
        -Action $psAction `
        -Level $psLevelForTimeline `
        -EvidenceType "PowerShell 4103/4104" `
        -Source "PowerShell" `
        -Target "ScriptBlock/Command" `
        -TechniqueId "T1059.001" `
        -TechniqueName "PowerShell" `
        -Tactic "Execution" `
        -Evidence "EventID=$($ps.EventID)，原因=$($ps.Reason)，摘要=$($ps.Summary)" `
        -Suggestion "结合时间、父进程、脚本路径判断是管理员临时操作还是攻击执行链。若伴随下载执行、编码命令、持久化或账户变更，应优先复核。"
}

# 4) 服务安装
foreach ($svc in ($ServiceEvents | Where-Object { $_.Level -in @("高危","中危") } | Sort-Object TimeCreated | Select-Object -First 40)) {
    Add-AttackTimelineEvent -TimeCreated $svc.TimeCreated `
        -Phase "持久化" `
        -Action "创建或安装可疑 Windows 服务" `
        -Level $svc.Level `
        -EvidenceType "System 7045" `
        -Source $svc.ServiceName `
        -Target $svc.ImagePath `
        -TechniqueId "T1543.003" `
        -TechniqueName "Windows Service" `
        -Tactic "Persistence" `
        -Evidence "服务=$($svc.ServiceName)，路径=$($svc.ImagePath)，原因=$($svc.Reason)" `
        -Suggestion "复核服务文件 Hash、签名、创建时间、父进程，以及是否与计划任务/启动项/矿池配置相关。"
}

# 5) 计划任务
foreach ($task in ($SuspiciousTasks | Select-Object -First 60)) {
    Add-AttackTimelineEvent -TimeCreated $EndTime `
        -Phase "持久化" `
        -Action "发现可疑计划任务" `
        -Level $task.Level `
        -EvidenceType "Scheduled Task" `
        -Source $task.TaskName `
        -Target $task.Actions `
        -TechniqueId "T1053.005" `
        -TechniqueName "Scheduled Task" `
        -Tactic "Persistence" `
        -Evidence "任务=$($task.TaskName)，动作=$($task.Actions)，原因=$($task.Reason)" `
        -Suggestion "复核任务触发器、创建时间、执行文件签名和命令行参数。"
}

# 6) 启动项 / Run Key / Startup Folder / 脚本宿主
foreach ($startup in ($SuspiciousStartup | Select-Object -First 80)) {
    $techId = "T1547.001"
    $techName = "Registry Run Keys / Startup Folder"
    $tactic = "Persistence"
    $phase = "持久化"

    if ($startup.Command -match "(?i)mshta\.exe") {
        $techId = "T1218.005"; $techName = "Mshta"; $tactic = "Defense Evasion"; $phase = "规避/脚本执行"
    }
    elseif ($startup.Command -match "(?i)wscript\.exe|cscript\.exe|\.vbs") {
        $techId = "T1059.005"; $techName = "Visual Basic"; $tactic = "Execution"; $phase = "脚本执行"
    }
    elseif ($startup.Command -match "(?i)powershell|\.ps1") {
        $techId = "T1059.001"; $techName = "PowerShell"; $tactic = "Execution"; $phase = "脚本执行"
    }

    Add-AttackTimelineEvent -TimeCreated $EndTime `
        -Phase $phase `
        -Action "发现可疑启动项" `
        -Level $startup.Level `
        -EvidenceType "Run/RunOnce/Startup" `
        -Source $startup.Location `
        -Target $startup.Command `
        -TechniqueId $techId `
        -TechniqueName $techName `
        -Tactic $tactic `
        -Evidence "位置=$($startup.Location)，名称=$($startup.Name)，命令=$($startup.Command)，原因=$($startup.Reason)" `
        -Suggestion "复核启动项文件是否仍存在、是否隐藏、是否由脚本宿主或 LOLBin 启动。"
}

# 7) 资源异常 / 挖矿活动
foreach ($ra in ($ResourceAnomalies | Where-Object { $_.CpuPercent -ge $CpuHighPercent -or $_.Tags -match "CPU占用" } | Select-Object -First 30)) {
    Add-AttackTimelineEvent -TimeCreated $EndTime `
        -Phase "影响" `
        -Action "资源占用异常 / 疑似资源劫持" `
        -Level $ra.Level `
        -EvidenceType "Process Resource" `
        -Source $ra.Name `
        -Target $ra.ExecutablePath `
        -TechniqueId "T1496" `
        -TechniqueName "Resource Hijacking" `
        -Tactic "Impact" `
        -Evidence "进程=$($ra.Name)，PID=$($ra.ProcessId)，CPU=$($ra.CpuPercent)%，路径=$($ra.ExecutablePath)，标签=$($ra.Tags)" `
        -Suggestion "结合矿池/钱包配置、服务/任务/启动项和文件 Hash 判断是否为活动中挖矿。"
}

# 8) 矿池 / 钱包配置
# v0.6.2：时间线中按'配置发现事件'聚合展示，避免 T1496 被同一组配置刷屏。
# 详细矿池/钱包值仍保留在「挖矿配置提取」表和 CSV 中。
if ($MiningConfigsGroupedArray.Count -gt 0) {
    $firstConfig = $MiningConfigsGroupedArray | Select-Object -First 1
    $eventTimeCandidates = @()
    foreach ($mc in $MiningConfigsGroupedArray) {
        $t = Get-FirstExistingFileTime -SourceFiles $mc.SourceFiles
        if ($t -and $t -ne [datetime]::MinValue) { $eventTimeCandidates += $t }
    }
    $eventTime = if ($eventTimeCandidates.Count -gt 0) { ($eventTimeCandidates | Sort-Object | Select-Object -First 1) } else { $EndTime }

    $previewValues = (($MiningConfigsGroupedArray | Select-Object -First 5 | ForEach-Object { "$($_.Type)=$($_.Value)" }) -join "；")
    $sourcePreview = (($MiningConfigsGroupedArray.SourceFiles -join "`n" -split "`n" | Where-Object { $_ } | Sort-Object -Unique | Select-Object -First 8) -join "`n")

    Add-AttackTimelineEvent -TimeCreated $eventTime `
        -Phase "影响" `
        -Action "发现矿池 / 钱包配置线索" `
        -Level "高危" `
        -EvidenceType "Mining Config" `
        -Source $sourcePreview `
        -Target "聚合线索数=$($MiningConfigsGroupedArray.Count)" `
        -TechniqueId "T1496" `
        -TechniqueName "Resource Hijacking" `
        -Tactic "Impact" `
        -Evidence "聚合后配置线索数=$($MiningConfigsGroupedArray.Count)，示例=$previewValues" `
        -Suggestion "确认配置文件是否仍被服务/计划任务/启动项引用，提取文件 Hash 并进行威胁情报检索。"
}

# 9) 账户创建 / 权限变更
foreach ($evt in ($SecurityEvents | Where-Object { $_.TimeCreated -ge $FocusStartTime -and $_.EventID -in @(4720,4732) } | Sort-Object TimeCreated | Select-Object -First 40)) {
    $techId = if ($evt.EventID -eq 4720) { "T1136.001" } else { "T1098" }
    $techName = if ($evt.EventID -eq 4720) { "Local Account" } else { "Account Manipulation" }
    Add-AttackTimelineEvent -TimeCreated $evt.TimeCreated `
        -Phase "账户变更" `
        -Action $evt.EventType `
        -Level "高危" `
        -EvidenceType "Security $($evt.EventID)" `
        -Source $evt.SubjectUser `
        -Target $evt.TargetUser `
        -TechniqueId $techId `
        -TechniqueName $techName `
        -Tactic "Persistence" `
        -Evidence "EventID=$($evt.EventID)，用户=$($evt.TargetUser)，成员=$($evt.MemberName)，操作者=$($evt.SubjectUser)，来源=$($evt.SourceIP)" `
        -Suggestion "核查新增账户/组成员是否为合法变更，并与远程登录和持久化时间线关联。"
}

# v0.6.2：先按时间排序，再重新生成 TL-001/TL-002，保证编号与时间线顺序一致。
$AttackTimelineRawSorted = @($AttackTimeline | Sort-Object TimeCreated,EvidenceId)
$AttackTimelineArray = @()
$timelineIndex = 0
foreach ($e in $AttackTimelineRawSorted) {
    $timelineIndex += 1
    $newEvidenceId = "TL-{0:D3}" -f $timelineIndex

    $AttackTimelineArray += [PSCustomObject]@{
        EvidenceId    = $newEvidenceId
        TimeCreated   = $e.TimeCreated
        Phase         = $e.Phase
        Action        = $e.Action
        Level         = $e.Level
        EvidenceType  = $e.EvidenceType
        Source        = $e.Source
        Target        = $e.Target
        TechniqueId   = $e.TechniqueId
        TechniqueName = $e.TechniqueName
        Tactic        = $e.Tactic
        Evidence      = $e.Evidence
        Suggestion    = $e.Suggestion
    }
}

$AttackTechniques = @()
foreach ($g in (($AttackTimelineArray | Where-Object { $_.TechniqueId }) | Group-Object TechniqueId | Sort-Object Name)) {
    $items = @($g.Group)
    $first = $items | Select-Object -First 1
    $AttackTechniques += [PSCustomObject]@{
        Tactic          = (($items.Tactic | Where-Object { $_ } | Sort-Object -Unique) -join ";")
        TechniqueId     = $g.Name
        TechniqueName   = $first.TechniqueName
        Count           = $items.Count
        EvidenceIds     = (($items.EvidenceId | Sort-Object -Unique) -join ";")
        ExampleEvidence = $first.Evidence
        Suggestion      = $first.Suggestion
    }
}

$EvidenceChain = @()
foreach ($e in ($AttackTimelineArray | Select-Object -First 120)) {
    $EvidenceChain += [PSCustomObject]@{
        EvidenceId  = $e.EvidenceId
        TimeCreated = $e.TimeCreated
        Phase       = $e.Phase
        Brief       = "$($e.Action) / $($e.TechniqueId)"
        Source      = $e.Source
        Target      = $e.Target
    }
}

Export-DetailCsv -Name "攻击时间线.csv" -Data $AttackTimelineArray
Export-DetailCsv -Name "ATTACK技术映射.csv" -Data $AttackTechniques
Export-DetailCsv -Name "证据链概览.csv" -Data $EvidenceChain

# =========================================================
# 模块 10：v0.7 证据链评分与处置建议生成器
# =========================================================

Write-Info "正在生成 v0.7 证据链评分与处置建议..."

function Limit-Score {
    param([int]$Score)
    if ($Score -lt 0) { return 0 }
    if ($Score -gt 100) { return 100 }
    return $Score
}

function Get-ScoreLevel {
    param([int]$Score)
    if ($Score -ge 80) { return "高危" }
    elseif ($Score -ge 50) { return "中危" }
    elseif ($Score -ge 25) { return "关注" }
    return "低"
}

function Get-EvidenceIdsByTechnique {
    param([string[]]$TechniqueIds)
    $ids = @()
    foreach ($tid in $TechniqueIds) {
        $ids += @($AttackTimelineArray | Where-Object { $_.TechniqueId -eq $tid } | Select-Object -ExpandProperty EvidenceId)
    }
    return (($ids | Where-Object { $_ } | Sort-Object -Unique) -join ";")
}

function Add-EvidenceScore {
    param(
        [System.Collections.Generic.List[object]]$List,
        [string]$Scenario,
        [int]$Score,
        [string]$Conclusion,
        [string]$Evidence,
        [string]$Priority,
        [string]$RecommendedAction,
        [string]$EvidenceIds
    )

    $finalScore = Limit-Score -Score $Score
    $List.Add([PSCustomObject]@{
        Level             = Get-ScoreLevel -Score $finalScore
        Scenario          = $Scenario
        Score             = $finalScore
        Priority          = $Priority
        Conclusion        = $Conclusion
        Evidence          = $Evidence
        EvidenceIds       = $EvidenceIds
        RecommendedAction = $RecommendedAction
    }) | Out-Null
}

function Add-CleanupAdvice {
    param(
        [System.Collections.Generic.List[object]]$List,
        [string]$Priority,
        [string]$RiskType,
        [string]$Target,
        [string]$Evidence,
        [string]$SuggestedCommand,
        [string]$SafetyNote
    )

    if ([string]::IsNullOrWhiteSpace($Target)) { return }

    foreach ($x in $List) {
        if ($x.RiskType -eq $RiskType -and $x.Target -eq $Target -and $x.SuggestedCommand -eq $SuggestedCommand) {
            return
        }
    }

    $List.Add([PSCustomObject]@{
        Priority         = $Priority
        RiskType         = $RiskType
        Target           = $Target
        Evidence         = $Evidence
        SuggestedCommand = $SuggestedCommand
        SafetyNote       = $SafetyNote
    }) | Out-Null
}

function Get-FirstPathFromText {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return "" }
    $m = [regex]::Match($Text, '(?i)[A-Z]:\\[^"''<>|\r\n]+?\.(exe|dll|ps1|vbs|bat|cmd|hta|js|conf|ini|db|bak|dat|txt)')
    if ($m.Success) { return $m.Value.Trim() }
    return ""
}

function Get-SafeRegDeleteCommand {
    param([string]$Location,[string]$Name)
    if ([string]::IsNullOrWhiteSpace($Location) -or [string]::IsNullOrWhiteSpace($Name)) { return "" }
    if ($Location -match '^HKLM:\\(.+)$') { return "reg delete `"HKLM\$($Matches[1])`" /v `"$Name`" /f" }
    if ($Location -match '^HKCU:\\(.+)$') { return "reg delete `"HKCU\$($Matches[1])`" /v `"$Name`" /f" }
    return ""
}

function Resolve-ServiceNameForCommand {
    param(
        [string]$ServiceName,
        [string]$ImagePath
    )

    # 7045 日志中的 ServiceName 在部分系统/语言环境里可能更像 DisplayName。
    # sc.exe 更适合使用 Win32_Service.Name，所以这里尽量反查真实服务名。
    try {
        $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue
        foreach ($svc in $services) {
            if ($svc.Name -eq $ServiceName) { return $svc.Name }
        }
        foreach ($svc in $services) {
            if ($svc.DisplayName -eq $ServiceName) { return $svc.Name }
        }
        if (-not [string]::IsNullOrWhiteSpace($ImagePath)) {
            $needle = ($ImagePath -replace '"','').Trim()
            foreach ($svc in $services) {
                $pn = ([string]$svc.PathName -replace '"','').Trim()
                if ($pn -eq $needle -or $pn.Contains($needle) -or $needle.Contains($pn)) {
                    return $svc.Name
                }
            }
        }
    } catch {}

    return $ServiceName
}

function Get-StartupArtifactPath {
    param(
        [string]$Location,
        [string]$Name,
        [string]$Command
    )

    # 注册表启动项没有文件路径本体，删除建议应走 reg delete。
    if ($Location -match '^HK') { return "" }

    # Startup 文件夹中的 .lnk/.vbs/.bat 等，处置对象应是 Startup 目录里的文件本身，
    # 不是快捷方式解析后的 wscript.exe 或 powershell.exe 命令行。
    try {
        if ((Test-Path $Location -PathType Container) -and -not [string]::IsNullOrWhiteSpace($Name)) {
            return (Join-Path $Location $Name)
        }
    } catch {}

    if ($Command -match '(?i)^[A-Z]:\\') { return $Command }
    return ""
}

function Test-IsSystemInterpreterPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }

    return ($Path -match '(?i)^C:\\Windows\\(System32|SysWOW64)\\(wscript|cscript|mshta|powershell|powershell_ise|cmd|rundll32|regsvr32|wmic|schtasks|sc)\.exe$')
}

$EvidenceScores = New-Object System.Collections.Generic.List[object]
$CleanupAdvices = New-Object System.Collections.Generic.List[object]
$HighRiskHashTargets = New-Object System.Collections.Generic.List[object]

# 1. 挖矿 / 资源滥用证据链评分
$minerScore = 0
$minerReasons = @()
if (@($activeMinerProcessEvidence).Count -gt 0) { $minerScore += 30; $minerReasons += "存在资源异常/高 CPU 可疑进程" }
if (@($minerConfigEvidence).Count -gt 0) { $minerScore += 30; $minerReasons += "发现矿池/钱包/资源劫持配置" }
if (@($minerServiceEvidence).Count -gt 0) { $minerScore += 15; $minerReasons += "存在可疑服务关联" }
if (@($SuspiciousTasks).Count -gt 0) { $minerScore += 10; $minerReasons += "存在可疑计划任务" }
if (@($SuspiciousStartup).Count -gt 0) { $minerScore += 10; $minerReasons += "存在可疑启动项" }
if (@($CustomAuthLogHits).Count -gt 0) { $minerScore += 5; $minerReasons += "存在自定义认证日志 IP 线索" }

if ($minerScore -gt 0) {
    Add-EvidenceScore -List $EvidenceScores -Scenario "挖矿 / 资源滥用" -Score $minerScore `
        -Conclusion "根据资源异常、矿池配置和持久化线索综合评分。" `
        -Evidence (($minerReasons | Sort-Object -Unique) -join "；") `
        -Priority "优先确认是否仍在运行，然后处理服务/任务/启动项与配置文件。" `
        -RecommendedAction "先留证与计算 Hash，再停止可疑进程，随后禁用相关服务/计划任务/启动项。" `
        -EvidenceIds (Get-EvidenceIdsByTechnique -TechniqueIds @("T1496","T1543.003","T1053.005","T1547.001"))
}

# 2. 持久化证据链评分
$persistenceScore = 0
$persistenceReasons = @()
if (@($ServiceEvents | Where-Object { $_.Level -in @("高危","中危") }).Count -gt 0) { $persistenceScore += 25; $persistenceReasons += "发现可疑服务安装/服务线索" }
if (@($SuspiciousTasks).Count -gt 0) { $persistenceScore += 25; $persistenceReasons += "发现可疑计划任务" }
if (@($SuspiciousStartup).Count -gt 0) { $persistenceScore += 25; $persistenceReasons += "发现可疑启动项" }
if (@($AttackTimelineArray | Where-Object { $_.TechniqueId -in @("T1543.003","T1053.005","T1547.001") }).Count -ge 3) { $persistenceScore += 15; $persistenceReasons += "多类持久化技术同时出现" }
if (@($MiningConfigsGroupedArray).Count -gt 0) { $persistenceScore += 10; $persistenceReasons += "持久化线索附近存在配置/IOC" }

if ($persistenceScore -gt 0) {
    Add-EvidenceScore -List $EvidenceScores -Scenario "持久化后门 / 自启动控制" -Score $persistenceScore `
        -Conclusion "根据服务、计划任务、启动项及其与 IOC 的关联综合评分。" `
        -Evidence (($persistenceReasons | Sort-Object -Unique) -join "；") `
        -Priority "优先处理仍启用的服务和计划任务，再处理 Run/Startup。" `
        -RecommendedAction "先导出任务 XML、服务配置和注册表项，再逐项禁用或删除。" `
        -EvidenceIds (Get-EvidenceIdsByTechnique -TechniqueIds @("T1543.003","T1053.005","T1547.001"))
}

# 3. 账户入侵证据链评分
$accountScore = 0
$accountReasons = @()
if (@($SuspiciousUsers | Where-Object { $_.Level -eq "高危" }).Count -gt 0) { $accountScore += 35; $accountReasons += "存在高危可疑账户" }
if (@($HiddenAccounts).Count -gt 0) { $accountScore += 30; $accountReasons += "存在 Winlogon 隐藏账户项" }
if (@($AccountSecurityEvents | Where-Object { $_.EventID -in @(4720,4732,4728) }).Count -gt 0) { $accountScore += 20; $accountReasons += "存在账户创建或敏感组变更事件" }
if (@($RdpMembers).Count -gt 0) { $accountScore += 10; $accountReasons += "远程桌面用户组存在成员，需要复核" }
if (@($FailedByIdentity | Where-Object { $_.TargetUser -match '(?i)hack|admin|svc_|\$' -and $_.FailedCount -ge 2 }).Count -gt 0) { $accountScore += 10; $accountReasons += "可疑账户存在登录失败痕迹" }

# v0.7.1：隐藏账户是账户入侵高价值证据。只要命中 Winlogon 隐藏账户项，
# 账户证据链最低提升到高危阈值，避免显示为“中危”而降低处置优先级。
if (@($HiddenAccounts).Count -gt 0 -and $accountScore -lt 80) {
    $accountScore = 80
    $accountReasons += "Winlogon 隐藏账户触发高危阈值"
}
if (@($HiddenAccounts).Count -gt 0 -and @($SuspiciousUsers | Where-Object { $_.Level -eq "高危" }).Count -gt 0 -and $accountScore -lt 85) {
    $accountScore = 85
    $accountReasons += "隐藏账户与高危可疑账户同时存在"
}

if ($accountScore -gt 0) {
    Add-EvidenceScore -List $EvidenceScores -Scenario "账户入侵 / 隐藏用户" -Score $accountScore `
        -Conclusion "根据可疑账户、隐藏账户、组成员和账户事件综合评分。" `
        -Evidence (($accountReasons | Sort-Object -Unique) -join "；") `
        -Priority "优先确认隐藏账户和新增管理员组成员。" `
        -RecommendedAction "留证后禁用未知账户，导出 Winlogon 隐藏账户注册表项，并复核 4720/4732/4624/4625。" `
        -EvidenceIds (Get-EvidenceIdsByTechnique -TechniqueIds @("T1136","T1098","T1110"))
}

# 4. 凭证攻击 / 爆破证据链评分
$credScore = 0
$credReasons = @()
$maxFailed = 0
try { $maxFailed = [int](($FailedByIdentity | Measure-Object -Property FailedCount -Maximum).Maximum) } catch { $maxFailed = 0 }
if ($maxFailed -ge 10) { $credScore += 35; $credReasons += "存在集中登录失败" }
elseif ($maxFailed -ge 5) { $credScore += 25; $credReasons += "存在多次登录失败" }
if (@($FailedByIP | Where-Object { $_.FailedCount -ge 5 }).Count -gt 0) { $credScore += 25; $credReasons += "存在按来源 IP 聚合的失败登录" }
if (@($FailedByIdentity | Where-Object { $_.FailedCount -ge 5 }).Count -gt 0) { $credScore += 15; $credReasons += "存在按 Workstation/账户聚合的失败登录" }
if ($RdpListening) { $credScore += 10; $credReasons += "RDP 端口处于监听状态" }
if ($SmbListening) { $credScore += 10; $credReasons += "SMB 端口处于监听状态" }
if (@($CustomAuthLogHits).Count -gt 0) { $credScore += 10; $credReasons += "存在自定义认证日志 IP 线索" }

if ($credScore -gt 0) {
    Add-EvidenceScore -List $EvidenceScores -Scenario "口令猜测 / 凭证攻击" -Score $credScore `
        -Conclusion "根据 4625 登录失败、服务监听和自定义认证日志综合评分。" `
        -Evidence (($credReasons | Sort-Object -Unique) -join "；") `
        -Priority "优先确认是否存在真实来源 IP、成功登录和后续账户/持久化变化。" `
        -RecommendedAction "导出登录失败明细，关联 4624 成功登录、RDP/SMB 访问和账户变更事件。" `
        -EvidenceIds (Get-EvidenceIdsByTechnique -TechniqueIds @("T1110","T1021.001"))
}

# 5. PowerShell / 脚本执行证据链评分
$scriptScore = 0
$scriptReasons = @()
if (@($PowerShellFindings | Where-Object { $_.Risk -in @("高危","中危") -or $_.Level -in @("高危","中危") }).Count -gt 0) { $scriptScore += 35; $scriptReasons += "存在高危 PowerShell/脚本日志特征" }
if (@($SuspiciousStartup | Where-Object { $_.Command -match '(?i)powershell|wscript|cscript|mshta|\.vbs|\.hta|\.ps1|\.bat|\.cmd' }).Count -gt 0) { $scriptScore += 25; $scriptReasons += "启动项中存在脚本解释器或脚本文件" }
if (@($SuspiciousTasks | Where-Object { $_.Actions -match '(?i)powershell|wscript|cscript|mshta|\.vbs|\.hta|\.ps1|\.bat|\.cmd' }).Count -gt 0) { $scriptScore += 25; $scriptReasons += "计划任务中存在脚本解释器或脚本文件" }
if (@($MiningConfigsGroupedArray | Where-Object { $_.Type -match '下载/投放URL' }).Count -gt 0) { $scriptScore += 15; $scriptReasons += "发现下载/投放 URL 候选" }

if ($scriptScore -gt 0) {
    Add-EvidenceScore -List $EvidenceScores -Scenario "脚本执行 / 投放链路" -Score $scriptScore `
        -Conclusion "根据 PowerShell/脚本日志、脚本型持久化和投放 URL 综合评分。" `
        -Evidence (($scriptReasons | Sort-Object -Unique) -join "；") `
        -Priority "优先复核脚本内容、执行来源和是否关联服务/任务/启动项。" `
        -RecommendedAction "导出脚本文件、计算 Hash，检查是否包含下载执行、EncodedCommand、Bypass、mshta/wscript 链路。" `
        -EvidenceIds (Get-EvidenceIdsByTechnique -TechniqueIds @("T1059.001","T1059.005","T1218.005"))
}

# 生成处置建议：仅输出建议，不自动执行
foreach ($p in ($ResourceAnomalies | Where-Object { $_.Level -in @("高危","中危") } | Select-Object -First 20)) {
    Add-CleanupAdvice -List $CleanupAdvices -Priority "P1" -RiskType "可疑进程" -Target "$($p.Name) PID=$($p.ProcessId)" `
        -Evidence "CPU=$($p.CpuPercent)，路径=$($p.ExecutablePath)，标签=$($p.Tags)" `
        -SuggestedCommand "Stop-Process -Id $($p.ProcessId) -Force" `
        -SafetyNote "先确认进程路径、签名、Hash 和业务归属；生产环境不建议未经确认直接停止。"
}

foreach ($s in ($ServiceEvents | Where-Object { $_.Level -in @("高危","中危") } | Select-Object -First 30)) {
    $svcCmdName = Resolve-ServiceNameForCommand -ServiceName $s.ServiceName -ImagePath $s.ImagePath
    Add-CleanupAdvice -List $CleanupAdvices -Priority "P1" -RiskType "可疑服务" -Target "$($s.ServiceName) [ServiceName=$svcCmdName]" `
        -Evidence "路径=$($s.ImagePath)，原因=$($s.Reason)" `
        -SuggestedCommand "sc.exe stop `"$svcCmdName`" ; sc.exe config `"$svcCmdName`" start= disabled" `
        -SafetyNote "先导出服务配置和服务文件 Hash；确认非业务服务后再禁用。命令优先使用 Win32_Service.Name，而不是显示名。"
}

foreach ($t in ($SuspiciousTasks | Select-Object -First 40)) {
    Add-CleanupAdvice -List $CleanupAdvices -Priority "P2" -RiskType "可疑计划任务" -Target $t.TaskName `
        -Evidence "动作=$($t.Actions)，原因=$($t.Reason)" `
        -SuggestedCommand "schtasks /Change /TN `"$($t.TaskName)`" /Disable" `
        -SafetyNote "建议先使用 schtasks /Query /TN 任务名 /XML 导出任务 XML 留证，确认后再禁用或删除。"
}

foreach ($st in ($SuspiciousStartup | Select-Object -First 40)) {
    $cmd = ""
    $artifactPath = Get-StartupArtifactPath -Location $st.Location -Name $st.Name -Command $st.Command

    if ($st.Location -match '^HK') {
        $cmd = Get-SafeRegDeleteCommand -Location $st.Location -Name $st.Name
    }
    elseif (-not [string]::IsNullOrWhiteSpace($artifactPath)) {
        $cmd = "Remove-Item -LiteralPath `"$artifactPath`" -Force"
    }
    else {
        $cmd = "# 请手工复核并备份后删除启动项：$($st.Name)"
    }

    Add-CleanupAdvice -List $CleanupAdvices -Priority "P2" -RiskType "可疑启动项" -Target $st.Name `
        -Evidence "位置=$($st.Location)，启动项文件=$artifactPath，命令=$($st.Command)，原因=$($st.Reason)" `
        -SuggestedCommand $cmd `
        -SafetyNote "先导出注册表项或备份 Startup 文件；对于 .lnk，应删除 Startup 目录中的 .lnk 本体，不要删除系统解释器。"
}

foreach ($u in ($SuspiciousUsers | Where-Object { $_.Level -in @("高危","中危") } | Select-Object -First 20)) {
    Add-CleanupAdvice -List $CleanupAdvices -Priority "P1" -RiskType "可疑账户" -Target $u.Name `
        -Evidence "原因=$($u.Reasons)，隐藏=$($u.IsHidden)，管理员组=$($u.IsAdmin)，远程桌面组=$($u.IsRemoteDesktopUser)" `
        -SuggestedCommand "Disable-LocalUser -Name `"$($u.Name)`"" `
        -SafetyNote "先确认账户归属并导出账户/组成员/登录事件；未知高危账户优先禁用而不是直接删除。"
}

foreach ($h in ($HiddenAccounts | Select-Object -First 20)) {
    Add-CleanupAdvice -List $CleanupAdvices -Priority "P1" -RiskType "Winlogon 隐藏账户" -Target $h.Account `
        -Evidence "注册表=$($h.RegPath)，值=$($h.Value)" `
        -SuggestedCommand "Remove-ItemProperty -Path `"$($h.RegPath)`" -Name `"$($h.Account)`"" `
        -SafetyNote "先导出注册表项留证；确认不是业务隐藏账户后再删除该隐藏项。"
}

# 高危文件 Hash 建议目标
$hashCandidates = @()
$hashCandidates += @($ResourceAnomalies | Where-Object { $_.ExecutablePath } | ForEach-Object { $_.ExecutablePath })
$hashCandidates += @($ServiceEvents | Where-Object { $_.Level -in @("高危","中危") } | ForEach-Object { Get-FirstPathFromText -Text $_.ImagePath })
$hashCandidates += @($SuspiciousStartup | ForEach-Object {
    $artifactPath = Get-StartupArtifactPath -Location $_.Location -Name $_.Name -Command $_.Command
    if ($artifactPath) { $artifactPath }
    $cmdPath = Get-FirstPathFromText -Text $_.Command
    if ($cmdPath) { $cmdPath }
})
$hashCandidates += @($SuspiciousTasks | ForEach-Object { Get-FirstPathFromText -Text $_.Actions })
$hashCandidates += @($MiningConfigFiles | ForEach-Object { $_.FilePath })

foreach ($hp in ($hashCandidates | Where-Object { $_ -and ($_ -notmatch ':\w+$') } | Sort-Object -Unique | Select-Object -First 120)) {
    if (Test-IsSystemInterpreterPath -Path $hp) { continue }

    $exists = Test-Path $hp -PathType Leaf
    $HighRiskHashTargets.Add([PSCustomObject]@{
        FilePath           = $hp
        Exists             = $exists
        SuggestedCommand   = "Get-FileHash -Algorithm SHA256 -LiteralPath `"$hp`""
        Note               = "优先计算 SHA256；必要时补充 MD5/SHA1 并进行威胁情报检索。系统解释器本体已降噪，重点关注被解释执行的脚本/配置/样本文件。"
    }) | Out-Null
}

$EvidenceScoresArray = @($EvidenceScores | Sort-Object Score -Descending)
$CleanupAdvicesArray = @($CleanupAdvices | Sort-Object Priority,RiskType,Target)
$HighRiskHashTargetsArray = @($HighRiskHashTargets | Sort-Object FilePath -Unique)

Export-DetailCsv -Name "证据链评分.csv" -Data $EvidenceScoresArray
Export-DetailCsv -Name "处置建议.csv" -Data $CleanupAdvicesArray
Export-DetailCsv -Name "高危文件Hash建议.csv" -Data $HighRiskHashTargetsArray

# =========================================================
# 输出报告
# =========================================================

Write-Info "正在生成报告..."

$FindingsArray = @()
foreach ($f in $Findings) { $FindingsArray += $f }

$ScenariosArray = @()
foreach ($s in $Scenarios) { $ScenariosArray += $s }

$FindingPath = Join-Path $OutputDir "重点关注项.csv"
$ScenarioPath = Join-Path $OutputDir "攻击场景判断.csv"

$FindingsArray | Export-Csv -Path $FindingPath -NoTypeInformation -Encoding UTF8
$ScenariosArray | Export-Csv -Path $ScenarioPath -NoTypeInformation -Encoding UTF8

$HighCount = @($FindingsArray | Where-Object { $_.Level -eq "高危" }).Count
$MidCount = @($FindingsArray | Where-Object { $_.Level -eq "中危" }).Count
$WatchCount = @($FindingsArray | Where-Object { $_.Level -eq "关注" }).Count

$SummaryPath = Join-Path $OutputDir "WinIR_Summary.txt"

$summaryLines = @()
$summaryLines += "WinIR-Helper $Version 应急响应摘要"
$summaryLines += "生成时间：$(Get-Date)"
$summaryLines += "扫描范围：$StartTime ~ $EndTime"
$summaryLines += "重点排查：$FocusStartTime ~ $EndTime"
$summaryLines += "输出目录：$OutputDir"
$summaryLines += ""
$summaryLines += "一、攻击场景判断"
foreach ($s in $ScenariosArray) {
    $summaryLines += "[$($s.Level)] $($s.Scenario)：$($s.Conclusion)"
    $summaryLines += "证据：$($s.Evidence)"
}
$summaryLines += ""
$summaryLines += "一-补充、v0.7 证据链评分"
foreach ($es in ($EvidenceScoresArray | Select-Object -First 8)) {
    $summaryLines += "[$($es.Level)] $($es.Scenario)：评分=$($es.Score)，优先级=$($es.Priority)"
    $summaryLines += "证据：$($es.Evidence)"
}
$summaryLines += ""
$summaryLines += "一-补充、处置建议预览"
foreach ($ca in ($CleanupAdvicesArray | Select-Object -First 10)) {
    $summaryLines += "[$($ca.Priority)] $($ca.RiskType)：$($ca.Target)；建议=$($ca.SuggestedCommand)"
}
$summaryLines += ""
$summaryLines += "二、风险统计"
$summaryLines += "高危：$HighCount"
$summaryLines += "中危：$MidCount"
$summaryLines += "关注：$WatchCount"
$summaryLines += ""
$summaryLines += "二-补充、账户与恶意用户排查"
$summaryLines += "可疑账户数：$($SuspiciousUsers.Count)，隐藏账户数：$($HiddenAccounts.Count)，管理员组成员数：$($AdminMembers.Count)，远程桌面用户组成员数：$($RdpMembers.Count)"
foreach ($au in ($SuspiciousUsers | Select-Object -First 10)) {
    $summaryLines += "[$($au.Level)] 用户=$($au.Name)，评分=$($au.Score)，原因=$($au.Reasons)，隐藏=$($au.IsHidden)，管理员组=$($au.IsAdmin)，远程桌面组=$($au.IsRemoteDesktopUser)"
}
$summaryLines += ""
$summaryLines += "三、登录失败 Top IP"
foreach ($ip in ($FailedByIP | Select-Object -First 10)) {
    $summaryLines += "$($ip.SourceIP)：疑似开始时间=$($ip.AttackStartTime)，失败=$($ip.FailedCount)，目标账户=$($ip.TargetUsers)，方式=$($ip.MainLogonMethod)，首次成功=$($ip.FirstSuccessTime)，判断=$($ip.AttackJudgement)"
}
$summaryLines += ""
$summaryLines += "三-补充、登录失败按来源/用户聚合（含无来源 IP）"
foreach ($fg in ($FailedByIdentity | Select-Object -First 10)) {
    $summaryLines += "$($fg.Source)：失败=$($fg.FailedCount)，目标账户=$($fg.TargetUser)，方式=$($fg.LogonTypeDesc)，开始=$($fg.AttackStartTime)，结束=$($fg.LastFailTime)"
}
$summaryLines += ""
$summaryLines += "四、危险监听端口"
foreach ($p in ($DangerPorts | Select-Object -First 20)) {
    $summaryLines += "[$($p.Level)] $($p.LocalPort) $($p.ServiceRisk) 监听地址=$($p.LocalAddress)"
}
$summaryLines += ""
$summaryLines += "五、挖矿配置提取"
$summaryLines += "配置扫描候选来源数：$($MiningCandidateSourcesArray.Count)，候选文件数：$($MiningConfigFiles.Count)，原始提取线索数：$($MiningConfigsArray.Count)，聚合后线索数：$($MiningConfigsGroupedArray.Count)"
foreach ($m in ($MiningConfigsGroupedArray | Select-Object -First 20)) {
    $summaryLines += "[$($m.Type)] $($m.Value) 出现=$($m.HitCount) 来源=$($m.SourceFiles) 置信度=$($m.Confidence)"
}
$summaryLines += ""
$summaryLines += "六、攻击时间线预览"
foreach ($tl in ($AttackTimelineArray | Select-Object -First 15)) {
    $summaryLines += "$($tl.EvidenceId) [$($tl.Level)] $($tl.TimeCreated) $($tl.Phase) - $($tl.Action) - $($tl.TechniqueId) $($tl.TechniqueName)"
}
$summaryLines += ""
$summaryLines += "七、ATT&CK 技术映射"
foreach ($tech in ($AttackTechniques | Select-Object -First 15)) {
    $summaryLines += "$($tech.TechniqueId) $($tech.TechniqueName)：命中=$($tech.Count)，战术=$($tech.Tactic)，证据=$($tech.EvidenceIds)"
}
$summaryLines += ""
$summaryLines += "八、建议"
$summaryLines += "1. 优先查看 WinIR_Report.html 的「攻击场景判断」和「攻击时间线」。"
$summaryLines += "2. 再查看「重点关注项」和「资源异常进程」。重点关注项默认突出最近 $FocusDays 天内事件。"
$summaryLines += "3. v0.6 新增 ATT&CK 映射和证据链编号，可用于报告复盘，但最终结论仍需人工复核。
4. 登录失败 Top IP 为空时，请优先查看「登录失败明细 / 无 IP 聚合」；本机测试通常只能得到 127.0.0.1 或空来源，真实来源 IP 需两台机器或真实远程登录场景验证。
5. 若「自定义认证日志IP线索」存在，请把它作为应用/实验日志辅助证据，不要直接等同于 Windows 4625 的真实来源 IP。
6. 下载/投放 URL 与矿池地址已分开展示：前者用于追踪投放链路，后者用于研判资源劫持/挖矿配置。
7. 若「ADS备用数据流线索」存在，请把 ADS 作为隐藏配置/规避痕迹优先复核；若无 ADS，不代表系统不存在 ADS，只代表候选文件轻量扫描未命中。
8. 若「账户与恶意用户排查」出现隐藏账户、可疑命名账户、远程桌面用户组异常成员或非预期管理员账户，请优先留证、确认来源并结合 4720/4732/4624/4625 事件复核。普通管理员组成员会在成员表展示，但不会仅因'属于管理员组'被判为可疑账户。
9. v0.7.1 修复处置建议命令生成：Startup LNK 删除建议指向 .lnk 本体，服务建议优先使用 ServiceName，系统解释器 Hash 降噪，隐藏账户证据链提升为高危。处置命令只作为人工复核建议，不会自动执行；生产环境请先留证、确认业务归属和变更窗口。"

$summaryLines | Out-File -FilePath $SummaryPath -Encoding UTF8

$scenarioForHtml = $ScenariosArray | Select-Object Level,Scenario,Conclusion,Evidence,Suggestion
$evidenceScoreForHtml = $EvidenceScoresArray | Select-Object Level,Scenario,Score,Priority,Conclusion,Evidence,EvidenceIds,RecommendedAction
$cleanupAdviceForHtml = $CleanupAdvicesArray | Select-Object Priority,RiskType,Target,Evidence,SuggestedCommand,SafetyNote
$hashTargetsForHtml = $HighRiskHashTargetsArray | Select-Object FilePath,Exists,SuggestedCommand,Note
$findingsForHtml = $FindingsArray | Select-Object Level,Category,Title,Evidence,Suggestion
$securityForHtml = $SecuritySummary | Select-Object EventID,EventType,Count
$suspiciousUsersForHtml = $SuspiciousUsers | Select-Object Level,Name,Enabled,Score,Reasons,IsHidden,IsAdmin,IsRemoteDesktopUser,IsCurrentUser,IsBuiltIn,LastLogon,PasswordLastSet,PasswordNeverExpires,UserMayChangePassword,Description,SID
$localUsersForHtml = $LocalUsers | Select-Object Name,Enabled,RID,LastLogon,PasswordLastSet,PasswordNeverExpires,UserMayChangePassword,Description,SID
$adminMembersForHtml = $AdminMembers | Select-Object Group,Name,ObjectClass,PrincipalSource,SID
$rdpMembersForHtml = $RdpMembers | Select-Object Group,Name,ObjectClass,PrincipalSource,SID
$hiddenAccountsForHtml = $HiddenAccounts | Select-Object Account,Value,Meaning,RegPath
$accountEventsForHtml = $AccountSecurityEvents | Select-Object TimeCreated,EventID,EventType,SubjectUser,TargetUser,MemberName,TargetDomain,LogonTypeDesc,SourceIP,WorkstationName
$failedForHtml = $FailedByIP | Select-Object SourceIP,FailedCount,AttackStartTime,LastFailTime,DurationMinutes,TargetUsers,TargetUserCount,MainLogonMethod,SourcePortRange,FirstSuccessTime,FirstSuccessUser,AttackJudgement,Reasons
$failedIdentityForHtml = $FailedByIdentity | Select-Object Source,FailedCount,AttackStartTime,LastFailTime,DurationMinutes,TargetUser,TargetDomain,LogonTypeDesc,FailureReasons,StatusCodes,Workstations,Note
$failedDetailsForHtml = $FailedLogonDetails | Select-Object TimeCreated,Source,SourceIP,WorkstationName,TargetUser,TargetDomain,LogonTypeDesc,FailureReason,Status,SubStatus,AuthPackage
$rdpForHtml = $RdpEvents | Select-Object TimeCreated,EventID,UserName,Domain,Address,Description
$serviceForHtml = $ServiceEvents | Where-Object { $_.Level -ne "正常" } | Select-Object Level,TimeCreated,ServiceName,ImagePath,AccountName,Reason
$startupForHtml = $SuspiciousStartup | Select-Object Level,Location,Name,Command,Signature,Reason
$taskForHtml = $SuspiciousTasks | Select-Object Level,TaskName,State,Actions,Reason
$portForHtml = $DangerPorts | Select-Object Level,LocalPort,LocalAddress,ServiceRisk,ProcessId,ProcessName,ProcessPath
$resourceForHtml = $ResourceAnomalies | Select-Object Level,Score,ProcessId,Name,CpuPercent,MemoryMB,MemoryPercent,PublicConnections,Tags,ExecutablePath,CommandLine
$netForHtml = $NetConns | Where-Object { $_.IsPublicIP -eq $true -and -not (Test-IsKnownPublicNetworkNoise -ProcessName $_.ProcessName -ProcessPath $_.ProcessPath) } | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,ProcessId,ProcessName,ProcessPath
$miningConfigForHtml = $MiningConfigsGroupedArray | Select-Object Type,Value,Confidence,HitCount,SourceFiles,SourceDirs,Context
$miningCandidateForHtml = $MiningCandidateSourcesArray | Select-Object SourceType,EvidenceName,Value,Reason,AddedDir
$psForHtml = $PowerShellFindings | Select-Object TimeCreated,EventID,Summary
$timelineForHtml = $AttackTimelineArray | Select-Object EvidenceId,TimeCreated,Phase,Action,Level,EvidenceType,Source,Target,TechniqueId,TechniqueName,Tactic,Evidence,Suggestion
$attackForHtml = $AttackTechniques | Select-Object Tactic,TechniqueId,TechniqueName,Count,EvidenceIds,ExampleEvidence,Suggestion
$chainForHtml = $EvidenceChain | Select-Object EvidenceId,TimeCreated,Phase,Brief,Source,Target

$ReportPath = Join-Path $OutputDir "WinIR_Report.html"

$css = @"
<style>
body { margin:0; padding:0; background:#0f172a; color:#e5e7eb; font-family:"Microsoft YaHei","Segoe UI",Arial,sans-serif; }
.container { max-width:1320px; margin:0 auto; padding:28px; }
.header { background:linear-gradient(135deg,#1e293b,#0f766e); border-radius:18px; padding:28px; box-shadow:0 10px 30px rgba(0,0,0,.25); }
.header h1 { margin:0 0 10px 0; font-size:30px; }
.header p { margin:4px 0; color:#d1fae5; }
.cards { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:16px; margin:22px 0; }
.card { background:#111827; border:1px solid #334155; border-radius:16px; padding:18px; }
.card .num { font-size:30px; font-weight:700; }
.card .label { color:#94a3b8; margin-top:6px; }
.high { color:#f87171; } .mid { color:#fbbf24; } .watch { color:#60a5fa; } .ok { color:#34d399; }
.section { margin-top:22px; background:#111827; border:1px solid #334155; border-radius:16px; padding:20px; overflow-x:auto; }
.section h2 { margin-top:0; color:#93c5fd; border-bottom:1px solid #334155; padding-bottom:10px; }
table { width:100%; border-collapse:collapse; font-size:13px; }
th,td { border-bottom:1px solid #334155; padding:8px 10px; text-align:left; vertical-align:top; }
th { color:#bfdbfe; background:#1f2937; white-space:nowrap; }
td { color:#e5e7eb; word-break:break-all; }
.badge { display:inline-block; padding:3px 8px; border-radius:999px; font-size:12px; font-weight:700; white-space:nowrap; }
.badge-high { background:rgba(248,113,113,.15); color:#f87171; }
.badge-mid { background:rgba(251,191,36,.15); color:#fbbf24; }
.badge-watch { background:rgba(96,165,250,.15); color:#60a5fa; }
.empty { color:#94a3b8; }
.footer { color:#94a3b8; margin-top:22px; font-size:13px; }
code { color:#a7f3d0; }
.hash-toolbar { display:flex; flex-wrap:wrap; gap:10px; align-items:center; margin:12px 0 14px 0; }
.hash-file { background:#0f172a; border:1px dashed #475569; border-radius:12px; padding:10px; color:#e5e7eb; min-width:280px; }
.hash-options { display:flex; flex-wrap:wrap; gap:10px; color:#cbd5e1; }
.hash-options label { background:#0f172a; border:1px solid #334155; border-radius:999px; padding:7px 10px; cursor:pointer; }
.hash-btn { border:0; border-radius:12px; padding:10px 14px; background:#2563eb; color:white; cursor:pointer; font-weight:700; }
.hash-btn.secondary { background:#334155; }
.hash-btn:disabled { opacity:.55; cursor:not-allowed; }
.hash-note { color:#a7f3d0; background:rgba(20,184,166,.08); border:1px solid rgba(45,212,191,.25); border-radius:12px; padding:10px 12px; }
.hash-status { color:#bfdbfe; margin:8px 0; }
.hash-actions { display:flex; gap:8px; flex-wrap:wrap; }
.hash-actions button { border:1px solid #475569; background:#0f172a; color:#dbeafe; border-radius:10px; padding:6px 8px; cursor:pointer; }
.hash-small { color:#94a3b8; font-size:12px; }
</style>
"@

$hashToolHtml = @'
    <div class="section" id="offline-hash-tool">
        <h2>零、离线文件 Hash 计算器</h2>
        <p class="hash-note">选择本地文件后，Hash 在当前浏览器中离线计算，文件不会上传到服务器，也不会写入报告目录。适合快速计算样本 Hash 后复制到 VirusTotal、微步、EDR 或情报平台中检索。</p>

        <div class="hash-toolbar">
            <input class="hash-file" id="hashFiles" type="file" multiple />
            <div class="hash-options" aria-label="Hash 算法选择">
                <label><input type="checkbox" name="hashAlgo" value="SHA-1" checked /> SHA-1</label>
                <label><input type="checkbox" name="hashAlgo" value="SHA-256" checked /> SHA-256</label>
                <label><input type="checkbox" name="hashAlgo" value="SHA-384" /> SHA-384</label>
                <label><input type="checkbox" name="hashAlgo" value="SHA-512" /> SHA-512</label>
            </div>
            <button class="hash-btn" id="hashCalcBtn" type="button">开始计算</button>
            <button class="hash-btn secondary" id="hashClearBtn" type="button">清空结果</button>
            <button class="hash-btn secondary" id="hashCsvBtn" type="button" disabled>导出 CSV</button>
        </div>

        <div class="hash-small">说明：浏览器原生 Web Crypto API 不支持 MD5。应急检索建议优先使用 SHA-256；如确需 MD5，可在 PowerShell 中使用 <code>Get-FileHash -Algorithm MD5</code>。</div>
        <div class="hash-status" id="hashStatus">尚未选择文件。</div>
        <div id="hashResultWrap"><p class="empty">计算结果会显示在这里。</p></div>
    </div>

    <script>
    (function () {
        var hashRows = [];
        var fileInput = document.getElementById('hashFiles');
        var calcBtn = document.getElementById('hashCalcBtn');
        var clearBtn = document.getElementById('hashClearBtn');
        var csvBtn = document.getElementById('hashCsvBtn');
        var statusBox = document.getElementById('hashStatus');
        var resultWrap = document.getElementById('hashResultWrap');

        function escapeHtml(value) {
            return String(value == null ? '' : value)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        }

        function bytesToHex(buffer) {
            var bytes = new Uint8Array(buffer);
            var hex = [];
            for (var i = 0; i < bytes.length; i++) {
                hex.push(bytes[i].toString(16).padStart(2, '0'));
            }
            return hex.join('');
        }

        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            var units = ['B', 'KB', 'MB', 'GB', 'TB'];
            var i = Math.floor(Math.log(bytes) / Math.log(1024));
            if (i < 0) i = 0;
            if (i >= units.length) i = units.length - 1;
            return (bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 2) + ' ' + units[i];
        }

        function getSelectedAlgorithms() {
            var checked = document.querySelectorAll('input[name="hashAlgo"]:checked');
            var arr = [];
            for (var i = 0; i < checked.length; i++) arr.push(checked[i].value);
            return arr;
        }

        function setBusy(isBusy) {
            calcBtn.disabled = isBusy;
            clearBtn.disabled = isBusy;
            csvBtn.disabled = isBusy || hashRows.length === 0;
        }

        async function calculateHashes() {
            if (!window.crypto || !window.crypto.subtle) {
                statusBox.textContent = '当前浏览器不支持 crypto.subtle。建议使用新版 Edge、Chrome 或 Firefox 打开本报告。';
                return;
            }

            var files = fileInput.files;
            var algorithms = getSelectedAlgorithms();

            if (!files || files.length === 0) {
                statusBox.textContent = '请先选择一个或多个文件。';
                return;
            }
            if (algorithms.length === 0) {
                statusBox.textContent = '请至少选择一种 Hash 算法。';
                return;
            }

            hashRows = [];
            resultWrap.innerHTML = '<p class="empty">正在计算，请勿关闭页面。大文件需要更多时间。</p>';
            setBusy(true);

            try {
                for (var f = 0; f < files.length; f++) {
                    var file = files[f];
                    statusBox.textContent = '正在读取：' + file.name + '（' + (f + 1) + '/' + files.length + '）';
                    var buffer = await file.arrayBuffer();

                    for (var a = 0; a < algorithms.length; a++) {
                        var algo = algorithms[a];
                        statusBox.textContent = '正在计算：' + file.name + ' / ' + algo;
                        var digest = await crypto.subtle.digest(algo, buffer);
                        var lower = bytesToHex(digest);
                        hashRows.push({
                            fileName: file.name,
                            fileSizeBytes: file.size,
                            fileSize: formatBytes(file.size),
                            lastModified: file.lastModified ? new Date(file.lastModified).toLocaleString() : '',
                            algorithm: algo,
                            hashUpper: lower.toUpperCase(),
                            hashLower: lower.toLowerCase()
                        });
                    }
                }
                statusBox.textContent = '计算完成：' + files.length + ' 个文件，' + hashRows.length + ' 条 Hash 结果。';
                renderTable();
            } catch (err) {
                statusBox.textContent = '计算失败：' + (err && err.message ? err.message : err);
                resultWrap.innerHTML = '<p class="empty">计算失败，请更换浏览器或减少单次选择的大文件数量后重试。</p>';
            } finally {
                setBusy(false);
            }
        }

        function renderTable() {
            if (hashRows.length === 0) {
                resultWrap.innerHTML = '<p class="empty">暂无计算结果。</p>';
                csvBtn.disabled = true;
                return;
            }

            var html = '<table><thead><tr>' +
                '<th>文件名</th><th>大小</th><th>修改时间</th><th>算法</th><th>Hash 大写</th><th>hash 小写</th><th>操作</th>' +
                '</tr></thead><tbody>';

            for (var i = 0; i < hashRows.length; i++) {
                var r = hashRows[i];
                html += '<tr>' +
                    '<td>' + escapeHtml(r.fileName) + '</td>' +
                    '<td>' + escapeHtml(r.fileSize) + '</td>' +
                    '<td>' + escapeHtml(r.lastModified) + '</td>' +
                    '<td>' + escapeHtml(r.algorithm) + '</td>' +
                    '<td><code>' + escapeHtml(r.hashUpper) + '</code></td>' +
                    '<td><code>' + escapeHtml(r.hashLower) + '</code></td>' +
                    '<td><div class="hash-actions">' +
                    '<button type="button" data-copy="upper" data-index="' + i + '">复制大写</button>' +
                    '<button type="button" data-copy="lower" data-index="' + i + '">复制小写</button>' +
                    '</div></td>' +
                    '</tr>';
            }

            html += '</tbody></table>';
            resultWrap.innerHTML = html;
            csvBtn.disabled = false;
        }

        function copyText(text) {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text).then(function () {
                    statusBox.textContent = '已复制到剪贴板。';
                }).catch(function () {
                    fallbackCopy(text);
                });
            } else {
                fallbackCopy(text);
            }
        }

        function fallbackCopy(text) {
            var ta = document.createElement('textarea');
            ta.value = text;
            document.body.appendChild(ta);
            ta.select();
            try {
                document.execCommand('copy');
                statusBox.textContent = '已复制到剪贴板。';
            } catch (e) {
                statusBox.textContent = '复制失败，请手动选中 Hash 复制。';
            }
            document.body.removeChild(ta);
        }

        function toCsvCell(value) {
            return '"' + String(value == null ? '' : value).replace(/"/g, '""') + '"';
        }

        function exportCsv() {
            if (hashRows.length === 0) return;
            var lines = [];
            lines.push(['FileName', 'FileSizeBytes', 'FileSize', 'LastModified', 'Algorithm', 'HashUpper', 'HashLower'].map(toCsvCell).join(','));
            for (var i = 0; i < hashRows.length; i++) {
                var r = hashRows[i];
                lines.push([r.fileName, r.fileSizeBytes, r.fileSize, r.lastModified, r.algorithm, r.hashUpper, r.hashLower].map(toCsvCell).join(','));
            }
            var blob = new Blob(['\ufeff' + lines.join('\r\n')], { type: 'text/csv;charset=utf-8' });
            var url = URL.createObjectURL(blob);
            var a = document.createElement('a');
            a.href = url;
            a.download = 'WinIR_Offline_File_Hash.csv';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            statusBox.textContent = 'CSV 已导出。';
        }

        calcBtn.addEventListener('click', calculateHashes);
        clearBtn.addEventListener('click', function () {
            hashRows = [];
            fileInput.value = '';
            statusBox.textContent = '已清空结果。';
            resultWrap.innerHTML = '<p class="empty">计算结果会显示在这里。</p>';
            csvBtn.disabled = true;
        });
        csvBtn.addEventListener('click', exportCsv);
        resultWrap.addEventListener('click', function (event) {
            var target = event.target;
            if (!target || !target.getAttribute) return;
            var mode = target.getAttribute('data-copy');
            var index = parseInt(target.getAttribute('data-index'), 10);
            if (!mode || isNaN(index) || !hashRows[index]) return;
            copyText(mode === 'upper' ? hashRows[index].hashUpper : hashRows[index].hashLower);
        });
    })();
    </script>
'@

$html = @"
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<title>WinIR-Helper $Version 应急响应报告</title>
$css
</head>
<body>
<div class="container">
    <div class="header">
        <h1>WinIR-Helper $Version 应急响应报告</h1>
        <p>生成时间：$(HtmlEncode (Get-Date))</p>
        <p>扫描范围：$(HtmlEncode $StartTime) ~ $(HtmlEncode $EndTime)</p>
        <p>重点排查窗口：$(HtmlEncode $FocusStartTime) ~ $(HtmlEncode $EndTime)</p>
        <p>说明：默认扫描最近 7 天，重点关注最近 3 天；如需长周期历史排查，可使用 <code>-Days 1000</code>。</p>
        <p>工具定位：辅助取证与线索整理，不做查杀，不替代专业安全工具。</p>
    </div>

    <div class="cards">
        <div class="card"><div class="num high">$HighCount</div><div class="label">高危项</div></div>
        <div class="card"><div class="num mid">$MidCount</div><div class="label">中危项</div></div>
        <div class="card"><div class="num watch">$WatchCount</div><div class="label">关注项</div></div>
        <div class="card"><div class="num ok">$($SecurityEvents.Count)</div><div class="label">安全事件数量</div></div>
    </div>

$hashToolHtml

    <div class="section">
        <h2>一、攻击场景判断</h2>
        $(ConvertTo-HtmlTable -Data $scenarioForHtml -MaxRows 50)
    </div>

    <div class="section">
        <h2>一-补充、v0.7 证据链评分与处置建议</h2>
        <p class="empty">本节为 v0.7 新增能力。评分用于帮助判断处置优先级，不会自动执行清理命令；所有建议命令均需人工复核后再使用。</p>
        <h3 style="color:#bfdbfe; margin-top:18px;">证据链评分</h3>
        $(ConvertTo-HtmlTable -Data $evidenceScoreForHtml -MaxRows 30)
        <h3 style="color:#bfdbfe; margin-top:18px;">处置建议生成器</h3>
        $(ConvertTo-HtmlTable -Data $cleanupAdviceForHtml -MaxRows 100)
        <h3 style="color:#bfdbfe; margin-top:18px;">高危文件 Hash 建议</h3>
        $(ConvertTo-HtmlTable -Data $hashTargetsForHtml -MaxRows 100)
    </div>

    <div class="section">
        <h2>二、重点关注项（近 $FocusDays 天事件 + 当前持久化/进程/配置痕迹）</h2>
        $(ConvertTo-HtmlTable -Data $findingsForHtml -MaxRows 100)
    </div>

    <div class="section">
        <h2>三、Windows 安全事件统计</h2>
        $(ConvertTo-HtmlTable -Data $securityForHtml -MaxRows 30)
    </div>

    <div class="section">
        <h2>三-补充、账户与恶意用户排查</h2>
        <p class="empty">本节显式展示本地用户、管理员组、远程桌面用户组、Winlogon 隐藏账户和账户相关安全事件。可疑账户会综合用户名、隐藏注册表、管理员组、远程桌面组、密码策略等特征打分。</p>

        <h3 style="color:#bfdbfe; margin-top:18px;">可疑本地账户</h3>
        $(ConvertTo-HtmlTable -Data $suspiciousUsersForHtml -MaxRows 80)

        <h3 style="color:#bfdbfe; margin-top:18px;">Winlogon 隐藏账户</h3>
        $(ConvertTo-HtmlTable -Data $hiddenAccountsForHtml -MaxRows 50)

        <h3 style="color:#bfdbfe; margin-top:18px;">管理员组成员</h3>
        $(ConvertTo-HtmlTable -Data $adminMembersForHtml -MaxRows 80)

        <h3 style="color:#bfdbfe; margin-top:18px;">远程桌面用户组成员</h3>
        $(ConvertTo-HtmlTable -Data $rdpMembersForHtml -MaxRows 80)

        <h3 style="color:#bfdbfe; margin-top:18px;">本地用户列表</h3>
        $(ConvertTo-HtmlTable -Data $localUsersForHtml -MaxRows 120)

        <h3 style="color:#bfdbfe; margin-top:18px;">账户相关安全事件</h3>
        $(ConvertTo-HtmlTable -Data $accountEventsForHtml -MaxRows 120)
    </div>

    <div class="section">
        <h2>四、登录失败来源 IP Top（含疑似攻击开始时间）</h2>
        $(ConvertTo-HtmlTable -Data $failedForHtml -MaxRows 50)
    </div>

    <div class="section">
        <h2>四-补充、登录失败明细 / 无 IP 聚合</h2>
        <p class="empty">部分 4625 事件可能没有来源 IP。本节按来源、用户和登录类型聚合，便于识别本机 IPC$、内网或字段缺失导致的失败登录。</p>
        $(ConvertTo-HtmlTable -Data $failedIdentityForHtml -MaxRows 50)
        <h3 style="color:#bfdbfe; margin-top:18px;">登录失败明细</h3>
        $(ConvertTo-HtmlTable -Data $failedDetailsForHtml -MaxRows 80)
    </div>

    <div class="section">
        <h2>五、RDP 相关事件</h2>
        $(ConvertTo-HtmlTable -Data $rdpForHtml -MaxRows 50)
    </div>

    <div class="section">
        <h2>六、危险监听端口</h2>
        <p class="empty">监听不等于公网可访问，需要结合 Windows 防火墙、云安全组、NAT/端口映射判断。</p>
        $(ConvertTo-HtmlTable -Data $portForHtml -MaxRows 50)
    </div>

    <div class="section">
        <h2>七、资源异常进程综合评分（已过滤低占用噪音）</h2>
        $(ConvertTo-HtmlTable -Data $resourceForHtml -MaxRows 50)
    </div>

    <div class="section">
        <h2>八、挖矿配置提取（矿池 / 钱包，按 Value 聚合）</h2>
        <p class="empty">该模块不做全盘深度扫描。v0.6.5 在 v0.6.4 的对抗样本覆盖基础上，继续优化 OneDrive/desktop.ini 降噪、WinIR 自身 PowerShell 噪音过滤、IOC 类型拆分、协议与 host:port 归一化去重，并增强 Startup LNK、ADS、Public 镜像目录与自定义认证日志关联。当前表格按 Value 聚合，HitCount 表示同一线索在多少处出现。</p>
        $(ConvertTo-HtmlTable -Data $miningConfigForHtml -MaxRows 80)
    </div>

    <div class="section">
        <h2>八-补充、挖矿配置扫描目录来源</h2>
        <p class="empty">用于解释为什么某个目录会被继续扫描，便于复核'资源异常 → 目录追踪 → 配置提取'的证据链。</p>
        $(ConvertTo-HtmlTable -Data $miningCandidateForHtml -MaxRows 80)
    </div>

    <div class="section">
        <h2>九、服务安装线索</h2>
        $(ConvertTo-HtmlTable -Data $serviceForHtml -MaxRows 80)
    </div>

    <div class="section">
        <h2>十、可疑启动项</h2>
        $(ConvertTo-HtmlTable -Data $startupForHtml -MaxRows 50)
    </div>

    <div class="section">
        <h2>十一、可疑计划任务</h2>
        $(ConvertTo-HtmlTable -Data $taskForHtml -MaxRows 50)
    </div>

    <div class="section">
        <h2>十二、公网网络连接（已降噪）</h2>
        <p class="empty">默认折叠 Defender、SearchApp、Skype、WindowsApps、部分 svchost 等常见系统连接，保留更值得复核的非系统公网连接。</p>
        $(ConvertTo-HtmlTable -Data $netForHtml -MaxRows 50)
    </div>

    <div class="section">
        <h2>十三、PowerShell 高危痕迹</h2>
        $(ConvertTo-HtmlTable -Data $psForHtml -MaxRows 50)
    </div>

    <div class="section">
        <h2>十四、攻击时间线（v0.6）</h2>
        <p class="empty">将登录失败、RDP、PowerShell、服务安装、计划任务、启动项、资源异常、挖矿配置等线索按时间顺序整理，并生成 EvidenceId，便于复盘攻击过程。</p>
        $(ConvertTo-HtmlTable -Data $timelineForHtml -MaxRows 120)
    </div>

    <div class="section">
        <h2>十五、MITRE ATT&CK 映射（v0.6）</h2>
        <p class="empty">将本次命中的行为映射到常见 ATT&CK 技术。映射用于辅助报告标准化，不代表最终定性。</p>
        $(ConvertTo-HtmlTable -Data $attackForHtml -MaxRows 80)
    </div>

    <div class="section">
        <h2>十六、证据链概览</h2>
        <p class="empty">按 EvidenceId 串联关键证据，可作为后续人工复核和报告写作的骨架。</p>
        $(ConvertTo-HtmlTable -Data $chainForHtml -MaxRows 120)
    </div>

    <div class="section">
        <h2>十七、处置建议</h2>
        <ol>
            <li>优先查看「攻击场景判断」，不要只看单条事件。</li>
            <li>RDP 判断需要结合 4625/4624、1149/21/25、3389 监听和来源 IP 是否一致。</li>
            <li>挖矿判断需要结合资源占用、路径、服务、计划任务、启动项、矿池/钱包配置和 Hash。</li>
            <li>启动项中 AppData/Public/Temp/ProgramData 下的 bat、ps1、vbs、exe 应重点复核。</li>
            <li>本工具仅做辅助线索整理，最终结论需要人工复核。</li>
        </ol>
    </div>

    <div class="footer">
        <p>报告文件：$(HtmlEncode $ReportPath)</p>
        <p>本工具仅用于合法授权的蓝队应急响应、靶场复盘与安全学习。</p>
    </div>
</div>
</body>
</html>
"@

$html | Out-File -FilePath $ReportPath -Encoding UTF8

Write-Host ""
Write-Ok "分析完成！"
Write-Host ""
Write-Host "优先查看：" -ForegroundColor Cyan
Write-Host "1. $ReportPath"
Write-Host "2. $SummaryPath"
Write-Host "3. $ScenarioPath"
Write-Host "4. $FindingPath"
Write-Host ""

try { Start-Process $ReportPath } catch {}
