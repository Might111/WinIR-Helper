<#
.SYNOPSIS
    v0.5.0-beta - Windows 应急响应场景聚合分析脚本

.DESCRIPTION
    v0.5-scenario 重点修复之前版本的几个问题：
    1. 不再把 cmd.exe / powershell.exe 这类系统工具仅凭进程名列为风险。
    2. 不再把大量 DWM / UMFD / SYSTEM 的普通 4648、4672 事件刷进重点关注项。
    3. 不再把 Microsoft Windows 内置计划任务、Defender 常规任务大量误报。
    4. 对 RDP 暴力破解、SMB/NTLM 爆破、挖矿、可疑持久化进行「场景聚合判断」。
    5. 新增 RDP 相关事件 1149 / 21 / 24 / 25 关联分析。
    6. 新增危险监听端口聚合扫描，重点关注 3389 / 445 / 5985 / 5986。
    7. 新增可疑启动项检查，重点识别 AppData / Public / Temp 下的 bat、ps1、vbs、exe 持久化。

.NOTES
    本工具只做蓝队应急响应辅助取证与线索整理，不做查杀，不替代 D盾、河马、EDR、杀毒软件等专业工具。
    请仅在合法授权环境中使用。
#>

param(
    [int]$Days = 365,

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

    [double]$MemoryHighPercent = 25
)

$Version = "v0.5.0-beta"
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

    if (-not $PSBoundParameters.ContainsKey("StartTime") -or $StartTime -eq [datetime]::MinValue) {
        if ($Days -le 0) { $script:Days = 365 }
        $script:StartTime = $script:EndTime.AddDays(-1 * [Math]::Abs($Days))
    }
    else {
        $script:StartTime = $StartTime
    }
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

    if ($Text -match "(?i)WinIR-Helper|WinIR_Output_|重点关注项\.csv|WinIR_Report\.html|WinIR_Summary\.txt|SuspiciousCmdRegex|MiningProcRegex|Cmdletization|Microsoft\.PowerShell\.Cmdletization") {
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

    if ($Command -match "(?i)\\Kingsoft\\WPS Office\\|ksolaunch\.exe|photolaunch\.exe|WPS Office|\\Oray\\SunLogin\\|SunloginClient\.exe|sunlogin_guard\.exe|SecurityHealthSystray\.exe|AzureArcSysTray\.exe|HipsTray\.exe") {
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

    # 去重：同一个文件、同一类型、同一值只保留一次
    foreach ($x in $List) {
        if ($x.Type -eq $Type -and $x.Value -eq $cleanValue -and $x.FilePath -eq $FilePath) {
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
Write-Host "时间范围：$StartTime ~ $EndTime"
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

# 减少 4648 / 4672 噪音，只保留有实际意义的事件
foreach ($evt in ($SecurityEvents | Where-Object { $_.EventID -in @(1102,4720,4726,4732,4698,4648,4672) })) {
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
# 模块 4：账户、管理员组、隐藏账户
# =========================================================

Write-Info "正在检查本地用户与管理员组..."

$LocalUsers = @()
try {
    $LocalUsers = Get-LocalUser -ErrorAction Stop | ForEach-Object {
        [PSCustomObject]@{
            Name            = $_.Name
            Enabled         = $_.Enabled
            LastLogon       = $_.LastLogon
            PasswordLastSet = $_.PasswordLastSet
            Description     = $_.Description
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
            }
        }
        if ($AdminMembers.Count -gt 0) { break }
    }
    catch {}
}

Export-DetailCsv -Name "本地用户.csv" -Data $LocalUsers
Export-DetailCsv -Name "管理员组成员.csv" -Data $AdminMembers

foreach ($u in ($LocalUsers | Where-Object { $_.Enabled -eq $true })) {
    if ($u.Name -match '(\$$|hack|hacker|test|support|backup|admin\d+|system\d+)') {
        Add-Finding -Level "中危" -Category "账户检查" -Title "发现可疑命名账户" `
            -Evidence "用户=$($u.Name)，最近登录=$($u.LastLogon)，描述=$($u.Description)" `
            -Suggestion "确认账户来源、创建时间、是否属于业务或运维账户。"
    }
}

try {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
    if (Test-Path $regPath) {
        $props = Get-ItemProperty -Path $regPath
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -notmatch "^PS") {
                Add-Finding -Level "高危" -Category "账户检查" -Title "发现 Winlogon 隐藏账户注册表项" `
                    -Evidence "账户=$($p.Name)，值=$($p.Value)，路径=$regPath" `
                    -Suggestion "确认该账户是否为攻击者隐藏账户；检查管理员组、登录日志与创建账户事件。"
            }
        }
    }
}
catch {}

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

    if ($reason.Count -gt 0) {
        $level = if ($t.Actions -match "(?i)xmrig|miner|c3pool|net\s+user|add-localgroupmember|downloadstring|-enc|-encodedcommand") { "高危" } else { "中危" }

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
            Get-ChildItem -Path $sf -File -ErrorAction SilentlyContinue | ForEach-Object {
                $StartupItems += [PSCustomObject]@{
                    Location  = $sf
                    Name      = $_.Name
                    Command   = $_.FullName
                    FilePath  = $_.FullName
                    Signature = ""
                }
            }
        }
    }
}
catch {}

$SuspiciousStartup = @()
foreach ($s in $StartupItems) {
    $reason = @()
    $isTrustedVendor = Test-IsTrustedVendorCommand -Command $s.Command
    $isDangerScriptOrCommand = Test-IsScriptOrDangerPersistence -Command $s.Command

    # 仅位于 AppData 不直接判为可疑；很多正常软件也会放在 AppData。
    # 只有脚本/危险命令/未知签名/明显可疑路径组合时才进入重点关注。
    if ((Test-IsSuspiciousPersistencePath -PathOrCommand $s.Command) -and (-not $isTrustedVendor) -and ($isDangerScriptOrCommand -or $s.Signature -ne "Valid")) {
        $reason += "启动项位于可疑目录且缺少可信特征"
    }

    if ($isDangerScriptOrCommand) {
        $reason += "启动项命令命中危险脚本或命令特征"
    }

    if ($s.Signature -and $s.Signature -notin @("Valid","NotSigned") -and (-not $isTrustedVendor)) {
        $reason += "签名状态异常：$($s.Signature)"
    }

    if ($reason.Count -gt 0) {
        $level = if ($s.Command -match "(?i)\.(bat|cmd|ps1|vbs|js|hta)\b|xmrig|miner|c3pool|downloadstring|-enc|-encodedcommand") { "高危" } else { "中危" }

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

# 1. 从已经命中的挖矿/持久化线索中提取目录
foreach ($r in $ResourceAnomalies) {
    if ("$($r.Name) $($r.ExecutablePath) $($r.CommandLine) $($r.Tags)" -match "(?i)xmrig|miner|c3pool|monero|stratum|WinRing0|nssm") {
        Add-MiningCandidateDir -List $MiningCandidateDirs -Value $r.ExecutablePath
        Add-MiningCandidateDir -List $MiningCandidateDirs -Value $r.CommandLine
    }
}

foreach ($s in $ServiceEvents) {
    if ("$($s.ServiceName) $($s.ImagePath) $($s.Reason)" -match "(?i)xmrig|miner|c3pool|monero|stratum|WinRing0|nssm") {
        Add-MiningCandidateDir -List $MiningCandidateDirs -Value $s.ImagePath
    }
}

foreach ($t in $SuspiciousTasks) {
    if ("$($t.TaskName) $($t.Actions) $($t.Reason)" -match "(?i)xmrig|miner|c3pool|monero|stratum|WinRing0|nssm") {
        Add-MiningCandidateDir -List $MiningCandidateDirs -Value $t.Actions
    }
}

foreach ($s in $SuspiciousStartup) {
    if ("$($s.Name) $($s.Command) $($s.Reason)" -match "(?i)xmrig|miner|c3pool|monero|stratum|WinRing0|nssm") {
        Add-MiningCandidateDir -List $MiningCandidateDirs -Value $s.Command
    }
}

# 2. 补充常见挖矿目录候选，不做大范围全盘扫描，避免太慢
try {
    $commonRoots = @("C:\Users", "C:\ProgramData", "C:\Windows\Temp")
    foreach ($root in $commonRoots) {
        if (Test-Path $root -PathType Container) {
            Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                if ($_.Name -match "(?i)c3pool|xmrig|miner|xmr|monero") {
                    if (-not $MiningCandidateDirs.Contains($_.FullName)) {
                        $MiningCandidateDirs.Add($_.FullName) | Out-Null
                    }
                }
            }
        }
    }
}
catch {}

$MiningConfigs = New-Object System.Collections.Generic.List[object]
$MiningConfigFiles = @()
$MiningTextExt = @(".json", ".conf", ".config", ".txt", ".bat", ".cmd", ".ps1", ".ini", ".yml", ".yaml", ".xml")

foreach ($dir in $MiningCandidateDirs) {
    if (-not (Test-Path $dir -PathType Container)) { continue }

    try {
        $files = Get-ChildItem -Path $dir -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Length -gt 0 -and $_.Length -lt 2MB -and ($MiningTextExt -contains $_.Extension.ToLower()) } |
            Select-Object -First 200

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

            # 矿池地址：stratum 协议最可靠
            foreach ($m in [regex]::Matches($content, '(?i)stratum\+(tcp|ssl)://[^\s"''<>]+')) {
                Add-MiningConfigHit -List $MiningConfigs -Type "矿池地址" -Value $m.Value -FilePath $f.FullName -SourceDir $dir -Context (Get-ShortContext -Text $content -Value $m.Value) -Confidence "高"
            }

            # JSON / 配置中的 url 字段
            foreach ($m in [regex]::Matches($content, '(?i)"url"\s*:\s*"([^"]+)"')) {
                $v = $m.Groups[1].Value
                if ($v -match '(?i)stratum|pool|:[0-9]{2,5}') {
                    Add-MiningConfigHit -List $MiningConfigs -Type "矿池地址" -Value $v -FilePath $f.FullName -SourceDir $dir -Context (Get-ShortContext -Text $content -Value $v) -Confidence "高"
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

            # user / wallet / -u 后面的长字符串，作为钱包或矿工用户名候选
            foreach ($m in [regex]::Matches($content, '(?i)("user"\s*:\s*"|"wallet"\s*:\s*"|--user\s+|-u\s+)([A-Za-z0-9_.+\-]{40,140})')) {
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

$MiningConfigsArray = @()
foreach ($mc in $MiningConfigs) {
    $MiningConfigsArray += $mc
}

Export-DetailCsv -Name "挖矿配置文件候选.csv" -Data $MiningConfigFiles
Export-DetailCsv -Name "挖矿配置提取.csv" -Data $MiningConfigsArray

if ($MiningConfigsArray.Count -gt 0) {
    $poolCount = @($MiningConfigsArray | Where-Object { $_.Type -match "矿池" }).Count
    $walletCount = @($MiningConfigsArray | Where-Object { $_.Type -match "钱包" }).Count

    Add-Finding -Level "高危" -Category "挖矿配置" -Title "发现矿池或钱包配置线索" `
        -Evidence "矿池线索=$poolCount，钱包线索=$walletCount，候选目录=$($MiningCandidateDirs -join ';')" `
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
        $PowerShellFindings += [PSCustomObject]@{
            TimeCreated = $evt.TimeCreated
            EventID     = $evt.Id
            RecordID    = $evt.RecordId
            Summary     = $msg.Substring(0, [Math]::Min(400, $msg.Length))
        }

        Add-Finding -Level "中危" -Category "PowerShell" -Title "PowerShell 事件日志命中高危命令特征" `
            -Evidence "时间=$($evt.TimeCreated)，EventID=$($evt.Id)，摘要=$($msg.Substring(0, [Math]::Min(300, $msg.Length)))" `
            -Suggestion "重点检查是否存在下载执行、编码命令、绕过策略、禁用防护、创建账户或添加管理员行为。"
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

foreach ($ipItem in $FailedByIP) {
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

$minerEvidence = @()
$minerEvidence += @($ResourceAnomalies | Where-Object { "$($_.Name) $($_.ExecutablePath) $($_.Tags) $($_.CommandLine)" -match "(?i)xmrig|miner|c3pool|monero|stratum|WinRing0" })
$minerEvidence += @($ServiceEvents | Where-Object { "$($_.ServiceName) $($_.ImagePath)" -match "(?i)c3pool|xmrig|miner|WinRing0|nssm|monero|stratum" })
$minerEvidence += @($MiningConfigsArray | Where-Object { "$($_.Type) $($_.Value)" -match "(?i)矿池|钱包|stratum|pool" })

if (@($minerEvidence).Count -gt 0) {
    Add-Scenario -Level "高危" -Scenario "疑似挖矿木马 / 资源滥用" `
        -Conclusion "发现挖矿相关进程、驱动或服务安装线索。" `
        -Evidence "相关线索数量=$(@($minerEvidence).Count)；示例=$((@($minerEvidence) | Select-Object -First 1 | Out-String).Trim())" `
        -Suggestion "优先检查挖矿进程、c3pool/xmrig 目录、WinRing0 驱动、服务持久化、计划任务、矿池地址和钱包地址。"
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

$accountEvidence = @($SecurityEvents | Where-Object { $_.EventID -in @(4720,4732) -and $_.TargetUser -match "(?i)Administrators|Remote Desktop Users|管理员|远程桌面用户|hack|test|support|admin" })
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
$summaryLines += "时间范围：$StartTime ~ $EndTime"
$summaryLines += "输出目录：$OutputDir"
$summaryLines += ""
$summaryLines += "一、攻击场景判断"
foreach ($s in $ScenariosArray) {
    $summaryLines += "[$($s.Level)] $($s.Scenario)：$($s.Conclusion)"
    $summaryLines += "证据：$($s.Evidence)"
}
$summaryLines += ""
$summaryLines += "二、风险统计"
$summaryLines += "高危：$HighCount"
$summaryLines += "中危：$MidCount"
$summaryLines += "关注：$WatchCount"
$summaryLines += ""
$summaryLines += "三、登录失败 Top IP"
foreach ($ip in ($FailedByIP | Select-Object -First 10)) {
    $summaryLines += "$($ip.SourceIP)：疑似开始时间=$($ip.AttackStartTime)，失败=$($ip.FailedCount)，目标账户=$($ip.TargetUsers)，方式=$($ip.MainLogonMethod)，首次成功=$($ip.FirstSuccessTime)，判断=$($ip.AttackJudgement)"
}
$summaryLines += ""
$summaryLines += "四、危险监听端口"
foreach ($p in ($DangerPorts | Select-Object -First 20)) {
    $summaryLines += "[$($p.Level)] $($p.LocalPort) $($p.ServiceRisk) 监听地址=$($p.LocalAddress)"
}
$summaryLines += ""
$summaryLines += "五、挖矿配置提取"
foreach ($m in ($MiningConfigsArray | Select-Object -First 20)) {
    $summaryLines += "[$($m.Type)] $($m.Value) 来源=$($m.FilePath) 置信度=$($m.Confidence)"
}
$summaryLines += ""
$summaryLines += "六、建议"
$summaryLines += "1. 优先查看 WinIR_Report.html 的「攻击场景判断」。"
$summaryLines += "2. 再查看「重点关注项」和「资源异常进程」。"
$summaryLines += "3. 本工具只做线索整理，不做查杀。最终结论需要人工复核。"

$summaryLines | Out-File -FilePath $SummaryPath -Encoding UTF8

$scenarioForHtml = $ScenariosArray | Select-Object Level,Scenario,Conclusion,Evidence,Suggestion
$findingsForHtml = $FindingsArray | Select-Object Level,Category,Title,Evidence,Suggestion
$securityForHtml = $SecuritySummary | Select-Object EventID,EventType,Count
$failedForHtml = $FailedByIP | Select-Object SourceIP,FailedCount,AttackStartTime,LastFailTime,DurationMinutes,TargetUsers,TargetUserCount,MainLogonMethod,SourcePortRange,FirstSuccessTime,FirstSuccessUser,AttackJudgement,Reasons
$rdpForHtml = $RdpEvents | Select-Object TimeCreated,EventID,UserName,Domain,Address,Description
$serviceForHtml = $ServiceEvents | Where-Object { $_.Level -ne "正常" } | Select-Object Level,TimeCreated,ServiceName,ImagePath,AccountName,Reason
$startupForHtml = $SuspiciousStartup | Select-Object Level,Location,Name,Command,Signature,Reason
$taskForHtml = $SuspiciousTasks | Select-Object Level,TaskName,State,Actions,Reason
$portForHtml = $DangerPorts | Select-Object Level,LocalPort,LocalAddress,ServiceRisk,ProcessId,ProcessName,ProcessPath
$resourceForHtml = $ResourceAnomalies | Select-Object Level,Score,ProcessId,Name,CpuPercent,MemoryMB,MemoryPercent,PublicConnections,Tags,ExecutablePath,CommandLine
$netForHtml = $NetConns | Where-Object { $_.IsPublicIP -eq $true } | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,ProcessId,ProcessName,ProcessPath
$miningConfigForHtml = $MiningConfigsArray | Select-Object Type,Value,Confidence,FilePath,SourceDir,Context
$psForHtml = $PowerShellFindings | Select-Object TimeCreated,EventID,Summary

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
</style>
"@

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
        <p>分析范围：$(HtmlEncode $StartTime) ~ $(HtmlEncode $EndTime)</p>
        <p>工具定位：辅助取证与线索整理，不做查杀，不替代专业安全工具。</p>
    </div>

    <div class="cards">
        <div class="card"><div class="num high">$HighCount</div><div class="label">高危项</div></div>
        <div class="card"><div class="num mid">$MidCount</div><div class="label">中危项</div></div>
        <div class="card"><div class="num watch">$WatchCount</div><div class="label">关注项</div></div>
        <div class="card"><div class="num ok">$($SecurityEvents.Count)</div><div class="label">安全事件数量</div></div>
    </div>

    <div class="section">
        <h2>一、攻击场景判断</h2>
        $(ConvertTo-HtmlTable -Data $scenarioForHtml -MaxRows 50)
    </div>

    <div class="section">
        <h2>二、重点关注项</h2>
        $(ConvertTo-HtmlTable -Data $findingsForHtml -MaxRows 100)
    </div>

    <div class="section">
        <h2>三、Windows 安全事件统计</h2>
        $(ConvertTo-HtmlTable -Data $securityForHtml -MaxRows 30)
    </div>

    <div class="section">
        <h2>四、登录失败来源 IP Top（含疑似攻击开始时间）</h2>
        $(ConvertTo-HtmlTable -Data $failedForHtml -MaxRows 50)
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
        <h2>八、挖矿配置提取（矿池 / 钱包）</h2>
        <p class="empty">该模块只扫描已命中的可疑挖矿目录和常见挖矿目录，不做全盘深度扫描，避免过慢和误报。</p>
        $(ConvertTo-HtmlTable -Data $miningConfigForHtml -MaxRows 80)
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
        <h2>十二、公网网络连接</h2>
        $(ConvertTo-HtmlTable -Data $netForHtml -MaxRows 50)
    </div>

    <div class="section">
        <h2>十三、PowerShell 高危痕迹</h2>
        $(ConvertTo-HtmlTable -Data $psForHtml -MaxRows 50)
    </div>

    <div class="section">
        <h2>十四、处置建议</h2>
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
