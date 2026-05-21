param(
    [int]$Days = 365,
    [int]$FailedThreshold = 10,
    [string]$StartTime = "",
    [string]$EndTime = "",
    [string[]]$WebRoots = @(),
    [string[]]$WebLogDirs = @(),
    [int]$MaxFileMB = 5,
    [int]$MaxScanFiles = 8000,
    [switch]$AllowNonAdmin
)

# ==============================
# WinIR-Helper v0.3 Web 应急响应辅助分析版
# 重点：WebShell 文件扫描、Web 日志 IP 统计、隐藏账户检查、挖矿 IOC 提取
# 注意：建议使用 UTF-8 with BOM 保存本脚本
# ==============================

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$Version = "v0.3-beta"
$CollectTime = Get-Date -Format "yyyyMMdd_HHmmss"
$OutputDir = Join-Path (Get-Location) "WinIR_应急响应结果_$CollectTime"
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "        WinIR-Helper $Version 应急采集工具" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "[+] 输出目录：$OutputDir" -ForegroundColor Green
Write-Host "[+] 默认日志范围：最近 $Days 天" -ForegroundColor Green
Write-Host "[+] Web 文件最大扫描大小：$MaxFileMB MB" -ForegroundColor Green
Write-Host "[+] Web 文件最大扫描数量：$MaxScanFiles" -ForegroundColor Green
Write-Host ""

# ==============================
# 0. 管理员权限检测
# ==============================

$CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($CurrentUser)
$IsAdmin = $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin -and -not $AllowNonAdmin) {
    Write-Host "[!] 当前不是管理员权限，无法可靠读取 Security 安全日志。" -ForegroundColor Red
    Write-Host "[!] 请右键 PowerShell，选择“以管理员身份运行”后重新执行脚本。" -ForegroundColor Yellow
    Write-Host "[!] 如果只是测试 Web 文件扫描功能，可以使用参数：-AllowNonAdmin" -ForegroundColor Yellow

    @"
WinIR-Helper $Version 权限检测结果

当前运行状态：非管理员权限
处理结果：脚本已主动退出
原因说明：读取 Windows Security 安全日志通常需要管理员权限。

解决方法：
1. 右键 PowerShell
2. 选择“以管理员身份运行”
3. 重新执行脚本

测试参数：
如果仅需测试 Web 文件扫描等非日志采集功能，可以运行：
.\WinIR-Helper-v0.3-WebModule.ps1 -AllowNonAdmin
"@ | Out-File "$OutputDir\权限检测说明.txt" -Encoding UTF8
    exit 1
}

if (-not $IsAdmin -and $AllowNonAdmin) {
    Write-Host "[!] 当前为非管理员权限，但已启用 -AllowNonAdmin，脚本将继续执行。" -ForegroundColor Yellow
    Write-Host "[!] 注意：Security 安全日志可能无法正常读取。" -ForegroundColor Yellow
    Write-Host ""
}

# ==============================
# 通用函数
# ==============================

function Export-ChineseCsv {
    param(
        [Parameter(ValueFromPipeline = $true)]
        $InputObject,
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    begin { $List = @() }
    process {
        if ($null -ne $InputObject) { $List += $InputObject }
    }
    end {
        if (@($List).Count -eq 0) {
            [PSCustomObject]@{ "提示" = "无结果" } | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
        } else {
            $List | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
        }
    }
}

function Convert-EventData {
    param([Parameter(Mandatory = $true)]$Event)
    [xml]$Xml = $Event.ToXml()
    $Data = [ordered]@{}
    $Index = 0

    foreach ($Item in $Xml.Event.EventData.Data) {
        $Name = [string]$Item.Name
        if ([string]::IsNullOrWhiteSpace($Name)) { $Name = "Data$Index" }
        if ($Data.Contains($Name)) { $Name = "$Name$Index" }
        $Data[$Name] = $Item.'#text'
        $Index++
    }
    return [PSCustomObject]$Data
}

function Get-TimeRange {
    $Now = Get-Date
    $Start = $Now.AddDays(-$Days)
    $End = $Now

    if (-not [string]::IsNullOrWhiteSpace($StartTime)) {
        try { $Start = [datetime]$StartTime } catch { Write-Host "[!] StartTime 格式错误，将使用最近 $Days 天。" -ForegroundColor Yellow }
    }

    if (-not [string]::IsNullOrWhiteSpace($EndTime)) {
        try { $End = [datetime]$EndTime } catch { Write-Host "[!] EndTime 格式错误，将使用当前时间。" -ForegroundColor Yellow }
    }

    return [PSCustomObject]@{ Start = $Start; End = $End }
}

function Get-LoginEvents {
    param([int]$EventId, [datetime]$Start, [datetime]$End)

    try {
        $Events = Get-WinEvent -FilterHashtable @{
            LogName   = "Security"
            Id        = $EventId
            StartTime = $Start
            EndTime   = $End
        } -ErrorAction Stop
    } catch {
        Write-Host "[!] 读取安全日志失败，事件 ID：$EventId" -ForegroundColor Yellow
        return @()
    }

    foreach ($Event in $Events) {
        $Data = Convert-EventData -Event $Event
        [PSCustomObject]@{
            "时间"       = $Event.TimeCreated
            "事件ID"     = $Event.Id
            "用户名"     = $Data.TargetUserName
            "域名"       = $Data.TargetDomainName
            "登录类型"   = $Data.LogonType
            "来源IP"     = $Data.IpAddress
            "工作站名"   = $Data.WorkstationName
            "进程名"     = $Data.ProcessName
            "状态码"     = $Data.Status
            "子状态码"   = $Data.SubStatus
        }
    }
}

function Get-ProcessNameById {
    param([int]$ProcessId)
    try { return (Get-Process -Id $ProcessId -ErrorAction Stop).ProcessName } catch { return "未知进程" }
}

function Get-ProcessPathById {
    param([int]$ProcessId)
    try { return (Get-CimInstance Win32_Process -Filter "ProcessId=$ProcessId" -ErrorAction Stop).ExecutablePath } catch { return "" }
}

function Test-InvalidAddress {
    param([string]$Address)
    if ([string]::IsNullOrWhiteSpace($Address)) { return $true }
    return (@("-", "*", "0.0.0.0", "::", "::1", "127.0.0.1", "localhost") -contains $Address)
}

function Test-PrivateIPv4 {
    param([string]$Address)
    $Ip = $null
    if (-not [System.Net.IPAddress]::TryParse($Address, [ref]$Ip)) { return $false }
    if ($Ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return $false }
    $Bytes = $Ip.GetAddressBytes()
    if ($Bytes[0] -eq 10) { return $true }
    if ($Bytes[0] -eq 172 -and $Bytes[1] -ge 16 -and $Bytes[1] -le 31) { return $true }
    if ($Bytes[0] -eq 192 -and $Bytes[1] -eq 168) { return $true }
    if ($Bytes[0] -eq 169 -and $Bytes[1] -eq 254) { return $true }
    return $false
}

function Test-PublicRemoteAddress {
    param([string]$Address)
    if (Test-InvalidAddress -Address $Address) { return $false }
    if (Test-PrivateIPv4 -Address $Address) { return $false }
    $Ip = $null
    return [System.Net.IPAddress]::TryParse($Address, [ref]$Ip)
}

function Get-FileHashSafe {
    param([string]$Path, [string]$Algorithm = "SHA256")
    try { return (Get-FileHash -Path $Path -Algorithm $Algorithm -ErrorAction Stop).Hash } catch { return "" }
}

function Get-TextPreviewLines {
    param([string]$Path, [int]$MaxLines = 500)
    try {
        return Get-Content -Path $Path -Encoding UTF8 -TotalCount $MaxLines -ErrorAction Stop
    } catch {
        try { return Get-Content -Path $Path -TotalCount $MaxLines -ErrorAction Stop } catch { return @() }
    }
}

function Resolve-WebRoots {
    param([string[]]$UserRoots)

    $Candidates = @()
    $Candidates += $UserRoots
    $Candidates += @(
        "C:\inetpub\wwwroot",
        "D:\inetpub\wwwroot",
        "C:\phpstudy_pro\WWW",
        "D:\phpstudy_pro\WWW",
        "C:\phpStudy\WWW",
        "D:\phpStudy\WWW",
        "C:\xampp\htdocs",
        "D:\xampp\htdocs",
        "C:\wamp64\www",
        "D:\wamp64\www",
        "C:\wwwroot",
        "D:\wwwroot",
        "C:\WWW",
        "D:\WWW"
    )

    $Existing = $Candidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique
    return @($Existing)
}

function Resolve-WebLogDirs {
    param([string[]]$UserLogDirs)

    $Candidates = @()
    $Candidates += $UserLogDirs

    # 只加入明确的 Web 日志目录，不加入 phpstudy_pro\Extensions 这种大目录
    $Candidates += @(
        "C:\inetpub\logs\LogFiles",
        "D:\inetpub\logs\LogFiles",

        "C:\phpstudy_pro\Extensions\Apache2.4.39\logs",
        "C:\phpstudy_pro\Extensions\Nginx1.15.11\logs",
        "D:\phpstudy_pro\Extensions\Apache2.4.39\logs",
        "D:\phpstudy_pro\Extensions\Nginx1.15.11\logs",

        "C:\phpStudy\PHPTutorial\Apache\logs",
        "D:\phpStudy\PHPTutorial\Apache\logs",
        "C:\phpStudy\PHPTutorial\nginx\logs",
        "D:\phpStudy\PHPTutorial\nginx\logs",

        "C:\xampp\apache\logs",
        "D:\xampp\apache\logs",
        "C:\wamp64\logs",
        "D:\wamp64\logs"
    )

    $Existing = @()

    foreach ($Path in $Candidates) {
        if ($Path -and (Test-Path $Path)) {
            $Existing += $Path
        }
    }

    return @($Existing | Select-Object -Unique)
}

function Test-SuspiciousWebLine {
    param([string]$Line)

    $Patterns = @(
        "(?i)eval\s*\(",
        "(?i)assert\s*\(",
        "(?i)base64_decode",
        "(?i)gzinflate",
        "(?i)str_rot13",
        "(?i)shell_exec",
        "(?i)passthru",
        "(?i)proc_open",
        "(?i)popen\s*\(",
        "(?i)system\s*\(",
        "(?i)cmd\.exe",
        "(?i)powershell",
        "(?i)WScript\.Shell",
        "(?i)CreateObject",
        "(?i)Request\s*\(",
        "(?i)Request\.Form",
        "(?i)Request\.QueryString",
        "(?i)\$_POST",
        "(?i)\$_GET",
        "(?i)\$_REQUEST",
        "(?i)antSword|蚁剑|caidao|菜刀|冰蝎|behinder|rebeyond|webshell|shell"
    )

    foreach ($Pattern in $Patterns) {
        if ($Line -match $Pattern) { return $true }
    }
    return $false
}

function Extract-ShellParamCandidates {
    param([string]$Line)

    $Results = @()
    $RegexList = @(
        '\$_(?:POST|GET|REQUEST)\s*\[\s*[''"]([^''"]+)[''"]\s*\]',
        'Request(?:\.Form|\.QueryString)?\s*\(\s*[''"]([^''"]+)[''"]\s*\)',
        'Request\s*\[\s*[''"]([^''"]+)[''"]\s*\]',
        '(?i)(?:pass|pwd|password|key)\s*=\s*[''"]([^''"]{1,80})[''"]'
    )

    foreach ($Regex in $RegexList) {
        $Matches = [regex]::Matches($Line, $Regex)
        foreach ($M in $Matches) {
            if ($M.Groups.Count -gt 1) { $Results += $M.Groups[1].Value }
        }
    }

    return @($Results | Where-Object { $_ } | Select-Object -Unique)
}

function Extract-DomainsFromText {
    param([string]$Text)

    $Results = @()
    $DomainRegex = "(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|cn|top|xyz|cc|io|me|info|biz|ru|pw|site|club|online|vip|work)"
    $Matches = [regex]::Matches($Text, $DomainRegex)
    foreach ($M in $Matches) { $Results += $M.Value.ToLower() }
    return @($Results | Select-Object -Unique)
}

function Test-MiningLine {
    param([string]$Line)
    return ($Line -match "(?i)(xmrig|monero|xmr|stratum|pool|mining|miner|wallet|cryptonight|nicehash|nanopool|supportxmr)")
}

# ==============================
# 1. 基础 Windows 登录日志与账号采集
# ==============================

$Range = Get-TimeRange
Write-Host "[+] 实际日志范围：$($Range.Start) 到 $($Range.End)" -ForegroundColor Green

Write-Host "[+] 正在导出 4624 登录成功日志..." -ForegroundColor Cyan
$SuccessLogons = Get-LoginEvents -EventId 4624 -Start $Range.Start -End $Range.End
$SuccessLogons | Export-ChineseCsv -Path "$OutputDir\4624_登录成功日志.csv"

Write-Host "[+] 正在导出 4625 登录失败日志..." -ForegroundColor Cyan
$FailedLogons = Get-LoginEvents -EventId 4625 -Start $Range.Start -End $Range.End
$FailedLogons | Export-ChineseCsv -Path "$OutputDir\4625_登录失败日志.csv"

Write-Host "[+] 正在统计来源 IP..." -ForegroundColor Cyan
$ExcludeIps = @("-", "127.0.0.1", "::1", "::", "0.0.0.0", "")
$AllIpRecords = @()
$AllIpRecords += $SuccessLogons | Where-Object { $_."来源IP" -and ($ExcludeIps -notcontains $_."来源IP") } | Select-Object "时间", "事件ID", "用户名", "来源IP", "登录类型"
$AllIpRecords += $FailedLogons | Where-Object { $_."来源IP" -and ($ExcludeIps -notcontains $_."来源IP") } | Select-Object "时间", "事件ID", "用户名", "来源IP", "登录类型"

$MediumThreshold = [Math]::Max(3, [int][Math]::Ceiling($FailedThreshold / 2))
$IpStats = foreach ($Group in ($AllIpRecords | Group-Object "来源IP")) {
    $SuccessCount = @($Group.Group | Where-Object { $_."事件ID" -eq 4624 }).Count
    $FailedCount = @($Group.Group | Where-Object { $_."事件ID" -eq 4625 }).Count
    $RiskLevel = "低危"
    $RiskReason = "暂未发现明显异常"
    if ($FailedCount -ge $FailedThreshold -and $SuccessCount -gt 0) {
        $RiskLevel = "高危"; $RiskReason = "该 IP 出现大量登录失败后又出现登录成功，疑似爆破成功"
    } elseif ($FailedCount -ge $FailedThreshold) {
        $RiskLevel = "高危"; $RiskReason = "该 IP 登录失败次数超过阈值，疑似暴力破解"
    } elseif ($FailedCount -ge $MediumThreshold) {
        $RiskLevel = "中危"; $RiskReason = "该 IP 存在多次登录失败，建议继续观察"
    }
    [PSCustomObject]@{
        "来源IP" = $Group.Name
        "总次数" = $Group.Count
        "成功次数" = $SuccessCount
        "失败次数" = $FailedCount
        "首次发现" = ($Group.Group | Sort-Object "时间" | Select-Object -First 1)."时间"
        "最后发现" = ($Group.Group | Sort-Object "时间" -Descending | Select-Object -First 1)."时间"
        "风险等级" = $RiskLevel
        "风险原因" = $RiskReason
    }
}
$IpStats = $IpStats | Sort-Object "失败次数", "总次数" -Descending
$IpStats | Export-ChineseCsv -Path "$OutputDir\来源IP统计.csv"
$HighRiskIps = $IpStats | Where-Object { $_."风险等级" -eq "高危" }
$HighRiskIps | Export-ChineseCsv -Path "$OutputDir\高危IP筛选.csv"

Write-Host "[+] 正在导出本地用户..." -ForegroundColor Cyan
try {
    Get-LocalUser | Select-Object @{
        Name = "用户名"; Expression = { $_.Name }
    }, @{
        Name = "是否启用"; Expression = { $_.Enabled }
    }, @{
        Name = "最后登录时间"; Expression = { $_.LastLogon }
    }, @{
        Name = "密码最后设置时间"; Expression = { $_.PasswordLastSet }
    }, @{
        Name = "描述"; Expression = { $_.Description }
    } | Export-ChineseCsv -Path "$OutputDir\本地用户.csv"
} catch { "本地用户导出失败。" | Out-File "$OutputDir\本地用户_错误.txt" -Encoding UTF8 }

Write-Host "[+] 正在检查隐藏账户..." -ForegroundColor Cyan
$HiddenAccountResults = @()
try {
    $UserListPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
    if (Test-Path $UserListPath) {
        $Props = Get-ItemProperty -Path $UserListPath
        $Props.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
            $HiddenAccountResults += [PSCustomObject]@{
                "检查类型" = "登录界面隐藏账户注册表"
                "账户名" = $_.Name
                "数值" = $_.Value
                "风险说明" = "该账户可能被配置为不在登录界面显示，需要核对是否为攻击者隐藏账户"
            }
        }
    }
} catch {}

try {
    Get-LocalUser | Where-Object { $_.Name -match "\$" -or $_.Description -match "(?i)(hidden|hide|test|admin|backup|system)" } | ForEach-Object {
        $HiddenAccountResults += [PSCustomObject]@{
            "检查类型" = "可疑本地账户命名"
            "账户名" = $_.Name
            "数值" = "Enabled=$($_.Enabled)"
            "风险说明" = "账户名或描述存在可疑特征，需要人工确认"
        }
    }
} catch {}
$HiddenAccountResults | Export-ChineseCsv -Path "$OutputDir\隐藏账户检查.csv"

Write-Host "[+] 正在导出管理员组成员..." -ForegroundColor Cyan
try {
    $AdminGroup = Get-LocalGroup | Where-Object { $_.SID.Value -eq "S-1-5-32-544" -or $_.SID -eq "S-1-5-32-544" }
    if ($AdminGroup) {
        Get-LocalGroupMember -Group $AdminGroup.Name | Select-Object @{
            Name = "成员名称"; Expression = { $_.Name }
        }, @{
            Name = "对象类型"; Expression = { $_.ObjectClass }
        }, @{
            Name = "来源"; Expression = { $_.PrincipalSource }
        } | Export-ChineseCsv -Path "$OutputDir\管理员组成员.csv"
    }
} catch { "管理员组成员导出失败。" | Out-File "$OutputDir\管理员组成员_错误.txt" -Encoding UTF8 }

Write-Host "[+] 正在导出启动项..." -ForegroundColor Cyan
try {
    $StartupItems = Get-CimInstance Win32_StartupCommand | Select-Object @{
        Name = "启动项名称"; Expression = { $_.Name }
    }, @{
        Name = "启动命令"; Expression = { $_.Command }
    }, @{
        Name = "启动位置"; Expression = { $_.Location }
    }, @{
        Name = "所属用户"; Expression = { $_.User }
    }
    $StartupItems | Export-ChineseCsv -Path "$OutputDir\启动项.csv"
} catch { $StartupItems = @() }

Write-Host "[+] 正在导出计划任务..." -ForegroundColor Cyan
try {
    $ScheduledTasks = Get-ScheduledTask | Select-Object @{
        Name = "任务名称"; Expression = { $_.TaskName }
    }, @{
        Name = "任务路径"; Expression = { $_.TaskPath }
    }, @{
        Name = "任务状态"; Expression = { $_.State }
    }, @{
        Name = "作者"; Expression = { $_.Author }
    }, @{
        Name = "执行动作"; Expression = { ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join " | " }
    }
    $ScheduledTasks | Export-ChineseCsv -Path "$OutputDir\计划任务.csv"
} catch { $ScheduledTasks = @() }

# ==============================
# 2. 网络连接、进程路径与 Hash
# ==============================

Write-Host "[+] 正在导出当前网络连接并关联进程路径..." -ForegroundColor Cyan
try {
    $NetConnections = Get-NetTCPConnection | ForEach-Object {
        $Conn = $_
        $Pid = $Conn.OwningProcess
        $PName = Get-ProcessNameById -ProcessId $Pid
        $PPath = Get-ProcessPathById -ProcessId $Pid
        [PSCustomObject]@{
            "本地地址" = $Conn.LocalAddress
            "本地端口" = $Conn.LocalPort
            "远程地址" = $Conn.RemoteAddress
            "远程端口" = $Conn.RemotePort
            "连接状态" = $Conn.State
            "进程ID" = $Pid
            "进程名" = $PName
            "进程路径" = $PPath
            "进程SHA256" = if ($PPath -and (Test-Path $PPath)) { Get-FileHashSafe -Path $PPath -Algorithm SHA256 } else { "" }
        }
    }
    $NetConnections | Export-ChineseCsv -Path "$OutputDir\当前网络连接.csv"
} catch {
    Write-Host "[!] 当前网络连接导出失败。" -ForegroundColor Yellow
    $NetConnections = @()
}

# ==============================
# 3. Web 目录可疑文件扫描
# ==============================

Write-Host "[+] 正在识别 Web 目录..." -ForegroundColor Cyan
$ResolvedWebRoots = Resolve-WebRoots -UserRoots $WebRoots
$ResolvedWebRoots | ForEach-Object { [PSCustomObject]@{ "Web目录" = $_ } } | Export-ChineseCsv -Path "$OutputDir\识别到的Web目录.csv"

$SuspiciousWebFiles = @()
$RecentWebFiles = @()
$ShellParamCandidates = @()
$MiningIocResults = @()
$WebFileCount = 0

$WebExtensions = @(".php", ".phtml", ".asp", ".aspx", ".ashx", ".asa", ".cer", ".cdx", ".jsp", ".jspx", ".js", ".config", ".txt", ".ini", ".conf")
$RecentThreshold = (Get-Date).AddDays(-$Days)

foreach ($Root in $ResolvedWebRoots) {
    Write-Host "[+] 扫描 Web 目录：$Root" -ForegroundColor Cyan
    try {
        $Files = Get-ChildItem -Path $Root -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
            $WebExtensions -contains $_.Extension.ToLower() -and ($_.Length -le ($MaxFileMB * 1MB))
        } | Select-Object -First $MaxScanFiles

        foreach ($File in $Files) {
            $WebFileCount++

            if ($File.LastWriteTime -ge $RecentThreshold) {
                $RecentWebFiles += [PSCustomObject]@{
                    "文件路径" = $File.FullName
                    "文件大小" = $File.Length
                    "最后修改时间" = $File.LastWriteTime
                    "SHA256" = Get-FileHashSafe -Path $File.FullName -Algorithm SHA256
                    "说明" = "最近 $Days 天内修改的 Web 目录文件"
                }
            }

            $Lines = Get-TextPreviewLines -Path $File.FullName -MaxLines 800
            $LineNo = 0
            foreach ($Line in $Lines) {
                $LineNo++
                if (Test-SuspiciousWebLine -Line $Line) {
                    $SuspiciousWebFiles += [PSCustomObject]@{
                        "文件路径" = $File.FullName
                        "文件大小" = $File.Length
                        "最后修改时间" = $File.LastWriteTime
                        "命中行号" = $LineNo
                        "命中内容" = ($Line.Trim() -replace "\s+", " ")
                        "SHA256" = Get-FileHashSafe -Path $File.FullName -Algorithm SHA256
                        "风险说明" = "命中 WebShell 或命令执行相关关键字，需要人工确认"
                    }
                }

                $Params = Extract-ShellParamCandidates -Line $Line
                foreach ($Param in $Params) {
                    $ShellParamCandidates += [PSCustomObject]@{
                        "文件路径" = $File.FullName
                        "最后修改时间" = $File.LastWriteTime
                        "疑似连接参数或密码字段" = $Param
                        "命中行号" = $LineNo
                        "命中内容" = ($Line.Trim() -replace "\s+", " ")
                        "SHA256" = Get-FileHashSafe -Path $File.FullName -Algorithm SHA256
                        "说明" = "该字段可能是 WebShell 连接参数或密码字段，需结合文件逻辑确认"
                    }
                }

                if (Test-MiningLine -Line $Line) {
                    $Domains = Extract-DomainsFromText -Text $Line
                    $MiningIocResults += [PSCustomObject]@{
                        "来源" = "Web文件"
                        "文件或对象" = $File.FullName
                        "命中内容" = ($Line.Trim() -replace "\s+", " ")
                        "提取域名" = ($Domains -join ";")
                        "说明" = "命中挖矿相关关键词，需要结合进程、计划任务、网络连接确认"
                    }
                }
            }
        }
    } catch {}
}

$RecentWebFiles | Sort-Object "最后修改时间" -Descending | Export-ChineseCsv -Path "$OutputDir\Web目录最近修改文件.csv"
$SuspiciousWebFiles | Sort-Object "最后修改时间" -Descending | Export-ChineseCsv -Path "$OutputDir\疑似WebShell文件.csv"
$ShellParamCandidates | Sort-Object "最后修改时间" -Descending | Export-ChineseCsv -Path "$OutputDir\疑似Shell密码或连接参数.csv"

# ==============================
# 4. Web 日志分析与攻击 IP 统计
# ==============================

Write-Host "[+] 正在识别 Web 日志目录..." -ForegroundColor Cyan
$ResolvedLogDirs = Resolve-WebLogDirs -UserLogDirs $WebLogDirs
$ResolvedLogDirs | ForEach-Object { [PSCustomObject]@{ "日志目录" = $_ } } | Export-ChineseCsv -Path "$OutputDir\识别到的Web日志目录.csv"

$WebLogIpRecords = @()
$SuspiciousWebRequests = @()
$WebShellAccessRecords = @()
$WebShellNames = @($SuspiciousWebFiles | ForEach-Object { Split-Path $_."文件路径" -Leaf } | Select-Object -Unique)

$LogExtensions = @(".log", ".txt")
$SuspiciousRequestPattern = "(?i)(upload|shell|cmd|eval|assert|base64|system|passthru|powershell|certutil|wget|curl|\.php\?|\.asp\?|\.aspx\?|\.jsp\?|select.+from|union.+select|\.\./|%2e%2e|%00)"

foreach ($LogDir in $ResolvedLogDirs) {
    Write-Host "[+] 分析 Web 日志目录：$LogDir" -ForegroundColor Cyan
    try {
        $LogFiles = Get-ChildItem -Path $LogDir -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
            $LogExtensions -contains $_.Extension.ToLower() -and $_.Length -le 200MB
        } | Select-Object -First 300

        foreach ($LogFile in $LogFiles) {
            $Fields = @()
            $LineNo = 0
            foreach ($Line in (Get-Content -Path $LogFile.FullName -ErrorAction SilentlyContinue)) {
                $LineNo++
                if ([string]::IsNullOrWhiteSpace($Line)) { continue }

                if ($Line.StartsWith("#Fields:")) {
                    $Fields = ($Line.Replace("#Fields:", "").Trim() -split "\s+")
                    continue
                }
                if ($Line.StartsWith("#")) { continue }

                $ClientIp = ""
                $Method = ""
                $UriStem = ""
                $UriQuery = ""
                $Status = ""
                $UserAgent = ""

                if ($Fields.Count -gt 0) {
                    $Parts = $Line -split "\s+"
                    for ($i = 0; $i -lt [Math]::Min($Fields.Count, $Parts.Count); $i++) {
                        switch ($Fields[$i]) {
                            "c-ip" { $ClientIp = $Parts[$i] }
                            "cs-method" { $Method = $Parts[$i] }
                            "cs-uri-stem" { $UriStem = $Parts[$i] }
                            "cs-uri-query" { $UriQuery = $Parts[$i] }
                            "sc-status" { $Status = $Parts[$i] }
                            "cs(User-Agent)" { $UserAgent = $Parts[$i] }
                        }
                    }
                } else {
                    $IpMatch = [regex]::Match($Line, "(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
                    if ($IpMatch.Success) { $ClientIp = $IpMatch.Value }
                    $ReqMatch = [regex]::Match($Line, '"(GET|POST|PUT|DELETE|HEAD) +([^ ]+)')
                    if ($ReqMatch.Success) {
                        $Method = $ReqMatch.Groups[1].Value
                        $UriStem = $ReqMatch.Groups[2].Value
                    }
                }

                if (-not [string]::IsNullOrWhiteSpace($ClientIp)) {
                    $WebLogIpRecords += [PSCustomObject]@{
                        "来源IP" = $ClientIp
                        "方法" = $Method
                        "路径" = $UriStem
                        "参数" = $UriQuery
                        "状态码" = $Status
                        "日志文件" = $LogFile.FullName
                        "行号" = $LineNo
                    }
                }

                $Combined = "$UriStem $UriQuery $Line"
                if ($Combined -match $SuspiciousRequestPattern) {
                    $SuspiciousWebRequests += [PSCustomObject]@{
                        "来源IP" = $ClientIp
                        "方法" = $Method
                        "路径" = $UriStem
                        "参数" = $UriQuery
                        "状态码" = $Status
                        "日志文件" = $LogFile.FullName
                        "行号" = $LineNo
                        "原始日志" = ($Line.Trim() -replace "\s+", " ")
                        "风险说明" = "命中可疑 Web 请求关键字，需要结合上传文件和 WebShell 文件确认"
                    }
                }

                foreach ($Name in $WebShellNames) {
                    if ($Name -and $Combined -match [regex]::Escape($Name)) {
                        $WebShellAccessRecords += [PSCustomObject]@{
                            "来源IP" = $ClientIp
                            "疑似WebShell文件名" = $Name
                            "方法" = $Method
                            "路径" = $UriStem
                            "参数" = $UriQuery
                            "状态码" = $Status
                            "日志文件" = $LogFile.FullName
                            "行号" = $LineNo
                            "原始日志" = ($Line.Trim() -replace "\s+", " ")
                            "说明" = "访问日志中出现疑似 WebShell 文件名，可用于辅助锁定攻击 IP"
                        }
                    }
                }
            }
        }
    } catch {}
}

$WebIpStats = $WebLogIpRecords | Group-Object "来源IP" | ForEach-Object {
    [PSCustomObject]@{
        "来源IP" = $_.Name
        "请求次数" = $_.Count
        "首次命中文件" = ($_.Group | Select-Object -First 1)."日志文件"
        "样例路径" = ($_.Group | Select-Object -First 1)."路径"
    }
} | Sort-Object "请求次数" -Descending

$WebIpStats | Export-ChineseCsv -Path "$OutputDir\Web访问IP统计.csv"
$SuspiciousWebRequests | Export-ChineseCsv -Path "$OutputDir\Web可疑请求.csv"
$WebShellAccessRecords | Export-ChineseCsv -Path "$OutputDir\WebShell访问记录.csv"

# ==============================
# 5. 挖矿 IOC 提取：进程、计划任务、启动项、Web 文件
# ==============================

Write-Host "[+] 正在提取挖矿 IOC..." -ForegroundColor Cyan

try {
    Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match "(?i)(xmrig|monero|xmr|stratum|pool|mining|miner|wallet|cryptonight|nicehash|nanopool|supportxmr)" } | ForEach-Object {
        $Domains = Extract-DomainsFromText -Text $_.CommandLine
        $MiningIocResults += [PSCustomObject]@{
            "来源" = "进程命令行"
            "文件或对象" = "$($_.ProcessId) / $($_.Name) / $($_.ExecutablePath)"
            "命中内容" = $_.CommandLine
            "提取域名" = ($Domains -join ";")
            "说明" = "进程命令行命中挖矿关键词"
        }
    }
} catch {}

foreach ($Item in $StartupItems) {
    $Text = "$($Item."启动项名称") $($Item."启动命令")"
    if (Test-MiningLine -Line $Text) {
        $MiningIocResults += [PSCustomObject]@{
            "来源" = "启动项"
            "文件或对象" = $Item."启动项名称"
            "命中内容" = $Item."启动命令"
            "提取域名" = ((Extract-DomainsFromText -Text $Text) -join ";")
            "说明" = "启动项命中挖矿关键词"
        }
    }
}

foreach ($Item in $ScheduledTasks) {
    $Text = "$($Item."任务名称") $($Item."执行动作")"
    if (Test-MiningLine -Line $Text) {
        $MiningIocResults += [PSCustomObject]@{
            "来源" = "计划任务"
            "文件或对象" = $Item."任务名称"
            "命中内容" = $Item."执行动作"
            "提取域名" = ((Extract-DomainsFromText -Text $Text) -join ";")
            "说明" = "计划任务命中挖矿关键词"
        }
    }
}

$MiningIocResults | Export-ChineseCsv -Path "$OutputDir\挖矿IOC提取.csv"

# ==============================
# 6. 重点关注项汇总
# ==============================

Write-Host "[+] 正在生成重点关注项..." -ForegroundColor Cyan
$FocusItems = @()

foreach ($Item in $HighRiskIps) {
    $FocusItems += [PSCustomObject]@{
        "类型" = "高危登录IP"
        "对象" = $Item."来源IP"
        "原因" = $Item."风险原因"
        "建议" = "结合 4624/4625 登录时间、用户名、登录类型进一步判断"
    }
}

foreach ($Item in $HiddenAccountResults) {
    $FocusItems += [PSCustomObject]@{
        "类型" = "隐藏或可疑账户"
        "对象" = $Item."账户名"
        "原因" = $Item."风险说明"
        "建议" = "核对账户创建时间、权限、登录记录和管理员组成员"
    }
}

foreach ($Item in ($SuspiciousWebFiles | Select-Object -First 50)) {
    $FocusItems += [PSCustomObject]@{
        "类型" = "疑似WebShell文件"
        "对象" = $Item."文件路径"
        "原因" = $Item."风险说明"
        "建议" = "查看命中内容、最后修改时间、访问日志和文件 Hash"
    }
}

foreach ($Item in ($ShellParamCandidates | Select-Object -First 50)) {
    $FocusItems += [PSCustomObject]@{
        "类型" = "疑似Shell连接参数"
        "对象" = "$($Item."疑似连接参数或密码字段") / $($Item."文件路径")"
        "原因" = "Web 文件中出现可能作为 WebShell 连接参数或密码字段的内容"
        "建议" = "结合 WebShell 文件逻辑确认真实 shell 密码或连接参数"
    }
}

foreach ($Item in ($WebShellAccessRecords | Select-Object -First 50)) {
    $FocusItems += [PSCustomObject]@{
        "类型" = "WebShell访问记录"
        "对象" = "$($Item."来源IP") -> $($Item."疑似WebShell文件名")"
        "原因" = "访问日志中出现疑似 WebShell 文件名"
        "建议" = "优先核对该 IP 是否为攻击者 IP"
    }
}

foreach ($Item in ($MiningIocResults | Select-Object -First 50)) {
    $FocusItems += [PSCustomObject]@{
        "类型" = "挖矿IOC"
        "对象" = $Item."提取域名"
        "原因" = $Item."说明"
        "建议" = "结合进程、计划任务、启动项和网络连接确认矿池域名"
    }
}

$FocusItems | Export-ChineseCsv -Path "$OutputDir\重点关注项.csv"

# ==============================
# 7. 生成摘要
# ==============================

$Summary = @"
WinIR-Helper $Version 应急响应采集摘要

采集时间：$(Get-Date)
日志范围：$($Range.Start) 到 $($Range.End)
管理员权限：$IsAdmin

一、基础日志
登录成功日志数量：$(@($SuccessLogons).Count)
登录失败日志数量：$(@($FailedLogons).Count)
高危登录 IP 数量：$(@($HighRiskIps).Count)

二、账户检查
隐藏或可疑账户数量：$(@($HiddenAccountResults).Count)

三、Web 应急模块
识别到的 Web 目录数量：$(@($ResolvedWebRoots).Count)
扫描 Web 文件数量：$WebFileCount
最近修改 Web 文件数量：$(@($RecentWebFiles).Count)
疑似 WebShell 文件数量：$(@($SuspiciousWebFiles).Count)
疑似 Shell 密码或连接参数数量：$(@($ShellParamCandidates).Count)

四、Web 日志分析
识别到的 Web 日志目录数量：$(@($ResolvedLogDirs).Count)
Web 访问 IP 数量：$(@($WebIpStats).Count)
Web 可疑请求数量：$(@($SuspiciousWebRequests).Count)
WebShell 访问记录数量：$(@($WebShellAccessRecords).Count)

五、挖矿 IOC
挖矿 IOC 数量：$(@($MiningIocResults).Count)

六、重点关注项
重点关注项数量：$(@($FocusItems).Count)

七、建议优先查看文件
1. 重点关注项.csv
2. 疑似WebShell文件.csv
3. 疑似Shell密码或连接参数.csv
4. WebShell访问记录.csv
5. Web访问IP统计.csv
6. Web可疑请求.csv
7. 隐藏账户检查.csv
8. 挖矿IOC提取.csv

八、说明
本工具只能做自动化辅助筛查，不能保证直接命中全部入侵答案。
对于 Web1 这类 Web 应急题，建议结合 WebShell 文件、Web 日志、隐藏账户和挖矿 IOC 进行人工复核。
"@

$Summary | Out-File "$OutputDir\采集摘要.txt" -Encoding UTF8

Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host "[+] 信息采集完成！" -ForegroundColor Green
Write-Host "[+] 登录成功日志数量：$(@($SuccessLogons).Count)" -ForegroundColor Green
Write-Host "[+] 登录失败日志数量：$(@($FailedLogons).Count)" -ForegroundColor Green
Write-Host "[+] 隐藏或可疑账户数量：$(@($HiddenAccountResults).Count)" -ForegroundColor Green
Write-Host "[+] 疑似 WebShell 文件数量：$(@($SuspiciousWebFiles).Count)" -ForegroundColor Green
Write-Host "[+] 疑似 Shell 密码或连接参数数量：$(@($ShellParamCandidates).Count)" -ForegroundColor Green
Write-Host "[+] Web 可疑请求数量：$(@($SuspiciousWebRequests).Count)" -ForegroundColor Green
Write-Host "[+] WebShell 访问记录数量：$(@($WebShellAccessRecords).Count)" -ForegroundColor Green
Write-Host "[+] 挖矿 IOC 数量：$(@($MiningIocResults).Count)" -ForegroundColor Green
Write-Host "[+] 重点关注项数量：$(@($FocusItems).Count)" -ForegroundColor Green
Write-Host "[+] 结果目录：$OutputDir" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
