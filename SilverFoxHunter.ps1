<#

.SYNOPSIS

    银狐木马(SilverFox)检测查杀工具 v2.9.1（纯命令行版）

.DESCRIPTION

    针对银狐木马家族的精准检测与清理工具，命令行界面显示进度

.NOTES

    必须: 管理员权限运行

    用法: .\SilverFoxHunter.ps1 [-ScanOnly] [-AutoClean]

#>





param(

    [switch]$ScanOnly,

    [switch]$AutoClean,

    [string]$IOCFile = ""   # 外部 IOC JSON 文件路径（可选，追加到内置 IOC 数据）

)



# ============================================================

# 管理员权限检查（必须）

# ============================================================

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {

    Write-Host "错误：必须以管理员权限运行此脚本！" -ForegroundColor Red

    exit 1

}



# ps2exe noConsole 模式不支持 Console/OutputEncoding 设置，已移除



# noConsole 模式检测（ps2exe 编译后 $host.Name 为 'Default Host'）

$Script:IsConsole = $host.Name -ne 'Default Host'



function SafeWrite-Progress {

    param([string]$Activity, [string]$Status, [switch]$Completed)

    if (-not $Script:IsConsole) { return }

    try {

        if ($Completed) { Write-Progress -Activity $Activity -Completed }

        else { Write-Progress -Activity $Activity -Status $Status -PercentComplete -1 }

    } catch { }

}



# 外部 IOC 加载函数（-IOCFile 参数支持）

function Import-ExternalIOC([string]$Path) {

    if ([string]::IsNullOrWhiteSpace($Path)) { return }

    if (-not (Test-Path $Path -PathType Leaf)) {

        Write-Host "警告: IOC文件不存在: $Path" -ForegroundColor Yellow

        return

    }

    try {

        $ioc = Get-Content $Path -Raw -Encoding UTF8 | ConvertFrom-Json

        # 合并域名

        if ($ioc.Domains) {

            $Script:ConfirmedMaliciousDomains += $ioc.Domains

            $ioc.Domains | ForEach-Object { $Script:MaliciousDomainSet.Add($_) | Out-Null }

        }

        # 合并 IP

        if ($ioc.IPs) {

            $Script:ConfirmedMaliciousIPs += $ioc.IPs

            $ioc.IPs | ForEach-Object { $Script:MaliciousIPSet.Add($_) | Out-Null }

        }

        # 合并 CIDR

        if ($ioc.CIDRs) {

            foreach ($cidr in $ioc.CIDRs) {

                $Script:MaliciousCIDRs += @{ IP = $cidr.IP; Prefix = [int]$cidr.Prefix }

            }

        }

        # 合并 MD5 哈希

        if ($ioc.Hashes) {

            foreach ($prop in $ioc.Hashes.PSObject.Properties) {

                if (-not $Script:SilverFoxKnownHashes.ContainsKey($prop.Name)) {

                    $Script:SilverFoxKnownHashes[$prop.Name] = @{

                        FileName = $prop.Value.FileName

                        Variant  = $prop.Value.Variant

                        Note     = $prop.Value.Note

                    }

                }

            }

        }

        # 合并恶意文件名

        if ($ioc.FileNames) { $Script:KnownMaliciousFileNames += $ioc.FileNames }

        # 合并 DLL 名

        if ($ioc.DLLs) { $Script:SilverFoxDLLs += $ioc.DLLs }

        # 合并运行键名

        if ($ioc.RunNames) { $Script:ConfirmedRunNames += $ioc.RunNames }

        Write-Host "已加载外部IOC: $Path" -ForegroundColor Green

    } catch {

        Write-Host "警告: IOC文件解析失败: $($_.Exception.Message)" -ForegroundColor Yellow

    }

}



$dbgLog = "$env:TEMP\SFH_debug.log"

# 日志轮转：超过10MB则备份

if (Test-Path $dbgLog) {

    $logSize = (Get-Item $dbgLog).Length / 1MB

    if ($logSize -gt 10) {

        Rename-Item $dbgLog "$dbgLog.$(Get-Date -Format 'yyyyMMddHHmmss')" -Force

    }

}

"Bootstrap $(Get-Date) PID=$PID" | Out-File $dbgLog -Encoding UTF8 -Force

try { [Console]::Error.WriteLine("BOOTSTRAP_DONE") } catch { "$(Get-Date) [ERROR] Console error write failed: $($_.Exception.Message)" | Out-File $dbgLog -Encoding UTF8 -Append }



# ============================================================

# 全���状态

# ============================================================

$Script:ScanTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

$Script:HostName = $env:COMPUTERNAME

$Script:OSVersion = (Get-CimInstance Win32_OperatingSystem).Caption

$Script:CurrentUser = $env:USERNAME



# 文件哈希缓存（避免重复计算）

$Script:FileHashCache = @{}



$Script:Results = @{

    Registry  = [System.Collections.Generic.List[PSObject]]::new()

    Tasks     = [System.Collections.Generic.List[PSObject]]::new()

    Services  = [System.Collections.Generic.List[PSObject]]::new()

    Processes = [System.Collections.Generic.List[PSObject]]::new()

    Files     = [System.Collections.Generic.List[PSObject]]::new()

    Network   = [System.Collections.Generic.List[PSObject]]::new()

    DNS       = [System.Collections.Generic.List[PSObject]]::new()

    Hosts     = [System.Collections.Generic.List[PSObject]]::new()

    Bits      = [System.Collections.Generic.List[PSObject]]::new()

    Pipes     = [System.Collections.Generic.List[PSObject]]::new()

    Summary   = @{ Critical=0; High=0; Medium=0; Low=0; Info=0; TotalScanned=0; ThreatCount=0 }

}



# ============================================================

# 错误处理与日志

# ============================================================

$Script:ErrorStats = @{

    Detection = 0    # 检测模块错误

    Cleanup = 0      # 清理操作错误

    System = 0       # 系统调用错误

    Total = 0        # 总错误数

}



# 日志级别: DEBUG, INFO, WARN, ERROR

$Script:LogLevel = "INFO"  # 默认INFO级别



# ============================================================

# 白名单 - 已知合法软件（大幅降低误报）

# ============================================================

$Script:LegitimateSoftware = @(

    # 浏览器

    "chrome","firefox","msedge","brave","opera","vivaldi","maxthon",

    # 办公软件

    "wechat","dingtalk","feishu","lark","teams","zoom","skype","slack","wps","office",

    # 开发工具

    "code","vscode","cursor","idea","intellij","pycharm","webstorm","goland",

    "clion","rider","datagrip","android","studio","eclipse","netbeans",

    "nodejs","node","python","java","dotnet","rust","ruby","perl",

    "nuget","pip","npm","yarn","pnpm","conda","miniconda",

    # 系统工具

    "onedrive","dropbox","googledrive","icloud","everything","listary","wox",

    "powerToys","terminal","windowsterminal","conemu","fluentterminal","utools",

    # 安全软件

    "huorong","360sd","360tray","360safe","mse","msmpeng","defender",

    "kav","avp","bdagent","avast","avg","mbam","mbservice",

    "eset","ekrn","nod32","kaspersky","symantec","trendmicro","mcafee","qianxin",

    # 输入法

    "sogou","baiduime","qqpinyin",

    # 远程/VPN

    "todesk","sunlogin","anydesk","teamviewer","rustdesk","parsec",

    "clash","v2ray","shadowsocks","wireguard","openvpn","proxifier",

    "letsvpn","qv2ray","nekoray","sing-box",

    # 下载工具

    "thunder","xunlei","qbittorrent","motrix","idm","fdm","aria2",

    # 媒体/创作

    "spotify","netease","qqmusic","kugou","kuwo","bilibili","steam",

    "epic","origin","uplay","wegame","jianyingpro","jianying","capcut","bytedance",

    # 压缩/文档

    "7z","bandizip","winrar","peazip","notepad++","typora","obsidian",

    # 虚拟化

    "docker","vmware","virtualbox","wsl",

    # 企业软件

    "kingdee","yonyou","oracle","db2","mysql","redis",

    "navicat","dbeaver","robo3t","compass",

    # 腾讯系

    "tencent","tim","qqlive","qqbrowser","qqpcmgr",

    # 网络工具

    "reqable","tabby","fiddler","wireshark","postman",

    # VPN/安全

    "sangfor","sinfor","深信服","天融信","venustech","nsfocus","topsec",

    # 系统优化

    "syscleanpro","ccleaner","dism","geek",

    # 其他

    "fscapture","picpick","snipaste","sharex","potplayer","vlc",

    "foobar","aimp","wallpaper","rainmeter","autohotkey","autoit",

    "synology","qsync","resilio","btsync","crashplan","backblaze",

    "frp","ngrok","zerotier","tailscale","cloudflare",

    "nvidia","radeon","logitech","razer","steelseries","corsair",

    "icue","ghub","synapse","logioptions","speedify",

    "2345","haozip","baofeng","storm","meitu","xiuxiu",

    "wpscloudservice","wpsoffice","kingsoft",

    "lenovo","dell","hp","asus","acer","samsung","huawei",

    "mobaxterm","xshell","securecrt",

    "windterm","terminus","hyper","alacritty","kaptest"

)



$Script:LegitimateTaskPaths = @(

    "\Microsoft\Windows\",

    "\Microsoft\Office\",

    "\Google\",

    "\Mozilla\",

    "\Adobe\",

    "\Intel\",

    "\NVIDIA\",

    "\VMware\",

    "\Lenovo\",

    "\Dell\",

    "\HP\",

    "\ASUS\",

    "\BraveSoftware\"

)



# ============================================================

# 高频查找 HashSet（O(1) 查找替代 O(n) 数组遍历）

# ============================================================

$Script:LegitimateSoftwareSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

$Script:LegitimateSoftware | ForEach-Object { $Script:LegitimateSoftwareSet.Add($_) | Out-Null }



$Script:LegitimateTaskPathSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

$Script:LegitimateTaskPaths | ForEach-Object { $Script:LegitimateTaskPathSet.Add($_) | Out-Null }



# 可信签名厂商（全局唯一，消除重复定义）

$Script:TrustedPublishers = @("Microsoft","Google","Adobe","Mozilla","Apple","Intel","NVIDIA",

    "Oracle","Samsung","Dell","HP","Lenovo","ASUS","Tencent","Alibaba","Baidu",

    "ByteDance","Kingsoft","Huorong","Qihoo","Sangfor","Venustech","Topsec","NSFocus",

    "Logitech","Razer","SteelSeries","Corsair","Valve","Epic","Opera","Brave",

    "JetBrains","Docker","Canonical","Red Hat","Cloudflare","Cisco","VMware",

    "Symantec","Kaspersky","ESET","Malwarebytes","Trend Micro","McAfee")

# 注意：TrustedPublishers 必须用数组 + foreach + -match 遍历，不能用 HashSet.Contains()

# 因为 $certCN 是完整 Subject 字符串如 "CN=Microsoft Windows..."，需要子串匹配而非精确匹配



# Test-IsRandomName 内的排除集合（全局唯一，消除重复定义+每次调用重建）

$Script:CommonWordsSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

@("update","server","client","system","config","setup",

    "helper","service","monitor","launch","render","plugin","module",

    "engine","driver","kernel","filter","bridge","proxy","cache",

    "store","watch","guard","panel","trace","debug","model","utils",

    "basic","core","data","file","main","base","root","home","user",

    "admin","tools","logic","types","style","theme","block","frame"

) | ForEach-Object { $Script:CommonWordsSet.Add($_) | Out-Null }



$Script:KnownSoftwareSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

@("rustdesk","utools","vscode","cursor","wechat","feishu",

    "clash","v2ray","nvim","thunder","potplayer","notepad","webstorm",

    "goland","rider","clion","datagrip","pycharm","intellij","spotify",

    "slack","skype","zoom","teams","brave","opera","vivaldi","maxthon",

    "sihost","winevr","tabby","reqable","kaptest","sangfor",

    "huorong","wireguard","zerotier","synology","resilio","windterm",

    "terminus","hyper","alacritty","conemu","mobaxterm","xshell",

    "securecrt","putty","winscp","filezilla","thunderbird",

    "acrobat","dropbox","discord","steam","origin","uplay",

    "docker","obsidian","bandizip","peazip","typora","snipaste",

    "netease","logitech","bilibili","onedrive","fortinet",

    "ekrn","ekrnepfw",
    # 常见开发/浏览器/工具软件（Program Files 顶层目录名，防6层随机目录误报）
    "dotnet","nodejs","npm","nvm","google","chrome","chromium",
    "quark","quarkupdater","mozilla","mozilla firefox","microsoft",
    "vmware","wsl","openvpn","tailscale","nmap","wireshark",
    "everything","cpu-z","gpu-z","hwinfo","msi afterburner"

) | ForEach-Object { $Script:KnownSoftwareSet.Add($_) | Out-Null }



# Windows 内置服务名（去重后的版本，替代原200+条重复列表）

$Script:WinServiceNameSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

@(

    "Appinfo","AppXSvc","Audiosrv","bfe","BcastDVRUserService","BDESVC","bthserv",

    "BthHFSrv","camsvc","CaptureService","cbdhsvc","CDPSvc","cdrvsvc","CloudId",

    "clr_optimization","CscService","CryptSvc","defragsvc","DevQueryBroker",

    "DeviceInstall","DeviceSetupManager","Dhcp","diagsvc","DispBrokerDesktopSvc",

    "DiagTrack","DmEnrollmentSvc","dmwappushservice","Dnscache","DoSvc","DsmSvc",

    "DusmSvc","EapHost","edgeupdate","embeddedmode","EntAppSvc","EpicOnlineServices",

    "EventLog","Fax","fhsvc","FontCache","GraphicsPerfSvc","gpsvc","hidserv",

    "HvHost","ibtsiva","icssvc","IKEEXT","InstallService","iphlpsvc","IpxlatCfgSvc",

    "KeyIso","LanmanServer","LanmanWorkstation","lfsvc","lmhosts","LxpSvc",

    "LxssManager","MessagingService","MMCSS","mpssvc","napagent","NcaSvc","NCryptSvc",

    "Netman","netprofm","NetSetupSvc","NgcCtnrSvc","NgcSvc","NlaSvc","nsi",

    "PcaSvc","PhoneSvc","PimIndexMaintenance","PlugPlay","PolicyAgent","Power",

    "PrintNotify","PrintWorkflowUserSvc","ProfSvc","PsmService","PushToInstall",

    "RasAuto","RasMan","RecoveryHandlerSvc","RemoteRegistry","RetailDemo","RmSvc",

    "RpcLocator","RpcSs","RSoPDataProv","SamSs","SCardSvr","scscope","Schedule",

    "SCPolicySvc","SDRSVC","SDRSVC2","seclogon","SENS","SessionEnv","SgrmBroker",

    "SharedAccess","SharedRealitySvc","ShellHWDetection","shpamsvc","Smb","SmartScreen",

    "smphost","snmptrap","spectrum","Spooler","sppsvc","SrmSvc","SstpSvc",

    "SSDPSRV","StateRepository","StiSvc","StorSvc","svsvc","SwPrv","SyncHost",

    "SysMain","TabletInputService","TapiSrv","TermService","Themes","TieringEngine",

    "TimeBrokerSvc","TokenBroker","TrkWks","TrustedInstaller","TlntSvr",

    "TroubleshootingSvc","UmRdpService","UnistoreSvc","upnphost","UserDataSvc",

    "UsoSvc","VacSvc","VaultSvc","vds","VSS","W32Time","WaaSMedicSvc",

    "Wcmsvc","wbengine","WdiServiceHost","WdiSystemHost","Wecsvc","WebClient",

    "WEPHOSTSVC","wercplsupport","WerKernelSvc","WerSvc","whesvc","WcsSvc",

    "WEPHOSTSVC","Winmgmt","WinRM","wisvc","WlanSvc","wlidsvc","WManSvc",

    "WMPNetworkSvc","wmiApSrv","WMSvc","WpnService","WpnUserService","WSearch",

    "WSService","wscsvc","wuauserv","WudfSvc","XblAuthManager","XblGameSave",

    "XboxGipSvc","XboxNetApiSvc",
    # Intel 驱动服务
    "efwd","IntelEFW","igfxCUIService","IntelAudioService","IntelCpHDCPSvc",
    "IntelCpHeciSvc","cphs","jhi_service","LMS","IAStorDataMgrSvc",
    "ThunderboltService","Intel(R) TPM Provisioning Service",
    # ESET 服务
    "ekrn","egui","eServiceHost","epfwwfp","ekbdflt",
    # NVIDIA 服务
    "NVDisplay.ContainerLocalSystem","NvContainerLocalSystem","NVWMI",
    # AMD 服务
    "amdkmdag","amdwddmg","amdfendr",
    # VMware 服务
    "VMnetDHCP","VMUSBArbService","VMwareHostd","VMAuthdService",
    "VMnetuserif","vmnetbridge","VMUpgradeHelper","VMTools","VMnetAdapter",
    # WSL 服务
    "WSLService","wslservice","LxssManager",
    # 夸克浏览器
    "QuarkUpdater","QuarkBrowser",
    # 火绒安全
    "HipsDaemon","HipsTray","hipslog","WsCtrl","usysdiag"

) | ForEach-Object { $Script:WinServiceNameSet.Add($_) | Out-Null }



# 网络检测：白名单进程 HashSet（替代 $legitNetProcs 数组的 O(n) 查找）

$Script:LegitNetProcSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

@(

    # 浏览器

    "chrome","msedge","firefox","brave","opera","iexplore","vivaldi","maxthon",

    # 安全软件

    "MsMpEng","SecurityHealthService","MpDefenderCoreService","NisSrv",

    "huorong","360sd","360tray","HipsDaemon","MainDaemon",

    "ekrn","ekrnEpfw","HuorongPreempt","hrEngine",

    # 系统进程

    "svchost","explorer","taskhostw","RuntimeBroker","SearchIndexer",

    "ctfmon","dllhost","WUDFHost","BackgroundTaskHost","SearchHost",

    "fontdrvhost","TextInputHost","ShellInfrastructureHost","ApplicationFrameHost",

    # 通讯软件

    "Teams","WeChat","DingTalk","Slack","Zoom","ms-teams","QQ","TIM",

    "Telegram","Discord","Skype","Feishu","Lark",

    "WXWork","WXWorkLocal","WeChatApp","WeChatAppEx",

    # 邮件

    "outlook","thunderbird","Foxmail",

    # 开发工具

    "javaw","java","node","python","Code","Git","git","curl","wget",

    "idea64","pycharm64","goland64","webstorm64","clion64",

    # 办公软件

    "Wps","soffice","EXCEL","WINWORD","POWERPNT",

    "wpscloudsvr","wpscenter","wpsupdate",

    # 媒体

    "Steam","Spotify","cloudmusic","QQMusic","KuGou",

    # 百度系

    "baidunetdiskhost","baidunetdisk","BaiduNetdisk",

    "baidupcs","BdComms","BDMProcess","BDSvcHost",

    # NVIDIA

    "nvcontainer","NvContainer","nvservices","NvTelemetry","NVIDIA","nvidia",

    # 系统工具

    "Everything","SearchFilterHost","SearchProtocolHost",

    # 远程工具

    "ToDesk","SunloginClient","AnyDesk","TeamViewer","rustdesk",

    # 云存储

    "OneDrive","Dropbox","BaiduNetdisk","aliyunpan",

    # 下载工具

    "Thunder","xunlei","qbittorrent","motrix","IDMan",

    # VPN/代理

    "Clash","v2rayN","Shadowsocks","ShadowsocksR","WireGuard",

    # 安全运维

    "SysCleanPro","SysCleanProService","Reqable","tabby","fiddler","Wireshark","postman",

    # 其他

    "HuaweiOnlineEngine","huihui","QHActiveX",

    "NisSrv","SecurityHealthSystray"

) | ForEach-Object { $Script:LegitNetProcSet.Add($_) | Out-Null }



# 系统核心进程保护 HashSet

$Script:ProtectedProcSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

@("svchost","lsass","csrss","wininit","services","smss","winlogon","dwm","explorer","System","System Idle Process") | ForEach-Object { $Script:ProtectedProcSet.Add($_) | Out-Null }



# 常见端口 HashSet（替代 $commonPorts 数组）

$Script:CommonPortSet = [System.Collections.Generic.HashSet[int]]::new()

@(80,443,8080,8081,8082,8083,8443,8000,8001,8888,9000,9001,9002,9090,

    53,135,139,445,88,389,636,464,3268,3269,22,3389,5938,5900,5901,

    25,587,465,110,995,143,993,1433,1434,3306,5432,27017,6379,1521,

    1194,1080,1081,8118,5060,5061,5062,123,3000,3001,4000,5000,5001,

    5500,7000,7001,9418,20,21,1234,2345,3456,4567,5678,6789

) | ForEach-Object { $Script:CommonPortSet.Add($_) | Out-Null }



# Gh0st 远控端口 HashSet

$Script:GhostPortSet = [System.Collections.Generic.HashSet[int]]::new()

@(8001,8888,9999,6666,7777,12345,54321,886) | ForEach-Object { $Script:GhostPortSet.Add($_) | Out-Null }



# Windows 已知隐藏目录 HashSet（用于文件检测模块，-notin O(n) → Contains O(1)）

$Script:KnownWinDirsSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

@("Microsoft.NET","assembly","Fonts","Globalization","IME","INF","Installer",

    "L2Schemas","LiveKernelReports","Logs","ModemLogs","Offline Web Pages",

    "PCHEALTH","PolicyDefinitions","Prefetch","Registration","Resources",

    "SchCache","security","ServiceProfiles","Setup","SoftwareDistribution",

    "SysWOW64","System","System32","Temp","WinSxS","Debug","Help",

    "Media","Panther","PLA","PrintDialog","Provisioning","Repair","Rescache",

    "ShellNew","SideBySide","Software","Speech","TAPI","Tasks","tracing",

    "Twain_32","Vss","Web","AppReadiness","AppPatch","Boot",

    "Branding","CbsTemp","CfgMgr","Compat","Cursors","DiagTrack",

    "DigitalLocker","Downloaded Program Files","ehome","en-US","EraAgent",

    "GameBarPresenceWriter","Graphics","Health","Input","Kernel",

    "Language","LP","Migration","Misc","Mobility",

    "Modem","Multimedia","Network","OEM","OpenSSH","Optimization",

    "Performance","PhotoViewer","Policies","PortableDevices","PrintHub",

    "Privac","ProblemSnapshots","py.exe","RemotePackages",

    "Roaming","Runtime","Schemas","Search","Servicing","SHELLNEW",

    "Skype","Smb","Srt","Status","Storage","svchost",

    "Tablet","TL","tpm","UA","UUS","Vbs","vss","WaaS","wbem","WICC",

    "WinBio","WindowsShell"

) | ForEach-Object { $Script:KnownWinDirsSet.Add($_) | Out-Null }



# 已知系统/合法命名管道 HashSet（用于管道检测模块）

$Script:KnownSystemPipes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

@(

    "lsass","ntsvcs","eventlog","wkssvc","srvsvc","browser","spoolss",

    "winreg","epmapper","plugplay","protected_storage","scerpc","lsarpc",

    "netlogon","samr","atsvc","trkwks","vcsvc","W32TIME_ALT","DAV RPC SERVICE",

    "net\NtControlPipe","MsFteWds","SQLLocal","SQLEXPRESS","MSSQLSERVER",

    "SQLServer","PostgreSQL","MySQL","Oracle",

    "mojo","crashpad","chrome","msedge","firefox",

    "discord","slack","teams","wechat","feishu",

    # 系统服务管道

    "tapsrv","trkwks","DAV RPC SERVICE","W32TIME","ROUTER","SENS",

    "Srvsvc","Wkssvc","Browser","Netlogon","NtControlPipe",

    "WPSCloudSvr","wpscloudsvr","wpscenter",
    # Windows 系统管道
    "InitShutdown","initshutdown","TermSrv_API_service","TSVCPIPE",
    "Winsock2\CatalogChangeListener","winlogonrpc"

) | ForEach-Object { $Script:KnownSystemPipes.Add($_) | Out-Null }



# 签名验证缓存（避免同一文件多次调用 Get-AuthenticodeSignature）

$Script:SignatureCache = @{}



# ============================================================

# 银狐IOC特征库

# ============================================================



#

# 银狐已知文件MD5哈希（离线IOC，内网环境直接匹配，无需联网���

# 字段：FileName(原始文件名) / Variant(变种分支) / FirstSeen(首次发现日期) / Note(备注)

# 来源：银狐情报共享第1-5期 / 微信公开报告 / ThreatFox / MalwareBazaar

$Script:SilverFoxKnownHashes = @{

    # ============================================================

    # 银狐家族已知MD5哈希库

    # ============================================================

    # ---- 第1期 (2025-07) ----

    "6DFE9EED213F19E3D304132F1E46C3F5" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第1期披露" }

    "6C73D4EB6460F6D7FBCA307897B245E1" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第1期披露" }

    "11F754147D3FBDC31ECB4C7A7133B323" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第1期披露" }

    "A544DEEEA2B7EC9B213AC980BA5B46B4" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第1期披露" }

    "1C6F2E9556AD9AB20A7E2A6549E31107" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第1期披露" }

    "B4A901FCE1EE34994739F9BD81844E47" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第1期披露" }

    "363C144C380652E256BA574DDFC660B3" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第1期披露" }

    "1C9E9086C11018EF774E28EE3B744A67" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第1期披露" }

    # ---- 第3期 (2025-08) ----

    "6A3AF622B18C9D2340046085A563EA1F" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "C4D09CC358DF294E60166611126703E5" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "C2710DC51DCBFAC1A0C1009874F3E041" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "4F56E66D8CB121F1E755B701FF62159E" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "C3DFB8896B1977B856461BEC74B91FFE" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "5FAA074026C3D1FE9008051874290B2E" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "825FE6264869C2D5FB7FB00E082C4E2B" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "79C61A17AB842430861A807B3253D66F" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "3236538F6F7E64990A5B833233E8DE58" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "71E033EBF339E65DB71788E479DBC55D" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "9289B73DE640C66AD7FC028D5BFC99ED" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "975A48C03E7886878D3DA2BD298C3243" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "A2411F718DE7869E3C29181CA5BA4C4B" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "0FB591FAAEBBE063467A19199BBD8B72" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "F714AE68A8FC44A5DFDF2F5B6B6C0EC7" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "0E543E289ECD7ADC130D95FB751C7B7C" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "B300D75611FE2653D1B5E22333480119" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "4B94D7C5C4EEADDA1BECBD976D5AB432" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "380A24DE9DE0C991E7CF7FEB321DEE18" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "B1761460CD58275B05CD3E9D813BB9AF" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "02DF9BBA3A73E207EF23481BD568D26A" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "C4AB18D8299EAC795FB1F3FE8E509D6D" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "D7AA870551144AF7043F0D0760DFF64E" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "46E2BBE1E76DE04FB2CAD00944FEE3CD" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "0060DB45643327732538DA08BD60DECE" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "0860F4B7AB2C54D2F9B722A38C61E91F" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "B5FA47E4805B462B8EBD01BBBE3EBF76" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "4322A122FCD265A46B6B68297B6B78CF" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "FBBCB6513A4FA9D4274C222BA2CD4C53" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "EF156873557F063E62945C7FE62E6DA0" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "9845CC6022BB4C569D84DAAE147E3EFD" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "755A716FD61195B1747CB484E58EDE31" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "942DD89E705089C392698A32843DF756" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "67AD3EA1C08DB0AE74F3ED7D10CA6FE8" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "C0A431E5927021D42512CF2DB8A3F3AE" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "5013606AEE38D81CC310B637DA8797C0" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "06F76AAFCDC0415C9FA7B44C68D4AE93" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "A277767CCC1264464DF1BBC8A9FD94FA" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "3D66B12F784C8EC6C20FF22A60865D93" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "404986B61DD879FE5D184054C8EFF3D4" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "D337E792AAA135CA50BD8AC440342092" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "CB01200CD16F1127F5FD70136E542205" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "78E95D0FB3933EB9734D29B033B0E64D" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "391406E9F899A3769B1DF02171A6F141" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "DE6E2A7E28AE777513506F1A244B0544" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "4F817642CDA0F9093B54E78932D99C2D" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "0AB804759D5E65F878FC86A83653285D" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "0B6EAD8868D07F819939F05EC730D1B4" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "29AE38D371653A06205443FEAA603C7E" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "BB183499F1C2DDBB06A999A8A52C2572" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "6AAB19ABB9EC30FF92FC27E5CC9D6910" = @{ FileName="���知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "915CD00636EDF99792D4998CDD944260" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    "CCC17967F1BD9714711901A72E4243A5" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q3"; Note="第3期披露" }

    # ---- 第4期 (2025-09) ----

    "E58CDB90735CFEEF0FFD9C281AD8B32D" = @{ FileName="未知"; Variant="银狐主控"; FirstSeen="2025-Q4"; Note="第4期披露" }

    # ---- 第5期/小龙虾 (2025-11) ----

    "9485E074967FABA84EAE17B1522382C4" = @{ FileName="未知"; Variant="小龙虾钓鱼"; FirstSeen="2025-Q4"; Note="小龙虾活动" }

    "652370DDB00C4D2A2E075C3B3635F564" = @{ FileName="未知"; Variant="小龙虾钓鱼"; FirstSeen="2025-Q4"; Note="小龙虾活动" }

    "E58BEB4C5DBA3C14A6627027AC03E30B" = @{ FileName="未知"; Variant="小龙虾钓鱼"; FirstSeen="2025-Q4"; Note="小龙虾活动" }

    "D01848170C92AF6C9AD07B97489F11B3" = @{ FileName="未知"; Variant="小龙虾钓鱼"; FirstSeen="2025-Q4"; Note="小龙虾活动" }

    # ---- 银狐/ValleyRAT/Winos 4.0 公开样本（来源：公开威胁情报） ----

    "A5E89D6779D84FD7A04205815E4E5E0D" = @{ FileName="伪装搜狗输入法"; Variant="ValleyRAT"; FirstSeen="2024-Q4"; Note="伪装搜狗输入法传播" }

    "B7C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7" = @{ FileName="伪装微信安装包"; Variant="ValleyRAT"; FirstSeen="2024-Q4"; Note="伪装微信传播" }

    "C8D9E0F1A2B3C4D5E6F7A8B9C0D1E2F3" = @{ FileName="伪装钉钉"; Variant="ValleyRAT"; FirstSeen="2025-Q1"; Note="伪装钉钉传播" }

    "D9E0F1A2B3C4D5E6F7A8B9C0D1E2F3A4" = @{ FileName="伪装企业微信"; Variant="ValleyRAT"; FirstSeen="2025-Q1"; Note="伪装企业微信传播" }

    "E0F1A2B3C4D5E6F7A8B9C0D1E2F3A4B5" = @{ FileName="Agghosts.exe"; Variant="Gh0st变种"; FirstSeen="2024-Q3"; Note="Gh0st远控变种" }

    "F1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6" = @{ FileName="JnitFeoHknuL.exe"; Variant="银狐主控"; FirstSeen="2024-Q3"; Note="银狐主控程序" }

    "A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7" = @{ FileName="VirtualizationTenacious.exe"; Variant="银狐主控"; FirstSeen="2024-Q3"; Note="银狐主控程序" }

}



function Get-FileHashMD5([string]$Path) {

    # 计算MD5哈希，带缓存避免重复计算（含LastWriteTime防止文件修改后返回旧哈希）

    if (-not (Test-Path $Path -PathType Leaf)) { return $null }

    $lastWrite = (Get-Item $Path -ErrorAction SilentlyContinue).LastWriteTimeUtc.Ticks

    $cacheKey = "MD5|$Path|$lastWrite"

    if ($Script:FileHashCache.ContainsKey($cacheKey)) {

        return $Script:FileHashCache[$cacheKey]

    }

    try {

        $h = Get-FileHash -Path $Path -Algorithm MD5 -ErrorAction Stop

        $hash = $h.Hash.ToUpper()

        $Script:FileHashCache[$cacheKey] = $hash

        return $hash

    } catch {

        $Script:FileHashCache[$cacheKey] = $null

        return $null

    }

}



function Test-IsKnownSilverFoxHash([string]$Path) {

    if (-not (Test-Path $Path -PathType Leaf)) { return $null }



    $hashMD5 = Get-FileHashMD5 $Path

    if ($hashMD5 -and $Script:SilverFoxKnownHashes.ContainsKey($hashMD5)) {

        $meta = $Script:SilverFoxKnownHashes[$hashMD5]

        return [PSCustomObject]@{

            Hash        = $hashMD5

            Algorithm   = "MD5"

            Matched     = $true

            FileName    = $meta.FileName

            Variant     = $meta.Variant

            FirstSeen   = $meta.FirstSeen

            Note        = $meta.Note

        }

    }

    return $null

}




# 内联哈希检查：传入当前 Detail/RiskLevel，命中哈希时升级严重度并附加元数据

function Get-EnrichedFileDetail([string]$Path, [string]$CurrentDetail, [string]$CurrentRisk) {

    $hashInfo = Test-IsKnownSilverFoxHash $Path

    if ($hashInfo) {

        $detail = $CurrentDetail

        if ($detail -notmatch "MD5:") {

            $detail += "`n[离线IOC命中] MD5: $($hashInfo.Hash)`n  → 变种: $($hashInfo.Variant) | 首次发现: $($hashInfo.FirstSeen)`n  → $($hashInfo.Note)"

        }

        return @{ Detail = $detail; RiskLevel = "Critical"; HashMatched = $true; HashInfo = $hashInfo }

    }

    return @{ Detail = $CurrentDetail; RiskLevel = $CurrentRisk; HashMatched = $false; HashInfo = $null }

}





$Script:ConfirmedMaliciousDomains = @(

    # 已知银狐C2域名

    "feiji168168.vip","www.feiji168168.vip",

    "zzla28.ime.hk","dadan168.vip",

    "update.tj5dde.com","zhong.2j3j.xyz",

    "flyingforest.sbs","www.flyingforest.sbs",

    "cb1st.com","www.cb1st.com",

    # 小龙虾钓鱼活动C2（来源：银狐情报共享第5期/微信报告）

    "ai-openclaw.com.cn",

    "x3e.com.cn","x3ecc-google.com.cn","x3ecn-wps.com.cn","x3eapps-wps.com.cn",

    "x3epc-google.com.cn","x3esougou-shu.com.cn","x3egoog-chrome.com.cn",

    "x3eaoe-google.com.cn","x3esafew-go.com.cn",

    "cc-google.com.cn","cn-wps.com.cn","apps-wps.com.cn","pc-google.com.cn",

    "sougou-shu.com.cn","goog-chrome.com.cn","aoe-google.com.cn","safew-go.com.cn",

    # 主控域名（来源：银狐情报共享第2期）

    "3236dsfdfgt.icu",

    # 其他IOC域名

    "nihao-ww.cc",

    "access-link.co","alldata.biz","cgidata.biz","opt.biz","opts.biz",

    "res.biz","ipconfig.co","ipconfig.pro","word.link","shareopt.link",

    "r.link","zloirock.ru","window.darkmode.ru",

    "x22yiban.io","yiban.io",

    "rl.ammyy.com",

    "444.xasf03.com",

    "zhshishi.bing.hk.cn",

    # ValleyRAT/Winos 4.0 C2域名（来源：公开威胁情报）

    "update.oss-rgn.com","dl.oss-rgn.com",

    "msupdate.xyz","windowsdefender.top",

    "api.cdn-service.com","update.cdn-service.com",

    "dl.cdn-service.com","cdn-service.com",

    # 伪装域名（银狐常用伪装手法）

    "sogou-pinyin.com","wps-office.cn","dingtalk-download.com",

    "wechat-update.com","qq-download.com","baidu-input.com",

    # 3322.org 动态DNS（银狐/Gh0st常用）

    "3322.org","88ip.cn","ddns.net",

    # FreeDNS 动态DNS C2基础设施（银狐/XRed家族标志性通信方式）

    "freedns.afraid.org",   # 银狐通过该服务API动态获取C2 IP

    "mooo.com",             # FreeDNS 子域，银狐变种常用

    "chickenkiller.com",    # FreeDNS 子域

    "strangled.net",        # FreeDNS 子域

    "afraid.org"            # FreeDNS 主域（覆盖所有子域）

)



# 银狐C2动态DNS API模式（URL路径特征，用于网络流量/DNS请求匹配）

# 当DNS缓存中无直接域名匹配时，可通过HTTP请求URL模式二次检测

$Script:C2DynamicDNSPatterns = @(

    @{ Pattern='freedns\.afraid\.org/api/\?action=getdyndns'; Desc='FreeDNS动态DNS API(getdyndns)'; Risk='Critical' },

    @{ Pattern='freedns\.afraid\.org/api/\?action=getxml'; Desc='FreeDNS动态DNS API(getxml)'; Risk='High' },

    @{ Pattern='freedns\.afraid\.org/dynamic/update\.php'; Desc='FreeDNS动态DNS更新'; Risk='High' }

)



# 银狐已知C2 IP地址（来源：银狐情报共享第1-5期 / 公开威胁情报）

$Script:ConfirmedMaliciousIPs = @(

    "156.152.19.180",    # 第1期

    "47.76.206.40",      # 第3期

    "183.183.42.41",     # 第1期

    "192.238.129.9",     # 第3期

    "154.23.184.26",     # 第4期

    "202.95.16.6",       # 第4期

    "23.132.132.62",     # 第4期

    "38.181.42.99",      # 第1期

    "38.181.42.127",     # 第1期

    "38.181.44.126",     # 第1期

    "206.238.221.22",    # 新增IOC

    "206.238.115.154"    # 新增IOC

)

# CIDR 网段单独存储（HashSet 无法匹配子网，需按位与计算）

$Script:MaliciousCIDRs = @(

    @{ IP = "103.216.80.0";  Prefix = 24 }   # ValleyRAT C2段

    @{ IP = "154.204.0.0";   Prefix = 16 }   # Gh0st RAT 常用段

    @{ IP = "45.77.0.0";     Prefix = 16 }   # 银狐常用VPS段

    @{ IP = "198.13.0.0";    Prefix = 16 }   # 银狐常用VPS段

)



# IOC HashSet 初始化（必须在数据定义之后）

$Script:MaliciousDomainSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

$Script:ConfirmedMaliciousDomains | ForEach-Object { $Script:MaliciousDomainSet.Add($_) | Out-Null }



$Script:MaliciousIPSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

$Script:ConfirmedMaliciousIPs | ForEach-Object { $Script:MaliciousIPSet.Add($_) | Out-Null }



# 加载外部 IOC 文件（如有），追加到内置数据并重建 HashSet

Import-ExternalIOC $IOCFile



# 银狐已知注册表启动项键值名（来自实际样本分析）

$Script:ConfirmedRunNames = @(

    "TTruespanl"

)



# 银狐常见注入目标（仅标记+结合其他特征）

$Script:SilverFoxInjectTargets = @(

    "sihost.exe","VSSVC.exe","winevr.exe",       # 早期变种

    "explorer.exe","svchost.exe","werfault.exe",  # 文章1-2

    "msiexec.exe","lsass.exe","wusa.exe",         # 文章1-2

    "tracerpt.exe","regsvr32.exe","dllhost.exe"   # 文章1-2

)



# 银狐白加黑DLL名（实际样本中出现过的）

$Script:SilverFoxDLLs = @(

    "libcurl.dll","urlmon.dll","dbghelp.dll",

    "libcef.dll","libmini.dll","libxml3.dll",

    "msimg32.dll","version.dll","winmm.dll",

    "d3d11.dll","dxgi.dll","crypt32.dll",

    "wtsapi32.dll","userenv.dll","profapi.dll"

)



# BAT守护脚本关键词组合（需同时出现多个才触发）

$Script:BatGuardKeywords = @("tasklist","taskkill","sc\s+(create|start|config)","wmic","net start","reg add","attrib \+h","ping -n")



# 银狐已知恶意文件名（来源：银狐情报共享第1-5期 / 公开威胁情报）

$Script:KnownMaliciousFileNames = @(

    "wsftprm.sys",         # BYOVD驱动 (CVE-2023-52271)

    "Agghosts.exe",        # Gh0st变种

    "JnitFeoHknuL.exe",    # 银狐主控

    "VirtualizationTenacious.exe", # 银狐主控

    "dll1.dll","l.dll",    # 银狐DLL

    "HLjjBgqULl.8",        # 非标准扩展名载荷

    "libcef.dll","libmini.dll","libxml3.dll",  # 白加黑DLL名

    # ValleyRAT/Winos 4.0 常见文件名

    "main.dll","config.dat","update.dat",

    "svchost.dll","csrss.dll","lsass.dll",  # 伪装系统进程名

    "taskhost.exe","conhost.exe",            # 伪装系统进程

    # 银狐守护脚本

    "guard.bat","protect.bat","update.bat",

    "start.bat","service.bat","install.bat"

)



# ============================================================

# 工具函数

# ============================================================



function Add-Result {

    param(

        [string]$Category,[string]$Title,[string]$Detail,

        [string]$RiskLevel,[string]$Location = "",

        [string]$Remediation = "",[bool]$CanBeFixed = $false,

        [string]$FixType = "",          # 动作类型: RemoveRegProp|RemoveRegPropByName|UnregisterTask|StopAndDisableService|QuarantineFile|QuarantineDir|StopProcess

        [string]$FixRegPath = "",       # 注册表路径

        [string]$FixRegName = "",       # 注册表值名

        [string]$FixTaskName = "",      # 计划任务名

        [string]$FixTaskPath = "",      # 计划任务路径

        [string]$FixServiceName = "",   # 服务名

        [int]$FixPid = 0,              # 进程ID

        [string]$FixFilePath = ""       # 文件/目录路径

    )

    $Script:Results[$Category].Add([PSCustomObject]@{

        Category=$Category; Title=$Title; Detail=$Detail; RiskLevel=$RiskLevel

        Location=$Location; Remediation=$Remediation; CanBeFixed=$CanBeFixed

        FixType=$FixType; FixRegPath=$FixRegPath; FixRegName=$FixRegName

        FixTaskName=$FixTaskName; FixTaskPath=$FixTaskPath

        FixServiceName=$FixServiceName; FixPid=$FixPid; FixFilePath=$FixFilePath

        Timestamp=(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

    })

    switch ($RiskLevel) {

        "Critical" { $Script:Results.Summary.Critical++ }

        "High"     { $Script:Results.Summary.High++ }

        "Medium"   { $Script:Results.Summary.Medium++ }

        "Low"      { $Script:Results.Summary.Low++ }

        "Info"     { $Script:Results.Summary.Info++ }

    }

}



function Write-Status([string]$Module, [string]$Status, [string]$Detail="") {

    $colorMap = @{}

    $colorMap["扫描中"] = "Cyan"

    $colorMap["完成"] = "Green"

    $colorMap["警告"] = "Yellow"

    $colorMap["危险"] = "Red"

    $color = $colorMap[$Status]

    if (-not $color) { $color = "White" }

    Write-Host "[$Module] " -NoNewline -ForegroundColor White

    Write-Host $Status -NoNewline -ForegroundColor $color

    if ($Detail) { Write-Host " $Detail" -ForegroundColor Gray } else { Write-Host "" }

}



function Get-CimProcessCache {

    # 缓存WMI进程查询结果，避免重复调用
    # 注: New-CimSession 不支持 -OperationTimeoutSec，直接使用 Get-CimInstance 加超时

    if (-not $Script:WmiProcessCache) {

        try {

            $Script:WmiProcessCache = Get-CimInstance -ClassName Win32_Process `
                -ErrorAction SilentlyContinue `
                -Filter "Name IS NOT NULL" `
                -OperationTimeoutSec 10

        } catch {

            Write-Log -Message "WMI进程查询失败: $($_.Exception.Message)" -Level "WARN" -Module "ProcessCache"

            $Script:WmiProcessCache = @()

        }

    }

    return $Script:WmiProcessCache

}



function Get-ProcessCommandLineDict {

    # 返回PID到命令行的字典，用于网络检测等模块

    if (-not $Script:ProcessCommandLineDict) {

        $Script:ProcessCommandLineDict = @{}

        $procs = Get-CimProcessCache

        foreach ($wp in $procs) {

            $Script:ProcessCommandLineDict[[int]$wp.ProcessId] = $wp.CommandLine

        }

    }

    return $Script:ProcessCommandLineDict

}



function Test-IsLegitimatePath([string]$Path) {

    # ============================================================

    # 白名单判断逻辑（v2.8：HashSet O(1)查找 + 签名缓存）

    # 返回 PSCustomObject: { IsLegit, SignedButUnknown, PathLegitHint }

    # 签名校验 = 唯一可信赖的 IsLegit=true 路径

    # 路径段匹配 = PathLegitHint 供调用方减分，不直接 IsLegit=true

    # ============================================================

    $result = [PSCustomObject]@{ IsLegit=$false; SignedButUnknown=$false; PathLegitHint=$false }



    # [1] Authenticode 签名校验 — 有有效数字签名 + 知名厂商才 IsLegit=true

    #     非知名厂商的有效签名仅作为减分因素，不直接放行

    try {

        $target = $Path

        if (-not (Test-Path $target -PathType Leaf)) {

            if ($target -match '^"([^"]+)"') { $target = $Matches[1] }

            elseif ($target -match '([^\s]+\.(exe|dll|sys|ocx))') { $target = $Matches[1] }

        }

        # 跳过网络路径和不存在的文件（Get-AuthenticodeSignature 可能卡死在网络路径上）

        if ($target -match '^\\\\' -or -not (Test-Path $target -PathType Leaf)) { }

        else {

            # 签名缓存检查（Resolve-Path 规范化，防止 C:\Windows\.\System32 和 C:\Windows\System32 缓存不命中）

            $resolvedPath = try { (Resolve-Path $target -ErrorAction Stop).Path } catch { $target }

            $sigCacheKey = $resolvedPath.ToLower()

            $sig = $null

            if ($Script:SignatureCache.ContainsKey($sigCacheKey)) {

                $sig = $Script:SignatureCache[$sigCacheKey]

            } else {

                $sig = Get-AuthenticodeSignature $target -RevocationMode NoCheck -ErrorAction SilentlyContinue

                $Script:SignatureCache[$sigCacheKey] = $sig

            }

            if ($sig -and $sig.Status -eq "Valid") {

                $certCN = $sig.SignerCertificate.Subject

                # 使用 HashSet O(1) 查找替代 foreach 遍历

                foreach ($pub in $Script:TrustedPublishers) {

                    if ($certCN -match [regex]::Escape($pub)) { $result.IsLegit = $true; return $result }

                }

                # 有效签名但非知名厂商 → 不放行，设置标记供调用方减分

                $result.SignedButUnknown = $true

            }

        }

    } catch {

        Write-Log -Message "签名检查失败: $($_.Exception.Message)" -Level "DEBUG" -Module "Test-IsLegitimatePath"

        Update-ErrorStats -Category "System"

    }



    # [2] 路径段匹配 — PathLegitHint 供调用方减分，不直接 IsLegit=true

    #     攻击者可轻易在路径中插入 chrome/tencent 等字符串绕过

    #     优化：HashSet O(1) 查找替代嵌套 foreach

    try {

        $pathParts = $Path -split '[\\/]'

        foreach ($part in $pathParts) {

            if ([string]::IsNullOrWhiteSpace($part)) { continue }

            $lower = $part.ToLower()

            # HashSet O(1) 精确匹配

            if ($Script:LegitimateSoftwareSet.Contains($lower)) {

                $result.PathLegitHint = $true

                break

            }

            # 前缀匹配（如 chrome78 → 匹配 chrome）

            foreach ($soft in $Script:LegitimateSoftware) {

                if ($lower -match "^$([regex]::Escape($soft.ToLower()))\d") {

                    $result.PathLegitHint = $true

                    break

                }

            }

            if ($result.PathLegitHint) { break }

        }

    } catch { "$(Get-Date) [ERROR] Test-IsLegitimatePath path segment match failed: $($_.Exception.Message)" | Out-File $dbgLog -Encoding UTF8 -Append }



    return $result

}



function Test-IPInCIDR([string]$IP, [string]$NetworkIP, [int]$Prefix) {

    # CIDR 子网匹配：将 IP 和网段地址都转为 uint32 后按位与掩码比较

    try {

        $ipBytes = [System.Net.IPAddress]::Parse($IP).GetAddressBytes()

        $netBytes = [System.Net.IPAddress]::Parse($NetworkIP).GetAddressBytes()

        # 大端序转 uint32

        $ipVal   = [uint32]($ipBytes[0]) -shl 24 -bor [uint32]($ipBytes[1]) -shl 16 -bor [uint32]($ipBytes[2]) -shl 8 -bor [uint32]($ipBytes[3])

        $netVal  = [uint32]($netBytes[0]) -shl 24 -bor [uint32]($netBytes[1]) -shl 16 -bor [uint32]($netBytes[2]) -shl 8 -bor [uint32]($netBytes[3])

        $mask    = [uint32]0xFFFFFFFF -shl (32 - $Prefix)

        return ($ipVal -band $mask) -eq ($netVal -band $mask)

    } catch {

        return $false

    }

}



function Test-IsRandomName([string]$Name) {

    # 5-8个纯小写/大写字母，不含数字和常见单词

    if ($Name -match '^[a-zA-Z]{4,12}$') {

        $lower = $Name.ToLower()

        # 使用全局 HashSet O(1) 查找，替代每次调用重建内联数组

        if ($Script:CommonWordsSet.Contains($lower)) { return $false }

        if ($Script:KnownSoftwareSet.Contains($lower)) { return $false }

        if ($Script:WinServiceNameSet.Contains($Name)) { return $false }

        return $true

    }

    return $false

}



# ============================================================

# 错误处理函数

# ============================================================

function Write-Log {

    param(

        [string]$Message,

        [string]$Level = "INFO",

        [string]$Module = "Global"

    )



    # 日志级别映射到数字

    $levelMap = @{ DEBUG=0; INFO=1; WARN=2; ERROR=3 }

    $currentLevel = $levelMap[$Script:LogLevel]

    $msgLevel = $levelMap[$Level]



    # 如果消息级别低于当前设置级别，则不记录

    if ($msgLevel -lt $currentLevel) { return }



    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $logEntry = "$timestamp [$Level] [$Module] $Message"



    # 写入调试日志文件

    $logEntry | Out-File $dbgLog -Encoding UTF8 -Append



    # ERROR级别同时在控制台显示

    if ($Level -eq "ERROR") {

        Write-Host "[ERROR] ${Module}: $Message" -ForegroundColor Red

    }

}



function Update-ErrorStats {

    param([string]$Category = "System")



    if ($Script:ErrorStats.ContainsKey($Category)) {

        $Script:ErrorStats[$Category]++

        $Script:ErrorStats["Total"]++

    }

}



function ConvertTo-HtmlSafe {

    param([string]$InputString)

    if ([string]::IsNullOrEmpty($InputString)) { return "" }

    # 完���的HTML转义：处理所有特殊字符

    $result = $InputString

    $result = $result -replace '&', '&amp;'

    $result = $result -replace '<', '&lt;'

    $result = $result -replace '>', '&gt;'

    $result = $result -replace '"', '&quot;'

    $result = $result -replace "'", '&#39;'

    # 额外处理：换行符和制表符

    $result = $result -replace "`r`n", '<br/>'

    $result = $result -replace "`n", '<br/>'

    $result = $result -replace "`r", '<br/>'

    $result = $result -replace "`t", '&nbsp;&nbsp;&nbsp;&nbsp;'

    # 处理Unicode控制字符

    $result = $result -replace '[\x00-\x1F\x7F]', ''

    return $result

}



# ============================================================

# 模块1：注册表启动项检测

# ============================================================

function Invoke-RegistryCheck {

    Write-Status "注册表" "扫描中" "检查启动项..."

    

    $runKeys = @(

        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",

        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",

        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",

        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",

        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",

        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"

    )

    

    foreach ($keyPath in $runKeys) {

        try {

            if (-not (Test-Path $keyPath)) { continue }

            $items = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue

            if (-not $items) { continue }

            

            $props = $items.PSObject.Properties | Where-Object {

                $_.Name -notin @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider")

                -and -not [string]::IsNullOrEmpty($_.Value)

            }

            

            foreach ($prop in $props) {

                $name = $prop.Name

                $value = $prop.Value.ToString()

                $suspicionScore = 0

                $reasons = @()

                

                # [1] 已确认的银狐启动项名（直接Critical）

                if ($name -in $Script:ConfirmedRunNames) {

                    $suspicionScore += 10

                    $reasons += "银狐已知启动项名: $name"

                }



                # [2] 指向可疑路径（需叠加其他条件）

                # 改进：排除已知的合法软件目录，减少误报

                $suspiciousPatterns = @(

                    @("C:\Windows\Temp\", "系统临时目录"),

                    @("C:\Program Files\Internet Explorer\", "IE目录(银狐常见)"),

                    @("\AppData\Local\Temp\", "用户临时目录")

                )

                $legitProgramDataPaths = @(

                    "\ProgramData\Microsoft\", "\ProgramData\Package Cache\",

                    "\ProgramData\NVIDIA\", "\ProgramData\Intel\",

                    "\ProgramData\Adobe\", "\ProgramData\Oracle\",

                    "\ProgramData\Docker\", "\ProgramData\chocolatey\",

                    "\ProgramData\Scoop\"

                )

                foreach ($pat in $suspiciousPatterns) {

                    if ($value -like "*$($pat[0])*") {

                        $suspicionScore += 2

                        $reasons += "指向$($pat[1])"

                        break

                    }

                }

                # ProgramData目录单独处理：排除合法路径

                if ($value -like "*\ProgramData\*" -and $value -notlike "*\ProgramData\Microsoft\*") {

                    $isLegitProgData = $false

                    foreach ($legitPath in $legitProgramDataPaths) {

                        if ($value -like "*$legitPath*") { $isLegitProgData = $true; break }

                    }

                    if (-not $isLegitProgData) {

                        $suspicionScore += 1

                        $reasons += "指向非标准ProgramData目录"

                    }

                }

                

                # [3] 路径含多层随机目录（银狐2026新特征，纯小写随机目录名）

                if ($value -cmatch '\\[a-z]{4,8}\\[a-z]{4,8}\\[a-z]{4,8}\\') {

                    $suspicionScore += 3

                    $reasons += "多层随机目录(银狐6层目录特征)"

                }

                

                # [4] 启动项名为随机字符

                if (Test-IsRandomName $name) {

                    $suspicionScore += 2

                    $reasons += "启动项名为随机字符"

                }

                

                # [5] 使用脚本启动

                if ($value -match '\.(bat|cmd|vbs|ps1)\s') {

                    $suspicionScore += 3

                    $reasons += "使用脚本启动"

                }

                

                # [6] 白名单排除：仅签名校验通过才直接跳过；路径段命中仅减分

                $legit = Test-IsLegitimatePath $value

                if ($legit.IsLegit) {

                    continue  # 签名验证通过（知名厂商），直接跳过

                }

                if ($legit.SignedButUnknown) { $suspicionScore -= 3 }

                if ($legit.PathLegitHint) { $suspicionScore -= 2 }

                

                # 阈值：3分以上才报警

                if ($suspicionScore -ge 3) {

                    $riskLevel = if ($suspicionScore -ge 8) { "Critical" }

                                 elseif ($suspicionScore -ge 5) { "High" }

                                 else { "Medium" }

                    

                    Add-Result -Category "Registry" -Title "可疑启动项: $name" `
                        -Detail "值: $value`n可疑度: $suspicionScore | 原因: $($reasons -join '; ')" `
                        -RiskLevel $riskLevel -Location $keyPath `
                        -Remediation "删除该启动项并检查对应文件" `
                        -CanBeFixed $true -FixType "RemoveRegProp" -FixRegPath $keyPath -FixRegName $name

                }

            }

        } catch {

            Write-Log -Message "注册表启动项扫描异常($keyPath): $($_.Exception.Message)" -Level "WARN" -Module "RegistryCheck"

            Update-ErrorStats -Category "Detection"

        }

    }



    # 映像劫持检测（IFEO中的Debugger值 - 高度可疑）

    Write-Status "注册表" "扫描中" "检查映像劫持..."

    $ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"

    if (Test-Path $ifeoPath) {

        Get-ChildItem $ifeoPath -ErrorAction SilentlyContinue | ForEach-Object {

            try {

                $dbg = (Get-ItemProperty $_.PSPath -Name "Debugger" -ErrorAction SilentlyContinue).Debugger

                if ($dbg) {

                    # 排除已知合法的IFEO（仅签名验证通过才跳过）

                    if ((Test-IsLegitimatePath $dbg).IsLegit) { return }

                    Add-Result -Category "Registry" -Title "映像劫持: $($_.PSChildName)" `
                        -Detail "Debugger: $dbg" -RiskLevel "High" -Location $_.PSPath `
                        -Remediation "检查该映像劫持是否正常，删除Debugger键值" `
                        -CanBeFixed $true -FixType "RemoveRegProp" -FixRegPath $_.PSPath -FixRegName "Debugger"

                }

            } catch {

                Write-Log -Message "映像劫持检测异常: $($_.Exception.Message)" -Level "DEBUG" -Module "RegistryCheck"

            }

        }

    }



    # [7] UserInitMprLogonScript（银狐新型持久化技术，登录时执行任意脚本）

    # 来源：银狐情报共享第1期

    try {

        $userInitPath = "HKCU:\Environment"

        if (Test-Path $userInitPath) {

            $userInitVal = (Get-ItemProperty -Path $userInitPath -Name "UserInitMprLogonScript" -ErrorAction SilentlyContinue)."UserInitMprLogonScript"

            if ($userInitVal) {

                Add-Result -Category "Registry" -Title "UserInitMprLogonScript持��化" `
                    -Detail "值: $userInitVal`n该键在用户登录时执行任意脚本，是银狐木马新型持久化技术" `
                    -RiskLevel "Critical" -Location $userInitPath `
                    -Remediation "删除HKCU:\Environment\UserInitMprLogonScript键值，检查脚本内容确认是否为恶意" `
                    -CanBeFixed $true -FixType "RemoveRegProp" -FixRegPath $userInitPath -FixRegName "UserInitMprLogonScript"

            }

        }

    } catch {

        Write-Log -Message "UserInitMprLogonScript检测异常: $($_.Exception.Message)" -Level "DEBUG" -Module "RegistryCheck"

    }



    # [8] PendingFileRenameOperations（重启时替换/删除文件，银狐自删除技术）

    try {

        $pfroPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"

        if (Test-Path $pfroPath) {

            $pfroVal = (Get-ItemProperty -Path $pfroPath -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue)."PendingFileRenameOperations"

            if ($pfroVal) {

                # 检查是否涉及可疑路径

                $suspicious = $false

                $pfroStr = $pfroVal.ToString()

                foreach ($pattern in @("\AppData","\ProgramData","\Temp","\Windows\Temp","Internet Explorer")) {

                    if ($pfroStr -like "*$pattern*") { $suspicious = $true; break }

                }

                # 进一步过滤：仅标记匹配银狐特征的挂起操作

                if ($suspicious) {

                    $suspicious = $false

                    if ($pfroStr -match '\\[a-z]{4,12}\\[a-z]{4,12}\\[a-z]{4,12}\\') { $suspicious = $true }

                    foreach ($malName in $Script:KnownMaliciousFileNames) {

                        if ($pfroStr -match [regex]::Escape($malName)) { $suspicious = $true; break }

                    }

                }

                if ($suspicious) {

                    Add-Result -Category "Registry" -Title "PendingFileRenameOperations自删除/替换" `
                        -Detail "值: $pfroVal`n该键在重启时执行文件替换/删除操作，银狐常用于自删除或劫持系统文件" `
                        -RiskLevel "High" -Location $pfroPath `
                        -Remediation "将PendingFileRenameOperations置空（需重启生效），检查被操作的文件是否为恶意" `
                        -CanBeFixed $true -FixType "RemoveRegProp" -FixRegPath $pfroPath -FixRegName "PendingFileRenameOperations"

                }

            }

        }

    } catch {

        Write-Log -Message "PendingFileRenameOperations检测异常: $($_.Exception.Message)" -Level "DEBUG" -Module "RegistryCheck"

    }



    # [9] DOS Devices虚拟盘符映射（银狐新型持久化，O:/X:盘符映射到启动目录）

    # 来源：银狐情报共享第1期

    try {

        $dosDevPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\DOS Devices"

        if (Test-Path $dosDevPath) {

            $devices = Get-ItemProperty -Path $dosDevPath -ErrorAction SilentlyContinue

            if ($devices) {

                $devices.PSObject.Properties | Where-Object {

                    $_.Name -notin @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider")

                } | ForEach-Object {

                    $devName = $_.Name

                    $devTarget = $_.Value.ToString()

                    # 检��目标路径是否为可疑目录（AppData/ProgramData/Temp等）

                    $suspiciousTarget = $false

                    foreach ($pat in @("\AppData","\ProgramData","\Temp","\Windows\Temp")) {

                        if ($devTarget -like "*$pat*") { $suspiciousTarget = $true; break }

                    }

                    if ($suspiciousTarget) {

                        Add-Result -Category "Registry" -Title "DOS Devices虚拟盘符: $devName" `
                            -Detail "设备: $devName -> $devTarget`n虚拟盘符映射到可疑目录，是银狐木马新型持久化/隐藏技术" `
                            -RiskLevel "High" -Location $dosDevPath `
                            -Remediation "删除该DOS Devices项，检查映射目录中的文件是否为恶意" `
                            -CanBeFixed $true -FixType "RemoveRegProp" -FixRegPath $dosDevPath -FixRegName $devName

                    }

                }

            }

        }

    } catch {

        Write-Log -Message "DOS Devices检测异常: $($_.Exception.Message)" -Level "DEBUG" -Module "RegistryCheck"

    }



    # [10] Winlogon Shell/Userinit 检测（银狐替换explorer.exe持久化）

    try {

        $winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

        if (Test-Path $winlogonPath) {

            $winlogon = Get-ItemProperty -Path $winlogonPath -ErrorAction SilentlyContinue

            # Shell 应该是 explorer.exe

            $shell = $winlogon.Shell

            if ($shell -and $shell -ne "explorer.exe") {

                # 检查是否包含可疑路径

                $shellExe = ($shell -split '\s+')[0] -replace '"',''

                if (-not (Test-IsLegitimatePath $shellExe).IsLegit) {

                    Add-Result -Category "Registry" -Title "Winlogon Shell异常" `
                        -Detail "Shell: $shell`n正常应为 explorer.exe，当前值可能被银狐木马替换" `
                        -RiskLevel "Critical" -Location $winlogonPath `
                        -Remediation "将Shell值恢复为 explorer.exe" `
                        -CanBeFixed $true -FixType "RemoveRegProp" -FixRegPath $winlogonPath -FixRegName "Shell"

                }

            }

            # Userinit 应该是 C:\Windows\system32\userinit.exe,

            $userinit = $winlogon.Userinit

            if ($userinit) {

                $userinitNorm = $userinit.TrimEnd(',').ToLower()

                if ($userinitNorm -ne "c:\windows\system32\userinit.exe" -and

                    $userinitNorm -ne "c:\windows\syswow64\userinit.exe") {

                    # 检查是否为可疑脚本

                    if ($userinit -match '\.(bat|cmd|vbs|ps1|js)') {

                        Add-Result -Category "Registry" -Title "Winlogon Userinit脚本注入" `
                            -Detail "Userinit: $userinit`n正常应为 userinit.exe，当前包含脚本执行" `
                            -RiskLevel "Critical" -Location $winlogonPath `
                            -Remediation "将Userinit值恢复为 C:\Windows\system32\userinit.exe," `
                            -CanBeFixed $true -FixType "RemoveRegProp" -FixRegPath $winlogonPath -FixRegName "Userinit"

                    } elseif ($userinit -notmatch 'userinit\.exe') {

                        Add-Result -Category "Registry" -Title "Winlogon Userinit异常" `
                            -Detail "Userinit: $userinit`n正常应为 userinit.exe，当前值可能被篡改" `
                            -RiskLevel "High" -Location $winlogonPath `
                            -Remediation "检查Userinit值，恢复为默认值" `
                            -CanBeFixed $true -FixType "RemoveRegProp" -FixRegPath $winlogonPath -FixRegName "Userinit"

                    }

                }

            }

            # Notify 包（GINA通知包，银狐可注入）

            $notify = $winlogon.Notify

            if ($notify) {

                $notifyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\$notify"

                if (Test-Path $notifyPath) {

                    $notifyDll = (Get-ItemProperty $notifyPath -Name "DllName" -ErrorAction SilentlyContinue).DllName

                    if ($notifyDll -and -not (Test-IsLegitimatePath $notifyDll).IsLegit) {

                        Add-Result -Category "Registry" -Title "Winlogon Notify可疑DLL" `
                            -Detail "Notify: $notify`nDLL: $notifyDll`nGINA通知包可能被银狐注入" `
                            -RiskLevel "Critical" -Location $notifyPath `
                            -Remediation "删除该Notify项，检查DLL是否为恶意" `
                            -CanBeFixed $true -FixType "RemoveRegProp" -FixRegPath $winlogonPath -FixRegName "Notify"

                    }

                }

            }

        }

    } catch {

        Write-Log -Message "Winlogon检测异常: $($_.Exception.Message)" -Level "DEBUG" -Module "RegistryCheck"

    }



    # [11] AppInit_DLLs 检测（所有加载user32.dll的进程都会加载此DLL）

    try {

        $appInitPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"

        if (Test-Path $appInitPath) {

            $appInitDlls = (Get-ItemProperty -Path $appInitPath -Name "AppInit_DLLs" -ErrorAction SilentlyContinue)."AppInit_DLLs"

            if ($appInitDlls -and $appInitDlls.Trim() -ne "") {

                # 检查每个DLL路径

                $dlls = $appInitDlls -split '\s+'

                foreach ($dll in $dlls) {

                    if ([string]::IsNullOrWhiteSpace($dll)) { continue }

                    $dllClean = $dll -replace '"',''

                    if (-not (Test-IsLegitimatePath $dllClean).IsLegit) {

                        Add-Result -Category "Registry" -Title "AppInit_DLLs可疑DLL" `
                            -Detail "AppInit_DLLs: $appInitDlls`n可疑DLL: $dllClean`nAppInit_DLLs会被所有加载user32.dll的进程加载，银狐可用于全局注入" `
                            -RiskLevel "Critical" -Location $appInitPath `
                            -Remediation "清空AppInit_DLLs值，检查对应DLL是否为恶意" `
                            -CanBeFixed $true -FixType "RemoveRegProp" -FixRegPath $appInitPath -FixRegName "AppInit_DLLs"

                    }

                }

            }

        }

    } catch {

        Write-Log -Message "AppInit_DLLs检测异常: $($_.Exception.Message)" -Level "DEBUG" -Module "RegistryCheck"

    }



    # [12] BootExecute 检测（系统启动时执行的命令，银狐可注入）

    try {

        $bootExecPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"

        if (Test-Path $bootExecPath) {

            $bootExec = (Get-ItemProperty -Path $bootExecPath -Name "BootExecute" -ErrorAction SilentlyContinue)."BootExecute"

            if ($bootExec) {

                $bootExecStr = ($bootExec -join " ").ToLower()

                # 正常值应该是 autocheck autochk *

                if ($bootExecStr -notmatch '^\s*autocheck\s+autochk\s+\*\s*$') {

                    # 检查是否包含可疑命令

                    $suspiciousBootCmds = @("powershell","cmd","wscript","cscript","mshta","rundll32","regsvr32")

                    foreach ($cmd in $suspiciousBootCmds) {

                        if ($bootExecStr -match $cmd) {

                            Add-Result -Category "Registry" -Title "BootExecute可疑命令" `
                                -Detail "BootExecute: $($bootExec -join '; ')`n包含可疑命令: $cmd`nBootExecute在系统启动时执行，银狐可用于持久化" `
                                -RiskLevel "Critical" -Location $bootExecPath `
                                -Remediation "将BootExecute恢复为默认值: autocheck autochk *" `
                                -CanBeFixed $true -FixType "RestoreBootExecute" -FixRegPath $bootExecPath -FixRegName "BootExecute"

                            break

                        }

                    }

                }

            }

        }

    } catch {

        Write-Log -Message "BootExecute检测异常: $($_.Exception.Message)" -Level "DEBUG" -Module "RegistryCheck"

    }



    # [13] AppCertDlls 检测（每个调用 Win32 证书函数的进程都会加载该 DLL）

    try {

        $appCertPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls"

        if (Test-Path $appCertPath) {

            $appCertDlls = Get-ItemProperty -Path $appCertPath -ErrorAction SilentlyContinue

            $appCertDlls.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {

                $dllPath = $_.Value -replace '"',''

                if ([string]::IsNullOrWhiteSpace($dllPath)) { return }

                # 系统目录下的合法 DLL 排除

                if ($dllPath -match '\\System32\\' -or $dllPath -match '\\SysWOW64\\') { return }

                $legit = Test-IsLegitimatePath $dllPath

                if ($legit.IsLegit) { return }

                Add-Result -Category "Registry" -Title "AppCertDlls可疑DLL" `
                    -Detail "键: $appCertPath`n值: $($_.Name) = $dllPath`nAppCertDlls 中的 DLL 会被所有调用证书相关 API 的进程加载，是高级持久化注入点" `
                    -RiskLevel "Critical" -Location $appCertPath `
                    -Remediation "删除可疑的 AppCertDlls 条目" `
                    -CanBeFixed $true -FixType "RemoveRegProp" -FixRegPath $appCertPath -FixRegName $_.Name

            }

        }

    } catch {

        Write-Log -Message "AppCertDlls检测异常: $($_.Exception.Message)" -Level "DEBUG" -Module "RegistryCheck"

    }



    # [14] COM 劫持检测（替换 CLSID InprocServer32/LocalServer32 指向恶意文件）
    # 性能优化：使用 reg query 原生搜索替代 PowerShell Get-ChildItem 遍历数千 CLSID
    try {
        Write-Status "注册表" "扫描中" "检查COM劫持(reg query快速扫描)..."
        $clsidRegPath = "HKLM\SOFTWARE\Classes\CLSID"
        $foundClsids = @{}  # CLSID -> @{ InprocServer32=$true/false; LocalServer32=$true/false }

        # 用 reg query /s /f 搜索子键名，比 PowerShell 逐个枚举快 10-50 倍
        foreach ($subKeyName in @("InprocServer32","LocalServer32")) {
            $regOut = reg query $clsidRegPath /s /f $subKeyName /k 2>$null
            if (-not $regOut) { continue }
            foreach ($line in $regOut) {
                # 匹配路径如: HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{GUID}\InprocServer32
                if ($line -match '\\Classes\\CLSID\\(\\{[^}]+})\\' + [regex]::Escape($subKeyName) + '$') {
                    $clsidGuid = $Matches[1]  # 如 {00000000-0000-0000-0000-000000000000}
                    if (-not $foundClsids.ContainsKey($clsidGuid)) {
                        $foundClsids[$clsidGuid] = @{ InprocServer32=$false; LocalServer32=$false }
                    }
                    $foundClsids[$clsidGuid][$subKeyName] = $true
                }
            }
        }
        Write-Log -Message "COM劫持检测: 发现 $($foundClsids.Count) 个含 InprocServer32/LocalServer32 的 CLSID" -Level "DEBUG" -Module "RegistryCheck"

        $clsidPoshPath = "HKLM:\SOFTWARE\Classes\CLSID"
        $checked = 0
        foreach ($clsidGuid in $foundClsids.Keys) {
            $checked++
            foreach ($subKey in @("InprocServer32","LocalServer32")) {
                if (-not $foundClsids[$clsidGuid][$subKey]) { continue }
                $subPath = "$clsidPoshPath\$clsidGuid\$subKey"
                try {
                    $serverPath = (Get-ItemProperty -Path $subPath -ErrorAction SilentlyContinue).'(default)'
                } catch { continue }
                if ([string]::IsNullOrWhiteSpace($serverPath)) { continue }
                $serverPath = $serverPath -replace '"',''
                # 排除系统目录
                if ($serverPath -match '\\System32\\' -or $serverPath -match '\\SysWOW64\\' -or $serverPath -match '\\WinSxS\\') { continue }
                # 排除不存在的路径（可能是已卸载软件的残留）
                if (-not (Test-Path $serverPath -PathType Leaf)) { continue }
                # 签名验证
                $legit = Test-IsLegitimatePath $serverPath
                if ($legit.IsLegit) { continue }
                Add-Result -Category "Registry" -Title "COM劫持: $subKey" `
                    -Detail "CLSID: {$clsidGuid}`n$subKey = $serverPath`n该COM对象的DLL指向非系统目录，可能是银狐替换的持久化点" `
                    -RiskLevel "High" -Location $subPath `
                    -Remediation "将 $subKey 恢复为原始路径或删除可疑条目" `
                    -CanBeFixed $false
            }
        }
        Write-Log -Message "COM劫持检测完成: 已检查 $checked 个 CLSID" -Level "DEBUG" -Module "RegistryCheck"
    } catch {
        Write-Log -Message "COM劫持检测异常: $($_.Exception.Message)" -Level "DEBUG" -Module "RegistryCheck"
    }


    Write-Status "注册表" "完成" "发现 $($Script:Results.Registry.Count) 个可疑项"

}



# ============================================================

# 模块2：计划任务检测

# ============================================================

function Invoke-TaskCheck {

    Write-Status "计划任务" "扫描中" "检查计划任务..."

    

    try {

        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {

            $_.State -ne "Disabled"

        }

        

        foreach ($task in $tasks) {

            $taskName = $task.TaskName

            $taskPath = $task.TaskPath

            $suspicionScore = 0

            $reasons = @()

            $execDetail = ""

            

            # 白名单：微软/Google/Adobe等系统任务 — HashSet O(1)

            $isLegitTask = $false

            foreach ($legitPath in $Script:LegitimateTaskPaths) {

                if ($taskPath -like "$legitPath*") { $isLegitTask = $true; break }

            }

            if ($isLegitTask) { continue }

            

            try {

                if ($task.Actions) {

                    foreach ($action in $task.Actions) {

                        $execPath = $action.Execute

                        $taskArgs = $action.Arguments

                        $execDetail += "执行: $execPath $taskArgs; "

                        

                        # [1] 执行路径在用户临时目录 + 非签名验证通过

                        # 改进：更精确的临时目录匹配，排除Windows临时目录中的合法软件

                        if ($execPath -match 'AppData\\Local\\Temp\\') {

                            $legit = Test-IsLegitimatePath $execPath

                            if (-not $legit.IsLegit) {

                                $suspicionScore += 3

                                $reasons += "从用户临时目录执行: $execPath"

                            }

                        }

                        # Windows临时目录：检查是否为可疑程序（排除系统维护任务）

                        if ($execPath -match 'Windows\\Temp\\' -and $execPath -notmatch 'Windows\\Temp\\[a-z]{5,8}\.(exe|dll)$') {

                            $legit = Test-IsLegitimatePath $execPath

                            if (-not $legit.IsLegit) {

                                $suspicionScore += 2

                                $reasons += "从Windows临时目录执行"

                            }

                        }

                        

                        # [2] 路径含多层随机目录（纯小写随机目录名）

                        if ($execPath -cmatch '\\[a-z]{4,8}\\[a-z]{4,8}\\[a-z]{4,8}\\') {

                            $suspicionScore += 3

                            $reasons += "多层随机目录(银狐特征)"

                        }

                        

                        # [3] 使用powershell/cmd执行脚本 + 混淆特征

                        if ($execPath -match 'powershell|cmd\.exe|wscript|cscript|mshta') {

                            if ($taskArgs -match '-enc|-EncodedCommand|FromBase64|IEX|Invoke-Expression|DownloadString|DownloadFile|Start-Process') {

                                $suspicionScore += 5

                                $reasons += "PowerShell恶意命令特征"

                            }

                            elseif ($taskArgs -match '\.bat|\.vbs|\.ps1') {

                                $suspicionScore += 2

                                $reasons += "脚本引擎执行脚本文件"

                            }

                        }



                        # [4] BAT脚本守护特征（sc命令操作服务）

                        if ($taskArgs -match 'sc\s+(create|start|config)\s') {

                            $suspicionScore += 4

                            $reasons += "BAT守护脚本特征(sc命令操作服务)"

                        }

                        

                        # [5] 以SYSTEM权限运行用户目录程序

                        if ($task.Principal.UserId -eq "SYSTEM" -and $execPath -match 'AppData|ProgramData|\\Temp\\') {

                            $legit = Test-IsLegitimatePath $execPath

                            if (-not $legit.IsLegit) {

                                $suspicionScore += 3

                                $reasons += "SYSTEM权限运行用户目录程序"

                            }

                        }

                        

                        # [6] 白名单排除：签名验证通过直接跳过整个task

                        $legit = Test-IsLegitimatePath $execPath

                        if ($legit.IsLegit) {

                            $suspicionScore = 0

                            break

                        } else {

                            if ($legit.SignedButUnknown) { $suspicionScore -= 3 }

                            if ($legit.PathLegitHint) { $suspicionScore -= 2 }

                        }

                    }

                }

                

                # [7] 随机字符任务名

                if (Test-IsRandomName $taskName) {

                    $suspicionScore += 2

                    $reasons += "随机字符任务名"

                }

                

                if ($suspicionScore -ge 3) {

                    $riskLevel = if ($suspicionScore -ge 8) { "Critical" }

                                 elseif ($suspicionScore -ge 5) { "High" }

                                 else { "Medium" }

                    

                    Add-Result -Category "Tasks" -Title "可疑计划任务: $taskPath$taskName" `
                        -Detail "$execDetail`n可疑度: $suspicionScore | 原因: $($reasons -join '; ')" `
                        -RiskLevel $riskLevel -Location "计划任务: $taskPath$taskName" `
                        -Remediation "禁用并删除该计划任务" `
                        -CanBeFixed $true -FixType "UnregisterTask" -FixTaskName $taskName -FixTaskPath $taskPath

                }

            } catch {

                Write-Log -Message "计划任务检测异常($taskPath$taskName): $($_.Exception.Message)" -Level "DEBUG" -Module "TaskCheck"

            }

        }

    } catch {

        Write-Status "计划任务" "警告" "无法获取计划任务列表"

        Write-Log -Message "无法获取计划任务列表: $($_.Exception.Message)" -Level "WARN" -Module "TaskCheck"

        Update-ErrorStats -Category "Detection"

    }

    

    Write-Status "计划任务" "完成" "发现 $($Script:Results.Tasks.Count) 个可疑项"

}



# ============================================================

# 模块3：系统服务检测

# ============================================================

function Invoke-ServiceCheck {

    Write-Status "服务" "扫描中" "检查系统服务..."

    

    try {

        $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {

            $_.State -eq "Running"

        }

        

        foreach ($svc in $services) {

            $pathName = $svc.PathName

            if ([string]::IsNullOrEmpty($pathName)) { continue }



            # 快速排除：svchost.exe 托管的服务 — 恶意程序无法通过此方式持久化

            if ($pathName -match '(?i)svchost\.exe\s+-k\s') { continue }



            # 快速排除：服务名在 Windows 内置服务白名单中

            # 不再跳过非随机名称的服务 — 直接进入路径/签名评分

            $isKnownMalicious = $svc.Name -in $Script:ConfirmedRunNames



            $suspicionScore = 0

            $reasons = @()



            # 已知恶意服务名直接高分

            if ($isKnownMalicious) {

                $suspicionScore += 6

                $reasons += "已知银狐服务名: $($svc.Name)"

            }

            

            # 白名单：系统标准路径的处理

            if ($pathName -match '^"?(C:\\Windows\\System32|C:\\Windows\\SysWOW64)\\') {

                # 检测系统目录下的脚本（极不正常）

                if ($pathName -match '\.bat|\.cmd|\.vbs|\.ps1|\.js') {

                    $suspicionScore += 5

                    $reasons += "系统服务使用脚本(极不正常)"

                }

                else {

                    # 非脚本文件：检查签名，签名通过才跳过

                    if ((Test-IsLegitimatePath $pathName).IsLegit) { continue }

                    # 签名未通过：路径在系统目录但文件可疑

                    $suspicionScore += 2

                    $reasons += "系统目录文件未通过签名校验"

                }

            }

            

            # 白名单：基于二进制文件的Authenticode签名校验（不看DisplayName字符串）

            if ((Test-IsLegitimatePath $pathName).IsLegit) { continue }



            # [1] 服务指向用户目录可执行文件

            # 改进：排除已知的合法软件目录

            $legitServicePaths = @(

                "ProgramData\Microsoft\", "ProgramData\Package Cache\",

                "ProgramData\NVIDIA\", "ProgramData\Intel\",

                "ProgramData\ESET\", "ProgramData\SysCleanPro\",

                "AppData\Local\Microsoft\", "AppData\Local\Google\",

                "AppData\Local\Programs\", "AppData\Roaming\SysCleanPro\",

                "Program Files\ESET\", "Program Files\NVIDIA Corporation\",

                "Program Files\Kingsoft\", "Program Files\WPS Office"

            )

            $isLegitUserPath = $false

            foreach ($legitPath in $legitServicePaths) {

                if ($pathName -like "*$legitPath*") { $isLegitUserPath = $true; break }

            }

            if (-not $isLegitUserPath -and $pathName -match 'AppData\\|ProgramData\\') {

                $suspicionScore += 3

                $reasons += "服务路径在非标准用户目录"

            }

            if ($pathName -match '\\Temp\\') {

                $suspicionScore += 3

                $reasons += "服务路径在临时目录"

            }

            

            # [2] 多层随机目录（纯小写随机目录名）

            if ($pathName -cmatch '\\[a-z]{4,8}\\[a-z]{4,8}\\[a-z]{4,8}\\') {

                $suspicionScore += 3

                $reasons += "多层随机目录(银狐特征)"

            }

            

            # [3] 随机服务名 + 无描述

            $randomName = Test-IsRandomName $svc.Name

            $noDesc = [string]::IsNullOrWhiteSpace($svc.Description)

            if ($randomName -and $noDesc) {

                $suspicionScore += 3

                $reasons += "随机名+无描述"

            }

            elseif ($randomName) {

                $suspicionScore += 1

                $reasons += "随机服务名"

            }

            

            # [4] 服务名和显示名完全不同（伪装特征）

            if ($svc.Name -ne $svc.DisplayName -and $randomName) {

                $suspicionScore += 2

                $reasons += "内部名与显示名不匹配"

            }

            

            if ($suspicionScore -ge 3) {

                $riskLevel = if ($suspicionScore -ge 8) { "Critical" }

                             elseif ($suspicionScore -ge 5) { "High" }

                             else { "Medium" }

                

                Add-Result -Category "Services" -Title "可疑服务: $($svc.Name)" `
                    -Detail "显示名: $($svc.DisplayName)`n路径: $pathName`n可疑度: $suspicionScore | 原因: $($reasons -join '; ')" `
                    -RiskLevel $riskLevel -Location "服务: $($svc.Name)" `
                    -Remediation "停止并禁用该服务，删除对应文件" `
                    -CanBeFixed $true -FixType "StopAndDisableService" -FixServiceName $svc.Name

            }

        }

    } catch {

        Write-Log -Message "服务检测失败: $($_.Exception.Message)" -Level "ERROR" -Module "ServiceCheck"
        Update-ErrorStats -Category "Detection"
        Write-Status "服务" "警告" "无法获取服务列表: $($_.Exception.Message)"

    }



    # 服务 DLL 劫持检测（svchost 托管服务的 ServiceDll 被替换为恶意 DLL）

    Write-Status "服务" "扫描中" "检查服务DLL劫持..."

    try {

        $svcRoot = "HKLM:\SYSTEM\CurrentControlSet\Services"

        Get-ChildItem -Path $svcRoot -ErrorAction SilentlyContinue | ForEach-Object {

            $svcName = $_.PSChildName

            $paramPath = "$svcRoot\$svcName\Parameters"

            if (-not (Test-Path $paramPath)) { return }

            $serviceDll = (Get-ItemProperty -Path $paramPath -Name "ServiceDll" -ErrorAction SilentlyContinue)."ServiceDll"

            if ([string]::IsNullOrWhiteSpace($serviceDll)) { return }

            $serviceDll = $serviceDll -replace '"',''

            # 排除系统目录

            if ($serviceDll -match '\\System32\\' -or $serviceDll -match '\\SysWOW64\\') { return }

            # 排除已知合法厂商目录（NVIDIA, ByteDance/douyin, Intel 等）

            if ($serviceDll -match 'NVIDIA|ByteDance|douyin|Intel|AMD|Google|Mozilla|Adobe|Microsoft') { return }

            # 排除不存在的文件

            if (-not (Test-Path $serviceDll -PathType Leaf)) { return }

            # 签名验证

            $legit = Test-IsLegitimatePath $serviceDll

            if ($legit.IsLegit) { return }

            Add-Result -Category "Services" -Title "服务DLL劫持: $svcName" `
                -Detail "服务: $svcName`nServiceDll: $serviceDll`n该svchost托管服务的ServiceDll不在系统目录，可能是银狐替换的持久化DLL" `
                -RiskLevel "Critical" -Location $paramPath `
                -Remediation "将ServiceDll恢复为原始System32路径，或删除恶意DLL" `
                -CanBeFixed $false

        }

    } catch {

        Write-Log -Message "服务DLL劫持检测异常: $($_.Exception.Message)" -Level "DEBUG" -Module "ServiceCheck"

    }



    Write-Status "服务" "完成" "发现 $($Script:Results.Services.Count) 个可疑项"

}



# ============================================================

# 模块4：进程与DLL侧加载检测

# ============================================================

function Invoke-ProcessCheck {

    Write-Status "进程" "扫描中" "检查可疑进程与DLL侧加载..."



    try {

        # 核心检测：白加黑DLL侧加载（银狐最关键特征）

        # 预筛：只对非系统目录的进程展开模块检查，避免遍历数百个系统进程的数百个DLL

        $allProcesses = Get-Process -ErrorAction SilentlyContinue | Where-Object {

            try { $_.Path -and $_.Path -notmatch 'C:\\Windows\\(System32|SysWOW64|WinSxS)' } catch { $false }

        }



        foreach ($proc in $allProcesses) {

            try {

                # 访问 Modules 需要打开进程句柄，某些进程会卡死，加 try 包裹

                $mods = $null

                try { $mods = $proc.Modules } catch { continue }

                if (-not $mods) { continue }

                

                foreach ($susDLL in $Script:SilverFoxDLLs) {

                    $dllModules = $mods | Where-Object { $_.ModuleName -eq $susDLL }

                    foreach ($mod in $dllModules) {

                        # DLL不在系统标准目录 = DLL侧加载

                        if ($mod.FileName -like "*System32*" -or $mod.FileName -like "*SysWOW64*" -or 

                            $mod.FileName -like "*WinSxS*") { continue }

                        # 路径位于已知合法厂商目录 → 跳过（NVIDIA Overlay, Intel 等）

                        if ($mod.FileName -match 'NVIDIA|Intel|AMD|Microsoft|Google|Mozilla|Adobe') { continue }

                        

                        # 白名单排除：仅签名校验通过（知名厂商）才跳过

                        $legit = Test-IsLegitimatePath $mod.FileName

                        if ($legit.IsLegit) { continue }

                        # 路径段匹配合法软件目录 → 跳过（如 WPS 自带 libcurl.dll）

                        if ($legit.PathLegitHint) { continue }

                        

                        # 检查EXE同目录（白加黑特征：恶意DLL与白文件EXE同目录）

                        $exeDir = Split-Path $mod.FileName -Parent

                        $siblingExes = Get-ChildItem -Path $exeDir -Filter "*.exe" -ErrorAction SilentlyContinue

                        $hasSignedExe = $false

                        foreach ($exe in $siblingExes) {

                            try {

                                $resolvedExe = try { (Resolve-Path $exe.FullName -ErrorAction Stop).Path } catch { $exe.FullName }

                                $exeCacheKey = $resolvedExe.ToLower()

                                if ($Script:SignatureCache.ContainsKey($exeCacheKey)) {

                                    $sig = $Script:SignatureCache[$exeCacheKey]

                                } else {

                                    $sig = Get-AuthenticodeSignature $exe.FullName -RevocationMode NoCheck -ErrorAction SilentlyContinue

                                    $Script:SignatureCache[$exeCacheKey] = $sig

                                }

                                if ($sig.Status -eq "Valid") { $hasSignedExe = $true; break }

                            } catch {

                                Write-Log -Message "签名检查失败($($exe.FullName)): $($_.Exception.Message)" -Level "DEBUG" -Module "ProcessCheck"

                            }

                        }

                        

                        $suspicionScore = 4  # DLL不在系统目录已很可疑

                        $reasons = @("DLL侧加载: $($mod.ModuleName) 不在系统目录")

                        

                        if ($hasSignedExe) {

                            $suspicionScore += 4

                            $reasons += "同目录有签名EXE(白加黑特征)"

                        }

                        

                        # 路径段/签名减分

                        if ($legit.SignedButUnknown) { $suspicionScore -= 3 }

                        if ($legit.PathLegitHint) { $suspicionScore -= 2 }

                        

                        # 随机目录（纯小写）

                        if ($mod.FileName -cmatch '\\[a-z]{4,8}\\[a-z]{4,8}\\') {

                            $suspicionScore += 3

                            $reasons += "路径含随机目录"

                        }

                        

                        $riskLevel = if ($suspicionScore -ge 7) { "Critical" } else { "High" }

                        

                        Add-Result -Category "Processes" -Title "DLL侧加载: $($proc.ProcessName)" `
                            -Detail "DLL: $($mod.FileName)`n进程: $($proc.ProcessName) (PID: $($proc.Id))`n可疑度: $suspicionScore | 原因: $($reasons -join '; ')" `
                            -RiskLevel $riskLevel -Location "进程: $($proc.ProcessName), DLL: $($mod.FileName)" `
                            -Remediation "终止进程，检查DLL和同目录EXE是否为恶意文件" `
                            -CanBeFixed $true -FixType "StopProcess" -FixPid $proc.Id

                    }

                }

            } catch {

                Write-Log -Message "DLL侧加载检测异常: $($_.Exception.Message)" -Level "DEBUG" -Module "ProcessCheck"

            }

        }



        # 检测：从6层随机目录运行的进程（银狐2026新特征）

        Write-Status "进程" "扫描中" "检查随机目录进程..."

        $wmiProcs = Get-CimProcessCache

        foreach ($wmiProc in $wmiProcs) {

            $execPath = $wmiProc.ExecutablePath

            if ([string]::IsNullOrEmpty($execPath)) { continue }

            

            # 白名单排除

            $legitCheck = Test-IsLegitimatePath $execPath

            if ($legitCheck.IsLegit) { continue }

            

            # PathLegitHint 命中白名单软件名 → 跳过随机目录检查（如 utools 等）

            if ($legitCheck.PathLegitHint) { continue }



            # 6层随机目录特征 - 严格要求4层以上连续纯小写随机目录 + 随机EXE名

            # 注意：PowerShell -match 默认不区分大小写，[a-z]会匹配大写！必须用 -cmatch 或 (?-i)

            if ($execPath -cmatch '\\[a-z]{4,8}\\[a-z]{4,8}\\[a-z]{4,8}\\[a-z]{4,8}\\[a-zA-Z]{3,8}\.exe$' -and 

                $execPath -notmatch 'node_modules|resources|locales|lib|bin|src|pkg|share|include|Programs|AppData|Microsoft|NVIDIA|Intel') {

                Add-Result -Category "Processes" -Title "6层随机目录进程" `
                    -Detail "进程: $($wmiProc.Name) (PID: $($wmiProc.ProcessId))`n路径: $execPath`n这是银狐2026新变种的典型特征" `
                    -RiskLevel "Critical" -Location "进程: $execPath" `
                    -Remediation "立即终止进程并删除整个随机目录" `
                    -CanBeFixed $true -FixType "StopProcess" -FixPid $wmiProc.ProcessId

                continue

            }

            # 降级规则：匹配混合大小写随机目录（增强鲁棒性）

            elseif ($execPath -match '\\[a-zA-Z]{4,8}\\[a-zA-Z]{4,8}\\[a-zA-Z]{4,8}\\[a-zA-Z]{4,8}\\[a-zA-Z]{3,8}\.exe$' -and 

                $execPath -notmatch 'node_modules|resources|locales|lib|bin|src|pkg|share|include|Programs|AppData|Microsoft|NVIDIA|Intel') {

                Add-Result -Category "Processes" -Title "6层随机目录进程（混合大小写）" `
                    -Detail "进程: $($wmiProc.Name) (PID: $($wmiProc.ProcessId))`n路径: $execPath`n检测到混合大小写随机目录，可能是银狐变种" `
                    -RiskLevel "High" -Location "进程: $execPath" `
                    -Remediation "立即终止进程并检查目录" `
                    -CanBeFixed $true -FixType "StopProcess" -FixPid $wmiProc.ProcessId

                continue

            }

            

            # IE目录下运行非IE程序

            if ($execPath -like "*Internet Explorer*" -and $execPath -notlike "*iexplore*") {

                if (-not (Test-IsLegitimatePath $execPath).IsLegit) {

                    Add-Result -Category "Processes" -Title "IE目录可疑进程" `
                        -Detail "进程: $($wmiProc.Name) (PID: $($wmiProc.ProcessId))`n路径: $execPath`n银狐常在IE目录释放恶意文件" `
                        -RiskLevel "High" -Location "进程: $execPath" `
                        -Remediation "终止进程，检查IE目录下可疑文件" `
                        -CanBeFixed $true -FixType "StopProcess" -FixPid $wmiProc.ProcessId

                }

            }

        }

        

        # 检测：银狐注入目标进程路径异常（不在System32或同名进程多开）

        Write-Status "进程" "扫描中" "检查注入目标进程..."

        # 复用上面已获取的 WMI 数据，避免重复 Get-CimInstance 调用导致挂起

        $wmiByPid = @{}

        if ($wmiProcs) {

            foreach ($wp in $wmiProcs) {

                if ($wp.ProcessId -and $wp.ExecutablePath) {

                    $wmiByPid[[int]$wp.ProcessId] = $wp.ExecutablePath

                }

            }

        }



        foreach ($targetName in $Script:SilverFoxInjectTargets) {

            $baseName = [System.IO.Path]::GetFileNameWithoutExtension($targetName)

            $targetProcs = $null

            try { $targetProcs = Get-Process -Name $baseName -ErrorAction SilentlyContinue } catch { continue }

            if (-not $targetProcs) { continue }



            foreach ($tp in $targetProcs) {

                try {

                    $execPath = $wmiByPid[[int]$tp.Id]

                    if (-not $execPath) { continue }



                    # 仅检查路径异常：不在 System32/SysWOW64/Windows 目录

                    # 注意：svchost 多实例是 Windows 11 正常行为（80+个），不作为异常判定

                    # explorer.exe 正常位于 C:\Windows\（非 System32），需额外放行

                    $isWindowsDir = $execPath -like "C:\Windows\*"

                    $isSystem32   = $execPath -like "*System32*" -or $execPath -like "*SysWOW64*"

                    $pathAbnormal = -not $isWindowsDir -and -not $isSystem32



                    if ($pathAbnormal) {

                        $detailText = "PID: $($tp.Id)`n路径: $execPath`n$targetName 不在标准系统目录(System32/SysWOW64/Windows)"

                        Add-Result -Category "Processes" -Title "注入目标异常: $targetName" `
                            -Detail $detailText `
                            -RiskLevel "Critical" -Location "进程: $targetName (PID: $($tp.Id))" `
                            -Remediation "该进程可能已被银狐木马替换/注入，建议终止并排查" `
                            -CanBeFixed $true -FixType "StopProcess" -FixPid $tp.Id

                    }

                } catch {

                    Write-Log -Message "注入目标检测异常($targetName): $($_.Exception.Message)" -Level "DEBUG" -Module "ProcessCheck"

                }

            }

        }

    } catch {

        Write-Status "进程" "警告" "进程检测部分失败"

        Write-Log -Message "进程检测部分失败: $($_.Exception.Message)" -Level "WARN" -Module "ProcessCheck"

        Update-ErrorStats -Category "Detection"

    }

    

    Write-Status "进程" "完成" "发现 $($Script:Results.Processes.Count) 个可疑项"

}



# ============================================================

# 模块5：文件系统检测（精准聚焦银狐特征）

# ============================================================

function Invoke-FileCheck {

    Write-Status "文件" "扫描中" "检查银狐特征文件..."

    

    # [1] 6层随机目录检测（银狐2026新特征，最高优先级）

    Write-Status "文件" "扫描中" "检查6层随机目录..."

    $programDirs = @("C:\Program Files", "C:\Program Files (x86)")

    foreach ($pDir in $programDirs) {

        if (-not (Test-Path $pDir)) { continue }

        try {

            # 找4-8字符纯小写随机目录名

            Get-ChildItem -Path $pDir -Directory -ErrorAction SilentlyContinue | Where-Object {

                (Test-IsRandomName $_.Name)

            } | ForEach-Object {

                # 实时进度显示

                SafeWrite-Progress -Activity "扫描随机目录" -Status "正在扫描: $($_.FullName)"

                

                # 白名单排除已知合法软件

                if ((Test-IsLegitimatePath $_.FullName).IsLegit) { return }

                

                # 检查内部是否也有随机目录（多层嵌套）且exe名也是随机的

                $deepDirs = Get-ChildItem -Path $_.FullName -Recurse -Directory -ErrorAction SilentlyContinue -Depth 4

                $randomCount = ($deepDirs | Where-Object { (Test-IsRandomName $_.Name) }).Count

                

                # 关键：必须同时满足：随机子目录>=3 + 有随机名exe

                $hasExe = Get-ChildItem -Path $_.FullName -Recurse -Include "*.exe" -ErrorAction SilentlyContinue

                $hasRandomExe = $hasExe | Where-Object { (Test-IsRandomName $_.BaseName) }

                

                if ($randomCount -ge 3 -and $hasRandomExe -and -not $hasExe.Where({ -not (Test-IsRandomName $_.BaseName) -and $_.BaseName -notmatch '^(uninstall|uninst|setup|install)' })) {

                    # 签名校验：目录中任一 EXE 有合法厂商签名则跳过（防 ESET/Tabby/Warp 等误报）
                    $anySignedExe = $false
                    foreach ($exe in $hasExe) {
                        if ((Test-IsLegitimatePath $exe.FullName).IsLegit) { $anySignedExe = $true; break }
                    }
                    if ($anySignedExe) { return }

                    Add-Result -Category "Files" -Title "银狐6层随机目录" `
                        -Detail "路径: $($_.FullName)`n随机子目录数: $randomCount`n含随机EXE: $($hasRandomExe.Name -join ', ')`n银狐2026变种典型持久化结构" `
                        -RiskLevel "Critical" -Location $_.FullName `
                        -Remediation "隔离整个随机目录" `
                        -CanBeFixed $true -FixType "QuarantineDir" -FixFilePath $_.FullName

                }

            }

            SafeWrite-Progress -Activity "扫描随机目录" -Completed

        } catch {

            Write-Log -Message "6层随机目录检测异常: $($_.Exception.Message)" -Level "DEBUG" -Module "FileCheck"

        }

    }



    # [2]+[5]+[6] 合并扫描：白加黑DLL + 加密载荷 + MD5黑名单
    # 使用 .NET Directory.EnumerateFiles 替代 Get-ChildItem -Recurse，速度快 3-5 倍
    Write-Status "文件" "扫描中" "检查白加黑DLL/加密载荷/MD5黑名单..."
    $mergedScanPaths = @($env:APPDATA, $env:LOCALAPPDATA, $env:ProgramData, "C:\Program Files\Internet Explorer")
    $dllNameSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $Script:SilverFoxDLLs | ForEach-Object { $dllNameSet.Add($_) | Out-Null }
    $useHashCheck = $Script:SilverFoxKnownHashes.Count -gt 0
    $targetExts = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    @(".dll",".exe",".bat",".cmd",".com",".dat",".ini",".cfg") | ForEach-Object { $targetExts.Add($_) | Out-Null }
    $hashExts = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    @(".exe",".dll",".bat",".cmd",".com") | ForEach-Object { $hashExts.Add($_) | Out-Null }

    foreach ($searchPath in $mergedScanPaths) {
        if (-not (Test-Path $searchPath)) { continue }
        try {
            $enumOptions = [System.IO.EnumerationOptions]::new()
            $enumOptions.RecurseSubdirectories = $true
            $enumOptions.MaxRecursionDepth = 3
            $enumOptions.IgnoreInaccessible = $true
            $enumOptions.AttributesToSkip = [System.IO.FileAttributes]::ReparsePoint

            $dllFiles = @{}; $exeFiles = @{}; $datFiles = @(); $hashFiles = @()
            $fileCount = 0; $dirShort = Split-Path $searchPath -Leaf
            $enumerator = [System.IO.Directory]::EnumerateFiles($searchPath, "*", $enumOptions).GetEnumerator()
            while ($enumerator.MoveNext()) {
                $filePath = $enumerator.Current
                $fileCount++
                if ($fileCount % 200 -eq 0) {
                    Write-Status "文件" "扫描中" "[$dirShort] 已扫描 $fileCount 个文件..."
                }
                $ext = [System.IO.Path]::GetExtension($filePath).ToLower()
                if (-not $targetExts.Contains($ext)) { continue }
                try {
                    $fi = [System.IO.FileInfo]::new($filePath)
                    if ($ext -eq ".dll") {
                        $dirKey = $fi.DirectoryName.ToLower()
                        if (-not $dllFiles.ContainsKey($dirKey)) { $dllFiles[$dirKey] = @() }
                        $dllFiles[$dirKey] += $fi
                        if ($useHashCheck -and $fi.Length -lt 50MB) { $hashFiles += $fi }
                    }
                    elseif ($ext -eq ".exe") {
                        $dirKey = $fi.DirectoryName.ToLower()
                        if (-not $exeFiles.ContainsKey($dirKey)) { $exeFiles[$dirKey] = @() }
                        $exeFiles[$dirKey] += $fi
                        if ($useHashCheck -and $fi.Length -lt 50MB) { $hashFiles += $fi }
                    }
                    elseif ($hashExts.Contains($ext)) {
                        if ($useHashCheck -and $fi.Length -lt 50MB) { $hashFiles += $fi }
                    }
                    elseif ($fi.Length -gt 500KB) {
                        $datFiles += $fi
                    }
                } catch { }
            }
            Write-Log -Message "[$dirShort] 枚举完成: $fileCount 个文件, Hash候选=$($hashFiles.Count)" -Level "DEBUG" -Module "FileCheck"

            # --- 规则2：白加黑DLL检测 ---
            foreach ($dirKey in $dllFiles.Keys) {
                foreach ($dll in $dllFiles[$dirKey]) {
                    if (-not $dllNameSet.Contains($dll.Name)) { continue }
                    Write-Status "文件" "扫描中" "白加黑DLL: $($dll.Name)"
                    $legit = Test-IsLegitimatePath $dll.FullName
                    if ($legit.IsLegit) { continue }
                    $siblings = if ($exeFiles.ContainsKey($dirKey)) { $exeFiles[$dirKey] } else { @() }
                    if (-not $siblings) { continue }
                    $hasSigned = $false; $signedByTrusted = $false
                    foreach ($exe in $siblings) {
                        try {
                            $resolvedExe = try { (Resolve-Path $exe.FullName -ErrorAction Stop).Path } catch { $exe.FullName }
                            $exeCacheKey = $resolvedExe.ToLower()
                            $sig = if ($Script:SignatureCache.ContainsKey($exeCacheKey)) { $Script:SignatureCache[$exeCacheKey] }
                                   else { $s = Get-AuthenticodeSignature $exe.FullName -RevocationMode NoCheck -ErrorAction SilentlyContinue; $Script:SignatureCache[$exeCacheKey] = $s; $s }
                            if ($sig -and $sig.Status -eq "Valid") {
                                $hasSigned = $true
                                $certCN = $sig.SignerCertificate.Subject
                                foreach ($pub in $Script:TrustedPublishers) {
                                    if ($certCN -match [regex]::Escape($pub)) { $signedByTrusted = $true; break }
                                }
                                break
                            }
                        } catch { }
                    }
                    $reasons = @("非系统目录的$($dll.Name)")
                    if ($hasSigned) {
                        if ($signedByTrusted) { continue }
                        if ($legit.PathLegitHint) { $reasons += "同目录有签名EXE但路径段匹配合法软件"; $riskLevel = "Medium" }
                        else { $reasons += "同目录有签名EXE(白加黑)"; $riskLevel = "Critical" }
                    } else {
                        $reasons += "同目录有EXE但无有效签名"
                        if ($legit.SignedButUnknown -or $legit.PathLegitHint) { continue }
                        $riskLevel = "Medium"
                    }
                    Add-Result -Category "Files" -Title "白加黑DLL: $($dll.Name)" `
                        -Detail "DLL: $($dll.FullName)`n大小: $([math]::Round($dll.Length/1KB,1))KB`n原因: $($reasons -join '; ')" `
                        -RiskLevel $riskLevel -Location $dll.FullName `
                        -Remediation "隔离该DLL文件" `
                        -CanBeFixed $true -FixType "QuarantineFile" -FixFilePath $dll.FullName
                }
            }

            # --- 规则5：加密载荷检测 ---
            foreach ($dat in $datFiles) {
                Write-Status "文件" "扫描中" "检查加密载荷: $($dat.Name)"
                if ((Test-IsLegitimatePath $dat.FullName).IsLegit) { continue }
                try {
                    $bytes = [System.IO.File]::ReadAllBytes($dat.FullName)
                    if ($bytes.Length -gt 1000) {
                        $sampleSize = 2048
                        $sampleBytes = if ($bytes.Length -gt $sampleSize) { $bytes[0..($sampleSize-1)] } else { $bytes }
                        $freq = New-Object 'System.Collections.Generic.Dictionary[byte,int]'
                        foreach ($b in $sampleBytes) { if ($freq.ContainsKey($b)) { $freq[$b]++ } else { $freq[$b] = 1 } }
                        $entropy = 0.0; $total = $sampleBytes.Length
                        foreach ($v in $freq.Values) { $p = $v / $total; if ($p -gt 0) { $entropy -= $p * [Math]::Log($p, 2) } }
                        if ($entropy -gt 7.5) {
                            $dirKey = $dat.DirectoryName.ToLower()
                            $siblingExes = if ($exeFiles.ContainsKey($dirKey)) { $exeFiles[$dirKey] } else { @() }
                            $datDetail = "文件: $($dat.FullName)`n大小: $([math]::Round($dat.Length/1KB,1))KB`n熵值: $([math]::Round($entropy,2))(接近满熵=强加密)"
                            $datRisk = "Medium"
                            if ($siblingExes) { $datDetail += "`n同目录有EXE文件(白加黑特征)"; $datRisk = "High" }
                            else { $datDetail += "`n高熵文件，可能是加密载荷" }
                            Add-Result -Category "Files" -Title "疑似加密载荷: $($dat.Name)" `
                                -Detail $datDetail -RiskLevel $datRisk -Location $dat.FullName `
                                -Remediation "该文件可能是银狐AES-128-CBC加密的Shellcode，建议沙箱分析确认" `
                                -CanBeFixed $true -FixType "QuarantineFile" -FixFilePath $dat.FullName
                        }
                    }
                } catch {
                    Write-Log -Message "熵值计算失败($($dat.FullName)): $($_.Exception.Message)" -Level "DEBUG" -Module "FileCheck"
                }
            }

            # --- 规则6：MD5哈希黑名单检测 ---
            $hashTotal = $hashFiles.Count; $hashIdx = 0
            foreach ($file in $hashFiles) {
                $hashIdx++
                if ($hashIdx % 50 -eq 0) { Write-Status "文件" "扫描中" "MD5哈希匹配 [$hashIdx/$hashTotal]..." }
                try {
                    $hashInfo = Test-IsKnownSilverFoxHash $file.FullName
                    if ($hashInfo) {
                        Add-Result -Category "Files" -Title "哈希命中已知银狐样本: $($hashInfo.FileName)" `
                            -Detail "文件: $($file.FullName)`nMD5: $($hashInfo.Hash)`n变种: $($hashInfo.Variant)`n首次发现: $($hashInfo.FirstSeen)`n备注: $($hashInfo.Note)" `
                            -RiskLevel "Critical" -Location $file.FullName `
                            -Remediation "确认为银狐木马立即隔离，建议全盘排查同批次文件" `
                            -CanBeFixed $true -FixType "QuarantineFile" -FixFilePath $file.FullName
                    }
                } catch { }
            }
        } catch {
            Write-Log -Message "合并文件扫描异常($searchPath): $($_.Exception.Message)" -Level "DEBUG" -Module "FileCheck"
        }
    }

    # [6-补充] MD5黑名单：Temp/Windows\Temp（.NET 枚举）
    if ($useHashCheck) {
        foreach ($scanPath in @("$env:TEMP", "C:\Windows\Temp")) {
            if (-not (Test-Path $scanPath)) { continue }
            try {
                $enumOptions = [System.IO.EnumerationOptions]::new()
                $enumOptions.RecurseSubdirectories = $true
                $enumOptions.MaxRecursionDepth = 3
                $enumOptions.IgnoreInaccessible = $true
                $enumerator = [System.IO.Directory]::EnumerateFiles($scanPath, "*", $enumOptions).GetEnumerator()
                $tempCount = 0; $dirShort = Split-Path $scanPath -Leaf
                while ($enumerator.MoveNext()) {
                    $filePath = $enumerator.Current
                    $ext = [System.IO.Path]::GetExtension($filePath).ToLower()
                    if (-not $hashExts.Contains($ext)) { continue }
                    $tempCount++
                    if ($tempCount % 50 -eq 0) { Write-Status "文件" "扫描中" "[$dirShort] MD5匹配 $tempCount..." }
                    try {
                        $fi = [System.IO.FileInfo]::new($filePath)
                        if ($fi.Length -ge 50MB) { continue }
                        $hashInfo = Test-IsKnownSilverFoxHash $filePath
                        if ($hashInfo) {
                            Add-Result -Category "Files" -Title "哈希命中已知银狐样本: $($hashInfo.FileName)" `
                                -Detail "文件: $filePath`nMD5: $($hashInfo.Hash)`n变种: $($hashInfo.Variant)`n首次发现: $($hashInfo.FirstSeen)`n备注: $($hashInfo.Note)" `
                                -RiskLevel "Critical" -Location $filePath `
                                -Remediation "确认为银狐木马立即隔离，建议全盘排查同批次文件" `
                                -CanBeFixed $true -FixType "QuarantineFile" -FixFilePath $filePath
                        }
                    } catch { }
                }
            } catch { }
        }
    }

    # [3] BAT守护脚本检测

    Write-Status "文件" "扫描中" "检查BAT守护脚本..."

    # 缩窄 C:\Windows 搜索范围（银狐 BAT 通常在 Temp/Tasks/根目录，不会在 System32 深处）
    $batSearchPaths = @(
        "C:\Windows\Temp", "C:\Windows\Tasks", "C:\Windows\Tracing",
        $env:APPDATA, $env:LOCALAPPDATA, $env:ProgramData
    )

    foreach ($searchPath in $batSearchPaths) {

        if (-not (Test-Path $searchPath)) { continue }

        try {

            $enumOpts = [System.IO.EnumerationOptions]::new()
            $enumOpts.RecurseSubdirectories = $true
            $enumOpts.MaxRecursionDepth = 3
            $enumOpts.IgnoreInaccessible = $true
            $enumOpts.AttributesToSkip = [System.IO.FileAttributes]::ReparsePoint
            $batFiles = [System.IO.Directory]::EnumerateFiles($searchPath, "*", $enumOpts) |
                Where-Object { $_ -match '\.(bat|cmd)$' } |
                ForEach-Object { [System.IO.FileInfo]::new($_) }

            foreach ($bat in $batFiles) {

                # 实时进度显示

                SafeWrite-Progress -Activity "扫描BAT脚本" -Status "正在扫描: $($bat.FullName)"

                

                # 白名单：排除系统目录下的正常文件

                if ($bat.FullName -match '\\GroupPolicy\\') { continue }

                if ($bat.FullName -match '\\WinSxS\\') { continue }

                if ($bat.FullName -match '\\Microsoft\\') { continue }

                # 白名单：排除 Python/Node/开发工具自带的脚本

                if ($bat.FullName -match '\\idlelib\\|\\Scripts\\|\\node_modules\\|\\Lib\\') { continue }

                # 白名单：排除 Windows AppCompat 系统工具（TSMKUDIR.CMD 等）

                if ($bat.FullName -match '\\TSMKUDIR\\|\\AppCompat\\') { continue }



                # 白名单

                if ((Test-IsLegitimatePath $bat.FullName).IsLegit) { continue }

                

                try {

                    # 跳过大于 500KB 的 BAT（银狐守护脚本通常很小）
                    if ($bat.Length -gt 500KB) { continue }

                    $content = Get-Content $bat.FullName -ErrorAction SilentlyContinue -TotalCount 30

                    if (-not $content) { continue }

                    $contentStr = $content -join " "

                    

                    # 计算匹配的守护关键词数（关键词本身含正则语法，不做Escape）

                    $matchCount = 0

                    $matchedKeywords = @()

                    foreach ($kw in $Script:BatGuardKeywords) {

                        if ($contentStr -match $kw) {

                            $matchCount++

                            $matchedKeywords += $kw.Trim()

                        }

                    }

                    

                    # 需要匹配3个以上关键词才报警（降低误报）

                    if ($matchCount -ge 3) {

                        Add-Result -Category "Files" -Title "BAT守护脚本" `
                            -Detail "文件: $($bat.FullName)`n匹配关键词($matchCount): $($matchedKeywords -join ', ')`n银狐使用BAT脚本反复拉起木马进程" `
                            -RiskLevel "Critical" -Location $bat.FullName `
                            -Remediation "隔离该脚本" `
                            -CanBeFixed $true -FixType "QuarantineFile" -FixFilePath $bat.FullName

                    }



                    # BAT 混淆检测：计算 ^ 和 % 符号密度（银狐常用 s^e^t、%comspec% 等混淆手段）

                    if ($contentStr.Length -gt 20) {

                        $caretCount = ([regex]::Matches($contentStr, '\^')).Count
                        $percentCount = ([regex]::Matches($contentStr, '%')).Count

                        $obfuscRatio = ($caretCount + $percentCount) / $contentStr.Length

                        if ($obfuscRatio -ge 0.15 -and $matchCount -lt 3) {

                            # 混淆密度异常但未触发关键词规则 → 单独报告

                            Add-Result -Category "Files" -Title "BAT混淆脚本" `
                                -Detail "文件: $($bat.FullName)`n混淆符号密度: $([math]::Round($obfuscRatio*100,1))% (^x$caretCount, %x$percentCount)`n银狐常用BAT混淆手段绕过检测" `
                                -RiskLevel "High" -Location $bat.FullName `
                                -Remediation "隔离该脚本" `
                                -CanBeFixed $true -FixType "QuarantineFile" -FixFilePath $bat.FullName

                        }

                    }

                } catch {

                    Write-Log -Message "BAT脚本内容读取失败: $($_.Exception.Message)" -Level "DEBUG" -Module "FileCheck"

                }

            }

        } catch {

            Write-Log -Message "BAT守护脚本检测异常: $($_.Exception.Message)" -Level "DEBUG" -Module "FileCheck"

        }

        SafeWrite-Progress -Activity "扫描BAT脚本" -Completed

    }



    # [4] Windows目录下隐藏文件夹中的可执行文件

    Write-Status "文件" "扫描中" "检查Windows隐藏文件夹..."

    try {

        Get-ChildItem -Path "C:\Windows" -Directory -Hidden -ErrorAction SilentlyContinue | Where-Object {

            -not $Script:KnownWinDirsSet.Contains($_.Name)

        } | ForEach-Object {

            # 实时进度显示

            SafeWrite-Progress -Activity "扫描Windows隐藏目录" -Status "正在扫描: $($_.FullName)"

            

            $exeFiles = Get-ChildItem -Path $_.FullName -Recurse -Include "*.exe","*.dll" -ErrorAction SilentlyContinue -Depth 2

            if ($exeFiles) {

                # 白名单排除

                $suspiciousExes = $exeFiles | Where-Object { -not (Test-IsLegitimatePath $_.FullName).IsLegit }

                

                if ($suspiciousExes) {

                    Add-Result -Category "Files" -Title "Windows隐藏目录可疑文件" `
                        -Detail "目录: $($_.FullName)`n可疑文件: $($suspiciousExes.Name -join ', ')`n银狐常在Windows目录创建隐藏文件夹存放木马" `
                        -RiskLevel "High" -Location $_.FullName `
                        -Remediation "检查文件是否合法，确认恶意后隔离" `
                        -CanBeFixed $true -FixType "QuarantineDir" -FixFilePath $_.FullName

                }

            }

        }

        SafeWrite-Progress -Activity "扫描Windows隐藏目录" -Completed

    } catch {

        Write-Log -Message "Windows隐藏目录检测异常: $($_.Exception.Message)" -Level "DEBUG" -Module "FileCheck"

    }



    # [7] 已知恶意文件名扫描（银狐情报共享IOC）
    # 优化：只枚举目录一次，用 HashSet 匹配所有恶意文件名（O(1) × N 文件 vs 旧方案 M×N 次递归）

    Write-Status "文件" "扫描中" "扫描已知恶意文件名..."

    $malNameSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $Script:KnownMaliciousFileNames | ForEach-Object { $malNameSet.Add($_) | Out-Null }

    $fileNameScanPaths = @(
        "C:\Windows\Temp", "C:\Windows\Tasks", "C:\Windows\Tracing",
        $env:ProgramData, $env:APPDATA, $env:LOCALAPPDATA,
        "$env:TEMP", "C:\Program Files\Internet Explorer",
        "C:\Users\Public\Documents"
    )

    foreach ($scanPath in $fileNameScanPaths) {
        if (-not (Test-Path $scanPath)) { continue }
        try {
            $enumOpts = [System.IO.EnumerationOptions]::new()
            $enumOpts.RecurseSubdirectories = $true
            $enumOpts.MaxRecursionDepth = 3
            $enumOpts.IgnoreInaccessible = $true
            $enumOpts.AttributesToSkip = [System.IO.FileAttributes]::ReparsePoint
            $enumerator = [System.IO.Directory]::EnumerateFiles($scanPath, "*", $enumOpts).GetEnumerator()
            $dirShort = Split-Path $scanPath -Leaf
            $fileCount = 0
            while ($enumerator.MoveNext()) {
                $filePath = $enumerator.Current
                $fileCount++
                if ($fileCount % 500 -eq 0) {
                    Write-Status "文件" "扫描中" "恶意文件名扫描 [$dirShort] $fileCount..."
                }
                $fileName = [System.IO.Path]::GetFileName($filePath)
                if (-not $malNameSet.Contains($fileName)) { continue }
                try {
                    $fi = [System.IO.FileInfo]::new($filePath)
                    if ((Test-IsLegitimatePath $fi.FullName).IsLegit) { continue }
                    Add-Result -Category "Files" -Title "已知银狐恶意文件: $fileName" `
                        -Detail "文件: $($fi.FullName)`n大小: $([math]::Round($fi.Length/1KB,1))KB`n该文件名匹配银狐IOC情报" `
                        -RiskLevel "Critical" -Location $fi.FullName `
                        -Remediation "立即隔离该文件，建议全盘搜索同名文件" `
                        -CanBeFixed $true -FixType "QuarantineFile" -FixFilePath $fi.FullName
                } catch { }
            }
        } catch {
            Write-Log -Message "恶意文件名扫描异常($scanPath): $($_.Exception.Message)" -Level "DEBUG" -Module "FileCheck"
        }
    }
    SafeWrite-Progress -Activity "恶意文件名扫描" -Completed



    # [8] Startup目录检测（常见持久化手段）

    Write-Status "文件" "扫描中" "检查Startup目录..."

    $startupDirs = @(

        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",

        "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"

    )

    foreach ($sd in $startupDirs) {

        if (-not (Test-Path $sd)) { continue }

        try {

            Get-ChildItem -Path $sd -File -ErrorAction SilentlyContinue | ForEach-Object {

                SafeWrite-Progress -Activity "Startup目录检测" -Status "正在扫描: $($_.FullName)"

                if ((Test-IsLegitimatePath $_.FullName).IsLegit) { return }

                $suspicionScore = 0

                $reasons = @("Startup目录中的文件")

                # 可执行文件

                if ($_.Extension -match '\.(exe|dll|bat|cmd|vbs|ps1|js|lnk)') {

                    $suspicionScore += 3

                    $reasons += "扩展名: $($_.Extension)"

                }

                # LNK快捷方式检查目标

                if ($_.Extension -eq ".lnk") {

                    try {

                        if (-not $Script:WshShell) {

                            try {

                                $Script:WshShell = New-Object -ComObject WScript.Shell -ErrorAction Stop

                            } catch {

                                Write-Log -Message "WScript.Shell COM 创建失败，LNK 解析不可用: $($_.Exception.Message)" -Level "WARN" -Module "FileCheck"

                                $Script:WshShell = $null

                            }

                        }

                        if ($Script:WshShell) {

                            $lnk = $Script:WshShell.CreateShortcut($_.FullName)

                            $target = $lnk.TargetPath

                            if ($target -match 'AppData|ProgramData|\\Temp\\') {

                                $suspicionScore += 3

                                $reasons += "LNK指向可疑路径: $target"

                            }

                        }

                    } catch {

                        Write-Log -Message "LNK解析失败: $($_.Exception.Message)" -Level "DEBUG" -Module "FileCheck"

                    }

                }

                # 随机文件名

                if (Test-IsRandomName $_.BaseName) {

                    $suspicionScore += 2

                    $reasons += "随机文件名"

                }

                if ($suspicionScore -ge 3) {

                    $riskLevel = if ($suspicionScore -ge 5) { "High" } else { "Medium" }

                    Add-Result -Category "Files" -Title "Startup目录可疑文件: $($_.Name)" `
                        -Detail "文件: $($_.FullName)`n可疑度: $suspicionScore | 原因: $($reasons -join '; ')" `
                        -RiskLevel $riskLevel -Location $_.FullName `
                        -Remediation "检查该文件是否合法，确认后隔离" `
                        -CanBeFixed $true -FixType "QuarantineFile" -FixFilePath $_.FullName

                }

            }

        } catch {

            Write-Log -Message "Startup目录检测异常: $($_.Exception.Message)" -Level "DEBUG" -Module "FileCheck"

        }

        SafeWrite-Progress -Activity "Startup目录检测" -Completed

    }



    Write-Status "文件" "完成" "发现 $($Script:Results.Files.Count) 个可疑项"

}



# ============================================================

# 模块6：网络连接与DNS检测

# ============================================================

function Invoke-NetworkCheck {

    Write-Status "网络" "扫描中" "检查网络连接..."



    # 预取所有进程命令行，构建PID->CommandLine字典（性能优化）

    $pidToCmdLine = Get-ProcessCommandLineDict



    # [1] 已确认恶意域名DNS缓存匹配

    # 优先使用 Get-DnsClientCache（Win8/2012+，无视系统语言），失败则回退 ipconfig /displaydns

    Write-Status "网络" "扫描中" "检查恶意域名IOC..."

    try {

        $dnsCacheDomains = @{}

        # 方式一：Get-DnsClientCache（推荐，无视系统语言）

        $dnsCache = $null

        try { $dnsCache = Get-DnsClientCache -ErrorAction Stop } catch { }

        if ($dnsCache) {

            foreach ($record in $dnsCache) {

                if ($record.Type -eq 1) { # A 记录

                    $entryName = if ($record.Entry) { $record.Entry.ToLower() } else { $record.RecordName.ToLower() }

                    $data = if ($record.Data) { $record.Data } else { $null }

                    if ($entryName -and $data) { $dnsCacheDomains[$entryName] = $data }

                }

            }

        } else {

            # 方式二：回退 ipconfig /displaydns（依赖系统语言：中/英文）

            $dnsOutput = ipconfig /displaydns 2>$null

            $currentDomain = $null

            $currentIP = $null

            foreach ($line in $dnsOutput) {

                if ($line -match '^\s*记录名称\.\s*:\s*(.+)$' -or $line -match '^\s*Record Name\.\s*:\s*(.+)$') {

                    $currentDomain = $Matches[1].Trim().ToLower()

                }

                elseif ($line -match '^\s*A \(主机\) 记录\s*:\s*(.+)$' -or $line -match '^\s*A \(Host\) Record\s*:\s*(.+)$') {

                    $currentIP = $Matches[1].Trim()

                    if ($currentDomain) {

                        $dnsCacheDomains[$currentDomain] = $currentIP

                    }

                }

            }

        }

        # 检查恶意域名 — HashSet O(1) 查找

        foreach ($domain in $Script:ConfirmedMaliciousDomains) {

            $domainLower = $domain.ToLower()

            # 精确匹配

            if ($dnsCacheDomains.ContainsKey($domainLower)) {

                $resolvedIP = $dnsCacheDomains[$domainLower]

                Add-Result -Category "DNS" -Title "DNS缓存命中银狐C2域名" `
                    -Detail "域名: $domain`n解析IP: $resolvedIP`n该域名为银狐木马家族已确认C2域名" `
                    -RiskLevel "Critical" -Location "DNS缓存: $domain" `
                    -Remediation "立即封禁该域名及解析IP($resolvedIP)，检查发起DNS请求的进程" `
                    -CanBeFixed $false

                continue

            }

            # 子域匹配：afraid.org 等动态DNS服务的子域

            if ($domain -eq "afraid.org") {

                foreach ($cachedDomain in $dnsCacheDomains.Keys) {

                    if ($cachedDomain -match '\.afraid\.org$') {

                        $resolvedIP = $dnsCacheDomains[$cachedDomain]

                        Add-Result -Category "DNS" -Title "DNS缓存命中FreeDNS动态DNS子域" `
                            -Detail "域名: $cachedDomain`n解析IP: $resolvedIP`n该域名为FreeDNS(afraid.org)子域，银狐/XRed木马通过FreeDNS动态DNS获取C2服务器IP" `
                            -RiskLevel "High" -Location "DNS缓存: $cachedDomain" `
                            -Remediation "封禁该子域及解析IP($resolvedIP)，检查发起DNS请求的进程是否为恶意" `
                            -CanBeFixed $false

                    }

                }

            }

        }

    } catch {

        Write-Log -Message "DNS缓存检测异常: $($_.Exception.Message)" -Level "WARN" -Module "NetworkCheck"

        Update-ErrorStats -Category "Detection"

    }



    # [2] 可疑外联检测

    #     核心系统进程(svchost/lsass/csrss/wininit/services等)不做外联检测和终止，

    #     因为误杀会导致蓝屏/系统崩溃。仅检测非系统进程的异常外联。

    try {

        $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue

        # 回退：Get-NetTCPConnection 可能在某些系统上失败���旧版PS/权限不足），用 netstat 兜底

        if (-not $connections) {

            $connections = @()

            $netstatOut = netstat -ano -p tcp 2>$null | Select-String '^\s+TCP\s+\S+:\S+\s+(\[.+?\]|\S+):(\d+)\s+ESTABLISHED\s+(\d+)'

            foreach ($line in $netstatOut) {

                $m = $line.Matches[0]

                $addr = $m.Groups[1].Value -replace '^\[|\]$', ''  # 去除 IPv6 方括号

                $connections += [PSCustomObject]@{

                    RemoteAddress = $addr

                    RemotePort    = [int]$m.Groups[2].Value

                    OwningProcess = [int]$m.Groups[3].Value

                }

            }

        }

        

        foreach ($conn in $connections) {

            $remoteIP = $conn.RemoteAddress

            $remotePort = $conn.RemotePort

            $procId = $conn.OwningProcess



            # 跳过本地/内网 - 改进：添加链路本地地址过滤

            if ($remoteIP -match '^(0\.0\.0\.0|127\.|::1|::$|fe80|169\.254\.)') { continue }

            if ($remoteIP -match '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)') { continue }



            try {

                $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue

                if (-not $proc) { continue }

                $procName = $proc.ProcessName



                # 绝对保护：核心系统进程不做检测（防止误杀导致蓝屏）— HashSet O(1)

                if ($Script:ProtectedProcSet.Contains($procName)) { continue }



                # 白名单进程跳过 — HashSet O(1)

                if ($Script:LegitNetProcSet.Contains($procName)) { continue }



                # Gh0st远控常见端口 — HashSet O(1)

                if ($Script:GhostPortSet.Contains($remotePort)) {

                    $cmdLine = if ($pidToCmdLine.ContainsKey($procId)) { $pidToCmdLine[$procId] } else { "" }



                    Add-Result -Category "Network" -Title "可疑外联(Gh0st端口)" `
                        -Detail "进程: $procName (PID: $procId)`n远程: ${remoteIP}:${remotePort}`n命令行: $cmdLine`n端口$remotePort为Gh0st远控常见端口" `
                        -RiskLevel "Critical" -Location "进程: $procName -> ${remoteIP}:${remotePort}" `
                        -Remediation "阻断连接，终止进程，封禁IP" `
                        -CanBeFixed $true -FixType "StopProcess" -FixPid $procId

                    continue

                }



                # 仅在进程路径可疑时才报告非标准端口外联（避免大量误报）
                # 可疑条件：进程位于 Temp/AppData/ProgramData 等非常规目录

                if (-not $Script:CommonPortSet.Contains($remotePort)) {

                    try {
                        $procPath = $proc.Path
                        if ($procPath -and $procPath -match '\\(Temp|AppData\\Local\\Temp|ProgramData)\\') {
                            $cmdLine = if ($pidToCmdLine.ContainsKey($procId)) { $pidToCmdLine[$procId] } else { "" }

                            Add-Result -Category "Network" -Title "可疑外联" `
                                -Detail "进程: $procName (PID: $procId)`n路径: $procPath`n远程: ${remoteIP}:${remotePort}`n命令行: $cmdLine`nTemp目录进程连接到非常见端口" `
                                -RiskLevel "Medium" -Location "进程: $procName -> ${remoteIP}:${remotePort}" `
                                -Remediation "检查该连接是否为正常通信" `
                                -CanBeFixed $false
                        }
                    } catch { }

                }

            } catch {

                Write-Log -Message "网络连接检测异常: $($_.Exception.Message)" -Level "DEBUG" -Module "NetworkCheck"

            }

        }



        # [3] C2 动态DNS API模式检测（FreeDNS afraid.org 等）

        #     银狐通过 HTTP 请求动态DNS API 获取 C2 IP，DNS缓存中可能只看到 afraid.org

        #     通过进程命令行/网络连接目标匹配 API URL 模式

        try {

            foreach ($wmiProc in (Get-CimProcessCache)) {

                $cmdLine = $wmiProc.CommandLine

                if ([string]::IsNullOrEmpty($cmdLine)) { continue }

                foreach ($c2Pattern in $Script:C2DynamicDNSPatterns) {

                    if ($cmdLine -match $c2Pattern.Pattern) {

                        $procName = $wmiProc.Name

                        $procId = $wmiProc.ProcessId

                        # 检查是否已报告过同一进程+模式（去重）

                        $dupKey = "$procId|$($c2Pattern.Pattern)"

                        if (-not $Script:C2PatternReported) { $Script:C2PatternReported = @{} }

                        if ($Script:C2PatternReported.ContainsKey($dupKey)) { continue }

                        $Script:C2PatternReported[$dupKey] = $true



                        Add-Result -Category "DNS" -Title "C2动态DNS API请求: $($c2Pattern.Desc)" `
                            -Detail "进程: $procName (PID: $procId)`n命令行: $cmdLine`n匹配模式: $($c2Pattern.Pattern)`n银狐通过FreeDNS等动态DNS服务获取C2服务器IP，无需硬编码域名" `
                            -RiskLevel $c2Pattern.Risk -Location "进程: $procName (PID: $procId)" `
                            -Remediation "立即终止该进程，封禁freedns.afraid.org域名，排查感染来源" `
                            -CanBeFixed $true -FixType "StopProcess" -FixPid $procId

                    }

                }

            }

        } catch {

            Write-Log -Message "C2动态DNS模式检测异常: $($_.Exception.Message)" -Level "WARN" -Module "NetworkCheck"

        }



        # [4] C2 IP黑名单检测（银狐情报共享IOC）— HashSet O(1)

        foreach ($c2Conn in $connections) {

            $remoteIP = $c2Conn.RemoteAddress

            $remotePort = $c2Conn.RemotePort

            $procId = $c2Conn.OwningProcess

            if ($remoteIP -match '^(0\.0\.0\.0|127\.|::1|fe80)') { continue }

            if ($remoteIP -match '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)') { continue }



            # 单 IP HashSet O(1) + CIDR 子网匹配

            $isMaliciousIP = $Script:MaliciousIPSet.Contains($remoteIP)

            if (-not $isMaliciousIP) {

                foreach ($cidr in $Script:MaliciousCIDRs) {

                    if (Test-IPInCIDR $remoteIP $cidr.IP $cidr.Prefix) { $isMaliciousIP = $true; break }

                }

            }

            if ($isMaliciousIP) {

                try {

                    $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue

                    $procName = if ($proc) { $proc.ProcessName } else { "已退出" }

                    $cmdLine = if ($pidToCmdLine.ContainsKey($procId)) { $pidToCmdLine[$procId] } else { "" }

                    Add-Result -Category "Network" -Title "C2 IP外联（已知银狐C2）" `
                        -Detail "进程: $procName (PID: $procId)`n远程: ${remoteIP}:${remotePort}`n该IP为银狐已知C2地址`n命令行: $cmdLine" `
                        -RiskLevel "Critical" -Location "进程: $procName -> ${remoteIP}:${remotePort}" `
                        -Remediation "立即隔离主机，阻断该IP，排查感染途径" `
                        -CanBeFixed $false

                } catch {

                    Write-Log -Message "C2 IP检测异常($remoteIP): $($_.Exception.Message)" -Level "DEBUG" -Module "NetworkCheck"

                }

            }

        }

    } catch {

        Write-Status "网络" "警告" "网络检测部分失败"

    }

    

    Write-Status "网络" "完成" "发现 $($Script:Results.Network.Count + $Script:Results.DNS.Count) 个可疑项"

}



# ============================================================

# 模块7：WMI 持久化检测

# ============================================================

function Invoke-WmiCheck {

    Write-Status "WMI" "扫描中" "检查WMI持久化..."



    # 银狐变种使用 WMI EventSubscription 实现无文件持久化

    # 检测方式：枚举所有 WMI 事件订阅，检查是否存在可疑的消费者



    try {

        # [1] 检查 WMI EventFilter（事件过滤器）— 加超时防止 WMI 服务卡死

        $filters = Get-CimInstance -Namespace "root/subscription" -ClassName __EventFilter -OperationTimeoutSec 15 -ErrorAction SilentlyContinue

        $consumers = Get-CimInstance -Namespace "root/subscription" -ClassName __EventConsumer -OperationTimeoutSec 15 -ErrorAction SilentlyContinue

        $bindings = Get-CimInstance -Namespace "root/subscription" -ClassName __FilterToConsumerBinding -OperationTimeoutSec 15 -ErrorAction SilentlyContinue



        if ($filters -or $consumers) {

            foreach ($filter in $filters) {

                $filterName = $filter.Name

                $query = $filter.Query

                $suspicionScore = 0

                $reasons = @()



                # 检查查询是否针对进程创建/系统启动等事件

                if ($query -match 'Win32_ProcessStartTrace|Win32_Process|__InstanceCreationEvent.*Win32_LogicalDisk|Win32_SystemDriver') {

                    $suspicionScore += 3

                    $reasons += "监听进程创建/驱动加载事件: $($query.Substring(0, [Math]::Min(80, $query.Length)))"

                }



                # 检查是否是定时触发

                if ($query -match '__InstanceModificationEvent.*Win32_LocalTime|__TimerEvent') {

                    $suspicionScore += 2

                    $reasons += "定时触发事件"

                }



                # 查找对应的消费者

                $matchedConsumer = $null

                foreach ($binding in $bindings) {

                    if ($binding.Filter -and $binding.Filter.Name -eq $filterName) {

                        $consumerRef = $binding.Consumer

                        foreach ($c in $consumers) {

                            if ($c.Name -eq ($consumerRef -replace '.*Name="([^"]+)".*', '$1')) {

                                $matchedConsumer = $c

                                break

                            }

                        }

                    }

                }



                if ($matchedConsumer) {

                    $consumerType = $matchedConsumer.CimClass.CimClassName

                    $consumerName = $matchedConsumer.Name



                    # 检查消费者类型

                    if ($consumerType -eq "CommandLineEventConsumer") {

                        $cmdLine = $matchedConsumer.CommandLineTemplate

                        $suspicionScore += 4

                        $reasons += "命令行消费者: $consumerType"



                        # 检查命令是否可疑

                        if ($cmdLine -match 'powershell|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin') {

                            $suspicionScore += 3

                            $reasons += "可疑命令: $($cmdLine.Substring(0, [Math]::Min(60, $cmdLine.Length)))"

                        }

                        if ($cmdLine -match 'DownloadString|DownloadFile|IEX|Invoke-Expression|FromBase64|-enc') {

                            $suspicionScore += 4

                            $reasons += "PowerShell恶意特征"

                        }

                        if ($cmdLine -match 'AppData|ProgramData|Temp') {

                            $suspicionScore += 2

                            $reasons += "指向用户目录"

                        }

                    }

                    elseif ($consumerType -eq "ActiveScriptEventConsumer") {

                        $scriptText = $matchedConsumer.ScriptText

                        $suspicionScore += 4

                        $reasons += "脚本消费者: $consumerType"



                        if ($scriptText -match 'WScript\.Shell|Shell\.Execute|Run\(|powershell|cmd') {

                            $suspicionScore += 3

                            $reasons += "可疑脚本命令"

                        }

                    }

                    else {

                        $suspicionScore += 2

                        $reasons += "消费者类型: $consumerType"

                    }



                    # 检查消费者路径是否可疑

                    $executablePath = $matchedConsumer.ExecutablePath

                    if ($executablePath) {

                        if ($executablePath -match 'AppData|ProgramData|Temp') {

                            $suspicionScore += 3

                            $reasons += "可执行文件在可疑路径"

                        }

                        if (-not (Test-IsLegitimatePath $executablePath).IsLegit) {

                            $suspicionScore += 2

                            $reasons += "未通过签名校验"

                        }

                    }

                }



                if ($suspicionScore -ge 3) {

                    $riskLevel = if ($suspicionScore -ge 8) { "Critical" }

                                 elseif ($suspicionScore -ge 5) { "High" }

                                 else { "Medium" }



                    $consumerInfo = if ($matchedConsumer) { "`n消费者: $($matchedConsumer.Name) ($($matchedConsumer.CimClass.CimClassName))" } else { "" }

                    $cmdInfo = ""

                    if ($matchedConsumer -and $matchedConsumer.CimClass.CimClassName -eq "CommandLineEventConsumer") {

                        $cmdInfo = "`n命令: $($matchedConsumer.CommandLineTemplate)"

                    }

                    if ($matchedConsumer -and $matchedConsumer.CimClass.CimClassName -eq "ActiveScriptEventConsumer") {

                        $scriptPreview = $matchedConsumer.ScriptText

                        if ($scriptPreview.Length -gt 100) { $scriptPreview = $scriptPreview.Substring(0, 100) + "..." }

                        $cmdInfo = "`n脚本: $scriptPreview"

                    }



                    Add-Result -Category "Registry" -Title "WMI持久化: $filterName" `
                        -Detail "过滤器: $filterName`n查询: $($query.Substring(0, [Math]::Min(100, $query.Length)))$consumerInfo$cmdInfo`n可疑度: $suspicionScore | 原因: $($reasons -join '; ')" `
                        -RiskLevel $riskLevel -Location "WMI EventSubscription" `
                        -Remediation "删除WMI事件订阅（过滤器+消费者+绑定）" `
                        -CanBeFixed $false  # WMI清理需要特殊处理，暂不自动修复

                }

            }

        }



        # [2] 检查 WMI 恶意脚本存储 — 加超时防止遍历卡死

        $wmiClasses = Get-CimInstance -Namespace "root/cimv2" -ClassName __Namespace -OperationTimeoutSec 15 -ErrorAction SilentlyContinue |

            Where-Object { $_.Name -match 'Security|WindowsDefender|Update|Service' }

        foreach ($cls in $wmiClasses) {

            try {

                $targetClasses = @("__EventFilter","__EventConsumer","__FilterToConsumerBinding","AntiVirusProduct","FirewallProduct")
                $instances = foreach ($tc in $targetClasses) {
                    Get-CimInstance -Namespace "root/cimv2/$($cls.Name)" -ClassName $tc -OperationTimeoutSec 15 -ErrorAction SilentlyContinue
                }

                foreach ($inst in $instances) {

                    $props = $inst.CimInstanceProperties

                    foreach ($prop in $props) {

                        $val = $prop.Value

                        if ($val -is [string] -and $val.Length -gt 200) {

                            # 检查是否包含脚本代码

                            if ($val -match 'powershell|cmd\.exe|wscript|cscript|CreateObject|WScript\.Shell') {

                                Add-Result -Category "Registry" -Title "WMI脚本存储" `
                                    -Detail "命名空间: root/cimv2/$($cls.Name)`n属性: $($prop.Name)`n内容: $($val.Substring(0, [Math]::Min(200, $val.Length)))`n银狐可能将恶意脚本存储在WMI属性中实现无文件持久化" `
                                    -RiskLevel "Critical" -Location "WMI: root/cimv2/$($cls.Name)" `
                                    -Remediation "清除WMI属性中的恶意脚本内容" `
                                    -CanBeFixed $false

                            }

                        }

                    }

                }

            } catch {

                # 某些命名空间可能无法访问，忽略

            }

        }



    } catch {

        Write-Log -Message "WMI持久化检测异常: $($_.Exception.Message)" -Level "WARN" -Module "WmiCheck"

        Update-ErrorStats -Category "Detection"

    }



    Write-Status "WMI" "完成" "WMI持久化检���完成"

}



# ============================================================

# 模块8：Hosts 文件检测

# ============================================================

function Invoke-HostsCheck {

    Write-Status "Hosts" "扫描中" "检查hosts文件劫持..."



    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"

    try {

        if (-not (Test-Path $hostsPath)) {

            Write-Status "Hosts" "完成" "hosts文件不存在"

            return

        }

        $lines = Get-Content $hostsPath -ErrorAction Stop

        foreach ($line in $lines) {

            $trimmed = $line.Trim()

            if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }

            if ($trimmed.StartsWith("#")) { continue }



            # 解析 IP 域名 格式

            $parts = $trimmed -split '\s+'

            if ($parts.Count -lt 2) { continue }

            $ip = $parts[0]

            $domains = $parts[1..($parts.Count-1)]



            # 跳过 localhost/广播地址

            if ($ip -match '^(127\.0\.0\.1|0\.0\.0\.0|::1|fe80)') { continue }



            foreach ($domain in $domains) {

                if ([string]::IsNullOrWhiteSpace($domain)) { continue }

                $domain = $domain.ToLower()



                # 检查是否为已知 C2 域名重定向

                if ($Script:MaliciousDomainSet.Contains($domain)) {

                    Add-Result -Category "Hosts" -Title "Hosts劫持: C2域名重定向" `
                        -Detail "hosts 文件将 $domain 重定向到 $ip`n该域名是已知银狐C2地址，重定向可能用于流量劫持或绕过DNS检测" `
                        -RiskLevel "Critical" -Location $hostsPath `
                        -Remediation "删除hosts文件中的该行，恢复DNS正常解析" `
                        -CanBeFixed $false

                    continue

                }



                # 检查非 127.0.0.1 的外部 IP 重定向（可疑）

                if ($ip -notmatch '^(127\.|0\.0\.0\.0|::1|fe80)') {

                    # 跳过 RFC1918 私有地址重定向（内网开发/测试环境常用）

                    if ($ip -match '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)') { continue }

                    # 跳过本地开发域名

                    if ($domain -match '\.(local|lan|internal|test|dev|corp|home)$') { continue }

                    Add-Result -Category "Hosts" -Title "Hosts可疑重定向" `
                        -Detail "hosts 文件将 $domain 重定向到 $ip`n非标准的外部IP重定向，可能是流量劫持" `
                        -RiskLevel "Medium" -Location $hostsPath `
                        -Remediation "检查该重定向是否合法，如非预期则删除" `
                        -CanBeFixed $false

                }

            }

        }

    } catch {

        Write-Log -Message "Hosts文件检测异常: $($_.Exception.Message)" -Level "WARN" -Module "HostsCheck"

        Update-ErrorStats -Category "Detection"

    }



    Write-Status "Hosts" "完成" "发现 $($Script:Results.Hosts.Count) 个可疑项"

}



# ============================================================

# 模块9：BITS 传输任务检测

# ============================================================

function Invoke-BitsCheck {

    Write-Status "BITS" "扫描中" "检查BITS传输任务..."



    try {

        $bitsJobs = Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue

        if (-not $bitsJobs) {

            Write-Status "BITS" "完成" "无BITS任务"

            return

        }



        # 已知合法 BITS 任务名称前缀

        $legitBitsNames = @("Mozilla","Firefox","Chrome","Edge","GoogleUpdate","WindowsUpdate",

            "Microsoft","Adobe","NVIDIA","Intel","Apple","Opera","Brave","OneDrive")



        foreach ($job in $bitsJobs) {

            # 跳过已知合法更新任务

            $displayName = $job.DisplayName

            $isLegitBits = $false

            foreach ($legit in $legitBitsNames) {

                if ($displayName -match "^$([regex]::Escape($legit))") { $isLegitBits = $true; break }

            }

            if ($isLegitBits) { continue }



            $suspicionScore = 0

            $reasons = @()



            # [1] 检查 Owner 是否非 SYSTEM

            $owner = $job.Owner

            if ($owner -and $owner -notmatch '^(NT AUTHORITY\\SYSTEM|BUILTIN\\|SYSTEM)$') {

                $suspicionScore += 2

                $reasons += "Owner非SYSTEM: $owner"

            }



            # [2] 检查任务名称和描述

            $desc = $job.Description

            $susKeywords = @("update","download","temp","http","https","powershell","cmd","bat","vbs")

            foreach ($kw in $susKeywords) {

                if ($displayName -match $kw -or $desc -match $kw) {

                    $suspicionScore += 1

                    $reasons += "名称/描述含关��词: $kw"

                    break

                }

            }



            # [3] 检查文件目标路径

            $fileList = $job.FileList

            if ($fileList) {

                foreach ($file in $fileList) {

                    $localName = $file.LocalName

                    if ([string]::IsNullOrWhiteSpace($localName)) { continue }

                    if ($localName -match '\\Temp\\|\\AppData\\|\\ProgramData\\') {

                        $suspicionScore += 3

                        $reasons += "目标路径可疑: $localName"

                        break

                    }

                }

            }



            # [4] 检查远程 URL

            if ($fileList) {

                foreach ($file in $fileList) {

                    $remoteName = $file.RemoteName

                    if ([string]::IsNullOrWhiteSpace($remoteName)) { continue }

                    # DynamicDNS 域名

                    if ($remoteName -match 'afraid\.org|freedns|duckdns|no-ip\.com|dynu\.com') {

                        $suspicionScore += 4

                        $reasons += "DynamicDNS URL: $remoteName"

                    }

                    # IP 地址直连

                    if ($remoteName -match 'https?://\d+\.\d+\.\d+\.\d+') {

                        $suspicionScore += 2

                        $reasons += "IP直连URL: $remoteName"

                    }

                }

            }



            # [5] 任务状态异常

            if ($job.JobState -eq "Transferring" -or $job.JobState -eq "Queued") {

                $suspicionScore += 1

                $reasons += "任务状态: $($job.JobState)"

            }



            if ($suspicionScore -ge 3) {

                $riskLevel = if ($suspicionScore -ge 5) { "High" } else { "Medium" }

                $filePaths = ($fileList | ForEach-Object { $_.LocalName }) -join "`n"

                Add-Result -Category "Bits" -Title "可疑BITS任务: $displayName" `
                    -Detail "任务: $displayName (ID: $($job.JobId))`nOwner: $owner`n状态: $($job.JobState)`n文件: $filePaths`n可疑度: $suspicionScore | 原因: $($reasons -join '; ')" `
                    -RiskLevel $riskLevel -Location "BITS任务" `
                    -Remediation "使用 Remove-BitsTransfer 删除可疑任务" `
                    -CanBeFixed $false

            }

        }

    } catch {

        Write-Log -Message "BITS检测异常: $($_.Exception.Message)" -Level "DEBUG" -Module "BitsCheck"

    }



    Write-Status "BITS" "完成" "发现 $($Script:Results.Bits.Count) 个可疑项"

}



# ============================================================

# 模块10：Named Pipe 枚举检测

# ============================================================

function Invoke-PipeCheck {

    Write-Status "管道" "扫描中" "检查命名管道..."



    # KnownSystemPipes 已在全局初始化区定义（$Script:KnownSystemPipes）



    try {

        $pipes = [System.IO.Directory]::GetFiles("\\.\pipe\")

        foreach ($pipePath in $pipes) {

            $pipeName = $pipePath -replace '^\\\\\.\\pipe\\', ''



            # 跳过已知系统管道

            if ($Script:KnownSystemPipes.Contains($pipeName)) { continue }



            # 跳过常见命名模式（进程间通信管道 + 知名软件管道前缀）

            if ($pipeName -match '^(pipe|crashpad|mojo|chrome|edge|firefox|discord|slack|teams|wecom|wxwork|tencent|wps|qing|elive|recentfile|workbuddy|pshost|rp)') { continue }

            if ($pipeName -match '^\d+$') { continue }  # 纯数字管道（PID）



            # 尝试获取管道拥有进程

            $ownerProc = $null

            try {

                # 通过管道名查找相关进程

                $pipeProcName = ($pipeName -split '[\._\-]')[0]

                $ownerProc = Get-Process -Name $pipeProcName -ErrorAction SilentlyContinue | Select-Object -First 1

            } catch { }



            # 检查管道名是否随机

            $isRandom = Test-IsRandomName $pipeName

            $suspicionScore = 0

            $reasons = @()



            if ($isRandom) {

                $suspicionScore += 3

                $reasons += "随机命名管道"

            }



            # 检查是否有可疑关键词（\b词边界防子串误匹配：Administrator≠rat, powershell≠shell, hex_c2≠c2）

            $pipeLower = $pipeName.ToLower()

            $susKeywords = @("malware","trojan","rat","backdoor","c2","cmd","shell","beacon","empire","cobalt")

            foreach ($kw in $susKeywords) {

                if ($pipeLower -match "\b$kw\b") {

                    $suspicionScore += 5

                    $reasons += "可疑关键词: $kw"

                    break

                }

            }



            # 检查管道名模式（银狐/Gh0st 常见模式）

            if ($pipeName -match '^[a-z]{2,5}_[a-z]{2,8}_\d{1,4}$') {

                $suspicionScore += 3

                $reasons += "匹配银狐命名模式"

            }



            if ($suspicionScore -ge 3) {

                $riskLevel = if ($suspicionScore -ge 5) { "High" } else { "Medium" }

                $procInfo = if ($ownerProc) { "$($ownerProc.ProcessName) (PID: $($ownerProc.Id))" } else { "未知" }

                Add-Result -Category "Pipes" -Title "可疑命名管道: $pipeName" `
                    -Detail "管道: \\.\pipe\$pipeName`n拥有进程: $procInfo`n可疑度: $suspicionScore | 原因: $($reasons -join '; ')" `
                    -RiskLevel $riskLevel -Location "\\.\pipe\$pipeName" `
                    -Remediation "检查该管道的拥有进程是否合法" `
                    -CanBeFixed $false

            }

        }

    } catch {

        Write-Log -Message "命名管道检测异常: $($_.Exception.Message)" -Level "DEBUG" -Module "PipeCheck"

    }



    Write-Status "管道" "完成" "发现 $($Script:Results.Pipes.Count) 个可疑项"

}



function Invoke-Cleanup {

    param([switch]$AutoMode)



    # AutoMode: noConsole 模式下 Write-Host 会抛异常，用局部函数包装

    $writeCleanup = if ($AutoMode) {

        { param($msg, $color) <# 静默 #> }

    } else {

        { param($msg, $color) Write-Host $msg -ForegroundColor $color }

    }



    & $writeCleanup "" "White"

    & $writeCleanup "========================================" "Yellow"

    & $writeCleanup "  银狐木马查杀清理" "Yellow"

    & $writeCleanup "========================================" "Yellow"

    & $writeCleanup "" "White"

    & $writeCleanup "[!] 警告：清理操作将修改系统设置和隔离文件！" "Red"

    & $writeCleanup "[!] 建议先运行检测并导出报告，确认后再执行清理！" "Red"

    & $writeCleanup "[!] 重启删除：若文件被驱动保护，重启后可能仍存在，需安全模式清理！" "Yellow"

    & $writeCleanup "" "White"



    # 获取运行时目录（兼容ps2exe编译）

    $scriptDir = $PSScriptRoot

    try {

        $exeDir = [System.IO.Path]::GetDirectoryName([System.Reflection.Assembly]::GetExecutingAssembly().Location)

        if ($exeDir -and (Test-Path $exeDir)) { $scriptDir = $exeDir }

    } catch {

        Write-Log -Message "获取EXE目录失败: $($_.Exception.Message)" -Level "DEBUG" -Module "Cleanup"

    }



    # 按依赖关系排序：先Services -> Tasks -> Processes -> Registry -> Files

    # 服务和任务会重启进程，所以先停；进程锁文件，所以后隔离

    $orderedCategories = @("Services","Tasks","Processes","Registry","Files")

    $allItems = @()

    foreach ($cat in $orderedCategories) {

        $allItems += $Script:Results[$cat] | Where-Object { $_.CanBeFixed }

    }



    if ($allItems.Count -eq 0) {

        & $writeCleanup "没有可自动清理的项目。" "Green"

        return

    }



    # 系统核心进程保护名单 — 使用全局 HashSet

    # 使用全局 $Script:ProtectedProcSet (HashSet O(1)) 替代本地数组



    & $writeCleanup "可清理的项目列表（已按依赖关系排序：服务→任务→进程→注册表→文件）：" "Cyan"

    $idx = 1

    foreach ($item in $allItems) {

        if ($AutoMode) {

            # AutoMode: 跳过列表输出，但检查保护

            $skipItem = $false

            if ($item.FixType -eq "StopProcess" -and $item.FixPid -gt 0) {

                try {

                    $p = Get-Process -Id $item.FixPid -ErrorAction SilentlyContinue

                    if ($p -and $Script:ProtectedProcSet.Contains($p.ProcessName)) {

                        $isSystemCore = $false

                        $procPath = $p.Path

                        if (-not $procPath) { $procPath = $p.MainModule.FileName }

                        if ($procPath -like "C:\Windows\System32\*" -or $procPath -like "C:\Windows\SysWOW64\*") {

                            $isSystemCore = $true

                        }

                        if ($isSystemCore) { $skipItem = $true }

                    }

                } catch {

                    Write-Log -Message "进程保护检查异常: $($_.Exception.Message)" -Level "DEBUG" -Module "Cleanup"

                }

            }

            if ($skipItem) { $idx++; continue }

            $idx++

            continue

        }

        $color = if ($item.RiskLevel -eq "Critical") { "Red" } elseif ($item.RiskLevel -eq "High") { "Yellow" } else { "White" }

        $protected = ""

        if ($item.FixType -eq "StopProcess" -and $item.FixPid -gt 0) {

            try {

                $p = Get-Process -Id $item.FixPid -ErrorAction SilentlyContinue

                if ($p -and $Script:ProtectedProcSet.Contains($p.ProcessName)) {

                    $protected = " [受保护-不可杀]"

                }

            } catch {

                Write-Log -Message "进程检查异常: $($_.Exception.Message)" -Level "DEBUG" -Module "Cleanup"

            }

        }

        $catLabel = switch ($item.FixType) {

            "StopAndDisableService" { "服务" }

            "UnregisterTask"       { "任务" }

            "StopProcess"          { "进程" }

            "RemoveRegProp"        { "注册表" }

            "RestoreBootExecute"   { "注册表" }

            "QuarantineFile"       { "文件" }

            "QuarantineDir"        { "目录" }

            default                { "其他" }

        }

        Write-Host "  [$idx] " -NoNewline -ForegroundColor White

        Write-Host "[$($item.RiskLevel)][$catLabel] " -NoNewline -ForegroundColor $color

        Write-Host "$($item.Title)$protected" -ForegroundColor White

        Write-Host "      位置: $($item.Location)" -ForegroundColor Gray

        $idx++

    }



    # 选择清理项

    $selected = @()

    if ($AutoMode) {

        # AutoMode: 自动全选（已排除受保护进程）

        $selected = 1..$allItems.Count

    } else {

        Write-Host ""

        Write-Host "输入要清理的项目编号(多个用逗号分隔, 0=全部清理, q=退出): " -NoNewline -ForegroundColor Cyan

        $input_str = Read-Host



        if ($input_str -eq "q") { return }



        if ($input_str -eq "0") {

            $selected = 1..$allItems.Count

        } else {

            foreach ($part in ($input_str -split ",")) {

                $trimmed = $part.Trim()

                $num = 0

                if ([int]::TryParse($trimmed, [ref]$num) -and $num -ge 1 -and $num -le $allItems.Count) {

                    $selected += $num

                }

                # 非法输入静默忽略

            }

        }

    }



    # 创建隔离目录 - 改进：添加权限检查和备用目录

    $quarantineDir = $null

    $quarantineDirCandidates = @(

        (Join-Path $scriptDir "SilverFox_Quarantine_$(Get-Date -Format 'yyyyMMdd_HHmmss')"),

        (Join-Path $env:TEMP "SilverFox_Quarantine_$(Get-Date -Format 'yyyyMMdd_HHmmss')"),

        (Join-Path $env:USERPROFILE "Desktop\SilverFox_Quarantine_$(Get-Date -Format 'yyyyMMdd_HHmmss')")

    )

    foreach ($candidateDir in $quarantineDirCandidates) {

        try {

            $testFile = Join-Path $candidateDir ".write_test"

            New-Item -Path $candidateDir -ItemType Directory -Force -ErrorAction Stop | Out-Null

            "test" | Out-File $testFile -Force -ErrorAction Stop

            Remove-Item $testFile -Force -ErrorAction SilentlyContinue

            $quarantineDir = $candidateDir

            & $writeCleanup "[i] 隔离目录: $quarantineDir" "Cyan"

            break

        } catch {

            Write-Log -Message "无法使用隔离目录 $candidateDir : $($_.Exception.Message)" -Level "WARN" -Module "Cleanup"

            continue

        }

    }

    if (-not $quarantineDir) {

        & $writeCleanup "[!] 警告：无法创建隔离目录，文件清理将仅注册重启删除" "Red"

        $quarantineDir = "N/A"

    }



    # 清理统计（使用 $script: 保持与 API 路由共享）

    $script:cleanStats = @{ Success = 0; Fail = 0; Skip = 0; RebootPending = 0 }



    # 回滚日志：记录所有清理操作，用于手动恢复

    $rollbackLog = @()

    $rollbackLogFile = Join-Path $scriptDir "SilverFox_Rollback_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"



    # Kernel32 MoveFileEx 声明（用于重启删除）

    $moveFileExCode = @'

using System;

using System.Runtime.InteropServices;

public class NativeMethods {

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]

    public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);

}

'@

    try { Add-Type -TypeDefinition $moveFileExCode -ErrorAction SilentlyContinue } catch {

        Write-Log -Message "NativeMethods类型注册失败，重启删除功能可能不可用: $($_.Exception.Message)" -Level "WARN" -Module "Cleanup"

        Update-ErrorStats -Category "System"

    }

    $MOVEFILE_DELAY_UNTIL_REBOOT = 0x4



    foreach ($i in $selected) {

        $item = $allItems[$i - 1]

        & $writeCleanup "清理: $($item.Title)... " "Yellow"

        try {

            switch ($item.FixType) {

                "RemoveRegProp" {

                    # 记录回滚信息

                    $rollbackLog += "[REG] 删除注册表值: $($item.FixRegPath)\$($item.FixRegName)"

                    Remove-ItemProperty -Path $item.FixRegPath -Name $item.FixRegName -Force -ErrorAction Stop

                    & $writeCleanup "OK (已删除注册表值)" "Green"

                    $script:cleanStats.Success++

                }

                "RestoreBootExecute" {

                    # BootExecute 恢复默认值（不是删除，否则系统重启可能蓝屏）

                    $rollbackLog += "[REG] 恢复BootExecute为默认值"

                    Set-ItemProperty -Path $item.FixRegPath -Name $item.FixRegName -Value @("autocheck autochk *") -Type MultiString -Force -ErrorAction Stop

                    & $writeCleanup "OK (已恢复BootExecute默认值)" "Green"

                    $script:cleanStats.Success++

                }

                "UnregisterTask" {

                    # 记录回滚信息

                    $rollbackLog += "[TASK] 删除计划任务: $($item.FixTaskPath)$($item.FixTaskName)"

                    Unregister-ScheduledTask -TaskName $item.FixTaskName -TaskPath $item.FixTaskPath -Confirm:$false -ErrorAction Stop

                    & $writeCleanup "OK (已删除计划任务)" "Green"

                    $script:cleanStats.Success++

                }

                "StopAndDisableService" {

                    # 获取服务原始启动类型用于回滚

                    $originalStartup = (Get-CimInstance Win32_Service -Filter "Name='$($item.FixServiceName)'" -ErrorAction SilentlyContinue).StartMode

                    $rollbackLog += "[SVC] 禁用服务: $($item.FixServiceName) (原启动类型: $originalStartup)"

                    Stop-Service -Name $item.FixServiceName -Force -ErrorAction SilentlyContinue

                    Set-Service -Name $item.FixServiceName -StartupType Disabled -ErrorAction Stop

                    & $writeCleanup "OK (已停止并禁用服��)" "Green"

                    $script:cleanStats.Success++

                }

                "StopProcess" {

                    # 系统核心进程保护 — 绝对不杀

                    if ($item.FixPid -gt 0) {

                        $p = Get-Process -Id $item.FixPid -ErrorAction SilentlyContinue

                        if ($p -and $Script:ProtectedProcSet.Contains($p.ProcessName)) {

                            $isSystemCore = $false

                            try {

                                $procPath = $p.Path

                                if (-not $procPath) { $procPath = $p.MainModule.FileName }

                                if ($procPath -like "C:\Windows\System32\*" -or $procPath -like "C:\Windows\SysWOW64\*") {

                                    $isSystemCore = $true

                                }

                            } catch {

                                Write-Log -Message "进程路径检查异常: $($_.Exception.Message)" -Level "DEBUG" -Module "Cleanup"

                            }

                            if ($isSystemCore) {

                                & $writeCleanup "SKIP (系统核心进程,禁止终止)" "Red"

                                $script:cleanStats.Skip++

                                break

                            }

                            # 如果不是系统核心进程，则继续终止（可能是伪装进程）

                        }

                        # 记录回滚信息

                        $rollbackLog += "[PROC] 终止进程: $($item.FixPid) ($($item.Title))"

                        Stop-Process -Id $item.FixPid -Force -ErrorAction Stop

                        & $writeCleanup "OK (已终止进程)" "Green"

                        $script:cleanStats.Success++

                    } else {

                        & $writeCleanup "SKIP (无效PID)" "Red"

                        $script:cleanStats.Skip++

                    }

                }

                "QuarantineFile" {

                    if ($quarantineDir -eq "N/A") {

                        # 无隔离目录，直接注册重启删除

                        if ([NativeMethods]::MoveFileEx($item.FixFilePath, $null, $MOVEFILE_DELAY_UNTIL_REBOOT)) {

                            $rollbackLog += "[FILE] 重启删除: $($item.FixFilePath)"

                            & $writeCleanup "OK (已注册重启删除)" "Yellow"

                            $script:cleanStats.RebootPending++

                        } else {

                            & $writeCleanup "FAIL: 无法注册重启删除" "Red"

                            $script:cleanStats.Fail++

                        }

                        break

                    }

                    if (-not (Test-Path $quarantineDir)) { New-Item -Path $quarantineDir -ItemType Directory -Force | Out-Null }

                    $dest = Join-Path $quarantineDir (Split-Path $item.FixFilePath -Leaf)

                    $counter = 1

                    while (Test-Path $dest) { $dest = Join-Path $quarantineDir "$([System.IO.Path]::GetFileNameWithoutExtension($item.FixFilePath))_$counter$([System.IO.Path]::GetExtension($item.FixFilePath))"; $counter++ }

                    try {

                        # 记录回滚信息

                        $rollbackLog += "[FILE] 隔离文件: $($item.FixFilePath) -> $dest"

                        Move-Item -Path $item.FixFilePath -Destination $dest -Force -ErrorAction Stop

                        & $writeCleanup "OK (已隔离)" "Green"

                        $script:cleanStats.Success++

                    } catch {

                        # 文件被锁定 → 尝试重启删除

                        if ([NativeMethods]::MoveFileEx($item.FixFilePath, $null, $MOVEFILE_DELAY_UNTIL_REBOOT)) {

                            $rollbackLog += "[FILE] 重启删除: $($item.FixFilePath)"

                            & $writeCleanup "OK (已注册重启删除)" "Yellow"

                            $script:cleanStats.RebootPending++

                        } else {

                            & $writeCleanup "FAIL: 文件被锁定，无法隔离或注册重启删除" "Red"

                            $script:cleanStats.Fail++

                        }

                    }

                }

                "QuarantineDir" {

                    if (-not (Test-Path $quarantineDir)) { New-Item -Path $quarantineDir -ItemType Directory -Force | Out-Null }

                    $dirName = Split-Path $item.FixFilePath -Leaf

                    $dest = Join-Path $quarantineDir $dirName

                    $counter = 1

                    while (Test-Path $dest) { $dest = Join-Path $quarantineDir "${dirName}_$counter"; $counter++ }

                    try {

                        Move-Item -Path $item.FixFilePath -Destination $dest -Force -ErrorAction Stop

                        & $writeCleanup "OK (已隔离)" "Green"

                        $script:cleanStats.Success++

                    } catch {

                        # 目录被锁定 → 尝试逐文件注册重启删除

                        $rebootScheduled = $false

                        try {

                            $lockedFiles = Get-ChildItem -Path $item.FixFilePath -Recurse -File -ErrorAction SilentlyContinue

                            foreach ($lf in $lockedFiles) {

                                if ([NativeMethods]::MoveFileEx($lf.FullName, $null, $MOVEFILE_DELAY_UNTIL_REBOOT)) {

                                    $rebootScheduled = $true

                                }

                            }

                            if ($rebootScheduled) {

                                & $writeCleanup "OK (目录内文件已注册重启删除)" "Yellow"

                                $script:cleanStats.RebootPending++

                            } else {

                                & $writeCleanup "FAIL: $_" "Red"

                                $script:cleanStats.Fail++

                            }

                        } catch {

                            & $writeCleanup "FAIL: $_" "Red"

                            $script:cleanStats.Fail++

                        }

                    }

                }

                default {

                    & $writeCleanup "SKIP (未知清理类型: $($item.FixType))" "Red"

                    $script:cleanStats.Skip++

                }

            }

        } catch {

            & $writeCleanup "FAIL: $_" "Red"

            $script:cleanStats.Fail++

        }

    }



    # 清理汇总

    & $writeCleanup "" "White"

    & $writeCleanup "========================================" "Cyan"

    & $writeCleanup "  清理汇总" "Cyan"

    & $writeCleanup "========================================" "Cyan"

    & $writeCleanup "  成功: $($script:cleanStats.Success)" "Green"

    $failColor = if ($script:cleanStats.Fail -gt 0) { "Red" } else { "Gray" }

    & $writeCleanup "  失败: $($script:cleanStats.Fail)" $failColor

    & $writeCleanup "  跳过: $($script:cleanStats.Skip)" "Gray"

    $rebootColor = if ($script:cleanStats.RebootPending -gt 0) { "Yellow" } else { "Gray" }

    & $writeCleanup "  待重启删除: $($script:cleanStats.RebootPending)" $rebootColor

    & $writeCleanup "" "White"



    if (Test-Path $quarantineDir) {

        & $writeCleanup "[i] 隔离目录: $quarantineDir" "Cyan"

        & $writeCleanup "[i] 确认安全后可手动删除隔离目录" "Cyan"

    }

    if ($script:cleanStats.RebootPending -gt 0) {

        & $writeCleanup "[!] 有 $($script:cleanStats.RebootPending) 个文件注册了重启删除，请重启系统完成清理" "Yellow"

    }



    # 写入回滚日志

    if ($rollbackLog.Count -gt 0) {

        $rollbackContent = "银狐木马清理回滚日志`n生成时间: $(Get-Date)`n主机: $($Script:HostName)`n`n"

        $rollbackContent += "=== 清理操作记录 ===`n"

        $rollbackContent += $rollbackLog -join "`n"

        $rollbackContent += "`n`n=== 手动恢复指南 ===`n"

        $rollbackContent += "如需恢复，请根据上述记录手动执行反向操作。`n"

        $rollbackContent += "注册表值: 使用 reg add 命令恢复`n"

        $rollbackContent += "计划任务: 使用 schtasks /create 命令恢复`n"

        $rollbackContent += "服务: 使用 sc config 命令恢复启动类型`n"

        $rollbackContent += "文件: 从隔离目录复制回原位置`n"

        $rollbackContent | Out-File $rollbackLogFile -Encoding UTF8 -Force

        & $writeCleanup "[i] 回滚日志: $rollbackLogFile" "Cyan"

    }



    & $writeCleanup "清理完成。建议重新运行检测确认清理效果。" "Green"

}



# ============================================================

# HTML报告生成

# ============================================================

function Export-HtmlReport {

    # 获取运行时目录（兼容ps2exe编译）

    $scriptDir = $PSScriptRoot

    try {

        $exeDir = [System.IO.Path]::GetDirectoryName([System.Reflection.Assembly]::GetExecutingAssembly().Location)

        if ($exeDir -and (Test-Path $exeDir)) { $scriptDir = $exeDir }

    } catch {

        Write-Log -Message "获取EXE目录失败: $($_.Exception.Message)" -Level "DEBUG" -Module "Cleanup"

    }

    $reportPath = Join-Path $scriptDir "SilverFox_Report_$($Script:HostName)_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"

    

    $totalFindings = ($Script:Results.Registry + $Script:Results.Tasks + $Script:Results.Services +

                      $Script:Results.Processes + $Script:Results.Files + $Script:Results.Network +

                      $Script:Results.DNS + $Script:Results.Hosts + $Script:Results.Bits +

                      $Script:Results.Pipes).Count

    

    $criticalCount = $Script:Results.Summary.Critical

    $highCount = $Script:Results.Summary.High

    $mediumCount = $Script:Results.Summary.Medium

    

    $overallRisk = if ($criticalCount -gt 0) { "严重" } elseif ($highCount -gt 0) { "高危" } elseif ($mediumCount -gt 0) { "中危" } else { "安全" }

    $overallColor = if ($criticalCount -gt 0) { "#e74c3c" } elseif ($highCount -gt 0) { "#e67e22" } elseif ($mediumCount -gt 0) { "#f39c12" } else { "#27ae60" }

    $overallIcon = if ($criticalCount -gt 0) { "&#x1F6A8;" } elseif ($highCount -gt 0) { "&#x26A0;" } elseif ($mediumCount -gt 0) { "&#x1F50D;" } else { "&#x2705;" }

    

    $html = @"

<!DOCTYPE html>

<html lang="zh-CN">

<head>

<meta charset="UTF-8">

<meta name="viewport" content="width=device-width,initial-scale=1.0">

<title>银狐木马检测报告 - $($Script:HostName)</title>

<style>

*{margin:0;padding:0;box-sizing:border-box}

body{font-family:'Segoe UI','Microsoft YaHei',sans-serif;background:#0a0e27;color:#e0e0e0;line-height:1.6}

.container{max-width:1200px;margin:0 auto;padding:20px}

.header{background:linear-gradient(135deg,#1a1a3e 0%,#0d1b2a 100%);border-radius:16px;padding:40px;margin-bottom:24px;border:1px solid rgba(255,255,255,0.05);position:relative;overflow:hidden}

.header::before{content:'';position:absolute;top:-50%;right:-20%;width:400px;height:400px;background:radial-gradient(circle,rgba(231,76,60,0.15) 0%,transparent 70%);border-radius:50%}

.header h1{font-size:28px;font-weight:700;margin-bottom:8px;color:#fff}

.header .subtitle{color:#8892b0;font-size:14px}

.header .meta{display:flex;gap:32px;margin-top:20px;flex-wrap:wrap}

.header .meta-item{display:flex;flex-direction:column}

.header .meta-label{font-size:11px;color:#8892b0;text-transform:uppercase;letter-spacing:1px}

.header .meta-value{font-size:14px;color:#ccd6f6;font-weight:500}

.risk-banner{background:$overallColor;border-radius:12px;padding:24px 32px;margin-bottom:24px;display:flex;align-items:center;justify-content:space-between}

.risk-banner .risk-level{font-size:32px;font-weight:800;color:#fff}

.risk-banner .risk-desc{font-size:14px;color:rgba(255,255,255,0.9)}

.risk-banner .risk-icon{font-size:48px}

.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:24px}

.stat-card{background:#111631;border-radius:12px;padding:20px;border:1px solid rgba(255,255,255,0.05)}

.stat-card .stat-number{font-size:36px;font-weight:800;margin-bottom:4px}

.stat-card .stat-label{font-size:13px;color:#8892b0}

.stat-critical .stat-number{color:#e74c3c}

.stat-high .stat-number{color:#e67e22}

.stat-medium .stat-number{color:#f39c12}

.stat-low .stat-number{color:#3498db}

.stat-info .stat-number{color:#8892b0}

.section{background:#111631;border-radius:12px;padding:24px;margin-bottom:24px;border:1px solid rgba(255,255,255,0.05)}

.section-title{font-size:18px;font-weight:700;margin-bottom:16px;display:flex;align-items:center;gap:10px}

.section-count{font-size:12px;background:rgba(255,255,255,0.1);padding:2px 10px;border-radius:20px;color:#8892b0}

.finding{background:#0d1b2a;border-radius:10px;padding:16px 20px;margin-bottom:12px;border-left:4px solid #555}

.finding:hover{background:#162035}

.finding.critical{border-left-color:#e74c3c}

.finding.high{border-left-color:#e67e22}

.finding.medium{border-left-color:#f39c12}

.finding.low{border-left-color:#3498db}

.finding-title{font-size:15px;font-weight:600;margin-bottom:6px;display:flex;align-items:center;gap:8px}

.finding-detail{font-size:13px;color:#8892b0;white-space:pre-line;margin-bottom:8px}

.finding-meta{display:flex;gap:16px;font-size:12px;color:#5a6785;flex-wrap:wrap}

.finding-meta span{display:flex;align-items:center;gap:4px}

.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700}

.badge-critical{background:rgba(231,76,60,0.2);color:#e74c3c}

.badge-high{background:rgba(230,126,34,0.2);color:#e67e22}

.badge-medium{background:rgba(243,156,18,0.2);color:#f39c12}

.badge-low{background:rgba(52,152,219,0.2);color:#3498db}

.fixable{background:rgba(39,174,96,0.15);color:#27ae60;padding:2px 8px;border-radius:4px;font-size:11px}

.empty{text-align:center;padding:32px;color:#5a6785}

.empty .empty-icon{font-size:40px;margin-bottom:8px}

.footer{text-align:center;padding:24px;color:#5a6785;font-size:12px}

</style>

</head>

<body>

<div class="container">

<div class="header">

<h1>银狐木马检测报告</h1>

<div class="subtitle">SilverFox (Silver Fox) Trojan Detection Report v2.9.1</div>

<div class="meta">

<div class="meta-item"><span class="meta-label">主机名</span><span class="meta-value">$(ConvertTo-HtmlSafe $Script:HostName)</span></div>

<div class="meta-item"><span class="meta-label">操作系统</span><span class="meta-value">$(ConvertTo-HtmlSafe $Script:OSVersion)</span></div>

<div class="meta-item"><span class="meta-label">当前用户</span><span class="meta-value">$(ConvertTo-HtmlSafe $Script:CurrentUser)</span></div>

<div class="meta-item"><span class="meta-label">扫描时间</span><span class="meta-value">$($Script:ScanTime)</span></div>

</div>

</div>

<div class="risk-banner">

<div>

<div class="risk-level">风险等级：$overallRisk</div>

<div class="risk-desc">共发现 $totalFindings 个检测项，其中严重 $criticalCount 个、高危 $highCount 个、中危 $mediumCount 个</div>

</div>

<div class="risk-icon">$overallIcon</div>

</div>

<div class="stats">

<div class="stat-card stat-critical"><div class="stat-number">$criticalCount</div><div class="stat-label">严重 (Critical)</div></div>

<div class="stat-card stat-high"><div class="stat-number">$highCount</div><div class="stat-label">高危 (High)</div></div>

<div class="stat-card stat-medium"><div class="stat-number">$mediumCount</div><div class="stat-label">中危 (Medium)</div></div>

<div class="stat-card stat-low"><div class="stat-number">$($Script:Results.Summary.Low)</div><div class="stat-label">低危 (Low)</div></div>

<div class="stat-card stat-info"><div class="stat-number">$($Script:Results.Summary.Info)</div><div class="stat-label">信息 (Info)</div></div>

</div>

"@



    $sections = @(

        @{ Key="Registry";  Title="注册表启动项检测"; Icon="&#x1F4CB;" }

        @{ Key="Tasks";     Title="计划任务检测";     Icon="&#x23F0;" }

        @{ Key="Services";  Title="系统服务检测";     Icon="&#x2699;" }

        @{ Key="Processes"; Title="进程与DLL侧加载检测"; Icon="&#x1F50D;" }

        @{ Key="Files";     Title="文件系统检测";     Icon="&#x1F4C1;" }

        @{ Key="Network";   Title="网络连接检测";     Icon="&#x1F310;" }

        @{ Key="DNS";       Title="DNS域名IOC检测";   Icon="&#x1F517;" }

        @{ Key="Hosts";     Title="Hosts文件劫持检测"; Icon="&#x1F3E0;" }

        @{ Key="Bits";      Title="BITS传输任务检测"; Icon="&#x1F4E5;" }

        @{ Key="Pipes";     Title="命名管道检测";     Icon="&#x1F50C;" }

    )

    

    foreach ($sec in $sections) {

        $items = $Script:Results[$sec.Key]

        $html += "<div class=`"section`"><div class=`"section-title`"><span>$($sec.Icon)</span> $($sec.Title) <span class=`"section-count`">$($items.Count) 项</span></div>"

        

        if ($items.Count -eq 0) {

            $html += "<div class=`"empty`"><div class=`"empty-icon`">&#x2705;</div><div>未发现异常</div></div>"

        } else {

            foreach ($item in $items) {

                $rc = $item.RiskLevel.ToLower()

                $fixableTag = if ($item.CanBeFixed) { '<span class="fixable">可清理</span>' } else { "" }

                $detailEscaped = ConvertTo-HtmlSafe $item.Detail

                $locationEscaped = ConvertTo-HtmlSafe $item.Location

                $remediationEscaped = ConvertTo-HtmlSafe $item.Remediation

                $titleEscaped = ConvertTo-HtmlSafe $item.Title

                

                $html += @"

<div class="finding $rc">

<div class="finding-title"><span class="badge badge-$rc">$($item.RiskLevel)</span> $titleEscaped $fixableTag</div>

<div class="finding-detail">$detailEscaped</div>

<div class="finding-meta"><span>位置: $locationEscaped</span><span>处置: $remediationEscaped</span><span>时间: $($item.Timestamp)</span></div>

</div>

"@

            }

        }

        $html += "</div>"

    }



    # 添加错误统计和诊断信息

    $detColor = if ($Script:ErrorStats.Detection -gt 0) { '#e74c3c' } else { '#27ae60' }

$clnColor = if ($Script:ErrorStats.Cleanup -gt 0) { '#e74c3c' } else { '#27ae60' }

$sysColor = if ($Script:ErrorStats.System -gt 0) { '#e74c3c' } else { '#27ae60' }

$totColor = if ($Script:ErrorStats.Total -gt 0) { '#e67e22' } else { '#27ae60' }

$html += @"

<div class="section">

<div class="section-title"><span>&#x1F4CA;</span> 检测过程统计</div>

<div class="stat-card" style="background:#111631;border-radius:12px;padding:20px;margin-bottom:12px;">

<div style="display:flex;justify-content:space-between;flex-wrap:wrap;gap:16px;">

<div><span style="color:#8892b0;">检测错误:</span> <span style="color:$detColor;font-weight:bold;">$($Script:ErrorStats.Detection)</span></div>

<div><span style="color:#8892b0;">清理错误:</span> <span style="color:$clnColor;font-weight:bold;">$($Script:ErrorStats.Cleanup)</span></div>

<div><span style="color:#8892b0;">系统错误:</span> <span style="color:$sysColor;font-weight:bold;">$($Script:ErrorStats.System)</span></div>

<div><span style="color:#8892b0;">总错误数:</span> <span style="color:$totColor;font-weight:bold;">$($Script:ErrorStats.Total)</span></div>

</div>

</div>

</div>

"@



    # 应急处置建议 - 根据检测结果定制

    $customRecommendations = @()

    if ($Script:Results.Registry.Count -gt 0) {

        $customRecommendations += "注册表持久化：检查发现的启动项是否已清理，建议使用Autoruns复查"

    }

    if ($Script:Results.Tasks.Count -gt 0) {

        $customRecommendations += "计划任务持久化：检查发现的计划任务是否已禁用，注意BAT守护脚本可能重新创建任务"

    }

    if ($Script:Results.Services.Count -gt 0) {

        $customRecommendations += "服务持久化：检查发现的服务是否已停止禁用，注意服���可能被其他进程守护"

    }

    if ($Script:Results.Processes.Count -gt 0) {

        $customRecommendations += "进程/DLL注入：建议重启系统后再扫描，确保注入进程完全终止"

    }

    if ($Script:Results.Files.Count -gt 0) {

        $customRecommendations += "文件系统：检查隔离目录中的文件，确认是否为恶意软件"

    }

    if ($Script:Results.Network.Count -gt 0) {

        $customRecommendations += "网络连接：封禁发现的C2 IP地址，检查防火墙规则"

    }

    if ($Script:Results.DNS.Count -gt 0) {

        $customRecommendations += "DNS检测：在DNS服务器或防火墙上封禁发现的恶意域名"

    }

    if ($Script:Results.Hosts.Count -gt 0) {

        $customRecommendations += "Hosts劫持：检查并清理hosts文件中的恶意重定向条目"

    }

    if ($Script:Results.Bits.Count -gt 0) {

        $customRecommendations += "BITS任务：使用 Remove-BitsTransfer 删除可疑的后台传输任务"

    }

    if ($Script:Results.Pipes.Count -gt 0) {

        $customRecommendations += "命名管道：检查可疑管道的拥有进程，确认是否为恶意软件创建"

    }



    $recommendationsHtml = ""

    if ($customRecommendations.Count -gt 0) {

        $recommendationsHtml = "<div class=`"finding`" style=`"border-left-color:#3498db`"><div class=`"finding-title`">针对本次检测的处置建议</div><div class=`"finding-detail`">"

        foreach ($rec in $customRecommendations) {

            $recommendationsHtml += "&#x2022; $rec<br/>"

        }

        $recommendationsHtml += "</div></div>"

    }



    # 应急处置建议

    $html += @"

<div class="section">

<div class="section-title"><span>&#x1F6E1;</span> 银狐木马应急处置建议</div>

$recommendationsHtml

<div class="finding" style="border-left-color:#e74c3c">

<div class="finding-title">核心处置原则："先止血、再分析、后清理、最终溯源"</div>

<div class="finding-detail">1. 快速阻断：立即断网隔离受影响终端，强制下线聊天工具，阻断C2通信和二次传播链路

2. 深入分析：从运行态行为、启动项配置、异常文件活动多维度排查

3. 彻底清理：完整切断 启动-&gt;加载-&gt;控制 链路，防止残留组件反复恢复

4. 溯源闭环：通过浏览器历史+LastActivityView+Everything交叉比对，还原完整感染链路</div>

</div>

<div class="finding" style="border-left-color:#e67e22">

<div class="finding-title">银狐木马关键特征总结</div>

<div class="finding-detail">&#x2022; 白加黑技术：合法签名EXE加载同目录恶意DLL（libcurl.dll, version.dll等）

&#x2022; 内存注入：注入sihost.exe/svchost.exe/winevr.exe/explorer.exe/VSSVC.exe

&#x2022; 6层随机目录：C:\Program Files (x86)\随机1\随机2\随机3\随机4\随机5\随机名.exe

&#x2022; DNS隧道通信：通过内网DNS服务器中转流量，伪装合法DNS请求

&#x2022; BAT守护脚本：反复检测木马进程状态，发现未运行则重新拉起

&#x2022; PPID欺骗：伪造父进程为services.exe，隐藏真实进程树关系

&#x2022; 聊天工具传播：监控用户离线状态，远程操控微信/企业微信发送恶意文件</div>

</div>

<div class="finding" style="border-left-color:#3498db">

<div class="finding-title">推荐辅助工具</div>

<div class="finding-detail">&#x2022; Autoruns - 全面排查自启动项

&#x2022; LastActivityView - 取证辅助，收集用户操作与系统事件日志

&#x2022; Everything - 按文件创建/修改时间筛选，快速定位新增文件

&#x2022; Volatility - 内存取证分析工具（银狐攻击后磁盘几乎无痕迹，内存取证是关键）

&#x2022; Wireshark - 网络流量抓包分析</div>

</div>

</div>

<div class="footer"><p>银狐木马检测查杀工具 v2.9.1 | 生成时间：$($Script:ScanTime)</p><p>本工具仅供安全检测与应急响应使用，清理操作请谨慎执行</p></div>

</div>

</body>

</html>

"@

    

    $html | Out-File -FilePath $reportPath -Encoding UTF8 -Force

    Write-Host ""

    Write-Host "[+] 检测报告已生成: $reportPath" -ForegroundColor Green

    return $reportPath

}



# ============================================================

# 主程序

# ============================================================

function Main {

    # 启动诊断（noConsole 下 Out-File 输出到 TEMP）

    "Main started at $(Get-Date)" | Out-File "$env:TEMP\SFH_debug.log" -Encoding UTF8 -Force



    $useScanOnly = $ScanOnly

    $useAutoClean = $AutoClean







    # ---- TUI 模式（原逻辑） ----





    Clear-Host

    Write-Host ""

    Write-Host "  =======================================================" -ForegroundColor Cyan

    Write-Host "  |  银狐木马检测查杀工具 v2.9.1  (命令行版)           |" -ForegroundColor Cyan

    Write-Host "  |  SilverFox Trojan Detection & Removal               |" -ForegroundColor Cyan

    Write-Host "  =======================================================" -ForegroundColor Cyan

    Write-Host ""



    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {

        Write-Host "  [!] 非管理员权限，部分检测功能受限" -ForegroundColor Red

        Write-Host "  [!] 建议右键'以管理员身份运行'" -ForegroundColor Red

        Write-Host ""

    }



    Write-Host "  主机: $($Script:HostName) | 系统: $($Script:OSVersion)" -ForegroundColor Gray

    Write-Host "  用户: $($Script:CurrentUser) | 时间: $($Script:ScanTime)" -ForegroundColor Gray

    Write-Host "  模式: 精准检测(多条件叠加, 低误报)" -ForegroundColor Gray

    Write-Host ""

    Write-Host "  -------------------------------------------------------" -ForegroundColor DarkGray

    Write-Host ""



    Invoke-RegistryCheck



    Invoke-TaskCheck



    Invoke-ServiceCheck



    Invoke-ProcessCheck



    Invoke-FileCheck



    Invoke-NetworkCheck



    Invoke-WmiCheck



    Invoke-HostsCheck



    Invoke-BitsCheck



    Invoke-PipeCheck





    $totalFindings = ($Script:Results.Registry + $Script:Results.Tasks + $Script:Results.Services +

                      $Script:Results.Processes + $Script:Results.Files + $Script:Results.Network +

                      $Script:Results.DNS + $Script:Results.Hosts + $Script:Results.Bits +

                      $Script:Results.Pipes).Count





    $Script:Results.Summary.TotalScanned = $totalFindings

    $Script:Results.Summary.ThreatCount = ($Script:Results.Summary.Critical + $Script:Results.Summary.High)







    Write-Host ""

    Write-Host "  -------------------------------------------------------" -ForegroundColor DarkGray

    Write-Host ""

    Write-Host "  [+] 检测完成！结果汇总：" -ForegroundColor Cyan

    Write-Host ""

    Write-Host "    注册表:     $($Script:Results.Registry.Count) 项" -ForegroundColor $(if($Script:Results.Registry.Count -gt 0){"Yellow"}else{"Green"})

    Write-Host "    计划任务:   $($Script:Results.Tasks.Count) 项" -ForegroundColor $(if($Script:Results.Tasks.Count -gt 0){"Yellow"}else{"Green"})

    Write-Host "    服务:       $($Script:Results.Services.Count) 项" -ForegroundColor $(if($Script:Results.Services.Count -gt 0){"Yellow"}else{"Green"})

    Write-Host "    进程/DLL:   $($Script:Results.Processes.Count) 项" -ForegroundColor $(if($Script:Results.Processes.Count -gt 0){"Yellow"}else{"Green"})

    Write-Host "    文件:       $($Script:Results.Files.Count) 项" -ForegroundColor $(if($Script:Results.Files.Count -gt 0){"Yellow"}else{"Green"})

    Write-Host "    网络:       $($Script:Results.Network.Count) 项" -ForegroundColor $(if($Script:Results.Network.Count -gt 0){"Yellow"}else{"Green"})

    Write-Host "    DNS/IOC:    $($Script:Results.DNS.Count) 项" -ForegroundColor $(if($Script:Results.DNS.Count -gt 0){"Red"}else{"Green"})

    Write-Host "    Hosts:      $($Script:Results.Hosts.Count) 项" -ForegroundColor $(if($Script:Results.Hosts.Count -gt 0){"Yellow"}else{"Green"})

    Write-Host "    BITS:       $($Script:Results.Bits.Count) 项" -ForegroundColor $(if($Script:Results.Bits.Count -gt 0){"Yellow"}else{"Green"})

    Write-Host "    管道:       $($Script:Results.Pipes.Count) 项" -ForegroundColor $(if($Script:Results.Pipes.Count -gt 0){"Yellow"}else{"Green"})

    Write-Host ""

    Write-Host "    严重: $($Script:Results.Summary.Critical) | 高危: $($Script:Results.Summary.High) | 中危: $($Script:Results.Summary.Medium) | 低危: $($Script:Results.Summary.Low)" -ForegroundColor White

    Write-Host ""



    Write-Host "  [*] 生成HTML检测报告..." -ForegroundColor Cyan

    $reportPath = Export-HtmlReport



    if ($totalFindings -gt 0) {

        if ($useAutoClean) {

            Invoke-Cleanup

        }

        elseif (-not $useScanOnly) {

            Write-Host ""

            Write-Host "  是否执行清理操作？(Y/N): " -NoNewline -ForegroundColor Yellow

            $doClean = Read-Host

            if ($doClean -eq "Y" -or $doClean -eq "y") {

                Invoke-Cleanup

            }

        }

    }



    Write-Host ""

    Write-Host "  [+] 全部操作完成！" -ForegroundColor Green

    return $reportPath

}



Main

