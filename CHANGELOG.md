# 更新日志

## [v2.9.2] - 2026-05-07

### Bug 修复
- **[严重] Task 多 Action 漏检** — 签名验证通过第一个 Action 后 `break` 退出整个 Action 循环，若 Task 有多个 Action（第一个合法、后续恶意），恶意 Action 永不被检测。改为 `continue` 仅跳过当前 Action
- **[中] HTML 转义顺序** — 手动 `-replace` 在输入已含 `&amp;` 时产生 `&amp;amp;` 双转义。改为 `[System.Net.WebUtility]::HtmlEncode()` 系统调用

### 性能优化
- **Task 检测签名缓存** — Action 循环内对同一 `$execPath` 重复调用 4 次 `Test-IsLegitimatePath`（`Get-AuthenticodeSignature` CryptoAPI 开销最高），改为循环开始时一次调用缓存为 `$cachedLegit` 复用
- **进程检测单次枚举** — `Get-Process -Name $baseName` 在 9 个注入目标名循环中每次枚举进程表，改为一次 `Get-Process` + `Where-Object` 客户端过滤
- **WMI 超时补全** — `Get-CimInstance Win32_Service` 缺 `-OperationTimeoutSec`（唯一遗漏的 CIM 调用），WMI 损坏时无限卡死

### 检测逻辑改进
- **风险评分统一** — Process/BITS/Pipe/Startup 模块评分→风险等级映射统一为 3 级（ge8=Critical, ge5=High, ge3=Medium），与原 Registry/Service 等模块一致
- **BAT 阈值放宽** — 跳过阈值从 500KB→2MB，防止含 base64 payload 的 BAT 被误跳过
- **熵检测样本增大** — 前 2048 字节→8192 字节，覆盖 PE 头后的加密载荷区域
- **服务检测死逻辑移除** — `$svc.Name -in $Script:ConfirmedRunNames` 使用 Run 键名单检查服务名（仅含 TTruespanl），永远为 `$false`，已注释

### 代码质量
- **死代码清理** — 删除未调用的 `Get-EnrichedFileDetail` 函数（20 行）和未使用的 `LegitimateTaskPathSet` HashSet
- **COM 对象释放** — `$Script:WshShell = $null` 前增加 `ReleaseComObject()` 调用
- **重复管理员检查移除** — Main 函数内冗余管理员权限检查（脚本头部已强制 exit 1），死代码已删除
- **ErrorStats 补全** — Invoke-FileCheck 和 Invoke-PipeCheck 异常捕获块增加 `Update-ErrorStats`，确保报告错误计数准确

### 已知待优化（延后）
- FileCheck 目录遍历合并（AppData/ProgramData 被 3 次递归枚举）
- Invoke-FileCheck（654行）/ Invoke-RegistryCheck（715行）函数拆分
- ```.NET EnumerateFiles``` 样板代码提取为公共函数

---

## [v2.9.1] - 2026-05-07

### 误报修复（严重）
- **管道关键词子串误匹配** — `-match "rat"` 匹配到 **Administrat**or**（几乎所有 Windows 命名管道都含用户名），导致 12/18 管道误报为高危；`-match "c2"` 匹配 hex hash `...ec2`；`-match "shell"` 匹配 power**shell**。全部改为 `"\b$kw\b"` 词边界正则匹配
- **6层随机目录—知名软件目录** — `dotnet`/`nodejs`/`Google`/`QuarkUpdater` 不在 KnownSoftwareSet，被误判为银狐持久化目录。新增 20+ 知名软件名到 KnownSoftwareSet
- **管道前缀白名单** — 新增 `wecom|wxwork|tencent|wps|qing|elive|recentfile|workbuddy|pshost|rp` 前缀跳过，覆盖企业微信、WPS、青办公、联想、火绒等软件管道
- **服务名白名单** — WinServiceNameSet 新增 VMware 服务（VMnetDHCP/VMUSBArbService 等）、WSL 服务、夸克浏览器、火绒安全 16 个服务名

---
## [v2.9.0] - 2026-05-06

### 新增
- **6 个新检测模块**
  - COM 劫持检测（CLSID InprocServer32/LocalServer32 替换）
  - AppCertDlls 检测（Session Manager 非法 DLL 注入）
  - 服务 DLL 劫持检测（svchost 托管服务 ServiceDll 替换）
  - Hosts 文件劫持检测（C2 域名重定向 / 外部 IP 劫持）
  - BITS 传输任务检测（可疑后台下载任务）
  - Named Pipe 枚举检测（随机命名 / 可疑关键词管道）
- **外部 IOC 加载** — 支持 `-IOCFile` 参数加载 JSON 格式 IOC 数据（域名/IP/CIDR/哈希/文件名/DLL/启动项），追加到内置数据并自动重建 HashSet
- **SafeWrite-Progress** — noConsole 模式（ps2exe 编译）下自动跳过 Write-Progress，避免异常输出

### 修复
- **BootExecute 清理 Bug** — 原 `RemoveRegProp` 会删除整个 BootExecute 值导致重启蓝屏，改为 `RestoreBootExecute` 恢复默认值 `autocheck autochk *`
- **CIDR IP 匹配** — 原 `MaliciousIPSet.Contains("103.216.80.0/24")` 精确匹配永远失败，新增 `Test-IPInCIDR` 函数用 uint32 位运算实现子网匹配
- **Hashtable 语法错误** — `SilverFoxKnownHashes` 中 `= {"Agghosts.exe";` 缺少 `@` 前缀，导致运行时该条目为 ScriptBlock 而非 Hashtable
- **Hosts 文件清理** — 原 `QuarantineFile` 会把整个 hosts 文件移到隔离目录，改为 `CanBeFixed $false`（仅报告，不自动清理）
- **COM 劫持清理风险** — 原 `RemoveRegProp` 可能误删合法 COM 的默认值，改为 `CanBeFixed $false`
- **netstat IPv6 支持** — 回退正则支持 `[::1]:port` 格式，提取时去除方括号
- **WMI 交互式提示** — `Invoke-WmiCheck` 中 `Get-CimInstance` 缺少 `-ClassName` 参数，导致非交互模式下提示用户输入类名。改为查询 5 个已知高风险类（`__EventFilter`/`__EventConsumer`/`__FilterToConsumerBinding`/`AntiVirusProduct`/`FirewallProduct`）

### 优化
- **COM 劫持检测性能** — 用 `reg query /s /f` 原生搜索替代 `Get-ChildItem` 遍历 3000+ CLSID，从卡死降至 1-3 秒
- **FileCheck 目录合并** — 规则 2（白加黑DLL）/ 5（加密载荷）/ 6（MD5黑名单）合并为单次目录遍历，AppData/LOCALAPPDATA/ProgramData/IE 从 14 次遍历降至 4 次
- **KnownSystemPipes 全局初始化** — 从 Invoke-PipeCheck 内部移至脚本顶层，避免每次调用重复创建
- **合并扫描 .NET API** — `Get-ChildItem -Recurse` 替换为 `[System.IO.Directory]::EnumerateFiles()`，AppData/ProgramData 大目录枚举速度提升 3-5 倍，配合 `EnumerationOptions`（MaxRecursionDepth=3, IgnoreInaccessible）避免权限异常卡死
- **签名缓存** — 合并扫描中的签名检查接入 `$Script:SignatureCache`，同目录 EXE 不重复验证
- **dllNameSet O(1) 查找** — 白加黑 DLL 匹配从 foreach 嵌套改为 HashSet.Contains() 单次查找
- **knownWinDirs HashSet** — 119 项数组 `-notin` O(n) 改为 HashSet `.Contains()` O(1)
- **WMI 超时** — 所有 `Get-CimInstance` 加 `-OperationTimeoutSec 15`，防止 WMI 服务卡死
- **WScript.Shell 缓存** — COM 对象创建失败记录 WARN 日志，后续调用跳过
- **BAT 守护脚本扫描** — 搜索路径从 `C:\Windows`（全盘）缩窄为 `C:\Windows\Temp`/`Tasks`/`Tracing` + AppData/ProgramData；`Get-ChildItem -Recurse` 替换为 .NET `EnumerateFiles`（MaxRecursionDepth=3）；跳过 >500KB 文件；混淆字符计数从 `ToCharArray() | Where-Object` 改为 `regex::Matches()`
- **恶意文件名扫描** — 原方案 25 个文件名 × 9 路径 = 225 次 `Get-ChildItem -Recurse`，改为每路径只枚举一次目录 + `HashSet` O(1) 匹配文件名；搜索路径从 `C:\Windows` 全盘缩窄为 `Temp`/`Tasks`/`Tracing`
- **版本号** — 全部更新为 v2.9.0

### 误报优化
- **网络连接检测** — 仅标记从 Temp/AppData/ProgramData 目录运行的进程的非标准端口外联，避免标记所有合法软件的网络连接（如浏览器、办公软件等）
- **DLL 侧加载检测** — 路径位于已知合法厂商目录（NVIDIA/Intel/AMD/Microsoft/Google/Mozilla/Adobe）的 DLL 直接跳过，避免 NVIDIA Overlay 等合法组件误报
- **服务 DLL 劫持检测** — ServiceDll 路径位于已知合法厂商目录（NVIDIA/ByteDance/douyin/Intel/AMD/Google/Mozilla/Adobe/Microsoft）直接跳过，避免抖音等合法服务误报
- **Hosts 文件检测** — 跳过 RFC1918 私有地址重定向（10.x/172.16-31.x/192.168.x）和本地开发域名（.local/.lan/.internal/.test/.dev/.corp/.home），避免内网环境误报
- **BITS 传输任务检测** — 新增已知合法更新任务白名单（Mozilla/Firefox/Chrome/Edge/GoogleUpdate/WindowsUpdate/Microsoft/Adobe/NVIDIA/Intel/Apple 等），避免合法软件更新任务误报
- **命名管道检测** — 新增系统服务管道白名单（tapsrv/trkwks/SENS/Srvsvc/Wkssvc/Browser/Netlogon/WPSCloudSvr 等），避免合法系统管道误报
- **正则修复** — DLL/服务路径排除的正则表达式反斜杠转义修正（`\\\\` → `\\`），确保路径匹配生效

### 代码审计修复
- **[严重] Test-IsLegitimatePath 布尔求值 Bug** — 6 处调用将 PSCustomObject（永真）当布尔值使用，导致 IE 目录进程检测、6 层随机目录检测、加密载荷检测、隐藏目录检测、恶意文件名扫描、Startup 目录检测 6 个模块静默失效。全部修正为 `.IsLegit` 属性访问
- **[严重] 厂商路径排除正则优先级错误** — `\(NVIDIA|ByteDance|...\)` 中 `|` 优先级最低导致匹配范围不一致，移除不必要的括号锚定
- **[高] DLL 侧加载签名缓存缺失** — 兄弟 EXE 签名检查未接入 `$Script:SignatureCache`，同一目录重复验证，已补全缓存逻辑
- **[高] 服务检测过度跳过** — 仅检查随机名称服务，导致伪装合法名称（如 "WindowsHelper"）的恶意服务被跳过，已移除早期退出过滤
- **[高] 随机目录正则过宽** — 3 层纯小写字母目录匹配到合法路径（如 `\code\src\lib\`），已加入 PendingFileRenameOperations 的 SilverFox 特征二次过滤
- **[中] HTML 报告 XSS 风险** — 主机名/用户名/OS 版本直接插入 HTML 未转义，已应用 `ConvertTo-HtmlSafe`
- **[中] 清理模块重复保护名单** — Invoke-Cleanup 本地数组 `$protectedProcs` 重复全局 `$Script:ProtectedProcSet`（HashSet O(1)），已统一
- **[中] PendingFileRenameOperations 误报** — 合法安装程序的挂起操作被标记为高危，已收窄为仅匹配银狐已知特征
- **[中] 随机名称检测范围不足** — 正则 `[a-z]{5,8}` 遗漏 4 字母和 9+ 字母随机名，已扩展为 `[a-z]{4,12}`

### 清理
- 删除死代码 `Write-ErrorLog` 函数（从未调用）
- 删除未使用的 `InjectionTargetExcludeSet`、`TrustedPublisherSet`

---

## [v2.8.0]

### 功能
- 7 个检测模块：注册表、计划任务、服务、进程/DLL、文件系统、网络连接、WMI
- 多因子评分机制（suspicionScore 叠加，阈值判定）
- 三层白名单模型（签名 → 非知名签名 → 路径段匹配）
- 已知银狐 IOC 数据库（域名/IP/哈希/文件名/DLL/启动项）
- 白加黑 DLL 检测 + 6 层随机目录检测
- BAT 守护脚本检测 + 混淆密度分析
- Gh0st 远控端口检测 + C2 动态DNS API 模式检测
- HTML 检测报告生成
- 自动清理（依赖排序：服务 → 任务 → 进程 → 注册表 → 文件）
- 回滚日志（SilverFox_Rollback_*.log）
- ps2exe 编译支持（noConsole 模式）
