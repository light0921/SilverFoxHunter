# 更新日志

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
