# SilverFoxHunter

> 银狐木马（SilverFox）精准检测与查杀工具 — PowerShell 纯命令行版

[![Version](https://img.shields.io/badge/version-2.9.0-blue)](CHANGELOG.md)
[![Platform](https://img.shields.io/badge/platform-Windows-0078D6)](https://www.microsoft.com/windows)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

SilverFoxHunter 是针对银狐木马家族（SilverFox Trojan）的专用检测与清理工具，覆盖 **11 个持久化维度**，采用多因子评分 + 三层白名单模型，兼顾检出率与低误报。

---

## 检测能力

| 模块 | 检测内容 | 银狐典型特征 |
|------|---------|------------|
| **注册表** | Run/RunOnce 启动项、BootExecute、AppCertDlls | 随机名启动项、IE 目录执行、C2 域名参数 |
| **计划任务** | 可疑计划任务、随机名触发器 | Temp 目录执行、混淆命令行参数 |
| **服务** | 恶意服务、ServiceDll 劫持 | svchost 托管服务 DLL 替换、随机服务名 |
| **进程/DLL** | 白加黑 DLL 侧加载、进程注入、COM 劫持 | 非系统目录加载系统 DLL、同目录签名 EXE + 无签名 DLL |
| **文件系统** | 6 层随机目录、BAT 守护脚本、加密载荷、MD5 黑名单 | 嵌套随机名目录 + 随机名 EXE、高混淆密度 BAT |
| **网络连接** | C2 通信检测、Gh0st 远控端口、DNS 缓存 IOC 匹配 | 非标准端口外联、动态 DNS 域名、Gh0st 特征端口 |
| **WMI** | WMI EventSubscription 无文件持久化 | __EventFilter / __EventConsumer 绑定 |
| **Hosts** | Hosts 文件劫持 | C2 域名重定向、外部 IP 劫持 |
| **BITS** | 可疑后台下载任务 | 随机名 BITS 任务、恶意 URL |
| **命名管道** | 可疑命名管道枚举 | 随机名管道、非系统服务进程持有 |
| **DNS/IOC** | DNS 缓存交叉匹配 | 已知银狐 C2 域名 / IP / CIDR 命中 |

---

## 核心机制

### 多因子评分

每个检测项采用 `suspicionScore` 累加机制，单一弱特征不告警，多特征叠加才触发：

- **≥10** → Critical（严重威胁）
- **7-9** → High（高危）
- **4-6** → Medium（中危）
- **1-3** → Low（低危）

### 三层白名单模型

| 层级 | 机制 | 效果 |
|------|------|------|
| L1 | Authenticode 数字签名校验（知名厂商） | `IsLegit=true` 直接放行 |
| L2 | 非知名厂商有效签名 | 减分因素，不直接放行 |
| L3 | 路径段匹配合法软件目录 | PathLegitHint 提示，供调用方减分 |

### IOC 数据库

内置银狐威胁情报，支持外部 JSON 扩展：

| IOC 类型 | 数量 | 示例 |
|---------|------|------|
| 恶意域名 | ~80 | `feiji168168.vip`, `flyingforest.sbs` |
| 恶意 IP | ~8 | `156.152.19.180`, `47.76.206.40` |
| CIDR 网段 | 4 | `103.216.80.0/24` (ValleyRAT), `154.204.0.0/16` (Gh0st) |
| MD5 哈希 | ~38 | 已知银狐变种样本 |
| 恶意文件名 | ~18 | 银狐常用载荷文件名 |
| 可疑 DLL | ~3 | `libcurl.dll`, `sqlite3.dll`, `libeay32.dll` |
| 已知启动项名 | ~8 | 银狐常用注册表 Run 键名 |

---

## 快速开始

### 要求

- Windows 7 / Server 2008 R2 及以上
- **管理员权限**（必须）
- PowerShell 5.1+

### 基本用法

```powershell
# 交互模式 — 检测后询问是否清理
.\SilverFoxHunter.ps1

# 仅检测，不清理
.\SilverFoxHunter.ps1 -ScanOnly

# 检测并自动清理（无交互确认）
.\SilverFoxHunter.ps1 -AutoClean

# 加载外部 IOC 数据
.\SilverFoxHunter.ps1 -IOCFile "C:\threat_intel\silverfox_ioc.json"
```

### 外部 IOC 格式

```json
{
  "Domains": ["evil.example.com", "c2.malware.top"],
  "IPs": ["1.2.3.4", "5.6.7.8"],
  "CIDRs": [
    {"IP": "10.20.30.0", "Prefix": 24}
  ],
  "Hashes": {
    "abc123def456": {
      "FileName": "payload.exe",
      "Variant": "SilverFox_2026Q2",
      "Note": "来源: 威胁情报"
    }
  },
  "FileNames": ["trojan.dll", "backdoor.exe"],
  "RunNames": ["WindowsUpdateHelper", "SystemService"]
}
```

---

## 输出

### 命令行界面

运行时实时显示各模块扫描状态和进度。检测完成后输出按风险和模块分类的汇总表。

### HTML 报告

自动生成可视化 HTML 报告，保存至脚本同目录：

```
SilverFox_Report_<主机名>_<时间戳>.html
```

包含：检测摘要、风险分布、各模块详细发现、清理建议。

### 回滚日志

执行清理时自动生成回滚日志：

```
SilverFox_Rollback_<时间戳>.log
```

---

## 检测流程

```
┌──────────────────────────────────────┐
│  管理员权限检查                        │
├──────────────────────────────────────┤
│  注册表启动项  →  计划任务  →  服务    │
│  →  进程/DLL侧加载  →  文件系统       │
│  →  网络连接  →  WMI 持久化           │
│  →  Hosts 劫持  →  BITS 任务          │
│  →  命名管道                          │
├──────────────────────────────────────┤
│  风险汇总 → HTML 报告 → 交互/自动清理   │
└──────────────────────────────────────┘
```

---

## 编译为 EXE

使用 [ps2exe](https://github.com/MScholtes/PS2EXE) 将脚本编译为独立可执行文件：

```powershell
Install-Module -Name ps2exe -Force
ps2exe -inputFile SilverFoxHunter.ps1 -outputFile SilverFoxHunter.exe -noConsole
```

脚本内置 `noConsole` 模式适配，编译后 `Write-Progress` 自动跳过，输出写至 `$env:TEMP\SFH_debug.log`。

---

## 误报优化

v2.9.0 经过大量误报优化，核心措施：

- **网络检测**: 仅标记 Temp/AppData/ProgramData 路径进程的非标准端口外联
- **DLL 侧加载**: NVIDIA/Intel/AMD/Microsoft/Google/Mozilla/Adobe 厂商路径自动跳过
- **Hosts 检测**: RFC1918 私有地址、本地开发域名（.local/.lan/.test/.dev 等）自动跳过
- **BITS 检测**: Mozilla/Chrome/Edge/NVIDIA/Adobe 等合法更新任务白名单
- **管道检测**: 内置 30+ 系统服务管道白名单
- **启动项**: 120+ 合法软件路径白名单

---

## 文件结构

```
SilverFoxHunter/
├── SilverFoxHunter.ps1    # 主程序 (6,837 行)
├── CHANGELOG.md           # 更新日志
├── README.md              # 本文件
└── .gitignore
```

---

## 版本历史

详见 [CHANGELOG.md](CHANGELOG.md)

### v2.9.0 (2026-05-06)

- 新增 6 个检测模块：COM 劫持、AppCertDlls、服务 DLL 劫持、Hosts 劫持、BITS 任务、命名管道
- 外部 IOC JSON 加载支持
- 大量性能优化（.NET API 替换、HashSet O(1)、签名缓存、合并扫描）
- 12+ 项误报优化
- 多项严重 Bug 修复（BootExecute 蓝屏、CIDR 匹配失效、布尔求值 Bug 等）

---

## 免责声明

本工具仅供授权的安全评估、应急响应和系统运维使用。使用者应遵守所在国家/地区的法律法规，在获得合法授权的前提下使用。作者不对任何未授权使用造成的后果承担责任。

---

## License

MIT
