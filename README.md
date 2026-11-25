# SlimBrave Neo 中文版

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/Builder-Python_3.9+_Stdlib_Only-3776AB)](build_zh.py)
[![Platforms](https://img.shields.io/badge/Platforms-Windows_%7C_Linux_%7C_macOS-brightgreen)](#快速使用)

[ChaoticSi1ence/SlimBrave-Neo](https://github.com/ChaoticSi1ence/SlimBrave-Neo) 的全平台简体中文汉化工程。采用 **词库解耦 + 运行时注入** 架构，**上游更新后无需手动解冲突**，重新运行一行构建命令（或由 GitHub Actions 自动同步）即可持续使用。

> [!IMPORTANT]
> 本项目仅发布源码脚本（无 `.exe` / `.msi` / `.dmg` 安装包），遵循上游 **GPL-3.0** 协议。所有写入系统的策略 Key 与预设 JSON 均保持原版英文，与上游 100% 互通，可在 `brave://policy` 逐项审计。

---

## 快速使用

### Windows（PowerShell，需管理员权限）

```powershell
powershell -ExecutionPolicy Bypass -File .\dist\SlimBrave-zh.ps1
```

### Linux / macOS（需 root）

```bash
# Linux
sudo python3 ./dist/slimbrave-linux-zh.py

# macOS（支持 --persist on 持久化配置描述文件）
sudo python3 ./dist/slimbrave-mac-zh.py
```

---

## 为什么上游更新后依然可用？

传统 Fork 直接改写上游上万行源码，上游一更新就会大面积冲突。本项目采用三层解耦设计：

| 组件 | 职责 | 抗更新机制 |
| :--- | :--- | :--- |
| [`locales/zh-CN.json`](locales/zh-CN.json) | 单一中文词库（90/90 策略、7 分类、6 预设、三端 UI） | 按稳定的 Chromium/Brave 策略 `Key`（及多行互斥 `Key:Value`）索引，不依赖行号 |
| [`build_zh.py`](build_zh.py) | 零依赖构建器与覆盖率审计器 | 在适配器后注入运行时汉化层；上游新增未翻译策略时自动回退显示英文原文不崩溃，并导出待翻译模板 |
| [`.github/workflows/sync-upstream.yml`](.github/workflows/sync-upstream.yml) | 自动追踪上游工作流 | 每日自动拉取上游、重建 `dist/`、执行验证测试，发现新策略自动提 Issue |

### 针对中文环境的专项修复
- **Windows**：强制输出 **UTF-8 with BOM** 并转义 Unicode 弯引号，彻底规避 Windows PowerShell 5.1 乱码与语法错误；自动适配微软雅黑 UI；重构搜索支持 **中文 + 英文 + 策略 Key** 混合检索；按钮显示文本与事件 ID 解耦。
- **Linux / macOS**：内置基于 `unicodedata.east_asian_width` 的 **CJK 全角双宽终端引擎**，修复 `curses` 框线、居中标题、右对齐计数、帮助页与 macOS 持久化弹窗错位；将输入框升级为 `get_wch()`，支持 `/` 搜索与路径输入框直接键入中文。

---

## 上游更新后如何同步

无需安装 `git`，仅需 Python 3.9+：

```bash
# 1. 拉取上游最新 main，自动构建三端单文件产物并导出新增未翻译词条（如有）
python3 build_zh.py --fetch --emit-missing missing.json

# 指定上游 Release Tag
python3 build_zh.py --fetch --ref v2.2.0

# 2. 运行全量自动化验证（含 PowerShell AST、CJK 排版与抗更新仿真测试）
python3 -m unittest discover -s tests -v
```

---

## 目录结构

```text
├── locales/zh-CN.json                 # 单一事实来源中文词库
├── build_zh.py                        # 零依赖自动化构建与审计脚本
├── dist/
│   ├── SlimBrave-zh.ps1               # Windows 汉化单文件（UTF-8-BOM）
│   ├── slimbrave-linux-zh.py          # Linux 汉化单文件
│   └── slimbrave-mac-zh.py            # macOS 汉化单文件
├── tests/test_localization.py         # 自动化边界与回归测试
├── .github/workflows/sync-upstream.yml# GitHub Actions 每日同步流
├── LICENSE                            # GNU GPL-3.0
└── README.md
```

## 致谢与许可

- 上游项目：[ChaoticSi1ence/SlimBrave-Neo](https://github.com/ChaoticSi1ence/SlimBrave-Neo)（衍生自 [ltx0101/SlimBrave](https://github.com/ltx0101/SlimBrave)）
- 开源协议：[GNU General Public License v3.0](LICENSE)
