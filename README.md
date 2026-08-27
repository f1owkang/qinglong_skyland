<div align="center">

# 💠 QingSkyland

**森空岛自动签到脚本，兼容青龙面板与 Hermes 定时任务**

[![Release](https://img.shields.io/github/v/release/f1owkang/QingSkyland?style=flat-square&label=Release&color=blue)](https://github.com/f1owkang/QingSkyland/releases)
[![Downloads](https://img.shields.io/github/downloads/f1owkang/QingSkyland/total?style=flat-square&label=Downloads&color=green)](https://github.com/f1owkang/QingSkyland/releases)
![Language](https://img.shields.io/badge/Language-Python-3776AB?style=flat-square&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Qinglong_%7C_Hermes-00bcd4?style=flat-square)
[![License](https://img.shields.io/badge/License-MIT-orange?style=flat-square)](LICENSE)

[功能特性](#功能特性) · [运行模式](#运行模式) · [青龙面板使用](#青龙面板使用) · [Hermes 定时任务使用](#hermes-定时任务使用) · [常见问题](#常见问题) · [开源协议](#开源协议)

</div>

> [!WARNING]
> 脚本需要**森空岛登录凭证（token）**，请妥善保管，切勿提交到仓库或分享给他人。

---

## 功能特性

- 自动签到明日方舟 / 终末地绑定角色，支持多账号（逗号分隔）
- 仅使用环境变量 / token 文件配置，无交互、无本地文件依赖（青龙模式）
- 支持**青龙面板**（自带 `notify.py` 通知）与 **Hermes 定时任务**（stdout 直投）两种运行环境
- Hermes 模式下自动创建虚拟环境安装依赖，token 存本地文件，不污染环境变量
- 全部签到成功时可静默（不产生任何输出，定时任务不打扰）

原项目：[skyland-auto-sign](https://gitee.com/FancyCabbage/skyland-auto-sign)

## 运行模式

| 模式 | 说明 | 适用场景 |
| :-- | :-- | :-- |
| `auto`（默认） | 同目录存在 `notify.py` 则走青龙模式，否则走 Hermes 模式 | 同一份代码两边通用 |
| `qinglong` | 强制青龙模式：日志输出到任务日志，通知走青龙 `notify.py` | 青龙面板 |
| `hermes` | 日志走 stderr，通知改为输出到 stdout，由 Hermes 定时任务原样投递 | Hermes 助手 |

## 青龙面板使用

### 1) 获取 token

token 获取方式依赖你使用的工具或项目来源。确保拿到的是有效 token 字符串，多个 token 用英文逗号分隔。

### 2) 配置脚本环境变量

在青龙面板 -> 环境变量 中新增（或编辑）：

- `SKYLAND_TOKENS`：必填，token 列表，逗号分隔
- `EXIT_WHEN_FAIL`：可选，`on/off`，失败时退出（默认 `off`）
- `USE_PROXY`：可选，`on/off`，是否使用代理（默认 `off`）
- `NOTIFY_TITLE`：可选，通知标题（默认 `森空岛自动签到`）

示例：

```
SKYLAND_TOKENS=token1,token2
EXIT_WHEN_FAIL=off
USE_PROXY=off
NOTIFY_TITLE=森空岛签到
```

### 3) 安装依赖

依赖：

```
requests
cryptography
```

安装：

```
pip install -r requirements.txt
```

### 4) 运行

```
python skyland.py
```

### 5) 通知设置（青龙）

脚本会自动调用同目录的 `notify.py`（青龙自带）。只要配置任意一种通知渠道即可。

#### 方式 A：青龙面板“通知设置”

1. 进入 系统设置 -> 通知设置
2. 选择一种通知渠道并填写（如 pushplus）
3. 保存后运行任务验证

#### 方式 B：环境变量配置（推荐简洁）

`notify.py` 读取的是全大写环境变量。以 pushplus 为例：

最小配置（单人推送）：

```
PUSH_PLUS_TOKEN=你的token
```

可选配置（群组/模板/渠道）：

```
PUSH_PLUS_USER=群组编码
PUSH_PLUS_TEMPLATE=markdown
PUSH_PLUS_CHANNEL=wechat
```

如果日志出现“无推送渠道”，说明没有配置任何通知变量。

## Hermes 定时任务使用

脚本可直接挂到 Hermes 的定时任务（cron）上，无需额外配置通知渠道：`run_skyland.sh` 的输出会由 Hermes 原样投递到目标会话。

### 1) 部署脚本

将仓库中的 `skyland.py`、`run_skyland.sh`、`requirements.txt` 放到 Hermes 的 scripts 目录（如 `~/scripts/skyland/`）。首次运行 `run_skyland.sh` 会自动创建 `.venv` 并安装依赖（优先使用 `uv`，回退 `python3 -m venv`）。

### 2) 准备 token 文件

在 `~/.config/skyland/tokens` 写入 token，每行一个，`#` 开头为注释：

```
# 我的森空岛 token
token1
token2
```

也可通过环境变量 `SKYLAND_TOKEN_FILE` 指定其他路径。token 文件与环境变量 `SKYLAND_TOKENS` 会合并去重。

### 3) 创建定时任务

在 Hermes 中创建一个 no_agent 模式的定时任务，`script` 字段指向 `run_skyland.sh` 的绝对路径，按需设置执行时间（如每天 `0 9 * * *`）。

脚本行为：

- 正常签到：stdout 输出签到结果，Hermes 投递消息
- 全部成功且 `SKYLAND_SILENT_OK=on`：无输出，不投递
- 配置错误（无 token）：stdout 输出错误提示，并以非零码退出，Hermes 会上报异常

## 常见问题

- 提示“请勿重复签到”：当天已签到，属于正常提示。
- 提示“无推送渠道”（青龙）：未配置通知变量或通知设置未保存。
- 提示“未配置任何 token”（Hermes）：`SKYLAND_TOKENS` 与 `SKYLAND_TOKEN_FILE` 均为空，请检查 token 文件路径。

## 致谢

- 原项目 [skyland-auto-sign](https://gitee.com/FancyCabbage/skyland-auto-sign)

## 开源协议

本项目基于 [MIT License](LICENSE) 开源。仅供学习与交流，请勿滥用。

---

<div align="center">

**Made with ❤ by [f1owkang](https://github.com/f1owkang)**

</div>
