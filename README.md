# skyland-auto-sign (Qinglong)

森空岛自动签到脚本（青龙版）。

原项目：
- https://gitee.com/FancyCabbage/skyland-auto-sign

## 功能
- 仅使用环境变量配置（无交互、无本地文件依赖）
- 支持多账号（逗号分隔）
- 使用青龙自带 `notify.py` 发送通知

## 最简单步骤（建议先跑通）
1. 在青龙面板添加依赖（或在容器内执行）
	- `requests`
	- `cryptography`
2. 在青龙面板新增环境变量：
	- `SKYLAND_TOKENS` = 你的 token（多账号用英文逗号分隔）
3. 运行脚本任务，确认能正常签到。
4. 需要通知时，再配置通知渠道（见下文“详细步骤 - 通知设置”）。

## 详细步骤

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
脚本会自动调用同目录的 `notify.py`（青龙自带）。
只要配置任意一种通知渠道即可。

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

## 常见问题
- 提示“请勿重复签到”：当天已签到，属于正常提示。
- 提示“无推送渠道”：未配置通知变量或通知设置未保存。

## 免责声明
仅供学习与交流，请勿滥用。