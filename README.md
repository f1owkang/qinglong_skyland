# skyland-auto-sign (Qinglong)

森空岛自动签到脚本（青龙版）。

原项目：
- https://gitee.com/FancyCabbage/skyland-auto-sign

## 功能
- 仅使用环境变量配置（无交互、无本地文件依赖）
- 支持多账号（逗号分隔）
- 使用青龙自带 `notify.py` 发送通知

## 环境变量
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

## 依赖
```
requests
cryptography
```

安装：
```
pip install -r requirements.txt
```

## 运行
```
python qinglong_skyland.py
```

## 青龙通知
脚本会自动调用同目录的 `notify.py`（青龙自带）。

## 免责声明
仅供学习与交流，请勿滥用。