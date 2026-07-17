# WeCom RPA

企业微信消息回调服务，接收、验签、解密企业微信消息，并将真实用户文本转发到影刀 RPA webhook，由 RPA / 大模型处理后自动回复。

## 功能

- **AI 智能机器人回调**（`wx_robot.py`，端口 5000）
  - 接收企业微信 AI 智能机器人的消息回调
  - 验签 + AES 解密
  - 将用户文本转发到影刀 RPA webhook
  - 支持 JSON / XML 两种解密后格式
  - 通过 `response_url` 支持异步回复（适合长耗时 RPA 任务）

- **微信客服回调**（`wx_wxkf.py`，端口 8887）
  - 接收微信客服消息事件回调
  - 验签 + AES 解密
  - 使用 `sync_msg` 增量同步，cursor 机制防止重复拉取
  - 只转发 `origin == 3`（微信客户发送）的文本消息
  - 逐条转发所有客户文本，每条独立线程处理

- **URL 验证服务**（`app.py`，端口 5000）
  - 独立的企业微信回调 URL 验证服务

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 配置环境变量

```bash
cp .env.example .env
# 编辑 .env 填入你的企业微信配置
```

所需环境变量见 `.env.example`。

### 3. 启动服务

```bash
# AI 智能机器人
python wx_robot.py

# 微信客服
python wx_wxkf.py

# URL 验证（可选，与 wx_robot 端口冲突时二选一）
python app.py
```

### 4. 后台运行（Linux）

```bash
nohup python3 -u wx_robot.py > wx_robot.log 2>&1 &
nohup python3 -u wx_wxkf.py > wx_wxkf.log 2>&1 &
```

## 企业微信后台配置

1. **AI 智能机器人**：在机器人详情页获取 Token、EncodingAESKey，配置回调地址为 `http://your-server:5000/wecom/callback`

2. **微信客服**：在客服账号详情页获取 Token、EncodingAESKey，配置回调地址为 `http://your-server:8887/wechatcallback`

3. **防火墙**：开放对应端口（5000 / 8887）

## 文件说明

| 文件 | 说明 |
|------|------|
| `wx_robot.py` | AI 智能机器人回调服务 |
| `wx_wxkf.py` | 微信客服回调服务 |
| `app.py` | URL 验证服务 |
| `config.py` | 环境变量读取辅助 |
| `WXBizMsgCrypt.py` | 企业微信消息加解密库 |
| `ierror.py` | 错误码定义 |
| `.env.example` | 环境变量示例 |

## 安全说明

- 所有敏感配置通过环境变量读取，不硬编码在代码中
- 日志不输出用户消息正文、access_token、webhook 地址
- `.env`、日志文件、cursor 文件已被 `.gitignore` 排除

## License

MIT
