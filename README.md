# 352 Air Purifier

Home Assistant 集成：控制 352 Z90 空气净化器，走**阿里云 IoT 平台**（`api.link.aliyun.com`）。

## 功能

| 平台 | 实体 |
|---|---|
| `fan` | 开关、风速档位 |
| `select` | 工作模式 |
| `switch` | 童锁、UV LED、除菌、智能模式、待机传感器 |
| `sensor` | PM2.5、PM10、甲醛、TVOC、温湿度、滤芯寿命、净化量、运行时长 |

## 安装

### HACS（推荐）

1. HACS → 集成 → 右上角菜单 → **自定义存储库**
2. 填入 `https://github.com/mylofsh/ha-air-purifier-352`，类型选 **Integration**
3. 搜索「352 Air Purifier」安装
4. **重启 Home Assistant**

### 手动

把 `custom_components/air_purifier_352` 整个目录复制到 HA 的
`config/custom_components/` 下，然后重启。

## 配置

**设置 → 设备与服务 → 添加集成 → 搜索「352」**

只需三项：

| 项 | 说明 |
|---|---|
| 352 账号 | 手机号 |
| 密码 | 352 App 登录密码 |
| appSecret | 阿里云网关签名密钥（见下） |

之后可在 **配置 → 选项** 更新账号密码或 appSecret，留空保持原值。

### 自动登录（无需手动抓 token）

集成内部用账号密码自动完成四步登录链路：

```
① POST app.352air.com/api/v1/enduser/login
     {account, password, area:"86"} → access_token(60天) / refresh_token / air_token
② POST api.link.aliyun.com/living/account/region/get
     authCode=access_token, type=THIRD_AUTHCODE → cn-shanghai
③ POST living-account.cn-shanghai.aliyuncs.com/api/prd/loginbyoauth.json
     form: loginByOauthRequest, authCode=access_token, oauthPlateform=23 → sid
④ POST api.link.aliyun.com/account/createSessionByAuthCode
     authCode=sid, accountType=OA_SESSION → iotToken(20h) / refreshToken(200h)
```

**令牌自动续期**（每次轮询前检查）：

| 令牌 | 有效期 | 续期策略 |
|---|---|---|
| iotToken | 20 小时 | 提前 1 小时用 refreshToken 刷新 |
| iotToken refreshToken | 200 小时 | 失效则用账号密码重新登录 |
| 352 access_token | 60 天 | 提前 1 天重新登录 |

刷新后的令牌自动写回配置，HA 重启不丢失。

## 阿里云网关签名

阿里云 API 网关强制校验 `x-ca-signature`，算法为 **HmacSHA1**：

```
content-md5    = base64(md5(raw_body))
string_to_sign = METHOD \n ACCEPT \n CONTENT-MD5 \n CONTENT-TYPE \n DATE \n
                 X-Ca-Version:1 \n X-Ca-Nonce:<uuid> \n X-Ca-Timestamp:<ms> \n
                 X-Ca-Stage:RELEASE \n X-Ca-Key:<appKey> \n PATH
signature      = base64(HmacSHA1(appSecret, string_to_sign))
```

- 签名实现：`custom_components/air_purifier_352/aliyun_sign.py`
- 回归验证：`custom_components/air_purifier_352/verify_sign.py`

### 获取 appSecret

`appSecret` 是 352 App 的内置常量，**不会出现在抓包流量中**，需反编译 App 获取。

仓库附带自动提取脚本，用真实抓包样本做 HmacSHA1 回归验证，命中即输出：

```bash
python extract_appsecret.py 352air.apk
```

## 故障排查

| 现象 | 处理 |
|---|---|
| 提示 `登录失败` | 检查账号密码；确认账号未被其他设备挤下线 |
| 提示 `网关签名校验失败` | `appSecret` 不正确，用 `extract_appsecret.py` 重新提取 |
| 提示 `该账号下未找到设备` | 登录成功但账号未绑定净化器 |
| 实体状态不更新 | 检查轮询间隔，或看 HA 日志中的 `UpdateFailed` 详情 |

## 许可

MIT
