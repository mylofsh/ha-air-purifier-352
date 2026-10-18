"""Constants for 352 Air Purifier integration."""
DOMAIN = "air_purifier_352"

# 阿里云 IoT API
ALIYUN_BASE = "https://api.link.aliyun.com"
APP_KEY = "27549861"
ALIYUN_REGION = "cn-shanghai"
ALIYUN_OA_BASE = "https://living-account.cn-shanghai.aliyuncs.com"

# 352 自有 API
API_352_BASE = "https://app.352air.com"

# 352 App 版本信息（用于登录 reason 字段与风控信息）
APP_VERSION = "1.9.0"
APP_BUILD_VERSION = "202608250951"
APP_PLATFORM = "iOS"

# 配置项
CONF_ACCOUNT = "account"
CONF_PASSWORD = "password"
CONF_AREA = "area"
CONF_APP_SECRET = "app_secret"      # 阿里云网关签名密钥（App 内置常量）

# 凭据（运行时获得，存入 entry.data）
CONF_ACCESS_TOKEN = "access_token"      # 352 access_token，60 天
CONF_REFRESH_TOKEN_352 = "refresh_token_352"
CONF_AIR_TOKEN = "air_token"
CONF_IOT_TOKEN = "iot_token"            # 20 小时
CONF_IOT_REFRESH_TOKEN = "iot_refresh_token"  # 200 小时
CONF_IDENTITY_ID = "identity_id"

# 兼容旧配置项名
CONF_APP_KEY = "app_key"
CONF_IOT_TOKEN_LEGACY = "iot_token"

DEFAULT_SCAN_INTERVAL = 60
DEFAULT_AREA = "86"

# 令牌刷新提前量（秒）：iotToken 20h，提前 1 小时刷新
IOT_TOKEN_REFRESH_MARGIN = 3600
# 352 access_token 60 天，提前 1 天刷新
ACCESS_TOKEN_REFRESH_MARGIN = 86400
