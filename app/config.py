# app/config.py
import os
from dotenv import load_dotenv

# 加载.env文件
load_dotenv()

class Settings:
    # 应用信息
    APP_NAME: str = "登山滑雪俱乐部API"
    API_PREFIX: str = "/api"
    
    # JWT设置
    SECRET_KEY: str = os.getenv("SECRET_KEY", "your-secret-key-for-jwt")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 1天
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7天
    
    # MongoDB设置
    MONGODB_URL: str = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
    DATABASE_NAME: str = os.getenv("DATABASE_NAME", "skiing_db")
    
    # 跨域设置
    CORS_ORIGINS: list = ["*"]  # 开发阶段允许所有源
    
    # 短信验证码设置
    SMS_EXPIRE_MINUTES: int = 5
    
    # 微信小程序设置
    WECHAT_APPID: str = os.getenv("WECHAT_APPID", "")
    WECHAT_SECRET: str = os.getenv("WECHAT_SECRET", "")
    
    # 阿里云短信服务设置
    SMS_ACCESS_KEY_ID: str = os.getenv("SMS_ACCESS_KEY_ID", "")
    SMS_ACCESS_KEY_SECRET: str = os.getenv("SMS_ACCESS_KEY_SECRET", "")
    SMS_SIGN_NAME: str = os.getenv("SMS_SIGN_NAME", "登山滑雪俱乐部")
    SMS_TEMPLATE_CODE: str = os.getenv("SMS_TEMPLATE_CODE", "")
    
    # 邮件服务设置
    MAIL_USERNAME: str = os.getenv("MAIL_USERNAME", "572149964@qq.com")  # QQ邮箱账号
    MAIL_PASSWORD: str = os.getenv("MAIL_PASSWORD", "keowimkexsnebedd")  # QQ邮箱授权码
    MAIL_FROM: str = os.getenv("MAIL_FROM", "572149964@qq.com")  # 发件人邮箱
    MAIL_PORT: int = int(os.getenv("MAIL_PORT", "587"))  # QQ邮箱SMTP端口
    MAIL_SERVER: str = os.getenv("MAIL_SERVER", "smtp.qq.com")  # QQ邮箱SMTP服务器

settings = Settings()