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

settings = Settings()