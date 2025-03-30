# app/database.py
import motor.motor_asyncio
from app.config import settings

# 创建MongoDB客户端
client = motor.motor_asyncio.AsyncIOMotorClient(settings.MONGODB_URL)
db = client[settings.DATABASE_NAME]

# 获取集合引用
users_collection = db.users
verification_codes_collection = db.verification_codes