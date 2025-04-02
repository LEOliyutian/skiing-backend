from motor.motor_asyncio import AsyncIOMotorClient
from app.config import settings
import logging
import traceback

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

async def test_mongodb_connection():
    try:
        # 创建MongoDB客户端
        logger.info("正在创建MongoDB客户端...")
        logger.info(f"连接URL: {settings.MONGODB_URL}")
        client = AsyncIOMotorClient(settings.MONGODB_URL)
        
        # 测试连接
        logger.info("正在测试连接...")
        await client.admin.command('ping')
        
        # 获取数据库
        logger.info("正在获取数据库...")
        db = client[settings.DATABASE_NAME]
        
        # 测试数据库操作
        logger.info("正在测试数据库操作...")
        result = await db.users.find_one()
        logger.info("数据库连接成功！")
        logger.info(f"当前数据库: {settings.DATABASE_NAME}")
        
        return True
    except Exception as e:
        logger.error(f"数据库连接失败: {str(e)}")
        logger.error(f"错误类型: {type(e).__name__}")
        logger.error("详细错误信息:")
        logger.error(traceback.format_exc())
        return False 