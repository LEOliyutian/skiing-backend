import logging
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import ConnectionFailure, OperationFailure
import traceback

from app.config import settings

# 配置日志记录器
logger = logging.getLogger(__name__)

async def test_mongodb_connection():
    """
    测试MongoDB连接
    
    使用settings中的MONGODB_URL尝试连接到MongoDB数据库，
    并执行一个简单的ping命令来验证连接有效性。
    
    Returns:
        dict: 包含连接状态和消息的字典
    """
    try:
        logger.info("正在创建MongoDB客户端...")
        # 使用配置中的连接字符串
        connection_url = settings.MONGODB_URL
        logger.info(f"连接URL: {connection_url}")
        
        # 创建客户端
        client = AsyncIOMotorClient(connection_url)
        
        # 测试连接
        logger.info("正在测试连接...")
        await client.admin.command('ping')
        
        logger.info("连接成功!")
        return {"status": "success", "message": "数据库连接成功"}
        
    except ConnectionFailure as e:
        logger.error(f"数据库连接失败: {str(e)}")
        logger.error(f"错误类型: {type(e).__name__}")
        logger.error("详细错误信息:")
        logger.error(traceback.format_exc())
        return {"status": "error", "message": f"数据库连接失败: {str(e)}"}
        
    except OperationFailure as e:
        logger.error(f"数据库连接失败: {str(e)}, full error: {e.details}")
        logger.error(f"错误类型: {type(e).__name__}")
        logger.error("详细错误信息:")
        logger.error(traceback.format_exc())
        return {"status": "error", "message": f"数据库操作失败: {str(e)}"}
        
    except Exception as e:
        logger.error(f"发生未知错误: {str(e)}")
        logger.error(f"错误类型: {type(e).__name__}")
        logger.error("详细错误信息:")
        logger.error(traceback.format_exc())
        return {"status": "error", "message": f"发生未知错误: {str(e)}"}