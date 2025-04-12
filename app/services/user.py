# app/services/user.py
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import random
import string
import re
import requests
import logging
from bson import ObjectId
from app.database import users_collection, verification_codes_collection
from app.models.user import UserInDB, UserCreate, UserInfo, Token
from app.auth.jwt import get_password_hash, verify_password, create_tokens
from app.config import settings
# 导入整个模块，而不是具体的实例
import app.services.email as email_module

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def get_user_by_id(user_id: str) -> Optional[UserInDB]:
    """根据ID获取用户"""
    try:
        user = await users_collection.find_one({"_id": ObjectId(user_id)})
        if user:
            # 转换_id为字符串
            user["_id"] = str(user["_id"])
            return UserInDB(**user)
        return None
    except:
        return None

async def get_user_by_username(username: str) -> Optional[UserInDB]:
    """根据用户名获取用户"""
    user = await users_collection.find_one({"username": username})
    if user:
        # 转换_id为字符串
        user["_id"] = str(user["_id"])
        return UserInDB(**user)
    return None

async def get_user_by_email(email: str) -> Optional[UserInDB]:
    """根据邮箱获取用户"""
    user = await users_collection.find_one({"email": email})
    if user:
        # 转换_id为字符串
        user["_id"] = str(user["_id"])
        return UserInDB(**user)
    return None

async def get_user_by_openid(openid: str) -> Optional[UserInDB]:
    """根据微信openid获取用户"""
    user = await users_collection.find_one({"openid": openid})
    if user:
        # 转换_id为字符串
        user["_id"] = str(user["_id"])
        return UserInDB(**user)
    return None

async def create_user(user_data: UserCreate) -> UserInDB:
    """创建新用户"""
    try:
        # 验证验证码
        await verify_code(user_data.email, user_data.code)
        
        # 检查用户名和邮箱是否已存在
        existing_user = await get_user_by_username(user_data.username)
        if existing_user:
            raise ValueError("用户名已存在")
        
        existing_email = await get_user_by_email(user_data.email)
        if existing_email:
            raise ValueError("邮箱已被注册")
        
        # 创建用户
        hashed_password = get_password_hash(user_data.password)
        user_dict = {
            "username": user_data.username,
            "email": user_data.email,
            "nickname": user_data.username,
            "hashed_password": hashed_password,
            "avatar": None,
            "phone": None,
            "gender": 0,
            "level": 0,
            "balance": 0.0,
            "is_active": True,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "last_login_at": None
        }
        
        result = await users_collection.insert_one(user_dict)
        user_dict["_id"] = str(result.inserted_id)  # 转换为字符串
        
        return UserInDB(**user_dict)
    except Exception as e:
        logger.error(f"创建用户失败: {str(e)}")
        raise ValueError(f"创建用户失败: {str(e)}")

async def authenticate_user(username: str, password: str) -> Optional[UserInDB]:
    """验证用户凭据"""
    # 支持用户名或邮箱登录
    user = await get_user_by_username(username)
    if not user:
        user = await get_user_by_email(username)
        
    if not user:
        return None
    
    if not verify_password(password, user.hashed_password):
        return None
    
    # 更新最后登录时间
    await users_collection.update_one(
        {"_id": ObjectId(user.id)},
        {"$set": {"last_login_at": datetime.utcnow(), "updated_at": datetime.utcnow()}}
    )
    
    return user

async def authenticate_wechat(code: str, user_info: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    """微信登录认证"""
    try:
        # 请求微信API获取openid和session_key
        url = f"https://api.weixin.qq.com/sns/jscode2session?appid={settings.WECHAT_APPID}&secret={settings.WECHAT_SECRET}&js_code={code}&grant_type=authorization_code"
        response = requests.get(url)
        data = response.json()
        
        # 添加微信API响应日志，用于调试
        logger.info(f"微信API响应: {data}")
        
        if "errcode" in data and data["errcode"] != 0:
            raise ValueError(f"微信认证失败: {data.get('errmsg', '未知错误')}")
        
        openid = data.get("openid")
        if not openid:
            raise ValueError("获取微信openid失败")
            
        # 记录用户信息获取情况
        if user_info:
            logger.info(f"收到用户信息数据: {user_info}")
        else:
            logger.info("未收到用户信息数据")
        
        # 查找对应用户
        user = await get_user_by_openid(openid)
        
        if not user:
            # 创建新用户
            # 使用前端传来的用户信息或生成默认值
            nickname = "游客"
            avatar = None
            gender = 0
            
            if user_info:
                # 检查不同可能的字段名
                # 微信返回格式可能是nickName，前端传来的可能是nickname
                nickname = user_info.get("nickName", user_info.get("nickname", f"wx_{openid[:8]}"))
                # 微信返回格式可能是avatarUrl，前端传来的可能是avatar
                avatar = user_info.get("avatarUrl", user_info.get("avatar"))
                gender = user_info.get("gender", 0)
                
                # 记录获取到的用户信息
                logger.info(f"从用户授权获取到信息: 昵称={nickname}, 头像={avatar}, 性别={gender}")
            
            username = f"wx_{openid[:8]}"
            i = 1
            while await get_user_by_username(username):
                username = f"wx_{openid[:8]}_{i}"
                i += 1
            
            user_dict = {
                "username": username,
                "nickname": nickname,
                "email": None,  # 微信用户可能没有绑定邮箱
                "openid": openid,
                "hashed_password": get_password_hash(openid),  # 使用openid作为初始密码
                "avatar": avatar,
                "phone": None,
                "gender": gender,
                "level": 0,
                "balance": 0.0,
                "is_active": True,
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
                "last_login_at": datetime.utcnow()
            }
            
            result = await users_collection.insert_one(user_dict)
            user_dict["_id"] = str(result.inserted_id)  # 转换为字符串
            user = UserInDB(**user_dict)
            
            is_new_user = True
        else:
            # 更新用户信息（如果前端提供了）
            if user_info:
                update_data = {}
                
                # 增强更新逻辑，针对多种可能的字段名和空值情况
                new_nickname = user_info.get("nickName", user_info.get("nickname"))
                new_avatar = user_info.get("avatarUrl", user_info.get("avatar"))
                
                # 只有当用户授权了信息且当前是游客名称时，才更新昵称
                if new_nickname and (user.nickname == "游客" or user.nickname != new_nickname):
                    update_data["nickname"] = new_nickname
                    logger.info(f"更新用户昵称: {user.nickname} -> {new_nickname}")
                
                # 只有当用户授权了信息且没有头像或头像变更时，才更新头像
                if new_avatar and user.avatar != new_avatar:
                    update_data["avatar"] = new_avatar
                    logger.info(f"更新用户头像: {user.avatar} -> {new_avatar}")
                
                if user_info.get("gender") is not None and user.gender != user_info.get("gender"):
                    update_data["gender"] = user_info.get("gender")
                    logger.info(f"更新用户性别: {user.gender} -> {user_info.get('gender')}")
                
                if update_data:
                    update_data["updated_at"] = datetime.utcnow()
                    await users_collection.update_one(
                        {"_id": ObjectId(user.id)},
                        {"$set": update_data}
                    )
                    
                    # 如果更新了数据，重新获取用户信息以保证返回最新数据
                    user = await get_user_by_id(str(user.id))
            
            # 更新最后登录时间
            await users_collection.update_one(
                {"_id": ObjectId(user.id)},
                {"$set": {"last_login_at": datetime.utcnow()}}
            )
            is_new_user = False
        
        # 生成token
        tokens = create_tokens(str(user.id))
        
        # 返回用户信息和token - 保持与原有代码的返回格式一致
        return {
            "success": True,
            "data": {
                "token": tokens["access_token"],  # 前端可能只期望一个token
                "userInfo": {
                    "id": str(user.id),
                    "username": user.username,
                    "nickname": user.nickname,
                    "avatar": user.avatar,
                    "email": user.email,
                    "is_new_user": is_new_user
                }
            },
            "message": "登录成功"
        }
        
    except Exception as e:
        logger.error(f"微信登录处理失败: {str(e)}")
        raise ValueError(f"微信登录处理失败: {str(e)}")

async def get_user_info(user_id: str) -> UserInfo:
    """获取用户信息"""
    user = await get_user_by_id(user_id)
    if not user:
        raise ValueError("用户不存在")
    
    return UserInfo(
        id=str(user.id),
        username=user.username,
        nickname=user.nickname,
        email=user.email,
        avatar=user.avatar,
        phone=user.phone,
        gender=user.gender,
        level=user.level,
        balance=user.balance,
        created_at=user.created_at
    )

async def update_user_info(user_id: str, user_data: dict) -> UserInfo:
    """更新用户信息"""
    user = await get_user_by_id(user_id)
    if not user:
        raise ValueError("用户不存在")
    
    # 可更新的字段
    allowed_fields = {"avatar", "email", "gender", "nickname"}
    update_data = {k: v for k, v in user_data.items() if k in allowed_fields}
    
    if not update_data:
        return await get_user_info(user_id)
    
    # 添加更新时间
    update_data["updated_at"] = datetime.utcnow()
    
    # 更新用户信息
    await users_collection.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": update_data}
    )
    
    return await get_user_info(user_id)

async def generate_verification_code() -> str:
    """生成6位数字验证码"""
    return ''.join(random.choices(string.digits, k=6))

async def send_verification_code(email: str) -> str:
    """发送验证码"""
    logger.info(f"尝试向 {email} 发送验证码")
    
    # 检查邮箱格式
    if not email or not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email):
        logger.error(f"邮箱格式不正确: {email}")
        raise ValueError("邮箱格式不正确")
    
    # 检查发送频率 - 1分钟内只能发送一次
    recent_code = await verification_codes_collection.find_one(
        {"email": email, "created_at": {"$gt": datetime.utcnow() - timedelta(minutes=1)}}
    )
    if recent_code:
        logger.warning(f"发送过于频繁: {email}")
        raise ValueError("发送过于频繁，请稍后再试")
    
    # 生成验证码
    code = await generate_verification_code()
    logger.info(f"为 {email} 生成验证码: {code}")
    
    current_time = datetime.utcnow()
    expires_at = current_time + timedelta(minutes=5)  # 5分钟有效期
    
    # 存储验证码
    result = await verification_codes_collection.update_one(
        {"email": email},
        {"$set": {
            "code": code,
            "created_at": current_time,
            "expires_at": expires_at
        }},
        upsert=True
    )
    
    logger.info(f"验证码存储结果: modified={result.modified_count}, upserted={result.upserted_id is not None}")
    
    # 发送验证码邮件 - 使用模块中的实例
    success = await email_module.email_service.send_verification_code(email, code)
    if not success:
        logger.error(f"验证码邮件发送失败: {email}")
        raise ValueError("验证码发送失败，请稍后重试")
    
    logger.info(f"成功向 {email} 发送验证码")
    return code

async def verify_code(email: str, code: str) -> bool:
    """验证邮箱验证码"""
    logger.info(f"开始验证 {email} 的验证码")
    
    if not code:
        logger.error("验证码不能为空")
        raise ValueError("验证码不能为空")
    
    # 格式化验证码（去除空格）
    formatted_code = code.strip()
    
    # 获取有效的验证码记录
    verification = await verification_codes_collection.find_one({
        "email": email,
        "expires_at": {"$gt": datetime.utcnow()}  # 只查找未过期的验证码
    })
    
    if not verification:
        logger.warning(f"验证码不存在或已过期: {email}")
        # 调试: 查看是否有过期的验证码
        expired_code = await verification_codes_collection.find_one({"email": email})
        if expired_code:
            expired_at = expired_code.get('expires_at')
            current_time = datetime.utcnow()
            logger.debug(f"找到过期的验证码: {expired_code.get('code')}, 过期时间: {expired_at}, 当前时间: {current_time}, 差异: {(current_time - expired_at).total_seconds()}秒")
        raise ValueError("验证码不存在或已过期")
    
    stored_code = verification.get("code", "").strip()
    logger.info(f"数据库中的验证码: {stored_code}, 用户输入的验证码: {formatted_code}")
    
    # 检查验证码是否正确
    if stored_code != formatted_code:
        logger.warning(f"验证码不匹配: 期望 {stored_code}, 收到 {formatted_code}")
        raise ValueError("验证码错误")
    
    # 验证成功后删除验证码
    delete_result = await verification_codes_collection.delete_one({"email": email})
    logger.info(f"验证成功，删除验证码记录: {delete_result.deleted_count}")
    
    return True

async def login_with_email(email: str, code: str) -> Dict[str, Any]:
    """邮箱验证码登录"""
    # 验证验证码
    try:
        await verify_code(email, code)
    except ValueError as e:
        logger.error(f"验证码验证失败: {str(e)}")
        raise ValueError(f"验证码验证失败: {str(e)}")
    
    # 查找用户
    user = await get_user_by_email(email)
    is_new_user = False
    
    if not user:
        # 创建新用户
        username = f"email_{email.split('@')[0]}"
        i = 1
        while await get_user_by_username(username):
            username = f"email_{email.split('@')[0]}_{i}"
            i += 1
        
        # 为新用户生成随机密码
        random_password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
        hashed_password = get_password_hash(random_password)
        
        user_dict = {
            "username": username,
            "nickname": f"用户{email.split('@')[0]}",
            "email": email,
            "hashed_password": hashed_password,
            "avatar": None,
            "phone": None,
            "gender": 0,
            "level": 0,
            "balance": 0.0,
            "is_active": True,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "last_login_at": datetime.utcnow()
        }
        
        result = await users_collection.insert_one(user_dict)
        user_dict["_id"] = str(result.inserted_id)  # 转换为字符串
        user = UserInDB(**user_dict)
        is_new_user = True
    else:
        # 更新最后登录时间
        await users_collection.update_one(
            {"_id": ObjectId(user.id)},
            {"$set": {"last_login_at": datetime.utcnow(), "updated_at": datetime.utcnow()}}
        )
    
    # 生成token
    tokens = create_tokens(str(user.id))
    
    # 返回用户信息和token
    return {
        "tokens": tokens,
        "user": {
            "id": str(user.id),
            "username": user.username,
            "nickname": user.nickname,
            "avatar": user.avatar,
            "email": user.email,
            "is_new_user": is_new_user
        }
    }

async def bind_user_email(user_id: str, email: str, code: str) -> bool:
    """绑定用户邮箱"""
    # 验证验证码
    try:
        await verify_code(email, code)
    except ValueError as e:
        logger.error(f"验证码验证失败: {str(e)}")
        raise ValueError(f"验证码验证失败: {str(e)}")
    
    # 检查邮箱是否已被其他用户绑定
    existing_user = await get_user_by_email(email)
    if existing_user and str(existing_user.id) != user_id:
        raise ValueError("该邮箱已被其他账号绑定")
    
    # 更新用户邮箱
    await users_collection.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {
            "email": email,
            "updated_at": datetime.utcnow()
        }}
    )
    
    return True

async def login_with_phone(phone: str, code: str) -> Dict[str, Any]:
    """手机验证码登录"""
    # 验证验证码
    try:
        await verify_code(phone, code)
    except ValueError as e:
        logger.error(f"验证码验证失败: {str(e)}")
        raise ValueError(f"验证码验证失败: {str(e)}")
    
    # 查找用户
    user = await users_collection.find_one({"phone": phone})
    
    if not user:
        # 如果用户不存在，创建新用户
        username = f"user_{phone[-4:]}"
        i = 1
        while await get_user_by_username(username):
            username = f"user_{phone[-4:]}_{i}"
            i += 1
        
        user_dict = {
            "username": username,
            "nickname": username,
            "email": None,
            "phone": phone,
            "hashed_password": get_password_hash(phone),  # 使用手机号作为初始密码
            "avatar": None,
            "gender": 0,
            "level": 0,
            "balance": 0.0,
            "is_active": True,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "last_login_at": datetime.utcnow()
        }
        
        result = await users_collection.insert_one(user_dict)
        user_dict["_id"] = str(result.inserted_id)  # 转换为字符串
        user = UserInDB(**user_dict)
        is_new_user = True
    else:
        # 转换_id为字符串
        user["_id"] = str(user["_id"])
        user = UserInDB(**user)
        # 更新最后登录时间
        await users_collection.update_one(
            {"_id": ObjectId(user.id)},
            {"$set": {"last_login_at": datetime.utcnow()}}
        )
        is_new_user = False
    
    # 生成token
    tokens = create_tokens(str(user.id))
    
    # 返回用户信息和token
    return {
        "tokens": tokens,
        "user": {
            "id": str(user.id),
            "username": user.username,
            "nickname": user.nickname,
            "avatar": user.avatar,
            "phone": user.phone,
            "is_new_user": is_new_user
        }
    }

async def bind_user_phone(user_id: str, phone: str, code: str) -> bool:
    """绑定用户手机号"""
    # 验证验证码
    try:
        await verify_code(phone, code)
    except ValueError as e:
        logger.error(f"验证码验证失败: {str(e)}")
        raise ValueError(f"验证码验证失败: {str(e)}")
    
    # 检查手机号是否已被其他用户绑定
    existing_user = await users_collection.find_one({"phone": phone})
    if existing_user and str(existing_user["_id"]) != user_id:
        raise ValueError("该手机号已被其他用户绑定")
    
    # 更新用户手机号
    result = await users_collection.update_one(
        {"_id": ObjectId(user_id)},
        {
            "$set": {
                "phone": phone,
                "updated_at": datetime.utcnow()
            }
        }
    )
    
    if result.modified_count == 0:
        raise ValueError("用户不存在")
    
    return True