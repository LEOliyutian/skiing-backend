# app/services/user.py
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import random
import string
import re
import requests
from bson import ObjectId
from app.database import users_collection, verification_codes_collection
from app.models.user import UserInDB, UserCreate, UserInfo, Token
from app.auth.jwt import get_password_hash, verify_password, create_tokens
from app.config import settings

async def get_user_by_id(user_id: str) -> Optional[UserInDB]:
    """根据ID获取用户"""
    try:
        user = await users_collection.find_one({"_id": ObjectId(user_id)})
        if user:
            return UserInDB(**user)
        return None
    except:
        return None

async def get_user_by_username(username: str) -> Optional[UserInDB]:
    """根据用户名获取用户"""
    user = await users_collection.find_one({"username": username})
    if user:
        return UserInDB(**user)
    return None

async def get_user_by_phone(phone: str) -> Optional[UserInDB]:
    """根据手机号获取用户"""
    user = await users_collection.find_one({"phone": phone})
    if user:
        return UserInDB(**user)
    return None

async def get_user_by_openid(openid: str) -> Optional[UserInDB]:
    """根据微信openid获取用户"""
    user = await users_collection.find_one({"openid": openid})
    if user:
        return UserInDB(**user)
    return None

async def create_user(user_data: UserCreate) -> UserInDB:
    """创建新用户"""
    # 验证验证码
    await verify_code(user_data.phone, user_data.code)
    
    # 检查用户名和手机号是否已存在
    existing_user = await get_user_by_username(user_data.username)
    if existing_user:
        raise ValueError("用户名已存在")
    
    existing_phone = await get_user_by_phone(user_data.phone)
    if existing_phone:
        raise ValueError("手机号已被注册")
    
    # 创建用户
    hashed_password = get_password_hash(user_data.password)
    user_dict = {
        "username": user_data.username,
        "phone": user_data.phone,
        "nickname": user_data.username,
        "hashed_password": hashed_password,
        "avatar": None,
        "email": None,
        "gender": 0,
        "level": 0,
        "balance": 0.0,
        "is_active": True,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
        "last_login_at": None
    }
    
    result = await users_collection.insert_one(user_dict)
    user_dict["_id"] = result.inserted_id
    
    return UserInDB(**user_dict)

async def authenticate_user(username: str, password: str) -> Optional[UserInDB]:
    """验证用户凭据"""
    # 支持用户名或手机号登录
    user = await get_user_by_username(username)
    if not user:
        user = await get_user_by_phone(username)
        
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
        
        if "errcode" in data and data["errcode"] != 0:
            raise ValueError(f"微信认证失败: {data.get('errmsg', '未知错误')}")
        
        openid = data.get("openid")
        if not openid:
            raise ValueError("获取微信openid失败")
        
        # 查找对应用户
        user = await get_user_by_openid(openid)
        
        if not user:
            # 创建新用户
            # 使用前端传来的用户信息或生成默认值
            nickname = "游客"
            avatar = None
            gender = 0
            
            if user_info:
                nickname = user_info.get("nickName", f"wx_{openid[:8]}")
                avatar = user_info.get("avatarUrl")
                gender = user_info.get("gender", 0)
            
            username = f"wx_{openid[:8]}"
            i = 1
            while await get_user_by_username(username):
                username = f"wx_{openid[:8]}_{i}"
                i += 1
            
            user_dict = {
                "username": username,
                "nickname": nickname,
                "phone": "",  # 微信用户可能没有绑定手机号
                "openid": openid,
                "hashed_password": get_password_hash(openid),  # 使用openid作为初始密码
                "avatar": avatar,
                "email": None,
                "gender": gender,
                "level": 0,
                "balance": 0.0,
                "is_active": True,
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
                "last_login_at": datetime.utcnow()
            }
            
            result = await users_collection.insert_one(user_dict)
            user_dict["_id"] = result.inserted_id
            user = UserInDB(**user_dict)
            
            is_new_user = True
        else:
            # 更新用户信息（如果前端提供了）
            if user_info:
                update_data = {}
                if user_info.get("nickName") and user.nickname != user_info.get("nickName"):
                    update_data["nickname"] = user_info.get("nickName")
                if user_info.get("avatarUrl") and user.avatar != user_info.get("avatarUrl"):
                    update_data["avatar"] = user_info.get("avatarUrl")
                if user_info.get("gender") and user.gender != user_info.get("gender"):
                    update_data["gender"] = user_info.get("gender")
                
                if update_data:
                    update_data["updated_at"] = datetime.utcnow()
                    await users_collection.update_one(
                        {"_id": ObjectId(user.id)},
                        {"$set": update_data}
                    )
            
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
        
    except Exception as e:
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
        phone=user.phone,
        avatar=user.avatar,
        email=user.email,
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

async def send_verification_code(phone: str) -> str:
    """发送验证码"""
    # 检查手机号格式
    if not phone or not re.match(r"^1[3-9]\d{9}$", phone):
        raise ValueError("手机号格式不正确")
    
    # 检查发送频率 - 1分钟内只能发送一次
    recent_code = await verification_codes_collection.find_one(
        {"phone": phone, "created_at": {"$gt": datetime.utcnow() - timedelta(minutes=1)}}
    )
    if recent_code:
        raise ValueError("发送过于频繁，请稍后再试")
    
    # 生成验证码
    code = await generate_verification_code()
    expires_at = datetime.utcnow() + timedelta(minutes=settings.SMS_EXPIRE_MINUTES)
    
    # 存储验证码
    await verification_codes_collection.update_one(
        {"phone": phone},
        {"$set": {
            "code": code,
            "created_at": datetime.utcnow(),
            "expires_at": expires_at
        }},
        upsert=True
    )
    
    # 集成短信发送服务
    # 这里是调用短信服务的代码，现在先打印到控制台
    print(f"【登山滑雪俱乐部】验证码：{code}，有效期5分钟。如非本人操作，请忽略此消息。")
    
    # 实际项目中，应集成短信服务商的API
    # 例如阿里云短信服务:
    # import json
    # from aliyunsdkcore.client import AcsClient
    # from aliyunsdkcore.request import CommonRequest
    
    # client = AcsClient(settings.SMS_ACCESS_KEY_ID, settings.SMS_ACCESS_KEY_SECRET, 'cn-hangzhou')
    # request = CommonRequest()
    # request.set_domain('dysmsapi.aliyuncs.com')
    # request.set_version('2017-05-25')
    # request.set_action_name('SendSms')
    # request.add_query_param('PhoneNumbers', phone)
    # request.add_query_param('SignName', '登山滑雪俱乐部')
    # request.add_query_param('TemplateCode', settings.SMS_TEMPLATE_CODE)
    # request.add_query_param('TemplateParam', json.dumps({'code': code}))
    # response = client.do_action_with_exception(request)
    
    return code

async def verify_code(phone: str, code: str) -> bool:
    """验证短信验证码"""
    # 获取验证码记录
    verification = await verification_codes_collection.find_one({"phone": phone})
    
    if not verification:
        raise ValueError("验证码不存在或已过期")
    
    stored_code = verification.get("code")
    expires_at = verification.get("expires_at")
    
    # 检查验证码是否正确
    if stored_code != code:
        raise ValueError("验证码错误")
    
    # 检查验证码是否过期
    if datetime.utcnow() > expires_at:
        raise ValueError("验证码已过期")
    
    # 验证成功后删除验证码
    await verification_codes_collection.delete_one({"phone": phone})
    
    return True

async def login_with_phone(phone: str, code: str) -> Dict[str, Any]:
    """手机验证码登录"""
    # 验证验证码
    try:
        await verify_code(phone, code)
    except ValueError as e:
        raise ValueError(f"验证码验证失败: {str(e)}")
    
    # 查找用户
    user = await get_user_by_phone(phone)
    is_new_user = False
    
    if not user:
        # 创建新用户
        username = f"phone_{phone[-4:]}"
        i = 1
        while await get_user_by_username(username):
            username = f"phone_{phone[-4:]}_{i}"
            i += 1
        
        # 为新用户生成随机密码
        random_password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
        hashed_password = get_password_hash(random_password)
        
        user_dict = {
            "username": username,
            "nickname": f"用户{phone[-4:]}",
            "phone": phone,
            "hashed_password": hashed_password,
            "avatar": None,
            "email": None,
            "gender": 0,
            "level": 0,
            "balance": 0.0,
            "is_active": True,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "last_login_at": datetime.utcnow()
        }
        
        result = await users_collection.insert_one(user_dict)
        user_dict["_id"] = result.inserted_id
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
        raise ValueError(f"验证码验证失败: {str(e)}")
    
    # 检查手机号是否已被其他用户绑定
    existing_user = await get_user_by_phone(phone)
    if existing_user and str(existing_user.id) != user_id:
        raise ValueError("该手机号已被其他账号绑定")
    
    # 更新用户手机号
    await users_collection.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {
            "phone": phone,
            "updated_at": datetime.utcnow()
        }}
    )
    
    return True