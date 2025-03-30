# app/api/user.py
from fastapi import APIRouter, Depends, HTTPException, status, Body
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError, jwt
from typing import Optional, Dict, Any

from app.models.user import UserCreate, UserLogin, UserInfo, Token, WechatLoginData
from app.services.user import (
    authenticate_user, 
    create_user, 
    get_user_info, 
    update_user_info, 
    send_verification_code,
    authenticate_wechat,
    login_with_phone,
    bind_user_phone
)
from app.auth.dependencies import get_current_active_user
from app.auth.jwt import decode_token, create_tokens
from app.config import settings

router = APIRouter()

@router.post("/register", response_model=dict)
async def register(user_data: UserCreate):
    """用户注册"""
    try:
        user = await create_user(user_data)
        return {"status": "success", "message": "注册成功", "user_id": str(user.id)}
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.post("/login", response_model=Dict[str, Any])
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """用户登录"""
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用户名或密码不正确",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    tokens = await user.generate_token()
    return {
        "tokens": tokens,
        "user": {
            "id": str(user.id),
            "username": user.username,
            "nickname": user.nickname,
            "avatar": user.avatar,
            "phone": user.phone
        }
    }

@router.post("/refresh-token", response_model=Token)
async def refresh_token(refresh_token: str = Body(...)):
    """刷新令牌"""
    try:
        token_data = decode_token(refresh_token)
        if token_data is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="无效的刷新令牌",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # 确认这是刷新令牌
        payload = jwt.decode(refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="无效的刷新令牌类型",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        user_id = token_data.user_id
        # 生成新的令牌
        tokens = create_tokens(user_id)
        return tokens
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="令牌过期或无效",
            headers={"WWW-Authenticate": "Bearer"},
        )

@router.post("/wechat-login", response_model=Dict[str, Any])
async def wechat_login(data: WechatLoginData):
    """微信登录"""
    try:
        result = await authenticate_wechat(data.code, data.user_info)
        if not result:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="微信登录失败",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.post("/phone-login", response_model=Dict[str, Any])
async def phone_login(phone: str = Body(...), code: str = Body(...)):
    """手机验证码登录"""
    try:
        result = await login_with_phone(phone, code)
        return result
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.post("/send-code")
async def send_code(phone: str = Body(...)):
    """发送验证码"""
    try:
        await send_verification_code(phone)
        return {"status": "success", "message": "验证码已发送"}
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.post("/bind-phone", response_model=dict)
async def bind_phone(
    phone: str = Body(...), 
    code: str = Body(...), 
    current_user = Depends(get_current_active_user)
):
    """绑定手机号"""
    try:
        await bind_user_phone(str(current_user.id), phone, code)
        return {"status": "success", "message": "手机号绑定成功"}
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.get("/info", response_model=UserInfo)
async def user_info(current_user = Depends(get_current_active_user)):
    """获取用户信息"""
    return await get_user_info(str(current_user.id))

@router.put("/info", response_model=UserInfo)
async def update_info(user_data: dict = Body(...), current_user = Depends(get_current_active_user)):
    """更新用户信息"""
    try:
        updated_user = await update_user_info(str(current_user.id), user_data)
        return updated_user
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )