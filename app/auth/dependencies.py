# app/auth/dependencies.py
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from app.auth.jwt import decode_token
from app.services.user import get_user_by_id
from app.models.user import UserInDB
from app.config import settings

# OAuth2密码流依赖
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_PREFIX}/user/login")

async def get_current_user(token: str = Depends(oauth2_scheme)) -> UserInDB:
    """获取当前认证用户"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="无效的认证凭据",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    token_data = decode_token(token)
    if token_data is None:
        raise credentials_exception
        
    user = await get_user_by_id(token_data.user_id)
    if user is None:
        raise credentials_exception
        
    return user

async def get_current_active_user(current_user: UserInDB = Depends(get_current_user)) -> UserInDB:
    """获取当前活跃用户"""
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="用户已禁用")
    return current_user