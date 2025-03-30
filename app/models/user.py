# app/models/user.py
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, EmailStr

class UserBase(BaseModel):
    username: str
    phone: str
    
class UserCreate(UserBase):
    password: str
    code: str  # 验证码
    
class UserLogin(BaseModel):
    username: str  # 用户名或手机号
    password: str
    
class UserInDB(UserBase):
    id: str = Field(..., alias="_id")
    hashed_password: str
    avatar: Optional[str] = None
    nickname: Optional[str] = None
    openid: Optional[str] = None
    email: Optional[EmailStr] = None
    gender: Optional[int] = None  # 0:未知 1:男 2:女
    level: int = 0  # 用户等级
    balance: float = 0.0  # 账户余额
    is_active: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    last_login_at: Optional[datetime] = None
    
    class Config:
        allow_population_by_field_name = True
        
    async def generate_token(self):
        from app.auth.jwt import create_tokens
        return create_tokens(str(self.id))
        
class UserInfo(BaseModel):
    id: str
    username: str
    phone: str
    nickname: Optional[str] = None
    avatar: Optional[str] = None
    email: Optional[EmailStr] = None
    gender: Optional[int] = None
    level: int = 0
    balance: float = 0.0
    created_at: datetime
    
class Token(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str
    
class TokenData(BaseModel):
    user_id: str
    
class VerificationCode(BaseModel):
    phone: str
    code: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime

class WechatLoginData(BaseModel):
    code: str
    user_info: Optional[Dict[str, Any]] = None