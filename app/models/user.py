# app/models/user.py
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, EmailStr

class UserBase(BaseModel):
    username: str
    email: Optional[EmailStr] = None
    nickname: Optional[str] = None
    avatar: Optional[str] = None
    gender: Optional[int] = 0
    level: Optional[int] = 0
    balance: Optional[float] = 0.0
    
class UserCreate(UserBase):
    password: str
    code: str  # 验证码
    
class UserUpdate(BaseModel):
    nickname: Optional[str] = None
    avatar: Optional[str] = None
    email: Optional[EmailStr] = None
    gender: Optional[int] = None
    
class UserLogin(BaseModel):
    username: str  # 用户名或手机号
    password: str
    
class UserInDB(UserBase):
    id: str = Field(..., alias="_id")
    hashed_password: str
    is_active: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    last_login_at: Optional[datetime] = None
    
    class Config:
        validate_by_name = True
        
    async def generate_token(self):
        from app.auth.jwt import create_tokens
        return create_tokens(str(self.id))
        
class UserInfo(UserBase):
    id: str
    created_at: datetime
    
class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    
class TokenData(BaseModel):
    user_id: Optional[str] = None
    
class VerificationCode(BaseModel):
    email: EmailStr
    code: str

class WechatLoginData(BaseModel):
    code: str
    user_info: Optional[Dict[str, Any]] = None

class EmailLogin(BaseModel):
    email: EmailStr
    code: str