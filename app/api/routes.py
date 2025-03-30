# app/api/routes.py
from fastapi import APIRouter
from app.api.user import router as user_router

# 创建API路由器
router = APIRouter()

# 注册用户路由
router.include_router(user_router, prefix="/user", tags=["用户"])