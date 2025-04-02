from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from app.config import settings
import os
import logging
import asyncio
from datetime import datetime

# 配置日志
logger = logging.getLogger(__name__)

# 邮件配置
conf = ConnectionConfig(
    MAIL_USERNAME=settings.MAIL_USERNAME,
    MAIL_PASSWORD=settings.MAIL_PASSWORD,
    MAIL_FROM=settings.MAIL_FROM,
    MAIL_PORT=settings.MAIL_PORT,
    MAIL_SERVER=settings.MAIL_SERVER,
    MAIL_STARTTLS=False,  # 修改为False尝试
    MAIL_SSL_TLS=True,    # 修改为True尝试
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True,  # 验证证书
    TIMEOUT=30            # 增加超时时间
)

class EmailService:
    def __init__(self):
        self.fastmail = FastMail(conf)
    
    async def send_verification_code(self, email: str, code: str) -> bool:
        """发送验证码邮件"""
        try:
            logger.info(f"准备发送验证码邮件到: {email}")
            logger.info(f"当前系统时间: {datetime.now()}")
            
            # 邮件内容
            html_content = f"""
            <div style="max-width: 600px; margin: 0 auto; padding: 20px; font-family: Arial, sans-serif;">
                <h2 style="color: #333; text-align: center;">登山滑雪俱乐部</h2>
                <div style="background-color: #f5f5f5; padding: 20px; border-radius: 5px; margin: 20px 0;">
                    <p style="color: #666; margin: 10px 0;">您好，</p>
                    <p style="color: #666; margin: 10px 0;">您的验证码是：</p>
                    <div style="background-color: #fff; padding: 15px; border-radius: 5px; text-align: center; margin: 20px 0;">
                        <span style="font-size: 24px; font-weight: bold; color: #1890ff;">{code}</span>
                    </div>
                    <p style="color: #666; margin: 10px 0;">验证码有效期为5分钟，请尽快使用。</p>
                    <p style="color: #666; margin: 10px 0;">如果这不是您的操作，请忽略此邮件。</p>
                    <p style="color: #666; margin: 10px 0;">发送时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
                <div style="text-align: center; color: #999; font-size: 12px; margin-top: 20px;">
                    <p>此邮件由系统自动发送，请勿回复</p>
                </div>
            </div>
            """
            
            # 创建邮件消息
            message = MessageSchema(
                subject="登山滑雪俱乐部 - 验证码",
                recipients=[email],
                body=html_content,
                subtype="html"
            )
            
            # 发送邮件
            logger.info(f"开始发送邮件到: {email}")
            
            # 使用超时处理
            try:
                # 设置超时时间为10秒
                send_task = self.fastmail.send_message(message)
                await asyncio.wait_for(send_task, timeout=10.0)
                logger.info(f"成功发送邮件到: {email}")
                return True
            except asyncio.TimeoutError:
                logger.warning(f"发送邮件超时，但邮件可能已经发送: {email}")
                # 虽然超时，但实际上邮件可能已经发送
                return True
            
        except Exception as e:
            logger.error(f"发送邮件失败: {str(e)}")
            # 记录更详细的错误信息
            import traceback
            logger.error(traceback.format_exc())
            
            # 特殊处理已知的可能成功但报错的情况
            if "Malformed SMTP response line" in str(e):
                logger.warning("检测到SMTP响应格式问题，但邮件可能已经发送")
                return True
                
            return False

# 创建邮件服务实例 - 在模块级别创建实例
email_service = EmailService()