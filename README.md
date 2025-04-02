# Skiing Backend

登山滑雪俱乐部的后端服务，基于 FastAPI 开发。

## 功能特点

- 用户认证（邮箱/手机号/微信登录）
- 用户管理
- 验证码服务
- 微信小程序集成
- MongoDB 数据库支持

## 技术栈

- FastAPI
- MongoDB
- JWT 认证
- 微信小程序 API
- 邮件服务

## 安装

1. 克隆项目
```bash
git clone https://github.com/yourusername/skiing-backend.git
cd skiing-backend
```

2. 创建虚拟环境
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

3. 安装依赖
```bash
pip install -r requirements.txt
```

4. 配置环境变量
复制 `.env.example` 文件为 `.env`，并填写必要的配置信息：
```bash
cp .env.example .env
```

5. 运行服务
```bash
python -m uvicorn app.main:app --reload
```

## API 文档

启动服务后访问：
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## 开发

1. 安装开发依赖
```bash
pip install -r requirements-dev.txt
```

2. 运行测试
```bash
pytest
```

## 许可证

MIT License 