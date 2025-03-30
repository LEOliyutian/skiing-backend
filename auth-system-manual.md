# 登山滑雪俱乐部认证系统技术手册

## 目录

1. [系统概述](#1-系统概述)
2. [技术架构](#2-技术架构)
3. [核心功能详解](#3-核心功能详解)
   - [JWT令牌认证](#31-jwt令牌认证)
   - [微信登录](#32-微信登录)
   - [手机验证码登录](#33-手机验证码登录)
   - [手机号绑定](#34-手机号绑定)
4. [数据模型](#4-数据模型)
5. [API接口文档](#5-api接口文档)
6. [开发与部署指南](#6-开发与部署指南)
7. [常见问题与解决方案](#7-常见问题与解决方案)

## 1. 系统概述

登山滑雪俱乐部认证系统是一个基于Python FastAPI和MongoDB的现代化认证系统，提供多种登录方式，包括传统的用户名密码登录、微信登录和手机验证码登录，满足不同用户的使用习惯和场景需求。系统使用JWT(JSON Web Token)进行身份验证，并提供令牌刷新机制，确保系统安全性的同时提供良好的用户体验。

### 核心功能结构

```
用户认证系统
├── 传统认证
│   ├── 用户名密码注册
│   ├── 用户名密码登录
│   └── JWT令牌管理
│       ├── 访问令牌 (Access Token)
│       └── 刷新令牌 (Refresh Token)
│
├── 第三方认证
│   └── 微信登录
│       ├── Code换取OpenID
│       ├── 新用户自动注册
│       └── 用户信息同步
│
├── 手机号认证
│   ├── 短信验证码发送
│   ├── 验证码登录
│   └── 新用户自动注册
│
└── 账号管理
    ├── 获取用户信息
    ├── 更新用户信息
    └── 手机号绑定
```

## 2. 技术架构

### 技术栈

- **后端框架**: FastAPI
- **数据库**: MongoDB
- **认证机制**: JWT (JSON Web Token)
- **API文档**: Swagger UI / ReDoc (自动生成)
- **异步支持**: 基于Python asyncio
- **短信服务**: 预留短信服务集成接口
- **第三方登录**: 微信小程序登录

### 系统架构图

```
┌─────────────────────┐
│    客户端应用       │
│  (小程序/网站/App)  │
└───────────┬─────────┘
            │
            ▼
┌─────────────────────┐     ┌─────────────────┐
│    FastAPI服务      │◄───►│   MongoDB       │
└───────────┬─────────┘     └─────────────────┘
            │
            ▼
┌────────────────────────────────────┐
│             外部服务               │
├────────────┬─────────┬─────────────┤
│  微信API    │ 短信服务 │  其他服务   │
└────────────┴─────────┴─────────────┘
```

## 3. 核心功能详解

### 3.1 JWT令牌认证

JWT (JSON Web Token) 是一种基于JSON的开放标准，用于在网络应用环境间传递声明。本系统使用JWT实现用户认证和授权。

#### 令牌类型

- **访问令牌 (Access Token)**: 用于访问受保护的资源，有效期相对较短(1天)
- **刷新令牌 (Refresh Token)**: 用于获取新的访问令牌，有效期较长(7天)

#### 工作流程

```
┌─────────┐       ┌──────────────┐       ┌──────────────┐
│  用户   │       │  前端应用    │       │  后端服务    │
└────┬────┘       └──────┬───────┘       └──────┬───────┘
     │  输入账号密码 │                          │
     │ ────────────> │                          │
     │               │      登录请求            │
     │               │ ─────────────────────────>
     │               │                          │
     │               │      验证成功            │
     │               │ <─────────────────────────
     │               │    返回Access Token      │
     │               │    和Refresh Token       │
     │  登录成功     │                          │
     │ <────────────────                        │
     │               │                          │
     │     请求资源  │                          │
     │ ────────────> │     携带Access Token     │
     │               │ ─────────────────────────>
     │               │       验证Token          │
     │               │ <─────────────────────────
     │               │      返回请求资源        │
     │  显示资源     │                          │
     │ <─────────────                           │
     │               │                          │
     │               │  Access Token过期        │
     │ ────────────> │                          │
     │               │    使用Refresh Token     │
     │               │ ─────────────────────────>
     │               │                          │
     │               │    返回新的Access Token  │
     │               │ <─────────────────────────
     │               │                          │
```

#### 关键实现

JWT令牌生成与验证在`app/auth/jwt.py`中实现：

```python
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """创建JWT令牌"""
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    
    return encoded_jwt

def create_tokens(user_id: str):
    """创建访问令牌和刷新令牌"""
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user_id, "type": "access"}, 
        expires_delta=access_token_expires
    )
    
    refresh_token_expires = timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)
    refresh_token = create_access_token(
        data={"sub": user_id, "type": "refresh"}, 
        expires_delta=refresh_token_expires
    )
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }
```

#### 安全考虑

- 访问令牌有效期较短，减少被盗用的风险
- 令牌中可加入用户IP等信息，提高安全性
- 应使用HTTPS传输令牌，防止中间人攻击
- 敏感操作可要求重新验证用户身份

### 3.2 微信登录

微信登录功能允许用户通过微信小程序或公众号进行快速登录，无需输入用户名和密码。

#### 工作流程

```
┌─────────┐       ┌──────────────┐       ┌──────────────┐       ┌──────────┐
│  用户   │       │  前端应用    │       │  后端服务    │       │ 微信服务 │
└────┬────┘       └──────┬───────┘       └──────┬───────┘       └────┬─────┘
     │  点击微信登录 │                          │                    │
     │ ────────────> │                          │                    │
     │               │      获取微信code        │                    │
     │               │ ──────────────────────────────────────────────>
     │               │                          │                    │
     │               │      返回code           │                    │
     │               │ <──────────────────────────────────────────────
     │               │                          │                    │
     │               │   发送code和用户信息     │                    │
     │               │ ─────────────────────────>                    │
     │               │                          │                    │
     │               │       code换取openid     │                    │
     │               │      ─────────────────────────────────────────>
     │               │                          │                    │
     │               │        返回openid        │                    │
     │               │      <─────────────────────────────────────────
     │               │                          │                    │
     │               │   查找或创建用户账号     │                    │
     │               │                          │                    │
     │               │      返回JWT令牌         │                    │
     │               │ <─────────────────────────                    │
     │  登录成功     │                          │                    │
     │ <─────────────                           │                    │
```

#### 关键实现

微信登录的核心实现在`app/services/user.py`中的`authenticate_wechat`函数：

```python
async def authenticate_wechat(code: str, user_info: Optional[Dict[str, Any]] = None):
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
        
        # 查找或创建用户
        user = await get_user_by_openid(openid)
        
        if not user:
            # 创建新用户
            # ... 代码略
            is_new_user = True
        else:
            # 更新用户信息
            # ... 代码略
            is_new_user = False
        
        # 生成token
        tokens = create_tokens(str(user.id))
        
        # 返回用户信息和token
        return {
            "tokens": tokens,
            "user": {
                "id": str(user.id),
                "username": user.username,
                "avatar": user.avatar,
                "phone": user.phone,
                "is_new_user": is_new_user
            }
        }
    except Exception as e:
        raise ValueError(f"微信登录处理失败: {str(e)}")
```

#### 配置要求

微信登录需要在微信开发者平台注册并配置以下信息：

- 小程序AppID
- 小程序AppSecret
- 合法域名配置

这些配置信息需要在`app/config.py`中设置：

```python
# 微信小程序设置
WECHAT_APPID: str = os.getenv("WECHAT_APPID", "")
WECHAT_SECRET: str = os.getenv("WECHAT_SECRET", "")
```

### 3.3 手机验证码登录

手机验证码登录允许用户通过手机号和短信验证码进行登录，无需记忆密码。

#### 工作流程

```
┌─────────┐       ┌──────────────┐       ┌──────────────┐
│  用户   │       │  前端应用    │       │  后端服务    │
└────┬────┘       └──────┬───────┘       └──────┬───────┘
     │  输入手机号  │                          │
     │ ────────────> │                          │
     │               │      请求发送验证码      │
     │               │ ─────────────────────────>
     │               │                          │
     │               │   生成并存储验证码       │
     │               │   (同时发送短信)         │
     │               │                          │
     │               │      返回发送成功        │
     │               │ <─────────────────────────
     │  输入验证码   │                          │
     │ ────────────> │                          │
     │               │   提交手机号和验证码     │
     │               │ ─────────────────────────>
     │               │                          │
     │               │  验证验证码              │
     │               │  查找或创建用户          │
     │               │                          │
     │               │      返回JWT令牌         │
     │               │ <─────────────────────────
     │  登录成功     │                          │
     │ <─────────────                           │
```

#### 关键实现

手机验证码登录的核心实现包含两部分：

1. 发送验证码(`app/services/user.py`中的`send_verification_code`函数)：

```python
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
    # 示例代码略...
    
    return code
```

2. 手机号登录(`app/services/user.py`中的`login_with_phone`函数)：

```python
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
        # ... 代码略
        is_new_user = True
    else:
        # 更新登录时间
        # ... 代码略
    
    # 生成token
    tokens = create_tokens(str(user.id))
    
    # 返回用户信息和token
    return {
        "tokens": tokens,
        "user": {
            "id": str(user.id),
            "username": user.username,
            "avatar": user.avatar,
            "phone": user.phone,
            "is_new_user": is_new_user
        }
    }
```

#### 安全考虑

- 验证码有效期短(5分钟)，降低被盗用风险
- 限制发送频率(1分钟1次)，防止短信轰炸
- 验证成功后立即删除验证码，防止重复使用
- 手机号格式严格验证，减少无效请求

### 3.4 手机号绑定

手机号绑定功能允许用户(特别是通过微信登录的用户)将手机号与账号关联，提高账号安全性。

#### 工作流程

```
┌─────────┐       ┌──────────────┐       ┌──────────────┐
│  用户   │       │  前端应用    │       │  后端服务    │
└────┬────┘       └──────┬───────┘       └──────┬───────┘
     │ 已登录状态   │                          │
     │ 输入手机号   │                          │
     │ ────────────> │                          │
     │               │      请求发送验证码      │
     │               │ ─────────────────────────>
     │               │                          │
     │               │   生成并存储验证码       │
     │               │   (同时发送短信)         │
     │               │                          │
     │               │      返回发送成功        │
     │               │ <─────────────────────────
     │  输入验证码   │                          │
     │ ────────────> │                          │
     │               │ 提交手机号、验证码和Token │
     │               │ ─────────────────────────>
     │               │                          │
     │               │  验证令牌和验证码        │
     │               │  检查手机号是否被占用    │
     │               │  更新用户手机号          │
     │               │                          │
     │               │      返回绑定成功        │
     │               │ <─────────────────────────
     │  绑定成功     │                          │
     │ <─────────────                           │
```

#### 关键实现

手机号绑定的核心实现在`app/services/user.py`中的`bind_user_phone`函数：

```python
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
```

#### 业务价值

- 便于用户找回账号
- 提高账号安全性
- 便于后续短信通知等功能
- 获取用户真实联系方式，便于线下业务开展

## 4. 数据模型

系统涉及的主要数据模型包括用户、验证码和令牌。

### 数据模型关系图

```
┌───────────────┐
│     User      │
├───────────────┤
│ id            │◄───┐
│ username      │    │
│ phone         │    │
│ nickname      │    │
│ openid        │    │    ┌───────────────┐
│ avatar        │    │    │VerificationCode│
│ gender        │    │    ├───────────────┤
│ email         │    │    │ phone         │
│ level         │    │    │ code          │
│ balance       │    │    │ created_at    │
│ created_at    │    │    │ expires_at    │
│ updated_at    │    │    └───────────────┘
│ last_login_at │    │
└───────────────┘    │
                     │
┌───────────────┐    │
│     Token     │    │
├───────────────┤    │
│ access_token  │    │
│ refresh_token │    │
│ token_type    │    │
│ user_id       │────┘
└───────────────┘
```

### 用户模型 (User)

用户模型定义在`app/models/user.py`中：

```python
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
```

### 验证码模型 (VerificationCode)

验证码模型定义在`app/models/user.py`中：

```python
class VerificationCode(BaseModel):
    phone: str
    code: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime
```

### 令牌模型 (Token)

令牌模型定义在`app/models/user.py`中：

```python
class Token(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str
    
class TokenData(BaseModel):
    user_id: str
```

## 5. API接口文档

下表列出了系统的主要API接口。详细的API文档可以通过访问`/docs`或`/redoc`查看。

| 路径 | 方法 | 功能描述 | 请求参数 | 响应 |
|------|------|---------|---------|------|
| `/api/user/register` | POST | 用户注册 | username, phone, password, code | 注册成功消息 |
| `/api/user/login` | POST | 用户名密码登录 | username, password | 令牌和用户信息 |
| `/api/user/refresh-token` | POST | 刷新令牌 | refresh_token | 新的访问令牌 |
| `/api/user/wechat-login` | POST | 微信登录 | code, user_info | 令牌和用户信息 |
| `/api/user/phone-login` | POST | 手机验证码登录 | phone, code | 令牌和用户信息 |
| `/api/user/send-code` | POST | 发送验证码 | phone | 发送成功消息 |
| `/api/user/bind-phone` | POST | 绑定手机号 | phone, code | 绑定成功消息 |
| `/api/user/info` | GET | 获取用户信息 | token(header) | 用户详细信息 |
| `/api/user/info` | PUT | 更新用户信息 | token(header), 更新字段 | 更新后的用户信息 |

### 示例请求与响应

#### 用户注册

请求:
```json
POST /api/user/register
{
  "username": "testuser",
  "phone": "13812345678",
  "password": "password123",
  "code": "123456"
}
```

响应:
```json
{
  "status": "success",
  "message": "注册成功",
  "user_id": "609c5ef0c254f6d6b8b0d1a3"
}
```

#### 用户登录

请求:
```json
POST /api/user/login
{
  "username": "testuser",
  "password": "password123"
}
```

响应:
```json
{
  "tokens": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "bearer"
  },
  "user": {
    "id": "609c5ef0c254f6d6b8b0d1a3",
    "username": "testuser",
    "nickname": "testuser",
    "avatar": null,
    "phone": "13812345678"
  }
}
```

#### 微信登录

请求:
```json
POST /api/user/wechat-login
{
  "code": "043dj4000OWQpM1Wjc000a0fzO2dj40Z",
  "user_info": {
    "nickName": "微信用户",
    "avatarUrl": "https://thirdwx.qlogo.cn/mmopen/...",
    "gender": 1
  }
}
```

响应:
```json
{
  "tokens": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "bearer"
  },
  "user": {
    "id": "609c5ef0c254f6d6b8b0d1a4",
    "username": "wx_oQjYM5a3",
    "nickname": "微信用户",
    "avatar": "https://thirdwx.qlogo.cn/mmopen/...",
    "phone": "",
    "is_new_user": true
  }
}
```

## 6. 开发与部署指南

### 开发环境搭建

1. **安装Python 3.10或更高版本**

2. **安装MongoDB**

3. **克隆项目并安装依赖**
   ```bash
   git clone <repository-url>
   cd <project-folder>
   python -m venv venv
   source venv/bin/activate  # Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

4. **创建.env文件并配置**
   ```bash
   # .env
   SECRET_KEY=your-secret-key-for-jwt
   MONGODB_URL=mongodb://localhost:27017
   DATABASE_NAME=skiing_db
   WECHAT_APPID=your-wechat-appid
   WECHAT_SECRET=your-wechat-secret
   ```

5. **启动开发服务器**
   ```bash
   uvicorn app.main:app --reload
   ```

6. **访问API文档**
   浏览器打开 http://localhost:8000/docs

### 代码结构

```
skiing-backend/
├── app/
│   ├── __init__.py
│   ├── main.py              # 应用主入口
│   ├── config.py            # 配置文件
│   ├── database.py          # MongoDB连接
│   ├── auth/
│   │   ├── __init__.py
│   │   ├── jwt.py           # JWT处理
│   │   └── dependencies.py  # 认证依赖
│   ├── api/
│   │   ├── __init__.py
│   │   ├── routes.py        # API路由注册
│   │   └── user.py          # 用户API
│   ├── models/
│   │   ├── __init__.py
│   │   └── user.py          # 用户模型
│   └── services/
│       ├── __init__.py
│       └── user.py          # 用户服务逻辑
└── requirements.txt
```

### 生产环境部署

1. **准备服务器环境**
   - 安装Python 3.10
   - 安装MongoDB
   - 配置防火墙和安全组
   - 安装Nginx反向代理(可选)

2. **部署项目**
   ```bash
   # 克隆项目
   git clone <repository-url>
   cd <project-folder>
   
   # 创建虚拟环境
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   
   # 创建.env文件并配置生产环境变量
   
   # 使用Gunicorn运行应用
   pip install gunicorn
   gunicorn -w 4 -k uvicorn.workers.UvicornWorker app.main:app
   ```

3. **Nginx配置(推荐)**

   ```nginx
   server {
       listen 80;
       server_name api.yourdomian.com;
       
       location / {
           proxy_pass http://localhost:8