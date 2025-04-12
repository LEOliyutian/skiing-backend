# 用 node 的官方运行环境做底层
FROM node:18

# 设置工作目录
WORKDIR /skiing-backend

# 把你当前的项目代码复制进去
COPY . .

# 安装依赖
RUN npm install

# 对外暴露端口（根据你实际服务端口）
EXPOSE 8000

# 启动命令
CMD ["node", "app.js"]
