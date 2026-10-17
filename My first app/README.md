# 时痕摄影交流论坛

## 本地运行

需要安装 .NET 7 SDK。在项目目录运行：

```powershell
dotnet run --project .\ShihenForum.csproj -- --urls http://127.0.0.1:5080
```

然后打开 <http://127.0.0.1:5080>。帖子、评论和账号哈希保存在 `App_Data/forum.json`，上传的图片保存在 `App_Data/uploads/`。密码使用 PBKDF2 哈希；登录会话由服务端保存，浏览器只持有 HttpOnly Cookie。

## 部署说明

当前配置面向单机本地预览，尚未部署到公网。让其他网友访问前，需要准备 HTTPS 域名与托管环境，并为反向代理配置可信转发头；同时建议把 JSON 单进程存储迁移到数据库、为会话配置持久化存储，并补上备份、内容审核和账号找回流程。不要把本地 HTTP 地址当作公网论坛地址。
