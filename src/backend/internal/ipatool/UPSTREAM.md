# ipatool 上游来源

AppleVault 内嵌了经过适配的 ipatool 代码。

2026-10-14 的认证同步参考官方正式版 [v2.7.0](https://github.com/majd/ipatool/releases/tag/v2.7.0)（`4484b55d366e177ae6c89758c61588712c572fad`），并同步上游主分支 [b0fe32d8](https://github.com/majd/ipatool/commit/b0fe32d8a1499c91969a490288cb32b30abd6072) 的 macOS 27 签名运行时。该提交在本次工作中通过 GitHub API 核对为当前 main。

本次同步范围：在校验苹果 bag URL 后，将认证地址规范为 `authenticate/`，保留服务器指定的 host 和 query；登录 POST 跳转时保留原始请求、相对跳转与次数限制、独立认证连接与超时、传输错误分类、有限次数退避及 Retry-After、验证码规范化、手机号账号的 Storefront 路由提示，以及稳定的设备标识选择（优先物理网卡的永久 MAC 地址、验证地址、缓存解析结果）。保留了 AppleVault 的数据目录、非交互密码输入、请求上下文、显式代理配置、脱敏诊断日志和中文界面提示。重试等待响应调用方的取消和超时。

SAP 的 assets、Mach-O 加载、ARM64 guest 和 Unicorn 运行时整体同步上述主分支；框架固定为 macOS 27.0.1 / 26A434，并验证各文件的大小和 SHA-256。通过稀疏 HTTP Range、AEA/APFS/dyld 解析提取框架，使用纯 Go LZFSE 兼容模块，避免新增 CGo 运行依赖。Go 版本升级到 1.26.5，go-macho 和 purego 与所参考上游一致。

这不是整个 SDK 的版本替换。历史版本下载保留 AppleVault 的实现，已加入从登录、验证码、账号保存到历史版本查询的完整模拟流程测试；未在真实账号上确认查询结果。

上游版权和许可见 [LICENSE.ipatool](LICENSE.ipatool)。

AppleVault 将 SAP 框架与 Unicorn 下载、证书及签名初始化请求接入应用配置的同一个 HTTP Transport，并传递请求上下文。关闭应用代理时，这些请求不会再单独读取系统 HTTP_PROXY/HTTPS_PROXY；启用代理时，下载、签名初始化和认证使用同一代理。

验证方法和已知限制见 [认证诊断记录](../../../../docs/authentication-diagnostics.md)。
