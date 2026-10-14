# 2026-10-14 认证诊断与验证

## 定位结果

本地日志显示旧版请求发送到 `https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate`，多次收到 HTTP 204 空响应，另外出现 HTTP 404 和缺失 Location 的 301。签名初始化成功不足以证明登录请求有效。

与 ipatool 当前 main `b0fe32d8a1499c91969a490288cb32b30abd6072` 对照时，发现 AppleVault 缺少上游对首次认证 URL 的规范化：应使用 `authenticate/`。差分测试先发现三组登录请求的 URL 不一致，修正后全部一致。

实际服务器验证使用空 plist，没有 Apple ID、密码、验证码、DSID 或账号令牌，仅带本次测试生成的签名。关闭代理、关闭自动跳转后，两条地址返回：

| 地址末尾 | HTTP 状态 | 响应字节 | 可解析为 plist |
| --- | --- | --- | --- |
| `authenticate` | 404 | 146 | 否 |
| `authenticate/` | 200 | 348 | 是，包含正常的认证失败字段 |

这确认了旧地址的路由问题；空请求的正常拒绝不代表真实账号已成功登录。

## 实现

- 对经过校验的 bag 认证 URL 补齐末尾 `/`，保留 host 和 query。
- 同步上游 macOS 27 / 26A434 ARM64 SAP 运行时、框架提取和完整性校验。
- 框架、Unicorn、证书和签名初始化共享应用代理配置和请求上下文。
- 登录重试的等待支持取消；保留限次重试、Retry-After、签名 POST 跳转、验证码处理和脱敏日志。

## 自动验证

普通测试不访问真实认证接口：

```powershell
go test ./...
go vet ./...
```

`go test ./...` 已通过。`go vet ./...` 在 Windows 原生 DLL 补丁代码中报告 9 处 `unsafe.Pointer` 提示；与未修改的上游运行同一检查时结果相同，这两个文件相对项目原始版本也没有变更。未为消除提示而改写原生指针逻辑；其余分析器通过 `go vet -unsafeptr=false ./...` 验证。

补充测试覆盖 bag 地址规范化、验证码、凭据重试、相对和 Store pod 跳转、Cookie 保留、账号保存、登录后历史版本查询、204 空响应分类，以及取消后不保存账号或继续等待。

原生运行时验证需要主动启用：

```powershell
$env:APPLEVAULT_NATIVE_TESTS = '1'
go test ./src/backend/... -count=1 -timeout=10m
```

本机已通过上述原生测试，包括向苹果证书及 SAP 初始化服务请求、生成两个不同的签名、关闭后拒绝签名，以及从 `NewAppStore` 默认 signer 到签名认证请求的完整调用路径。最后一项使用本地模拟认证回复，合成账号和密码不会发往苹果。其他普通测试中的原生 guest 测试也在本次启用后通过。

另在临时对照模块 `tmp/ipatool-reference-20261014-123839/wire-comparison` 中，将最新上游和 AppleVault 的全部 HTTPS 请求接到同一个本地 TLS 服务。邮箱、中国手机号、印度手机号三组场景，每组 7 条请求的 method、host、URL、正文原始字节、签名请求头、其他请求头、Cookie、账号保存和 signer 关闭次数全部相同。合成凭据只到达本地服务。

```powershell
go test -v -run '^TestWireMatchesLatestUpstream$' -count=1 ./...
```

上述命令在临时对照模块目录运行。匿名路由探测保存在同一目录的 `route_probe_test.go`，默认跳过，只有显式设置 `APPLEVAULT_ROUTE_PROBE=1` 才会向苹果发送空请求。

## 验证边界

Windows production 构建已完成，`build/bin/AppleVault-diagnostics.exe` 已替换并启动，进程启动日志确认 Go 1.26.5。此次文件 SHA-256 为 `66990017c5441997ae4a9c79363567a8d1b571742697f58210376e1712b3840c`，旧日志版可从同目录 `AppleVault-diagnostics-before-canonical-sap27-20261014155510.exe` 恢复。

用户随后反馈历史版本已可以查询。最初查询 404 是否由认证失败间接导致，现有日志不足以单独确认。自动验证没有读取或重用用户密码，也没有恢复删除的账号；认证路径探测、原生签名验证和模拟登录对照的结果见上文。
