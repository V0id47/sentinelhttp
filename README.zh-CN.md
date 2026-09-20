# SentinelHTTP

[English](README.md) · [Español](README.es.md) · [Русский](README.ru.md) · [简体中文](README.zh-CN.md)

SentinelHTTP 是一款本地、受限的 HTTP/HTTPS 配置评估工具，也是一个网络安全作品集项目。
默认只获取一个响应；它将审慎的发现与证据关联，计算显示证据覆盖情况的配置评分，
比较可比的报告，并在本地仪表盘中展示结果。它不证明漏洞可利用，也不保证整个网站安全。

仅对您拥有或已获授权评估的系统使用本工具。

## 快速开始

需要 Go 1.26 或更新版本（CI 使用 1.27.1）。仓库中的仪表盘资源无需 Node.js 即可运行；
重新构建前端需要 Node.js 24 和 npm。参阅[安装说明](docs/install.md)。

```console
go run ./cmd/sentinelhttp version
go run ./cmd/sentinelhttp scan http://127.0.0.1:8080/ --allow-private --format json --output report.json --lang zh-CN
go run ./cmd/sentinelhttp serve report.json
```

示例假设本机 8080 端口运行 HTTP 服务。仪表盘绑定 `127.0.0.1` 的随机端口；
使用 `--no-open` 可禁止自动打开浏览器。已有报告文件不会被覆盖。

在 Windows、macOS 和 iOS 上扫描 HTTPS 时，必须通过 `--ca-file roots.pem`
提供最新的 PEM CA 证书包。这样 Go 可在批准的网络边界内完成证书验证，
无需通过原生证书链构建过程向外获取颁发者。提供的证书包会替代本次扫描的系统根证书；
TLS 验证绝不会被关闭。

```console
go run ./cmd/sentinelhttp scan https://your-authorized-host.example/ --ca-file roots.pem --format json --output before.json --lang zh-CN
go run ./cmd/sentinelhttp diff before.json after.json --format terminal --lang zh-CN
go run ./cmd/sentinelhttp scan http://127.0.0.1:8080/ --allow-private --trace-redirects --probe-cors --max-redirects 3 --max-requests 7
```

默认扫描只发送一次 GET。最后一条命令显式启用本地实验：重定向追踪最多四次 GET，
另有三次不携带凭据的 CORS 采样。每次请求均经过同一范围批准和实际连接对端验证。
默认阻止私有及 loopback 地址；`--allow-private` 允许它们，同时将重定向限制在原主机。
HTTPS→HTTP 降级会被阻止。不提供爬取、登录、发送 cookie 或认证探测。

## 报告与隐私

版本化 JSON 记录有明确上限的 HTTP、TLS、安全响应头、cookie、CSP、CORS 和重定向证据。
每项发现区分观察、推断、置信度与局限。评分只覆盖一个已捕获的主要响应，
并显示哪些领域可评估。没有发现不等于应用安全。

报告不保存路径、查询参数、响应正文、cookie 值或原始 `Location` 值。
来源域名、证书信息和 cookie 名称仍可能敏感，请保护报告文件。
`diff` 只自动比较同一来源、无查询参数的根路径扫描；无法确认的变化标为 `unknown`。
仪表盘读取已验证的本地文件，但结构验证不能证明报告的来源真实性。

[报告格式](docs/reporting.md) · [评分](docs/scoring.md) ·
[差异比较](docs/diff.md) · [仪表盘](docs/dashboard.md) ·
[安全模型](docs/security.md)。

## 架构与验证

`network` 是扫描出站连接的唯一所有者；`dashboard` 仅开放本机回环入站监听。
分析器、发现引擎、评分、报告和差异引擎只处理已捕获证据，不自行联网。
React/TypeScript 前端内嵌于 Go 程序，无需 CDN。
[架构](docs/architecture.md) · [架构自评](docs/architecture-self-review.md) ·
[作品集案例](docs/portfolio.md)。

```console
go test ./...
go vet ./...
npm ci --prefix frontend
npm run build --prefix frontend
```

测试使用模拟 DNS/连接和本地 HTTP/TLS 服务，不扫描公共目标。Linux CI 运行 Go 竞争检测
和依赖安全审计；开发所用 Windows 机器缺少运行本地 `go test -race` 的 C 编译器。
界面支持英语、西班牙语、俄语和简体中文；`--lang` 不改变 JSON。
[CLI 说明](docs/cli.md) · [开发说明](docs/development.md)。
