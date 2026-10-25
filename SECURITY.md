# Security

请勿提交 `/etc/proxy-panel.env`、数据库、订阅链接、SOCKS5 凭据或 TLS 私钥。

发现安全问题时，请通过 GitHub Security Advisory 私下报告，不要先公开 Issue。

部署后建议：

- 使用 Cloudflare DNS 与严格 TLS；
- 后台使用至少 12 位随机密码；
- 仅开放 TCP 80/443 和必要的 SSH 管理端口；
- 定期更新 Ubuntu、Caddy、Xray-core 和 Python 依赖；
- 定期备份 `/var/lib/proxy-panel/panel.db` 与 `/etc/proxy-panel.env`，并加密保存。

