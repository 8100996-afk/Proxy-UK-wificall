# Proxy UK WiFi Call

面向 Ubuntu 的 SOCKS5 出口、VLESS/Trojan 订阅与英国 Wi‑Fi Calling 管理面板。

## 功能

- 最多管理 30 个 SOCKS5 出口，定时检测、故障停用与自动清理；
- 每个主订阅通过弹窗选择最多 3 个出口；单出口直接固定，多出口按实测延迟轮换，全部失效时回落服务器公网 IP；
- 生成优先使用 VLESS XHTTP（QUIC/HTTP3）的节点，并保留 XHTTP/HTTP2、VLESS/Trojan WebSocket 兼容回退、Base64 通用订阅和 Clash/Mihomo YAML；
- EE、Three UK、Vodafone UK 的 UDP 500/4500 健康监控；
- 主订阅与三级账号共享每月额度，显示实际用量和已分配额度，额度不足时阻止超额生成激活码；
- 服务器总出口流量默认 2 TB，可修改阈值并选择达量断开或全局限速；
- 独立 WiFi Call 专线账号：固定 5 Mbps，只允许 UDP 500/4500，其他流量在服务器端拒绝；支持独立订阅、停用、重置和删除；
- 二级订阅、10–100 Mbps 独立限速、批量激活码、前后四位搜索、批量复制/删除、网页兑换与凭码找回；
- 激活后开始计时，到期自动物理删除；
- 每天自动备份数据库和加密密钥，默认保留最近 14 天；
- 英国和新加坡双时区显示；
- Caddy 自动 HTTPS、systemd 服务与定时任务。

## 环境要求

- 全新的 Ubuntu 22.04 或 24.04；
- root/sudo 权限；
- 一个已托管到 Cloudflare 的新域名，例如 `example.com`。安装程序会自动使用：
  - `panel.example.com`：管理后台
  - `sub.example.com`：订阅和兑换页
  - `node.example.com`：VLESS XHTTP 及兼容回退节点
- Cloudflare 可使用 DNS only 或代理模式；节点需要支持 HTTP/2 与 WebSocket。

> Wi‑Fi Calling 是否注册成功还取决于运营商、SIM 权限、设备和服务器出口 IP。端口检测成功不等同于运营商一定允许 EAP-AKA 注册。

## 一键安装

```bash
git clone https://github.com/8100996-afk/Proxy-UK-wificall.git
cd Proxy-UK-wificall
chmod +x install.sh update.sh uninstall.sh
sudo ./install.sh
```

安装程序只询问根域名和后台密码，并自动生成 `panel.根域名`、`sub.根域名`、`node.根域名`。随后自动安装 Caddy、Xray-core、Python 环境、服务与定时任务。留空密码时会生成随机密码。

安装完成后访问 `https://你的后台域名`。公开兑换页位于 `https://你的订阅域名/redeem`。

## Cloudflare DNS

假设新服务器公网 IP 是 `203.0.113.10`，根域名是 `example.com`，在 Cloudflare DNS 添加：

| 类型 | 名称 | 内容 | 代理状态 |
| --- | --- | --- | --- |
| A | panel | 203.0.113.10 | 可开启代理 |
| A | sub | 203.0.113.10 | 可开启代理 |
| A | node | 203.0.113.10 | 可开启代理（XHTTP/HTTP2 与 WebSocket 回退） |

也可以先全部设为 DNS only，确认 Caddy 成功签发证书后再开启代理。Cloudflare 的 SSL/TLS 模式建议使用 `Full (strict)`。首次申请证书时请确认 TCP 80/443 可从公网访问，并避免缓存 `/s/*`、`/c/*`、`/redeem`。

## 更新

```bash
git pull
sudo ./update.sh
```

更新脚本不会覆盖数据库和 `/etc/proxy-panel.env`。

## 数据与备份

- 配置密钥：`/etc/proxy-panel.env`
- SQLite 数据库：`/var/lib/proxy-panel/panel.db`
- Xray 配置：`/usr/local/etc/xray/config.json`
- 每日备份：`/var/backups/proxy-panel/YYYY-MM-DD/`

备份时必须同时加密保存环境文件和数据库，否则无法恢复已加密的 SOCKS5 密码。

## 设计说明

Wi‑Fi Calling 的 IKE/IPsec 流量仅将 UDP 500/4500 固定从服务器直出。流量统计每 10 分钟只读累计计数，不使用 `statsquery -reset`，也不会在配置未变化时重启 Xray。

## 免责声明

请仅在你有权管理的服务器、网络和账号上使用，并遵守所在地法律、云服务商和运营商条款。项目不保证任意运营商或任意数据中心 IP 均可启用 Wi‑Fi Calling。

## License

[MIT](LICENSE)
