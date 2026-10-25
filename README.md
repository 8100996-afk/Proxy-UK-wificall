# Proxy UK WiFi Call

面向 Ubuntu 的 SOCKS5 出口、VLESS/Trojan 订阅与英国 Wi‑Fi Calling 管理面板。

## 功能

- 最多管理 30 个 SOCKS5 出口，定时检测、故障停用与自动清理；
- 每个主订阅选择最多 3 个出口，全部失效时回落服务器公网 IP；
- 生成 VLESS、Trojan、Base64 通用订阅和 Clash/Mihomo YAML；
- EE、Three UK、Vodafone UK 的 UDP 500/4500 健康监控；
- 每月流量额度与只读累计计数，避免重置统计干扰 UDP 会话；
- 二级订阅、10–100 Mbps 独立限速、批量激活码、网页兑换与凭码找回；
- 激活后开始计时，到期自动物理删除；
- 英国和新加坡双时区显示；
- Caddy 自动 HTTPS、systemd 服务与定时任务。

## 环境要求

- 全新的 Ubuntu 22.04 或 24.04；
- root/sudo 权限；
- 3 个指向服务器的域名，例如：
  - `panel.example.com`：管理后台
  - `sub.example.com`：订阅和兑换页
  - `node.example.com`：VLESS/Trojan WebSocket 节点
- Cloudflare 可使用 DNS only 或代理模式；节点需要支持 WebSocket。

> Wi‑Fi Calling 是否注册成功还取决于运营商、SIM 权限、设备和服务器出口 IP。端口检测成功不等同于运营商一定允许 EAP-AKA 注册。

## 一键安装

```bash
git clone https://github.com/8100996-afk/Proxy-UK-wificall.git
cd Proxy-UK-wificall
chmod +x install.sh update.sh uninstall.sh
sudo ./install.sh
```

安装程序会询问三个域名和后台密码，自动安装 Caddy、Xray-core、Python 环境、服务与定时任务。留空密码时会生成随机密码。

安装完成后访问 `https://你的后台域名`。公开兑换页位于 `https://你的订阅域名/redeem`。

## Cloudflare DNS

为三个子域名添加指向服务器 IPv4 的 `A` 记录。首次申请证书时请确认 TCP 80/443 可从公网访问。若使用 Cloudflare 代理，请保持 WebSocket 开启，并避免缓存 `/s/*`、`/c/*`、`/redeem`。

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

备份时必须同时加密保存环境文件和数据库，否则无法恢复已加密的 SOCKS5 密码。

## 设计说明

Wi‑Fi Calling 的 IKE/IPsec 流量仅将 UDP 500/4500 固定从服务器直出。流量统计每 10 分钟只读累计计数，不使用 `statsquery -reset`，也不会在配置未变化时重启 Xray。

## 免责声明

请仅在你有权管理的服务器、网络和账号上使用，并遵守所在地法律、云服务商和运营商条款。项目不保证任意运营商或任意数据中心 IP 均可启用 Wi‑Fi Calling。

## License

[MIT](LICENSE)
