import json
import os
import socket
import struct
import subprocess
import tempfile
import threading
import time

from .core import db, init_db, now


CARRIERS = {
    "EE": {
        "domain": "epdg.epc.mnc030.mcc234.pub.3gppnetwork.org",
        "dhgroup": 2,
        "port4500_probe_interval": 21600,
        "port4500_grace": 86400,
    },
    "Three UK": {
        "domain": "epdg.epc.mnc020.mcc234.pub.3gppnetwork.org",
        "dhgroup": 14,
        # Three rotates these ePDG addresses in DNS. Some gateways silently
        # drop a stateless UDP/4500 SA_INIT probe while another gateway in the
        # same pool responds normally, so carrier health must cover the pool
        # instead of treating one randomly returned address as authoritative.
        "endpoints": [
            "185.153.237.96",
            "185.153.237.97",
            "185.153.237.98",
            "185.153.237.99",
        ],
        # Repeated unauthenticated NAT-T probes trigger Three's ePDG rate
        # limiting and can create false outages. Verify UDP/4500 at a low
        # frequency, while UDP/500 remains an active check every ten minutes.
        "port4500_probe_interval": 21600,
        "port4500_grace": 86400,
        "max_candidates": 1,
    },
    "Vodafone UK": {
        "domain": "epdg.epc.mnc015.mcc234.pub.3gppnetwork.org",
        "dhgroup": 2,
        "port4500_probe_interval": 21600,
        "port4500_grace": 86400,
    },
}


def free_tcp_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def read_socks_address(sock, atyp):
    if atyp == 1:
        host = socket.inet_ntoa(sock.recv(4))
    elif atyp == 3:
        host = sock.recv(sock.recv(1)[0]).decode()
    elif atyp == 4:
        host = socket.inet_ntop(socket.AF_INET6, sock.recv(16))
    else:
        raise RuntimeError(f"未知 SOCKS 地址类型 {atyp}")
    return host, struct.unpack("!H", sock.recv(2))[0]


def socks_udp_associate(port):
    tcp = socket.create_connection(("127.0.0.1", port), 4)
    tcp.settimeout(10)
    tcp.sendall(b"\x05\x01\x00")
    if tcp.recv(2) != b"\x05\x00":
        raise RuntimeError("本地 SOCKS 协商失败")
    tcp.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    header = tcp.recv(4)
    if len(header) != 4 or header[1] != 0:
        raise RuntimeError("本地 SOCKS 不支持 UDP")
    relay = read_socks_address(tcp, header[3])
    if relay[0] in ("0.0.0.0", "::"):
        relay = ("127.0.0.1", relay[1])
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(0.4)
    return tcp, udp, relay


def strip_socks_udp(data):
    if len(data) < 10 or data[:3] != b"\x00\x00\x00":
        raise RuntimeError("无效 SOCKS UDP 响应")
    atyp = data[3]
    offset = 4
    if atyp == 1:
        offset += 4
    elif atyp == 3:
        offset += 1 + data[offset]
    elif atyp == 4:
        offset += 16
    else:
        raise RuntimeError("无效 SOCKS UDP 地址")
    return data[offset + 2 :]


def ike_probe(socks_port, ip, target_port, dhgroup):
    tcp, udp, relay = socks_udp_associate(socks_port)
    bridge = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bridge.bind(("127.0.0.1", 0))
    bridge.settimeout(0.3)
    bridge_port = bridge.getsockname()[1]
    stop = threading.Event()

    def forward():
        peer = None
        while not stop.is_set():
            try:
                payload, peer = bridge.recvfrom(16384)
                header = b"\x00\x00\x00\x01" + socket.inet_aton(ip) + struct.pack("!H", target_port)
                udp.sendto(header + payload, relay)
            except socket.timeout:
                pass
            try:
                response, _ = udp.recvfrom(32768)
                if peer:
                    bridge.sendto(strip_socks_udp(response), peer)
            except socket.timeout:
                pass

    thread = threading.Thread(target=forward, daemon=True)
    thread.start()
    args = [
        "ike-scan",
        "--ikev2",
        f"--dhgroup={dhgroup}",
        "--sport=0",
        f"--dport={bridge_port}",
        "--retry=2",
        "--timeout=2500",
        "127.0.0.1",
    ]
    if target_port == 4500:
        args.insert(2, "--nat-t")
    started = time.monotonic()
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=12)
        output = result.stdout + result.stderr
        ok = "Handshake returned" in output or "Notify message" in output
        kind = "handshake" if "Handshake returned" in output else ("notify" if "Notify message" in output else "timeout")
        return ok, kind, int((time.monotonic() - started) * 1000)
    finally:
        stop.set()
        thread.join(timeout=2)
        bridge.close()
        udp.close()
        tcp.close()


def start_xray_client(uuid_value, socks_port):
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"},
            }
        ],
        "outbounds": [
            {
                "protocol": "vless",
                "settings": {
                    "address": os.environ.get("NODE_DOMAIN", "node.example.com"),
                    "port": 443,
                    "id": uuid_value,
                    "encryption": "none",
                },
                "streamSettings": {
                    "method": "xhttp",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": os.environ.get("NODE_DOMAIN", "node.example.com"),
                        "alpn": ["h3"],
                    },
                    "xhttpSettings": {
                        "path": "/xhttp",
                        "mode": "auto",
                    },
                },
            }
        ],
    }
    fd, path = tempfile.mkstemp(prefix="wifi-call-client-", suffix=".json")
    with os.fdopen(fd, "w") as handle:
        json.dump(config, handle)
    process = subprocess.Popen(
        ["/usr/local/bin/xray", "run", "-c", path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(40):
        if process.poll() is not None:
            raise RuntimeError("测试客户端启动失败")
        try:
            test = socket.create_connection(("127.0.0.1", socks_port), 0.2)
            test.close()
            return process, path
        except OSError:
            time.sleep(0.1)
    process.terminate()
    raise RuntimeError("测试客户端启动超时")


def save_result(carrier, endpoint, results, error=None):
    port500 = bool(results.get(500, {}).get("ok"))
    port4500 = bool(results.get(4500, {}).get("ok"))
    latencies = [x["latency"] for x in results.values() if x.get("latency") is not None]
    detail = error or "; ".join(
        f"UDP {port}: {values.get('kind', 'error')}" for port, values in sorted(results.items())
    )
    with db() as conn:
        conn.execute(
            """INSERT INTO wifi_call_checks
               (carrier,endpoint,port500_ok,port4500_ok,ok,latency_ms,detail,checked_at,checked_at_epoch)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                carrier,
                endpoint,
                int(port500),
                int(port4500),
                int(port500 and port4500),
                int(sum(latencies) / len(latencies)) if latencies else None,
                detail[:500],
                now(),
                int(time.time()),
            ),
        )
        conn.execute(
            "DELETE FROM wifi_call_checks WHERE id NOT IN (SELECT id FROM wifi_call_checks ORDER BY id DESC LIMIT 3000)"
        )


def run_checks():
    init_db()
    with db() as conn:
        sub = conn.execute(
            "SELECT vless_uuid FROM subscriptions WHERE enabled=1 ORDER BY id LIMIT 1"
        ).fetchone()
    if not sub:
        for carrier in CARRIERS:
            save_result(carrier, None, {}, "没有已启用的 VLESS 订阅")
        return

    socks_port = free_tcp_port()
    process = None
    path = None
    try:
        process, path = start_xray_client(sub["vless_uuid"], socks_port)
        for carrier, settings in CARRIERS.items():
            results = {}
            endpoint = None
            try:
                current_epoch = int(time.time())
                last_4500_success = None
                if settings.get("port4500_probe_interval"):
                    with db() as conn:
                        previous = conn.execute(
                            """SELECT checked_at_epoch FROM wifi_call_checks
                               WHERE carrier=? AND port4500_ok=1
                                 AND detail LIKE '%UDP 4500: handshake%'
                               ORDER BY id DESC LIMIT 1""",
                            (carrier,),
                        ).fetchone()
                    if previous:
                        last_4500_success = previous["checked_at_epoch"]
                cached_4500 = bool(
                    last_4500_success
                    and current_epoch - last_4500_success
                    < settings.get("port4500_probe_interval", 0)
                )
                resolved = [
                    item[4][0]
                    for item in socket.getaddrinfo(settings["domain"], 0, socket.AF_INET, socket.SOCK_DGRAM)
                ]
                candidates = list(dict.fromkeys(settings.get("endpoints", []) + resolved))
                best_endpoint = None
                best_results = {}
                best_score = (-1, -1)
                for candidate in candidates[: settings.get("max_candidates", len(candidates))]:
                    candidate_results = {}
                    for port in (500, 4500):
                        if port == 4500 and cached_4500:
                            age_minutes = max(0, (current_epoch - last_4500_success) // 60)
                            candidate_results[port] = {
                                "ok": True,
                                "kind": f"最近实测成功（{age_minutes} 分钟前，限频保护）",
                                "latency": None,
                            }
                        else:
                            ok, kind, latency = ike_probe(socks_port, candidate, port, settings["dhgroup"])
                            candidate_results[port] = {"ok": ok, "kind": kind, "latency": latency}
                    successes = sum(int(value["ok"]) for value in candidate_results.values())
                    total_latency = sum((value.get("latency") or 0) for value in candidate_results.values())
                    score = (successes, -total_latency)
                    if score > best_score:
                        best_endpoint, best_results, best_score = candidate, candidate_results, score
                    if successes == 2:
                        break
                endpoint, results = best_endpoint, best_results
                # A silent NAT-T probe from Three is inconclusive rather than
                # proof of an outage. Preserve a recent verified result while
                # still requiring the fresh UDP/500 IKE check to pass.
                if (
                    settings.get("port4500_grace")
                    and results.get(500, {}).get("ok")
                    and not results.get(4500, {}).get("ok")
                    and last_4500_success
                    and current_epoch - last_4500_success < settings["port4500_grace"]
                ):
                    age_minutes = max(0, (current_epoch - last_4500_success) // 60)
                    results[4500] = {
                        "ok": True,
                        "kind": f"网关限频，沿用最近实测（{age_minutes} 分钟前）",
                        "latency": None,
                    }
                save_result(carrier, endpoint, results)
            except Exception as exc:
                save_result(carrier, endpoint, results, str(exc))
    finally:
        if process:
            process.terminate()
            try:
                process.wait(timeout=4)
            except subprocess.TimeoutExpired:
                process.kill()
        if path and os.path.exists(path):
            os.unlink(path)


if __name__ == "__main__":
    run_checks()

