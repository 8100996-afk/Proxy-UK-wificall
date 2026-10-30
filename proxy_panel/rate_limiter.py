import asyncio
import socket
import struct
import time

from .core import db, decrypt, get_setting, init_db


class Bucket:
    def __init__(self, speed_mbps):
        self.speed_mbps = speed_mbps
        self.rate = speed_mbps * 1_000_000 / 8
        self.capacity = self.rate / 2
        self.tokens = self.capacity
        self.updated = time.monotonic()
        self.lock = asyncio.Lock()

    def set_speed(self, speed_mbps):
        if self.speed_mbps == speed_mbps:
            return
        self.speed_mbps = speed_mbps
        self.rate = speed_mbps * 1_000_000 / 8
        self.capacity = self.rate / 2
        self.tokens = min(self.tokens, self.capacity)

    async def consume(self, amount):
        while True:
            async with self.lock:
                current = time.monotonic()
                self.tokens = min(self.capacity, self.tokens + (current - self.updated) * self.rate)
                self.updated = current
                if self.tokens >= amount:
                    self.tokens -= amount
                    return
                delay = (amount - self.tokens) / self.rate
            await asyncio.sleep(delay)


buckets = {}


def enabled_wifi_speeds():
    with db() as conn:
        return {
            f"wifi-{row['id']}": int(row["speed_mbps"])
            for row in conn.execute("SELECT id,speed_mbps FROM wifi_access WHERE enabled=1")
        }


async def refresh_wifi_bucket_speeds():
    """Apply admin speed changes without restarting active UDP associations."""
    while True:
        await asyncio.sleep(5)
        try:
            speeds = await asyncio.to_thread(enabled_wifi_speeds)
            for key, speed in speeds.items():
                bucket = buckets.get(key)
                if bucket:
                    bucket.set_speed(speed)
        except Exception:
            continue


async def read_address(reader, atyp):
    if atyp == 1:
        return socket.inet_ntoa(await reader.readexactly(4))
    if atyp == 3:
        length = (await reader.readexactly(1))[0]
        return (await reader.readexactly(length)).decode("idna")
    if atyp == 4:
        return socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
    raise ValueError("unsupported address type")


def encoded_address(host):
    try:
        return b"\x01" + socket.inet_aton(host)
    except OSError:
        pass
    try:
        return b"\x04" + socket.inet_pton(socket.AF_INET6, host)
    except OSError:
        value = host.encode("idna")
        return b"\x03" + bytes([len(value)]) + value


async def discard_reply_address(reader, atyp):
    if atyp == 1:
        await reader.readexactly(4)
    elif atyp == 3:
        await reader.readexactly((await reader.readexactly(1))[0])
    elif atyp == 4:
        await reader.readexactly(16)
    else:
        raise OSError("invalid upstream response")
    await reader.readexactly(2)


def upstreams(sub_id):
    with db() as conn:
        return conn.execute(
            """SELECT s.* FROM subscription_socks ss JOIN socks s ON s.id=ss.socks_id
               WHERE ss.subscription_id=? AND s.status='active'
               ORDER BY s.latency_ms IS NULL,s.latency_ms,ss.position LIMIT 3""",
            (sub_id,),
        ).fetchall()


def account_info(username):
    with db() as conn:
        if username.startswith("wifi-"):
            try:
                account_id = int(username[5:])
            except ValueError:
                return None
            row = conn.execute(
                "SELECT id,speed_mbps FROM wifi_access WHERE id=? AND enabled=1", (account_id,)
            ).fetchone()
            return (None, [(username, int(row["speed_mbps"]))]) if row else None
        if username.startswith("server-sub-"):
            sub_id = int(username[11:])
            row = conn.execute(
                "SELECT id,quota_exceeded FROM subscriptions WHERE id=? AND enabled=1", (sub_id,)
            ).fetchone()
            speed = max(1, int(get_setting("server_traffic_limit_mbps") or 10))
            if not row:
                return None
            specs = [("server-global", speed)]
            if row["quota_exceeded"]:
                specs.append((f"parent-{sub_id}", 10))
            return sub_id, specs
        if username.startswith("server-child-"):
            child_id = int(username[13:])
            row = conn.execute(
                """SELECT p.parent_subscription_id,a.speed_mbps,s.quota_exceeded FROM activation_codes a
                   JOIN secondary_plans p ON p.id=a.plan_id
                   JOIN subscriptions s ON s.id=p.parent_subscription_id
                   WHERE a.id=? AND a.status='active' AND a.quota_exceeded=0
                     AND a.expires_at>? AND s.enabled=1""",
                (child_id, time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())),
            ).fetchone()
            if not row:
                return None
            server_speed = max(1, int(get_setting("server_traffic_limit_mbps") or 10))
            specs = [("server-global", server_speed)]
            if row["quota_exceeded"]:
                specs.append((f"parent-{row['parent_subscription_id']}", 10))
            specs.append((f"child-{child_id}", int(row["speed_mbps"])))
            return row["parent_subscription_id"], specs
        if username.startswith("sub-"):
            sub_id = int(username[4:])
            row = conn.execute(
                "SELECT id FROM subscriptions WHERE id=? AND enabled=1", (sub_id,)
            ).fetchone()
            return (sub_id, [(f"parent-{sub_id}", 10)]) if row else None
        if username.startswith("child-"):
            child_id = int(username[6:])
            row = conn.execute(
                """SELECT p.parent_subscription_id,a.speed_mbps,s.quota_exceeded FROM activation_codes a
                   JOIN secondary_plans p ON p.id=a.plan_id
                   JOIN subscriptions s ON s.id=p.parent_subscription_id
                   WHERE a.id=? AND a.status='active' AND a.quota_exceeded=0
                     AND a.expires_at>? AND s.enabled=1""",
                (child_id, time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())),
            ).fetchone()
            if not row:
                return None
            specs = []
            if row["quota_exceeded"]:
                specs.append((f"parent-{row['parent_subscription_id']}", 10))
            specs.append((username, int(row["speed_mbps"])))
            return row["parent_subscription_id"], specs
    return None


async def connect_upstream(row, host, port):
    reader, writer = await asyncio.wait_for(asyncio.open_connection(row["host"], row["port"]), 8)
    username = decrypt(row["username_enc"]).encode()
    password = decrypt(row["password_enc"]).encode()
    method = b"\x02" if username or password else b"\x00"
    writer.write(b"\x05\x01" + method)
    await writer.drain()
    if await reader.readexactly(2) != b"\x05" + method:
        raise OSError("upstream authentication method rejected")
    if method == b"\x02":
        writer.write(b"\x01" + bytes([len(username)]) + username + bytes([len(password)]) + password)
        await writer.drain()
        if await reader.readexactly(2) != b"\x01\x00":
            raise OSError("upstream authentication failed")
    writer.write(b"\x05\x01\x00" + encoded_address(host) + struct.pack("!H", port))
    await writer.drain()
    reply = await reader.readexactly(4)
    if reply[1] != 0:
        raise OSError(f"upstream connect failed: {reply[1]}")
    await discard_reply_address(reader, reply[3])
    return reader, writer


async def open_target(sub_id, host, port):
    for row in upstreams(sub_id):
        try:
            return await connect_upstream(row, host, port)
        except Exception:
            continue
    return await asyncio.wait_for(asyncio.open_connection(host, port), 10)


async def relay(reader, writer, rate_buckets):
    try:
        while data := await reader.read(65536):
            for bucket in rate_buckets:
                await bucket.consume(len(data))
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()


def decode_udp_packet(data):
    if len(data) < 7 or data[:3] != b"\x00\x00\x00":
        raise ValueError("invalid SOCKS5 UDP packet")
    atyp = data[3]
    offset = 4
    if atyp == 1:
        if len(data) < offset + 4 + 2:
            raise ValueError("short IPv4 packet")
        host = socket.inet_ntoa(data[offset:offset + 4])
        offset += 4
    elif atyp == 3:
        length = data[offset]
        offset += 1
        if len(data) < offset + length + 2:
            raise ValueError("short domain packet")
        host = data[offset:offset + length].decode("idna")
        offset += length
    elif atyp == 4:
        if len(data) < offset + 16 + 2:
            raise ValueError("short IPv6 packet")
        host = socket.inet_ntop(socket.AF_INET6, data[offset:offset + 16])
        offset += 16
    else:
        raise ValueError("invalid address type")
    port = struct.unpack("!H", data[offset:offset + 2])[0]
    return host, port, data[offset + 2:]


async def consume_all(rate_buckets, amount):
    for bucket in rate_buckets:
        await bucket.consume(amount)


async def udp_associate(client_reader, client_writer, rate_buckets):
    """Relay one authenticated SOCKS5 UDP association on loopback only."""
    loop = asyncio.get_running_loop()
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.setblocking(False)
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 20)
    udp_socket.bind(("127.0.0.1", 0))
    bound_host, bound_port = udp_socket.getsockname()
    client_writer.write(
        b"\x05\x00\x00" + encoded_address(bound_host) + struct.pack("!H", bound_port)
    )
    await client_writer.drain()

    tcp_closed = asyncio.create_task(client_reader.read(1))
    client_address = None
    try:
        while True:
            udp_received = asyncio.create_task(loop.sock_recvfrom(udp_socket, 65535))
            done, _ = await asyncio.wait(
                {tcp_closed, udp_received}, return_when=asyncio.FIRST_COMPLETED
            )
            if tcp_closed in done:
                udp_received.cancel()
                await asyncio.gather(udp_received, return_exceptions=True)
                break
            data, source = udp_received.result()
            if client_address is None:
                if not source[0].startswith("127."):
                    continue
                client_address = source
            if source == client_address:
                try:
                    host, port, payload = decode_udp_packet(data)
                    # Defence in depth: this private relay can never be used as
                    # a general-purpose UDP proxy even if routing is misconfigured.
                    if port not in (500, 4500) or not payload:
                        continue
                    addresses = await loop.getaddrinfo(
                        host, port, family=socket.AF_INET, type=socket.SOCK_DGRAM
                    )
                    destination = addresses[0][4]
                    await consume_all(rate_buckets, len(payload))
                    await loop.sock_sendto(udp_socket, payload, destination)
                except (OSError, ValueError, UnicodeError):
                    continue
            else:
                await consume_all(rate_buckets, len(data))
                response = b"\x00\x00\x00" + encoded_address(source[0])
                response += struct.pack("!H", source[1]) + data
                await loop.sock_sendto(udp_socket, response, client_address)
    finally:
        tcp_closed.cancel()
        await asyncio.gather(tcp_closed, return_exceptions=True)
        udp_socket.close()


async def handle(client_reader, client_writer):
    remote_writer = None
    try:
        header = await client_reader.readexactly(2)
        methods = await client_reader.readexactly(header[1])
        if header[0] != 5 or 2 not in methods:
            client_writer.write(b"\x05\xff")
            return
        client_writer.write(b"\x05\x02")
        await client_writer.drain()
        auth = await client_reader.readexactly(2)
        username = (await client_reader.readexactly(auth[1])).decode()
        password_length = (await client_reader.readexactly(1))[0]
        password = (await client_reader.readexactly(password_length)).decode()
        info = account_info(username) if auth[0] == 1 else None
        if not info or password != "local-quota-limiter":
            client_writer.write(b"\x01\x01")
            return
        sub_id, bucket_specs = info
        client_writer.write(b"\x01\x00")
        await client_writer.drain()
        request = await client_reader.readexactly(4)
        if request[0] != 5 or request[2] != 0:
            raise OSError("invalid SOCKS5 request")
        host = await read_address(client_reader, request[3])
        port = struct.unpack("!H", await client_reader.readexactly(2))[0]
        rate_buckets = []
        for bucket_key, speed_mbps in bucket_specs:
            bucket = buckets.get(bucket_key)
            if not bucket:
                bucket = buckets[bucket_key] = Bucket(speed_mbps)
            elif bucket.speed_mbps != speed_mbps:
                bucket.set_speed(speed_mbps)
            rate_buckets.append(bucket)
        if request[1] == 3:
            await udp_associate(client_reader, client_writer, rate_buckets)
            return
        if request[1] != 1 or sub_id is None:
            raise OSError("command not permitted")
        remote_reader, remote_writer = await open_target(sub_id, host, port)
        client_writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        await client_writer.drain()
        await asyncio.gather(
            relay(client_reader, remote_writer, rate_buckets),
            relay(remote_reader, client_writer, rate_buckets),
            return_exceptions=True,
        )
    except Exception:
        try:
            client_writer.write(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
            await client_writer.drain()
        except Exception:
            pass
    finally:
        if remote_writer:
            remote_writer.close()
        client_writer.close()


async def main_async():
    init_db()
    refresh_task = asyncio.create_task(refresh_wifi_bucket_speeds())
    server = await asyncio.start_server(handle, "127.0.0.1", 11080)
    try:
        async with server:
            await server.serve_forever()
    finally:
        refresh_task.cancel()
        await asyncio.gather(refresh_task, return_exceptions=True)


if __name__ == "__main__":
    asyncio.run(main_async())
