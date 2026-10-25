import asyncio
import socket
import struct
import time

from .core import db, decrypt, init_db


class Bucket:
    def __init__(self, speed_mbps):
        self.speed_mbps = speed_mbps
        self.rate = speed_mbps * 1_000_000 / 8
        self.capacity = self.rate / 2
        self.tokens = self.capacity
        self.updated = time.monotonic()
        self.lock = asyncio.Lock()

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
        if username.startswith("sub-"):
            sub_id = int(username[4:])
            row = conn.execute(
                "SELECT id FROM subscriptions WHERE id=? AND enabled=1", (sub_id,)
            ).fetchone()
            return (sub_id, 10) if row else None
        if username.startswith("child-"):
            child_id = int(username[6:])
            row = conn.execute(
                """SELECT p.parent_subscription_id,a.speed_mbps FROM activation_codes a
                   JOIN secondary_plans p ON p.id=a.plan_id
                   WHERE a.id=? AND a.status='active' AND a.quota_exceeded=0 AND a.expires_at>?""",
                (child_id, time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())),
            ).fetchone()
            return (row["parent_subscription_id"], row["speed_mbps"]) if row else None
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


async def relay(reader, writer, bucket):
    try:
        while data := await reader.read(65536):
            await bucket.consume(len(data))
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()


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
        sub_id, speed_mbps = info
        client_writer.write(b"\x01\x00")
        await client_writer.drain()
        request = await client_reader.readexactly(4)
        if request[:3] != b"\x05\x01\x00":
            raise OSError("only CONNECT is supported")
        host = await read_address(client_reader, request[3])
        port = struct.unpack("!H", await client_reader.readexactly(2))[0]
        remote_reader, remote_writer = await open_target(sub_id, host, port)
        client_writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        await client_writer.drain()
        bucket_key = username
        bucket = buckets.get(bucket_key)
        if not bucket or bucket.speed_mbps != speed_mbps:
            bucket = buckets[bucket_key] = Bucket(speed_mbps)
        await asyncio.gather(
            relay(client_reader, remote_writer, bucket),
            relay(remote_reader, client_writer, bucket),
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
    server = await asyncio.start_server(handle, "127.0.0.1", 11080)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main_async())
