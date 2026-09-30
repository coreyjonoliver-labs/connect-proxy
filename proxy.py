"""connect-proxy: a minimal HTTP CONNECT proxy for a VPN-gateway sidecar.

Deliberately small and strict, because its input is an untrusted browser:

  - CONNECT only. Plain proxied requests (GET http://host/…) are refused;
    HTTPS is the only thing it relays, so it never parses or rewrites a
    request body or response.
  - Target ports 443 and 80 only.
  - The target hostname is resolved with the container's own resolver (in
    the intended deployment, the VPN container's DNS-over-TLS forwarder on
    127.0.0.1), and EVERY address it resolves to must be a global unicast
    IPv4 address. Loopback, private (RFC 1918), link-local, carrier-grade
    NAT (100.64/10), multicast, reserved, unspecified and all IPv6 are
    refused — a browser behind this proxy cannot reach the host, the
    cluster, or the LAN through it. The connection is made to the vetted
    address, never by re-resolving the name (no rebinding window).
  - No authentication: who may reach the listener is the network policy's
    job, not this process's.
  - Bounded: request line / header size, concurrent connection count, idle
    timeout on both directions, and a hard cap on the CONNECT handshake.
  - Logs NOTHING per request — not the host, not the port, not the client.
    A proxy log is a browsing history. Startup and refusal COUNTS only.

Environment: LISTEN (default 0.0.0.0:8888), MAX_CONNECTIONS (64),
IDLE_TIMEOUT seconds (300), CONNECT_TIMEOUT seconds (15).
Python 3 standard library only.
"""
import ipaddress
import os
import select
import socket
import sys
import threading
import time

LISTEN = os.environ.get("LISTEN", "0.0.0.0:8888")
MAX_CONNECTIONS = int(os.environ.get("MAX_CONNECTIONS", "64"))
IDLE_TIMEOUT = float(os.environ.get("IDLE_TIMEOUT", "300"))
CONNECT_TIMEOUT = float(os.environ.get("CONNECT_TIMEOUT", "15"))
ALLOWED_PORTS = (443, 80)
MAX_HEADER_BYTES = 8192
MAX_HOST_LEN = 253
RELAY_BUF = 65536

_sem = threading.BoundedSemaphore(MAX_CONNECTIONS)
_stats = {"accepted": 0, "relayed": 0, "refused": 0, "failed": 0}
_stats_lock = threading.Lock()


def bump(key):
    with _stats_lock:
        _stats[key] += 1


def send(sock, status, reason):
    try:
        sock.sendall(f"HTTP/1.1 {status} {reason}\r\nProxy-Agent: connect-proxy\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".encode())
    except OSError:
        pass


def read_request(sock):
    """Read the CONNECT request head (bounded). Returns bytes or None."""
    sock.settimeout(CONNECT_TIMEOUT)
    data = b""
    while b"\r\n\r\n" not in data:
        if len(data) >= MAX_HEADER_BYTES:
            return None
        chunk = sock.recv(min(4096, MAX_HEADER_BYTES - len(data)))
        if not chunk:
            return None
        data += chunk
    return data


def parse_target(head):
    """`CONNECT host:port HTTP/1.x` → (host, port) or None."""
    line = head.split(b"\r\n", 1)[0]
    try:
        text = line.decode("ascii")
    except UnicodeDecodeError:
        return None
    parts = text.split(" ")
    if len(parts) != 3 or parts[0] != "CONNECT" or not parts[2].startswith("HTTP/1."):
        return None
    target = parts[1]
    if target.count(":") != 1 or target.startswith("[") or "/" in target or "@" in target:
        return None  # no IPv6 literals, no paths, no userinfo
    host, port_s = target.rsplit(":", 1)
    if not port_s.isdigit():
        return None
    port = int(port_s)
    if port not in ALLOWED_PORTS:
        return None
    host = host.strip().lower().rstrip(".")
    if not host or len(host) > MAX_HOST_LEN:
        return None
    if not all(c.isalnum() or c in "-." for c in host):
        return None
    if host.split(".")[-1].isdigit():
        # An IP literal — vetted like any other address below, but a
        # dotted-quad that is NOT global unicast is refused there.
        pass
    return host, port


def vet(host):
    """Resolve and return ONE global-unicast IPv4 address, or None."""
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError):
        return None
    if not infos:
        return None
    chosen = None
    for family, _, _, _, sockaddr in infos:
        try:
            ip = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            return None
        # Any non-global or non-IPv4 answer poisons the whole name: a name
        # that resolves to a private address alongside a public one is a
        # rebinding/dual-answer trick, not a legitimate site.
        if ip.version != 4 or not ip.is_global or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            return None
        if chosen is None:
            chosen = str(ip)
    return chosen


def relay(a, b):
    """Bidirectional copy until either side closes or idles out."""
    a.setblocking(False)
    b.setblocking(False)
    socks = [a, b]
    last = time.monotonic()
    while True:
        remaining = IDLE_TIMEOUT - (time.monotonic() - last)
        if remaining <= 0:
            return
        readable, _, errored = select.select(socks, [], socks, min(remaining, 30))
        if errored:
            return
        if not readable:
            continue
        for s in readable:
            try:
                data = s.recv(RELAY_BUF)
            except (BlockingIOError, InterruptedError):
                continue
            except OSError:
                return
            if not data:
                return
            other = b if s is a else a
            try:
                other.sendall(data)
            except OSError:
                return
            last = time.monotonic()


def handle(client):
    upstream = None
    try:
        bump("accepted")
        head = read_request(client)
        if head is None:
            bump("refused")
            send(client, 400, "Bad Request")
            return
        target = parse_target(head)
        if target is None:
            bump("refused")
            send(client, 405, "Method Not Allowed")  # CONNECT to :443/:80 only
            return
        host, port = target
        ip = vet(host)
        if ip is None:
            bump("refused")
            send(client, 403, "Forbidden")  # non-global, IPv6, or unresolvable
            return
        try:
            upstream = socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT)
        except OSError:
            bump("failed")
            send(client, 502, "Bad Gateway")
            return
        try:
            client.sendall(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: connect-proxy\r\n\r\n")
        except OSError:
            return
        bump("relayed")
        # Anything after the head belongs to the tunnel (TLS ClientHello).
        rest = head.split(b"\r\n\r\n", 1)[1]
        if rest:
            upstream.sendall(rest)
        relay(client, upstream)
    finally:
        for s in (client, upstream):
            if s is not None:
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    s.close()
                except OSError:
                    pass
        _sem.release()


def stats_reporter():
    while True:
        time.sleep(600)
        with _stats_lock:
            print("connect-proxy stats accepted=%(accepted)d relayed=%(relayed)d refused=%(refused)d failed=%(failed)d" % _stats, flush=True)


def main():
    host, port = LISTEN.rsplit(":", 1)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, int(port)))
    srv.listen(128)
    print(f"connect-proxy listening on {LISTEN} (CONNECT to :443/:80, global IPv4 targets only, max {MAX_CONNECTIONS} connections)", flush=True)
    threading.Thread(target=stats_reporter, daemon=True).start()
    while True:
        client, _ = srv.accept()
        if not _sem.acquire(blocking=False):
            send(client, 503, "Service Unavailable")
            try:
                client.close()
            except OSError:
                pass
            continue
        threading.Thread(target=handle, args=(client,), daemon=True).start()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
