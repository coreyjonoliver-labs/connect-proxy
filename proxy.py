"""connect-proxy: a minimal HTTP CONNECT proxy for a VPN-gateway sidecar.

Deliberately small and strict, because its input is an untrusted browser:

  - CONNECT only. Plain proxied requests (GET http://host/…) are refused;
    HTTPS is the only thing it relays, so it never parses or rewrites a
    request body or response.
  - Target ports 443 and 80 only.
  - The target hostname is resolved with the container's own resolver (in
    the intended deployment, the VPN container's DNS-over-TLS forwarder on
    127.0.0.1), asking for IPv4 answers only, and EVERY address it resolves
    to must be a global unicast IPv4 address. Loopback, private (RFC 1918),
    link-local, carrier-grade NAT (100.64/10), multicast, reserved and
    unspecified addresses are refused — a browser behind this proxy cannot
    reach the host, the cluster, or the LAN through it. The connection is
    made to the vetted address, never by re-resolving the name (no
    rebinding window). IPv6 is never dialled.
  - No authentication: who may reach the listener is the network policy's
    job, not this process's.
  - Bounded: request head size, concurrent connection count, idle timeout
    on both directions, and an ABSOLUTE deadline on the CONNECT handshake
    (a client trickling one byte per timeout cannot hold a slot open).
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
MAX_PENDING = 4 * RELAY_BUF  # per direction, before the reading side is paused

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
    """Read the CONNECT request head (bounded). Returns bytes or None.

    The bound is an absolute deadline of CONNECT_TIMEOUT from the first
    call, not a per-recv timeout: a per-recv timeout lets a client that
    sends one byte every few seconds hold a connection slot for hours."""
    deadline = time.monotonic() + CONNECT_TIMEOUT
    data = b""
    while b"\r\n\r\n" not in data:
        if len(data) >= MAX_HEADER_BYTES:
            return None
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        sock.settimeout(remaining)
        try:
            chunk = sock.recv(min(4096, MAX_HEADER_BYTES - len(data)))
        except OSError:  # timeout (TimeoutError is an OSError), reset, …
            return None
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
    return host, port


def vet(host):
    """Resolve (IPv4 only) and return ONE global-unicast IPv4 address, or None."""
    try:
        # AF_INET: ask the resolver for A records only. A dual-stack site's
        # AAAA answer must not poison an otherwise-global name (this proxy
        # never dials IPv6 anyway); the version check below stays as a
        # belt-and-braces guard on what the resolver hands back.
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
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
        # Any non-global answer poisons the whole name: a name that
        # resolves to a private address alongside a public one is a
        # rebinding/dual-answer trick, not a legitimate site.
        if ip.version != 4 or not ip.is_global or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            return None
        if chosen is None:
            chosen = str(ip)
    return chosen


def relay(a, b):
    """Bidirectional copy until either side closes or idles out.

    Non-blocking on both sides, with select() driving BOTH readability and
    writability: bytes read from one side wait in a per-direction buffer
    until the other side can take them, and a side whose peer's buffer is
    full is simply not read until it drains (backpressure, bounded to
    MAX_PENDING per direction). Never calls sendall on a non-blocking
    socket — that raised BlockingIOError the moment a slow reader's window
    filled and tore down every large download — and never blocks in a
    write, so two heavy directions cannot deadlock each other."""
    a.setblocking(False)
    b.setblocking(False)
    other = {a: b, b: a}
    pending = {a: b"", b: b""}  # bytes waiting to be written TO that socket
    last = time.monotonic()
    while True:
        remaining = IDLE_TIMEOUT - (time.monotonic() - last)
        if remaining <= 0:
            return
        want_r = [s for s in (a, b) if len(pending[other[s]]) < MAX_PENDING]
        want_w = [s for s in (a, b) if pending[s]]
        readable, writable, errored = select.select(want_r, want_w, [a, b], min(remaining, 30))
        if errored:
            return
        for s in writable:
            try:
                n = s.send(pending[s])
            except (BlockingIOError, InterruptedError):
                continue
            except OSError:
                return
            pending[s] = pending[s][n:]
            last = time.monotonic()
        for s in readable:
            try:
                data = s.recv(RELAY_BUF)
            except (BlockingIOError, InterruptedError):
                continue
            except OSError:
                return
            if not data:
                return  # either side closing ends the tunnel (no half-close semantics for TLS)
            pending[other[s]] += data
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
            send(client, 403, "Forbidden")  # non-global or unresolvable
            return
        try:
            upstream = socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT)
        except OSError:
            bump("failed")
            send(client, 502, "Bad Gateway")
            return
        try:
            client.sendall(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: connect-proxy\r\n\r\n")
            # Anything after the head belongs to the tunnel (TLS ClientHello).
            rest = head.split(b"\r\n\r\n", 1)[1]
            if rest:
                upstream.sendall(rest)
        except OSError:
            return
        bump("relayed")
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
