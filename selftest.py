"""connect-proxy selftest: starts the proxy on a loopback port and drives the
refusal paths and a loopback-target relay through it. No network needed —
the only "upstream" is a local echo listener on 127.0.0.1, which the proxy
must REFUSE by policy; the relay path is exercised with a monkeypatched
vet() that returns the echo listener's address.

Run: python3 selftest.py   (exit 0 = all PASS)
"""
import importlib.util
import os
import socket
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
os.environ["LISTEN"] = "127.0.0.1:0"
spec = importlib.util.spec_from_file_location("proxy", os.path.join(HERE, "proxy.py"))
proxy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proxy)


def start_proxy():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)
    port = srv.getsockname()[1]

    def loop():
        while True:
            c, _ = srv.accept()
            proxy._sem.acquire()
            threading.Thread(target=proxy.handle, args=(c,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return port


def start_echo():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    port = srv.getsockname()[1]

    def loop():
        while True:
            c, _ = srv.accept()

            def echo(c=c):
                try:
                    while True:
                        d = c.recv(4096)
                        if not d:
                            break
                        c.sendall(d.upper())
                finally:
                    c.close()

            threading.Thread(target=echo, daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return port


def status_of(pport, request):
    s = socket.create_connection(("127.0.0.1", pport), timeout=5)
    s.sendall(request)
    data = b""
    try:
        while b"\r\n\r\n" not in data:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    s.close()
    return data.split(b" ", 2)[1].decode() if data.startswith(b"HTTP/1.1 ") else "none"


fails = 0


def check(name, got, want):
    global fails
    ok = got == want
    fails += not ok
    print(("PASS" if ok else "FAIL"), name, "->", got, "" if ok else f"(want {want})")


pport = start_proxy()
eport = start_echo()

# ── refusals ─────────────────────────────────────────────────────────────
check("GET (non-CONNECT) refused", status_of(pport, b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"), "405")
check("CONNECT to a disallowed port refused", status_of(pport, b"CONNECT example.com:22 HTTP/1.1\r\n\r\n"), "405")
check("CONNECT loopback refused", status_of(pport, b"CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n"), "403")
check("CONNECT localhost refused", status_of(pport, b"CONNECT localhost:443 HTTP/1.1\r\n\r\n"), "403")
check("CONNECT RFC1918 refused", status_of(pport, b"CONNECT 192.168.0.10:443 HTTP/1.1\r\n\r\n"), "403")
check("CONNECT RFC1918 (10/8) refused", status_of(pport, b"CONNECT 10.0.0.1:443 HTTP/1.1\r\n\r\n"), "403")
check("CONNECT CGNAT refused", status_of(pport, b"CONNECT 100.64.0.1:443 HTTP/1.1\r\n\r\n"), "403")
check("CONNECT link-local refused", status_of(pport, b"CONNECT 169.254.169.254:80 HTTP/1.1\r\n\r\n"), "403")
check("CONNECT IPv6 literal refused", status_of(pport, b"CONNECT [2606:4700::1]:443 HTTP/1.1\r\n\r\n"), "405")
check("CONNECT with userinfo refused", status_of(pport, b"CONNECT a@example.com:443 HTTP/1.1\r\n\r\n"), "405")
check("CONNECT with path refused", status_of(pport, b"CONNECT example.com:443/x HTTP/1.1\r\n\r\n"), "405")
check("oversized head refused", status_of(pport, b"CONNECT example.com:443 HTTP/1.1\r\nX: " + b"a" * 9000 + b"\r\n\r\n"), "400")
check("garbage refused", status_of(pport, b"\x00\x01\x02\r\n\r\n"), "405")

# ── the vet() policy itself ───────────────────────────────────────────────
check("vet(127.0.0.1) is None", proxy.vet("127.0.0.1"), None)
check("vet(10.0.0.1) is None", proxy.vet("10.0.0.1"), None)
check("vet(172.16.0.1) is None", proxy.vet("172.16.0.1"), None)
check("vet(192.168.1.1) is None", proxy.vet("192.168.1.1"), None)
check("vet(100.64.0.1) is None", proxy.vet("100.64.0.1"), None)
check("vet(0.0.0.0) is None", proxy.vet("0.0.0.0"), None)
check("vet(224.0.0.1) is None", proxy.vet("224.0.0.1"), None)
check("vet(::1) is None", proxy.vet("::1"), None)
check("vet(2606:4700::1) is None (IPv6 refused)", proxy.vet("2606:4700::1"), None)
check("vet(1.1.1.1) is global", proxy.vet("1.1.1.1"), "1.1.1.1")
check("vet(8.8.8.8) is global", proxy.vet("8.8.8.8"), "8.8.8.8")

# ── the relay path ────────────────────────────────────────────────────────
# vet() is patched to "approve" the loopback echo listener, and
# create_connection is pointed at its port (the proxy would otherwise dial
# 127.0.0.1:443). This exercises the handshake + bidirectional relay only;
# the policy that forbids exactly this target is tested unpatched above.
proxy.vet = lambda host: "127.0.0.1"
_real_cc = socket.create_connection
socket.create_connection = lambda addr, timeout=None: _real_cc(("127.0.0.1", eport), timeout=timeout)
try:
    # The CLIENT side must use the real connect (the patch above is for the
    # proxy's upstream dial only; both live in the same socket module).
    s = _real_cc(("127.0.0.1", pport), timeout=5)
    s.sendall(b"CONNECT echo.test:443 HTTP/1.1\r\nHost: echo.test:443\r\n\r\nhello")
    head = b""
    while b"\r\n\r\n" not in head:
        head += s.recv(4096)
    check("relay: 200 Connection Established", head.split(b" ", 2)[1].decode(), "200")
    tail = head.split(b"\r\n\r\n", 1)[1]
    while len(tail) < 5:
        tail += s.recv(4096)
    check("relay: bytes after the head reach the target and come back", tail[:5], b"HELLO")
    s.sendall(b"again")
    got = b""
    while len(got) < 5:
        got += s.recv(4096)
    check("relay: bidirectional after the handshake", got[:5], b"AGAIN")
    s.close()
finally:
    socket.create_connection = _real_cc

print("ALL PASS" if fails == 0 else f"{fails} FAILURE(S)")
sys.exit(1 if fails else 0)
