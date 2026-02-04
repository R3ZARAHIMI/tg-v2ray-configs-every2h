import re
import asyncio
import base64
import json
import os
from urllib.parse import urlparse, parse_qs
from pyrogram import Client
from pyrogram.errors import FloodWait
from typing import Optional, Dict, Any, Set, List

# =============================================================================
# FILTERS
# =============================================================================

BAD_SS_CIPHERS = {
    "rc4-md5",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb"
}

BAD_HOST_KEYWORDS = {
    "cloudflare", "workers.dev", "pages.dev",
    "github.io", "vercel.app", "arvan", "derak"
}

PUBLIC_DOMAINS = {
    "google.com", "bing.com", "yahoo.com",
    "wikipedia.org", "telegram.org", "instagram.com",
    "speedtest.net", "chatgpt.com"
}

UUID_REGEX = re.compile(
    r"^[0-9a-fA-F]{8}-"
    r"[0-9a-fA-F]{4}-"
    r"[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-"
    r"[0-9a-fA-F]{12}$"
)

V2RAY_PATTERNS = [
    re.compile(r'(vless://[^\s\'\"<>`]+)'),
    re.compile(r'(vmess://[^\s\'\"<>`]+)'),
    re.compile(r'(trojan://[^\s\'\"<>`]+)'),
    re.compile(r'(ss://[^\s\'\"<>`]+)'),
    re.compile(r'(hysteria2://[^\s\'\"<>`]+)'),
    re.compile(r'(hy2://[^\s\'\"<>`]+)'),
    re.compile(r'(tuic://[^\s\'\"<>`]+)')
]

# =============================================================================
# SETTINGS
# =============================================================================

API_ID = int(os.environ["API_ID"])
API_HASH = os.environ["API_HASH"]
SESSION_STRING = os.environ["SESSION_STRING"]

CHANNELS = os.environ.get("CHANNELS_LIST", "").split(",")
GROUPS = [int(x) for x in os.environ.get("GROUPS_LIST", "").split(",") if x]

CHANNEL_LIMIT = int(os.environ.get("CHANNEL_SEARCH_LIMIT", 5))
GROUP_LIMIT = int(os.environ.get("GROUP_SEARCH_LIMIT", 100))

OUTPUT_FILE = "sing-box.json"

# =============================================================================
# CLASH / SING-BOX SAFE FILTER
# =============================================================================

def is_safe_proxy(p: Dict[str, Any]) -> bool:
    server = p.get("server")
    if not server:
        return False

    s = server.lower()
    if s in PUBLIC_DOMAINS:
        return False
    if any(k in s for k in BAD_HOST_KEYWORDS):
        return False

    t = p["type"]

    if t == "ss" and p.get("cipher") in BAD_SS_CIPHERS:
        return False

    if t in ("vmess", "vless", "tuic"):
        if not p.get("uuid") or not UUID_REGEX.match(p["uuid"]):
            return False

    if t == "vless" and p.get("reality"):
        r = p["reality"]
        if not r.get("public_key") or not r.get("short_id"):
            return False

    return True

# =============================================================================
# MAIN CLASS
# =============================================================================

class V2RayExtractor:
    def __init__(self):
        self.raw: Set[str] = set()
        self.client = Client(
            "my_account",
            api_id=API_ID,
            api_hash=API_HASH,
            session_string=SESSION_STRING
        )

    # -------------------------------------------------------------------------
    # PARSERS
    # -------------------------------------------------------------------------

    def parse(self, url: str) -> Optional[Dict[str, Any]]:
        try:
            if url.startswith("vmess://"):
                data = json.loads(base64.b64decode(url[8:] + "==").decode())
                return {
                    "type": "vmess",
                    "server": data.get("add"),
                    "port": int(data.get("port", 443)),
                    "uuid": data.get("id"),
                    "tls": data.get("tls") == "tls",
                    "servername": data.get("sni") or data.get("host"),
                    "ws": data.get("net") == "ws",
                    "ws_path": data.get("path"),
                    "ws_host": data.get("host")
                }

            if url.startswith("vless://"):
                p = urlparse(url)
                q = parse_qs(p.query)
                return {
                    "type": "vless",
                    "server": p.hostname,
                    "port": p.port or 443,
                    "uuid": p.username,
                    "servername": q.get("sni", [""])[0],
                    "flow": q.get("flow", [""])[0],
                    "reality": {
                        "public_key": q.get("pbk", [""])[0],
                        "short_id": q.get("sid", [""])[0]
                    } if q.get("security", [""])[0] == "reality" else None
                }

            if url.startswith("trojan://"):
                p = urlparse(url)
                q = parse_qs(p.query)
                return {
                    "type": "trojan",
                    "server": p.hostname,
                    "port": p.port or 443,
                    "password": p.username,
                    "servername": q.get("sni", [""])[0]
                }

            if url.startswith("ss://"):
                raw = url[5:]
                user, host = raw.split("@", 1)
                cipher, password = base64.b64decode(user + "==").decode().split(":")
                server, port = host.split(":")
                return {
                    "type": "ss",
                    "server": server,
                    "port": int(port),
                    "cipher": cipher,
                    "password": password
                }

            if url.startswith(("hy2://", "hysteria2://")):
                p = urlparse(url)
                return {
                    "type": "hysteria2",
                    "server": p.hostname,
                    "port": p.port or 443,
                    "password": p.username
                }

            if url.startswith("tuic://"):
                p = urlparse(url)
                q = parse_qs(p.query)
                return {
                    "type": "tuic",
                    "server": p.hostname,
                    "port": p.port or 443,
                    "uuid": p.username,
                    "password": q.get("password", [""])[0]
                }
        except:
            return None
        return None

    # -------------------------------------------------------------------------
    # SCAN
    # -------------------------------------------------------------------------

    async def scan(self, chat_id: int, limit: int):
        try:
            async for m in self.client.get_chat_history(chat_id, limit=limit):
                text = m.text or m.caption or ""
                for pat in V2RAY_PATTERNS:
                    self.raw.update(pat.findall(text))
        except FloodWait as e:
            await asyncio.sleep(e.value + 1)
            await self.scan(chat_id, limit)
        except:
            pass

    # -------------------------------------------------------------------------
    # BUILD SING-BOX
    # -------------------------------------------------------------------------

    def build_singbox(self, proxies: List[Dict[str, Any]]) -> Dict[str, Any]:
        outbounds = []

        for i, p in enumerate(proxies, 1):
            tag = f"proxy-{i}"
            t = p["type"]

            base = {
                "tag": tag,
                "type": t,
                "server": p["server"],
                "server_port": p["port"]
            }

            if t == "vmess":
                o = {**base, "uuid": p["uuid"], "security": "auto"}
                if p.get("tls"):
                    o["tls"] = {
                        "enabled": True,
                        "server_name": p.get("servername"),
                        "insecure": True
                    }
                outbounds.append(o)

            elif t == "vless":
                o = {**base, "uuid": p["uuid"], "tls": {
                    "enabled": True,
                    "server_name": p.get("servername"),
                    "insecure": True
                }}
                if p.get("flow"):
                    o["flow"] = p["flow"]
                if p.get("reality"):
                    o["tls"]["reality"] = {
                        "enabled": True,
                        "public_key": p["reality"]["public_key"],
                        "short_id": p["reality"]["short_id"]
                    }
                outbounds.append(o)

            elif t == "trojan":
                outbounds.append({**base, "password": p["password"], "tls": {
                    "enabled": True,
                    "server_name": p.get("servername"),
                    "insecure": True
                }})

            elif t == "ss":
                outbounds.append({
                    "type": "shadowsocks",
                    "tag": tag,
                    "server": p["server"],
                    "server_port": p["port"],
                    "method": p["cipher"],
                    "password": p["password"]
                })

            elif t == "hysteria2":
                outbounds.append({
                    **base,
                    "password": p["password"],
                    "up_mbps": 100,
                    "down_mbps": 100,
                    "tls": {"enabled": True, "insecure": True}
                })

            elif t == "tuic":
                outbounds.append({
                    **base,
                    "uuid": p["uuid"],
                    "password": p["password"],
                    "tls": {"enabled": True, "insecure": True}
                })

        tags = [o["tag"] for o in outbounds]

        return {
            "log": {"level": "warn", "timestamp": True},
            "dns": {
                "servers": [
                    {"tag": "dns-direct", "address": "8.8.8.8"},
                    {"tag": "dns-proxy", "address": "https://dns.google/dns-query", "detour": "PROXY"}
                ],
                "rules": [{"outbound": "any", "server": "dns-proxy"}],
                "final": "dns-proxy"
            },
            "inbounds": [{
                "type": "mixed",
                "listen": "127.0.0.1",
                "listen_port": 2080,
                "sniff": True
            }],
            "outbounds": [
                {"type": "direct", "tag": "direct"},
                {"type": "block", "tag": "block"},
                {"type": "dns", "tag": "dns-out"},
                *outbounds,
                {"type": "selector", "tag": "PROXY", "outbounds": tags, "default": tags[0] if tags else "direct"}
            ],
            "route": {
                "rules": [{"protocol": "dns", "outbound": "dns-out"}]
            }
        }

    # -------------------------------------------------------------------------
    # RUN
    # -------------------------------------------------------------------------

    def save(self):
        proxies = []
        for url in self.raw:
            p = self.parse(url)
            if p and is_safe_proxy(p):
                proxies.append(p)

        config = self.build_singbox(proxies)

        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)

        print(f"✔ sing-box.json generated ({len(proxies)} proxies)")

# =============================================================================
# ENTRY
# =============================================================================

async def main():
    ex = V2RayExtractor()
    async with ex.client:
        tasks = []
        for c in CHANNELS:
            if c.strip():
                tasks.append(ex.scan(c.strip(), CHANNEL_LIMIT))
        for g in GROUPS:
            tasks.append(ex.scan(g, GROUP_LIMIT))
        await asyncio.gather(*tasks)
    ex.save()

if __name__ == "__main__":
    asyncio.run(main())
