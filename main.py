import re
import asyncio
import base64
import json
import os
from urllib.parse import urlparse, parse_qs
from pyrogram import Client
from pyrogram.errors import FloodWait
from typing import Optional, Dict, Any, Set, List

# ================================================================================
# GLOBAL FILTERS
# ================================================================================

BAD_CIPHERS = {"rc4-md5", "aes-128-cfb", "aes-256-cfb"}

BAD_HOST_KEYWORDS = {
    "cloudflare", "workers.dev", "pages.dev", "github.io", "vercel.app",
    "arvan", "derak"
}

PUBLIC_DOMAINS = {
    "chatgpt.com", "speedtest.net", "google.com", "bing.com",
    "yahoo.com", "wikipedia.org", "telegram.org", "instagram.com"
}

UUID_REGEX = re.compile(
    r"^[0-9a-fA-F]{8}-"
    r"[0-9a-fA-F]{4}-"
    r"[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-"
    r"[0-9a-fA-F]{12}$"
)

V2RAY_PATTERNS = [
    re.compile(r'(vless:\/\/[^\s\'\"<>`]+)'),
    re.compile(r'(vmess:\/\/[^\s\'\"<>`]+)'),
    re.compile(r'(trojan:\/\/[^\s\'\"<>`]+)'),
    re.compile(r'(ss:\/\/[^\s\'\"<>`]+)'),
    re.compile(r"(hysteria2:\/\/[^\s'\"<>`]+)"),
    re.compile(r"(hy2:\/\/[^\s'\"<>`]+)"),
    re.compile(r"(tuic:\/\/[^\s'\"<>`]+)")
]

# ================================================================================
# SETTINGS
# ================================================================================

API_ID = int(os.environ.get("API_ID"))
API_HASH = os.environ.get("API_HASH")
SESSION_STRING = os.environ.get("SESSION_STRING")
CHANNELS_STR = os.environ.get("CHANNELS_LIST")
GROUPS_STR = os.environ.get("GROUPS_LIST")

CHANNEL_SEARCH_LIMIT = int(os.environ.get("CHANNEL_SEARCH_LIMIT", 5))
GROUP_SEARCH_LIMIT = int(os.environ.get("GROUP_SEARCH_LIMIT", 100))

OUTPUT_SINGBOX = "sing-box.json"

def process_lists():
    channels = [c.strip() for c in CHANNELS_STR.split(',')] if CHANNELS_STR else []
    groups = []
    if GROUPS_STR:
        try:
            groups = [int(g.strip()) for g in GROUPS_STR.split(',')]
        except:
            pass
    return channels, groups

CHANNELS, GROUPS = process_lists()

# ================================================================================
# MAIN CLASS
# ================================================================================

class V2RayExtractor:

    def __init__(self):
        self.raw_configs: Set[str] = set()
        self.client = Client(
            "my_account",
            api_id=API_ID,
            api_hash=API_HASH,
            session_string=SESSION_STRING
        )

    # ---------------------------------------------------------------------------
    # VALIDATION
    # ---------------------------------------------------------------------------

    def is_valid_proxy_object(self, p: Dict[str, Any]) -> bool:
        server = p.get("server")
        if not server:
            return False

        s = server.lower()
        if s in PUBLIC_DOMAINS:
            return False
        if any(k in s for k in BAD_HOST_KEYWORDS):
            return False

        if p["type"] in ("vless", "vmess", "tuic"):
            if not p.get("uuid") or not UUID_REGEX.match(p["uuid"]):
                return False

        if p["type"] == "trojan":
            if not p.get("password") or len(str(p["password"])) < 6:
                return False

        if p["type"] == "ss" and p.get("cipher") in BAD_CIPHERS:
            return False

        if p["type"] == "vless" and p.get("reality-opts"):
            r = p["reality-opts"]
            if not r.get("public-key") or not r.get("short-id"):
                return False

        return True

    # ---------------------------------------------------------------------------
    # PARSERS
    # ---------------------------------------------------------------------------

    def parse_config_for_clash(self, url: str) -> Optional[Dict[str, Any]]:
        try:
            if url.startswith("vmess://"):
                return self.parse_vmess(url)
            if url.startswith("vless://"):
                return self.parse_vless(url)
            if url.startswith("trojan://"):
                return self.parse_trojan(url)
            if url.startswith("ss://"):
                return self.parse_ss(url)
            if url.startswith(("hy2://", "hysteria2://")):
                return self.parse_hysteria2(url)
            if url.startswith("tuic://"):
                return self.parse_tuic(url)
        except:
            return None
        return None

    def parse_vmess(self, url: str):
        data = json.loads(base64.b64decode(url[8:] + "==").decode())
        return {
            "type": "vmess",
            "server": data.get("add"),
            "port": int(data.get("port", 443)),
            "uuid": data.get("id"),
            "cipher": data.get("scy", "auto"),
            "alterId": int(data.get("aid", 0)),
            "tls": data.get("tls") == "tls",
            "servername": data.get("sni") or data.get("host"),
            "ws-opts": {
                "path": data.get("path", "/"),
                "headers": {"Host": data.get("host", "")}
            } if data.get("net") == "ws" else None
        }

    def parse_vless(self, url: str):
        p = urlparse(url)
        q = parse_qs(p.query)

        ws = None
        if q.get("type", [""])[0] == "ws":
            ws = {
                "path": q.get("path", ["/"])[0],
                "headers": {"Host": q.get("host", [""])[0]}
            }

        reality = None
        if q.get("security", [""])[0] == "reality":
            reality = {
                "public-key": q.get("pbk", [""])[0],
                "short-id": q.get("sid", [""])[0]
            }

        return {
            "type": "vless",
            "server": p.hostname,
            "port": p.port or 443,
            "uuid": p.username,
            "flow": q.get("flow", [""])[0],
            "tls": True,
            "servername": q.get("sni", [""])[0],
            "ws-opts": ws,
            "reality-opts": reality
        }

    def parse_trojan(self, url: str):
        p = urlparse(url)
        q = parse_qs(p.query)
        return {
            "type": "trojan",
            "server": p.hostname,
            "port": p.port or 443,
            "password": p.username,
            "servername": q.get("sni", [""])[0]
        }

    def parse_ss(self, url: str):
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

    def parse_hysteria2(self, url: str):
        p = urlparse(url)
        return {
            "type": "hysteria2",
            "server": p.hostname,
            "port": p.port or 443,
            "password": p.username,
            "sni": p.hostname
        }

    def parse_tuic(self, url: str):
        p = urlparse(url)
        q = parse_qs(p.query)
        return {
            "type": "tuic",
            "server": p.hostname,
            "port": p.port or 443,
            "uuid": p.username,
            "password": q.get("password", [""])[0],
            "sni": q.get("sni", [""])[0]
        }

    # ---------------------------------------------------------------------------
    # EXTRACTION
    # ---------------------------------------------------------------------------

    def extract_configs(self, text: str):
        found = set()
        for pat in V2RAY_PATTERNS:
            found.update(pat.findall(text))
        return found

    async def scan_chat(self, chat_id: int, limit: int):
        try:
            async for msg in self.client.get_chat_history(chat_id, limit=limit):
                text = msg.text or msg.caption or ""
                self.raw_configs.update(self.extract_configs(text))
        except FloodWait as e:
            await asyncio.sleep(e.value + 1)
            await self.scan_chat(chat_id, limit)
        except:
            pass

    # ---------------------------------------------------------------------------
    # SING-BOX EXPORT (LOSSLESS)
    # ---------------------------------------------------------------------------

    def convert_to_singbox_outbound(self, p: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        t = p["type"]
        base = {
            "tag": p["name"],
            "type": t,
            "server": p["server"],
            "server_port": p["port"]
        }

        tls_base = {
            "enabled": True,
            "server_name": p.get("servername") or p.get("server"),
            "insecure": True,
            "utls": {"enabled": True, "fingerprint": "chrome"}
        }

        if t == "vmess":
            out = {**base, "uuid": p["uuid"], "security": "auto"}
            if p.get("alterId", 0):
                out["alter_id"] = p["alterId"]
            if p.get("tls"):
                out["tls"] = tls_base
            if p.get("ws-opts"):
                out["transport"] = {
                    "type": "ws",
                    "path": p["ws-opts"]["path"],
                    "headers": p["ws-opts"].get("headers", {})
                }
            return out

        if t == "vless":
            out = {**base, "uuid": p["uuid"], "tls": tls_base}
            if p.get("flow"):
                out["flow"] = p["flow"]
            if p.get("reality-opts"):
                out["tls"]["reality"] = {
                    "enabled": True,
                    "public_key": p["reality-opts"]["public-key"],
                    "short_id": p["reality-opts"]["short-id"]
                }
            elif p.get("ws-opts"):
                out["transport"] = {
                    "type": "ws",
                    "path": p["ws-opts"]["path"],
                    "headers": p["ws-opts"].get("headers", {})
                }
            return out

        if t == "trojan":
            return {**base, "password": p["password"], "tls": tls_base}

        if t == "ss":
            return {
                "type": "shadowsocks",
                "tag": base["tag"],
                "server": base["server"],
                "server_port": base["server_port"],
                "method": p["cipher"],
                "password": p["password"]
            }

        if t == "hysteria2":
            return {
                **base,
                "password": p["password"],
                "up_mbps": 100,
                "down_mbps": 100,
                "tls": tls_base
            }

        if t == "tuic":
            tuic_tls = dict(tls_base)
            tuic_tls["alpn"] = ["h3"]
            return {
                **base,
                "uuid": p["uuid"],
                "password": p["password"],
                "congestion_control": "bbr",
                "tls": tuic_tls
            }

        return None

    # ---------------------------------------------------------------------------
    # SAVE
    # ---------------------------------------------------------------------------

    def save(self):
        proxies: List[Dict[str, Any]] = []

        for i, url in enumerate(sorted(self.raw_configs), 1):
            p = self.parse_config_for_clash(url)
            if not p or not self.is_valid_proxy_object(p):
                continue
            p["name"] = f"Config_jo-{i:03d}-{p['type'].upper()}"
            proxies.append(p)

        outbounds = []
        for p in proxies:
            o = self.convert_to_singbox_outbound(p)
            if o:
                outbounds.append(o)

        tags = [o["tag"] for o in outbounds]

        config = {
            "log": {"level": "warn"},
            "dns": {
                "servers": [{"tag": "google", "address": "8.8.8.8", "detour": "PROXY"}]
            },
            "inbounds": [{
                "type": "mixed",
                "listen": "127.0.0.1",
                "listen_port": 2080
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

        with open(OUTPUT_SINGBOX, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)

        print(f"✨ sing-box READY — {len(outbounds)} outbounds")

# ================================================================================
# ENTRY
# ================================================================================

async def main():
    ex = V2RayExtractor()
    async with ex.client:
        tasks = []
        for c in CHANNELS:
            tasks.append(ex.scan_chat(c, CHANNEL_SEARCH_LIMIT))
        for g in GROUPS:
            tasks.append(ex.scan_chat(g, GROUP_SEARCH_LIMIT))
        await asyncio.gather(*tasks)
    ex.save()

if __name__ == "__main__":
    asyncio.run(main())
