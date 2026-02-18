import re
import asyncio
import base64
import json
import yaml
import os
import datetime
import ipaddress
import socket
import geoip2.database
from urllib.parse import urlparse, parse_qs, unquote, urlunparse
from pyrogram import Client, enums
from pyrogram.errors import FloodWait
from typing import Optional, Dict, Any, Set, List

# =================================================================================
# Settings and Constants
# =================================================================================

API_ID = int(os.environ.get("API_ID"))
API_HASH = os.environ.get("API_HASH")
SESSION_STRING = os.environ.get("SESSION_STRING")
CHANNELS_STR = os.environ.get('CHANNELS_LIST')
GROUPS_STR = os.environ.get('GROUPS_LIST')
CHANNEL_SEARCH_LIMIT = int(os.environ.get('CHANNEL_SEARCH_LIMIT', 5))
GROUP_SEARCH_LIMIT = int(os.environ.get('GROUP_SEARCH_LIMIT', 100))

OUTPUT_YAML_PRO = "Config-jo.yaml"
OUTPUT_TXT = "Config_jo.txt"
OUTPUT_JSON_CONFIG_JO = "Config_jo.json"
OUTPUT_ORIGINAL_CONFIGS = "Original-Configs.txt"
OUTPUT_NO_CF = "Config_no_cf.txt"

WEEKLY_FILE = "conf-week.txt"
HISTORY_FILE = "conf-week-history.json"
GEOIP_DATABASE_PATH = 'dbip-country-lite.mmdb'

NO_CF_HISTORY_FILE = "no_cf_history.json"
BLOCKED_IPS_FILE = "blocked_ips.txt"

CHANNEL_MAX_INACTIVE_DAYS = 4
MAX_CONFIGS_PER_SOURCE = 20

# ریجکس دقیق برای استخراج لینک‌ها بدون جذب کاراکترهای مزاحم انتهای پیام
V2RAY_PATTERNS = [
    re.compile(r'(vless:\/\/[^\s\'\"<>`|()\[\]{}]+)'), 
    re.compile(r'(vmess:\/\/[^\s\'\"<>`|()\[\]{}]+)'),
    re.compile(r'(trojan:\/\/[^\s\'\"<>`|()\[\]{}]+)'), 
    re.compile(r'(ss:\/\/[^\s\'\"<>`|()\[\]{}]+)'),
    re.compile(r"(hy2://[^\s'\"<>`|()\[\]{}]+)"), 
    re.compile(r"(hysteria2://[^\s'\"<>`|()\[\]{}]+)"),
    re.compile(r"(tuic://[^\s'\"<>`|()\[\]{}]+)")
]
BASE64_PATTERN = re.compile(r"([A-Za-z0-9+/=]{50,})", re.MULTILINE)

COUNTRY_FLAGS = {
    'AD': '🇦🇩', 'AE': '🇦🇪', 'AF': '🇦🇫', 'AG': '🇦🇬', 'AI': '🇦🇮', 'AL': '🇦🇱', 'AM': '🇦🇲', 'AO': '🇦🇴', 'AQ': '🇦🇶', 'AR': '🇦🇷', 'AS': '🇦🇸', 'AT': '🇦🇹', 'AU': '🇦🇺', 'AW': '🇦🇼', 'AX': '🇦🇽', 'AZ': '🇦🇿', 'BA': '🇧🇦', 'BB': '🇧🇧', 'BD': '🇧🇩', 'BE': '🇧🇪', 'BF': '🇧🇫', 'BG': '🇧🇬', 'BH': '🇧🇭', 'BI': '🇧🇮', 'BJ': '🇧🇯', 'BL': '🇧🇱', 'BM': '🇧🇲', 'BN': '🇧🇳', 'BO': '🇧🇴', 'BR': '🇧🇷', 'BS': '🇧🇸', 'BT': '🇧🇹', 'BW': '🇧🇼', 'BY': '🇧🇾', 'BZ': '🇧🇿', 'CA': '🇨🇦', 'CC': '🇨🇨', 'CD': '🇨🇩', 'CF': '🇨🇫', 'CG': '🇨🇬', 'CH': '🇨🇭', 'CI': '🇨🇮', 'CK': '🇨🇰', 'CL': '🇨🇱', 'CM': '🇨🇲', 'CN': '🇨🇳', 'CO': '🇨🇴', 'CR': '🇨🇷', 'CU': '🇨🇺', 'CV': '🇨🇻', 'CW': '🇨🇼', 'CX': '🇨🇽', 'CY': '🇨🇾', 'CZ': '🇨🇿', 'DE': '🇩🇪', 'DJ': '🇩🇯', 'DK': '🇩🇰', 'DM': '🇩🇲', 'DO': '🇩🇴', 'DZ': '🇩🇿', 'EC': '🇪🇨', 'EE': '🇪🇪', 'EG': '🇪🇬', 'EH': '🇪🇭', 'ER': '🇪🇷', 'ES': '🇪🇸', 'ET': '🇪🇹', 'FI': '🇫🇮', 'FJ': '🇫🇯', 'FK': '🇫🇰', 'FM': '🇫🇲', 'FO': '🇫🇴', 'FR': '🇫🇷', 'GA': '🇬🇦', 'GB': '🇬🇬', 'GD': '🇬🇩', 'GE': '🇬🇪', 'GF': '🇬🇫', 'GG': '🇬🇬', 'GH': '🇬🇭', 'GI': '🇬🇮', 'GL': '🇬🇱', 'GM': '🇬🇲', 'GN': '🇬🇳', 'GP': '🇬🇵', 'GQ': '🇬🇶', 'GR': '🇬🇷', 'GT': '🇬🇹', 'GU': '🇬🇺', 'GW': '🇬🇼', 'GY': '🇬🇾', 'HK': '🇭🇰', 'HN': '🇭🇳', 'HR': '🇭🇷', 'HT': '🇭🇹', 'HU': '🇭🇺', 'ID': '🇮🇩', 'IE': '🇮🇪', 'IL': '🇮🇱', 'IM': '🇮🇲', 'IN': '🇮🇳', 'IO': '🇮🇴', 'IQ': '🇮🇶', 'IR': '🇮🇷', 'IS': '🇮🇸', 'IT': '🇮🇹', 'JE': '🇯🇪', 'JM': '🇯🇲', 'JO': '🇯🇴', 'JP': '🇯🇵', 'KE': '🇰🇪', 'KG': '🇰🇬', 'KH': '🇰🇭', 'KI': '🇰🇮', 'KM': '🇰🇲', 'KN': '🇰🇳', 'KP': '🇰🇵', 'KR': '🇰🇷', 'KW': '🇰🇼', 'KY': '🇰🇾', 'KZ': '🇰🇿', 'LA': '🇱🇦', 'LB': '🇱🇧', 'LC': '🇱🇨', 'LI': '🇱🇮', 'LK': '🇱🇰', 'LR': '🇱🇷', 'LS': '🇱🇸', 'LT': '🇱🇹', 'LU': '🇱🇺', 'LV': '🇱🇻', 'LY': '🇱🇾', 'MA': '🇲🇦', 'MC': '🇲🇨', 'MD': '🇲🇩', 'ME': '🇲🇪', 'MF': '🇲🇫', 'MG': '🇲🇬', 'MH': '🇲🇭', 'MK': '🇲🇰', 'ML': '🇲🇱', 'MM': '🇲🇲', 'MN': '🇲🇳', 'MO': '🇲🇴', 'MP': '🇲🇵', 'MQ': '🇲🇶', 'MR': '🇲🇷', 'MS': '🇲🇸', 'MT': '🇲🇹', 'MU': '🇲🇺', 'MV': '🇲🇻', 'MW': '🇲🇼', 'MX': '🇲🇽', 'MY': '🇲🇾', 'MZ': '🇲🇿', 'NA': '🇳🇦', 'NC': '🇳🇨', 'NE': '🇳🇪', 'NF': '🇳🇫', 'NG': '🇳🇬', 'NI': '🇳🇮', 'NL': '🇳🇱', 'NO': '🇳🇴', 'NP': '🇳🇵', 'NR': '🇳🇷', 'NU': '🇳🇺', 'NZ': '🇳🇿', 'OM': '🇴🇲', 'PA': '🇵🇦', 'PE': '🇵🇪', 'PF': '🇵🇫', 'PG': '🇵🇬', 'PH': '🇵🇭', 'PK': '🇵🇰', 'PL': '🇵🇱', 'PM': '🇵🇲', 'PN': '🇵🇳', 'PR': '🇵🇷', 'PS': '🇵🇸', 'PT': '🇵🇹', 'PW': '🇵🇼', 'PY': '🇵🇾', 'QA': '🇶🇦', 'RE': '🇷🇪', 'RO': '🇷🇴', 'RS': '🇷🇸', 'RU': '🇷🇺', 'RW': '🇷🇼', 'SA': '🇸🇦', 'SB': '🇸🇧', 'SC': '🇸🇨', 'SD': '🇸🇩', 'SE': '🇸🇪', 'SG': '🇸🇬', 'SH': '🇸🇭', 'SI': '🇸🇮', 'SK': '🇸🇰', 'SL': '🇸🇱', 'SM': '🇸🇲', 'SN': '🇸🇳', 'SO': '🇸🇴', 'SR': '🇸🇷', 'SS': '🇸🇸', 'ST': '🇸🇹', 'SV': '🇸🇻', 'SX': '🇸🇽', 'SY': '🇸🇾', 'SZ': '🇸🇿', 'TC': '🇹🇨', 'TD': '🇹🇩', 'TG': '🇹🇬', 'TH': '🇹🇭', 'TJ': '🇹🇯', 'TK': '🇹🇰', 'TL': '🇹🇱', 'TM': '🇹🇲', 'TN': '🇹🇳', 'TO': '🇹🇴', 'TR': '🇹🇷', 'TT': '🇹🇹', 'TV': '🇹🇻', 'TW': '🇹🇼', 'TZ': '🇹🇿', 'UA': '🇺🇦', 'UG': '🇺🇬', 'US': '🇺🇸', 'UY': '🇺🇾', 'UZ': '🇺🇿', 'VA': '🇻🇦', 'VC': '🇻🇨', 'VE': '🇻🇪', 'VG': '🇻🇬', 'VI': '🇻🇮', 'VN': '🇻🇳', 'VU': '🇻🇺', 'WF': '🇼🇫', 'WS': '🇼🇸', 'YE': '🇾🇪', 'YT': '🇾🇹', 'ZA': '🇿🇦', 'ZM': '🇿🇲', 'ZW': '🇿🇼'
}

GEOIP_READER = None
BLOCKED_NETWORKS = []

def load_ip_data():
    global GEOIP_READER
    try:
        GEOIP_READER = geoip2.database.Reader(GEOIP_DATABASE_PATH)
        print(f"✅ Successfully loaded GeoIP database.")
    except Exception: pass

def load_blocked_ips():
    global BLOCKED_NETWORKS
    if os.path.exists(BLOCKED_IPS_FILE):
        try:
            with open(BLOCKED_IPS_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        try: BLOCKED_NETWORKS.append(ipaddress.ip_network(line, strict=False))
                        except ValueError: pass
        except Exception: pass

def is_clean_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified: return False
        for network in BLOCKED_NETWORKS:
            if ip in network: return False 
        return True 
    except ValueError: return False 

def process_lists():
    channels = [ch.strip() for ch in CHANNELS_STR.split(',')] if CHANNELS_STR else []
    groups = []
    if GROUPS_STR:
        try: groups = [int(g.strip()) for g in GROUPS_STR.split(',')]
        except ValueError: pass
    return channels, groups

CHANNELS, GROUPS = process_lists()

class V2RayExtractor:
    def __init__(self):
        self.raw_configs: Set[str] = set()
        self.client = Client("my_account", api_id=API_ID, api_hash=API_HASH, session_string=SESSION_STRING)
        self._country_cache: Dict[str, str] = {}

    def get_country_iso_code(self, hostname: str) -> str:
        if not hostname or not GEOIP_READER: return "N/A"
        if hostname in self._country_cache: return self._country_cache[hostname]
        try:
            ip_addr = hostname
            try: socket.inet_aton(hostname)
            except:
                try: ip_addr = socket.gethostbyname(hostname)
                except: return "N/A"
            res = GEOIP_READER.country(ip_addr)
            iso = res.country.iso_code or "N/A"
            self._country_cache[hostname] = iso
            return iso
        except: return "N/A"

    def parse_config_for_clash(self, url: str) -> Optional[Dict[str, Any]]:
        parsers = {'vmess://': self.parse_vmess, 'vless://': self.parse_vless, 'trojan://': self.parse_trojan, 'ss://': self.parse_shadowsocks, 'hysteria2://': self.parse_hysteria2, 'hy2://': self.parse_hysteria2, 'tuic://': self.parse_tuic}
        for prefix, parser in parsers.items():
            if url.startswith(prefix):
                try: return parser(url)
                except: return None
        return None

    def parse_vmess(self, url: str) -> Optional[Dict[str, Any]]:
        c = json.loads(base64.b64decode(url[8:] + '=' * 4).decode('utf-8'))
        ws_opts = {'path': c.get('path', '/'), 'headers': {'Host': c.get('host', c.get('add'))}} if c.get('net') == 'ws' else None
        return {'name': c.get('ps', ''), 'type': 'vmess', 'server': c.get('add'), 'port': int(c.get('port', 443)), 'uuid': c.get('id'), 'alterId': int(c.get('aid', 0)), 'cipher': c.get('scy', 'auto'), 'tls': c.get('tls')=='tls', 'network': c.get('net', 'tcp'), 'udp': True, 'ws-opts': ws_opts, 'servername': c.get('sni', c.get('host'))}

    def parse_vless(self, url: str) -> Optional[Dict[str, Any]]:
        p = urlparse(url)
        q = {k: v[0] for k, v in parse_qs(p.query).items()}
        def fix_b64(s): return s.replace(' ', '+') if s else s
        pbk = fix_b64(q.get('pbk') or q.get('pk'))
        reality_opts = {'public-key': pbk} if q.get('security') == 'reality' and pbk else None
        if reality_opts and q.get('sid'): reality_opts['short-id'] = q.get('sid')
        # اصلاح هدر Host (فقط اولین آدرس را نگه می‌دارد)
        raw_host = q.get('host') or q.get('sni') or p.hostname
        ws_host = raw_host.split(',')[0].strip() if raw_host else None
        ws_opts = {'path': q.get('path', '/'), 'headers': {'Host': ws_host}} if q.get('type') == 'ws' else None
        return {'name': unquote(p.fragment or ''), 'type': 'vless', 'server': p.hostname, 'port': p.port or 443, 'uuid': p.username, 'udp': True, 'tls': q.get('security') in ['tls', 'reality'], 'flow': q.get('flow'), 'client-fingerprint': q.get('fp'), 'network': q.get('type', 'tcp'), 'servername': q.get('sni'), 'ws-opts': ws_opts, 'reality-opts': reality_opts}

    def parse_trojan(self, url: str) -> Optional[Dict[str, Any]]:
        p = urlparse(url)
        q = {k: v[0] for k, v in parse_qs(p.query).items()}
        raw_host = q.get('host') or q.get('sni') or p.hostname
        ws_host = raw_host.split(',')[0].strip() if raw_host else None
        ws_opts = {'path': q.get('path', '/'), 'headers': {'Host': ws_host}} if q.get('type')=='ws' else None
        return {'name': unquote(p.fragment or ''), 'type': 'trojan', 'server': p.hostname, 'port': p.port or 443, 'password': p.username, 'udp': True, 'sni': q.get('sni'), 'network': q.get('type', 'tcp'), 'ws-opts': ws_opts, 'client-fingerprint': q.get('fp')}

    def parse_shadowsocks(self, url: str) -> Optional[Dict[str, Any]]:
        try:
            content = url[5:]
            name = unquote(content.split('#', 1)[1]) if '#' in content else ''
            content = content.split('#', 1)[0]
            userinfo_b64, server_part = content.rsplit('@', 1)
            server_host, server_port = server_part.rsplit(':', 1)
            userinfo = base64.b64decode(userinfo_b64 + '=' * (-len(userinfo_b64) % 4)).decode('utf-8')
            cipher, password = userinfo.split(':', 1)
            
            # اصلاح الگوریتم chacha20-poly1305 به نسخه استاندارد کلش
            if cipher == 'chacha20-poly1305': cipher = 'chacha20-ietf-poly1305'
            
            return {'name': name, 'type': 'ss', 'server': server_host, 'port': int(server_port), 'cipher': cipher, 'password': password, 'udp': True}
        except: return None

    def parse_hysteria2(self, url: str) -> Optional[Dict[str, Any]]:
        p = urlparse(url)
        q = {k: v[0] for k, v in parse_qs(p.query).items()}
        return {'name': unquote(p.fragment or ''), 'type': 'hysteria2', 'server': p.hostname, 'port': p.port or 443, 'password': p.username or p.password, 'sni': q.get('sni', [p.hostname])[0], 'skip-cert-verify': q.get('insecure')=='1'}

    def parse_tuic(self, url: str) -> Optional[Dict[str, Any]]:
        p = urlparse(url); q = {k: v[0] for k, v in parse_qs(p.query).items()}
        return {'name': unquote(p.fragment or ''), 'type': 'tuic', 'server': p.hostname, 'port': p.port or 443, 'uuid': p.username, 'password': q.get('password'), 'sni': q.get('sni', [p.hostname])[0]}

    def generate_sip002_link(self, proxy: Dict[str, Any]) -> str:
        try:
            uinfo = base64.urlsafe_b64encode(f"{proxy['cipher']}:{proxy['password']}".encode()).decode().rstrip('=')
            return f"ss://{uinfo}@{proxy['server']}:{proxy['port']}#{proxy.get('name', 'Shadowsocks')}"
        except: return None

    async def find_raw_configs_from_chat(self, chat_id: int, limit: int):
        local_configs = set()
        try:
            is_active = False
            async for last_msg in self.client.get_chat_history(chat_id, limit=1):
                if last_msg.date > (datetime.datetime.now() - datetime.timedelta(days=CHANNEL_MAX_INACTIVE_DAYS)): is_active = True
                break 
            if not is_active: return
            async for message in self.client.get_chat_history(chat_id, limit=limit):
                if len(local_configs) >= MAX_CONFIGS_PER_SOURCE: break
                text = (message.text or message.caption or "")
                texts_to_scan = [text]
                if message.entities:
                    for ent in message.entities:
                        if ent.type in [enums.MessageEntityType.CODE, enums.MessageEntityType.PRE]:
                            texts_to_scan.append(text[ent.offset : ent.offset + ent.length].replace('\n', '').replace(' ', ''))
                for b64 in BASE64_PATTERN.findall(text):
                    try: texts_to_scan.append(base64.b64decode(b64 + '=' * 4).decode('utf-8', errors='ignore'))
                    except: pass
                for t in texts_to_scan:
                    found = set()
                    for pattern in V2RAY_PATTERNS: found.update(pattern.findall(t))
                    for url in found:
                        url = url.strip()
                        if not url.startswith('vmess://') and '#' in url: url = url.split('#')[0]
                        local_configs.add(url)
                        if len(local_configs) >= MAX_CONFIGS_PER_SOURCE: break
            final = list(local_configs)[:MAX_CONFIGS_PER_SOURCE]
            print(f"   ✅ Fetched {len(final)} configs from {chat_id}")
            self.raw_configs.update(final)
        except FloodWait as e:
            await asyncio.sleep(e.value + 2); await self.find_raw_configs_from_chat(chat_id, limit)

    def handle_weekly_file(self, new_configs: List[str]):
        now = datetime.datetime.now()
        history = {}
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, 'r') as f: history = json.load(f)
        new_history = {k: v for k, v in history.items() if datetime.datetime.fromisoformat(v['date']) > (now - datetime.timedelta(days=7))}
        for cfg in new_configs:
            base = cfg.split('#')[0]
            if base not in new_history: new_history[base] = {"link": cfg, "date": now.isoformat()}
        with open(HISTORY_FILE, 'w') as f: json.dump(new_history, f, indent=2)
        links = [v['link'] for v in new_history.values()]
        with open(WEEKLY_FILE, 'w', encoding='utf-8') as f: f.write("\n".join(sorted(links)))
        print(f"📅 7-Day Weekly: Total {len(links)} configs.")

    def handle_no_cf_retention(self, new_configs: List[str]):
        now = datetime.datetime.now()
        history = {}
        if os.path.exists(NO_CF_HISTORY_FILE):
            with open(NO_CF_HISTORY_FILE, 'r') as f: history = json.load(f)
        new_history = {k: v for k, v in history.items() if datetime.datetime.fromisoformat(v['date']) > (now - datetime.timedelta(hours=72))}
        for cfg in new_configs:
            p = self.parse_config_for_clash(cfg)
            if p:
                uid = str(p.get('uuid') or p.get('password') or cfg.split('#')[0])
                if uid not in new_history: new_history[uid] = {"link": cfg, "date": now.isoformat()}
        with open(NO_CF_HISTORY_FILE, 'w') as f: json.dump(new_history, f, indent=2)
        links = [v['link'] for v in new_history.values()]
        with open(OUTPUT_NO_CF, 'w', encoding='utf-8') as f: f.write("\n".join(sorted(links)))
        print(f"⏱️ 72h Retention: Total {len(links)} configs.")

    def build_pro_config(self, proxies):
        clean_proxies, clean_names, seen_names = [], [], set()
        for p in proxies:
            if p.get('type') in ['vless', 'vmess', 'tuic'] and not p.get('uuid'): continue
            if p.get('type') == 'trojan' and not p.get('password'): continue
            # فیلتر تبلیغات و آدرس‌های طولانی
            server = p.get('server', '').lower()
            if not server or any(x in server for x in ['update', 'subscription', 'dayyyy']) or len(server) > 60: continue
            # اصلاح SNI (حذف اموجی و کاراکتر غیرمجاز)
            sni = p.get('servername') or p.get('sni')
            if sni and re.search(r'[^\w\.\-]', sni): p['servername'] = p['sni'] = p['server']
            # فیلتر Reality ناقص (زیر ۴۳ کاراکتر)
            if p.get('reality-opts') and len(p['reality-opts'].get('public-key', '')) < 43: continue
            # فیلتر شبکه‌های ناسازگار با کلش معمولی
            if p.get('network') in ['xhttp', 'httpupgrade']: continue
            
            name = p['name']
            counter = 1; original_name = name
            while name in seen_names:
                name = f"{original_name}_{counter}"; counter += 1
            p['name'] = name; seen_names.add(name)
            clean_proxies.append({k: v for k, v in p.items() if v is not None and v != ''})
            clean_names.append(name)
        if not clean_proxies: return {}
        return {'port': 7890, 'socks-port': 7891, 'allow-lan': True, 'mode': 'rule', 'log-level': 'info', 'external-controller': '127.0.0.1:9090', 'dns': {'enable': True, 'listen': '0.0.0.0:53', 'default-nameserver': ['8.8.8.8', '1.1.1.1'], 'enhanced-mode': 'fake-ip', 'fake-ip-range': '198.18.0.1/16', 'nameserver': ['https://dns.google/dns-query', 'https://cloudflare-dns.com/dns-query'], 'fallback': ['https://dns.google/dns-query', 'https://cloudflare-dns.com/dns-query'], 'fallback-filter': {'geoip': True, 'ipcidr': ['240.0.0.0/4', '0.0.0.0/32']}}, 'proxies': clean_proxies, 'proxy-groups': [{'name': 'PROXY', 'type': 'select', 'proxies': ['⚡ Auto-Select', 'DIRECT', *clean_names]}, {'name': '⚡ Auto-Select', 'type': 'url-test', 'proxies': clean_names, 'url': 'http://www.gstatic.com/generate_204', 'interval': 300}, {'name': '🇮🇷 Iran', 'type': 'select', 'proxies': ['DIRECT', 'PROXY']}, {'name': '🛑 Block-Ads', 'type': 'select', 'proxies': ['REJECT', 'DIRECT']}], 'rule-providers': {'iran_domains': {'type': 'http', 'behavior': 'domain', 'url': "https://raw.githubusercontent.com/bootmortis/iran-clash-rules/main/iran-domains.txt", 'path': './rules/iran_domains.txt', 'interval': 86400}, 'blocked_domains': {'type': 'http', 'behavior': 'domain', 'url': "https://raw.githubusercontent.com/bootmortis/iran-clash-rules/main/blocked-domains.txt", 'path': './rules/blocked_domains.txt', 'interval': 86400}, 'ad_domains': {'type': 'http', 'behavior': 'domain', 'url': "https://raw.githubusercontent.com/bootmortis/iran-clash-rules/main/ad-domains.txt", 'path': './rules/ad_domains.txt', 'interval': 86400}}, 'rules': ['RULE-SET,ad_domains,🛑 Block-Ads', 'RULE-SET,blocked_domains,PROXY', 'RULE-SET,iran_domains,🇮🇷 Iran', 'GEOIP,IR,🇮🇷 Iran', 'MATCH,PROXY']}

    def build_sing_box_config(self, proxies: List[Dict[str, Any]]) -> Dict[str, Any]:
        from copy import deepcopy
        outbounds = []
        for p in proxies:
            sb_out = {'type': p['type'] if p['type']!='ss' else 'shadowsocks', 'tag': p['name'], 'server': p['server'], 'server_port': p['port']}
            if p['type']=='vmess': sb_out.update({'uuid': p['uuid'], 'alter_id': p['alterId'], 'security': p['cipher'], 'tls': {'enabled': True, 'server_name': p['servername']} if p.get('tls') else None})
            if p['type']=='vless': sb_out.update({'uuid': p['uuid'], 'flow': p.get('flow',''), 'tls': {'enabled': True, 'server_name': p['servername'], 'reality': {'enabled': True, 'public_key': p.get('reality-opts',{}).get('public-key'), 'short_id': p.get('reality-opts',{}).get('short-id')} if p.get('reality-opts') else None} if p.get('tls') else None})
            if p['type']=='trojan': sb_out.update({'password': p['password'], 'tls': {'enabled': True, 'server_name': p.get('sni')}})
            if p['type']=='ss': sb_out.update({'method': p['cipher'], 'password': p['password']})
            if p['type'] in ['hysteria2','tuic']: sb_out.update({'password': p.get('password'), 'tls': {'enabled': True, 'server_name': p.get('sni'), 'insecure': p.get('skip-cert-verify')}})
            if p.get('ws-opts'): sb_out['transport'] = {'type': 'ws', 'path': p['ws-opts']['path'], 'headers': p['ws-opts']['headers']}
            outbounds.append(sb_out)
        tags = [o['tag'] for o in outbounds]
        return {"log": {"level": "warn"}, "dns": {"servers": [{"tag": "dns_proxy", "address": "https://dns.google/dns-query", "detour": "PROXY"}, {"tag": "dns_direct", "address": "1.1.1.1"}], "rules": [{"outbound": "PROXY", "server": "dns_proxy"}, {"rule_set": ["geosite-ir", "geoip-ir"], "server": "dns_direct"}], "final": "dns_direct"}, "inbounds": [{"type": "mixed", "listen": "0.0.0.0", "listen_port": 2080}], "outbounds": [{"type": "direct", "tag": "direct"}, {"type": "block", "tag": "block"}, {"type": "dns", "tag": "dns-out"}, *outbounds, {"type": "selector", "tag": "PROXY", "outbounds": ["auto", *tags]}, {"type": "urltest", "tag": "auto", "outbounds": tags, "url": "http://www.gstatic.com/generate_204", "interval": "5m"}], "route": {"rule_set": [{"tag": "geosite-ir", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/Chocolate4U/Iran-sing-box-rules@rule-set/geosite-ir.srs", "download_detour": "direct"}, {"tag": "geoip-ir", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/Chocolate4U/Iran-sing-box-rules@rule-set/geoip-ir.srs", "download_detour": "direct"}], "rules": [{"protocol": "dns", "outbound": "dns-out"}, {"rule_set": ["geosite-ir", "geoip-ir"], "outbound": "direct"}], "final": "PROXY"}}

    def save_files(self):
        if not self.raw_configs: return
        valid_urls = set()
        for url in self.raw_configs:
            try:
                p = urlparse(url)
                if p.hostname in ['127.0.0.1', 'localhost', '0.0.0.0']: continue
                valid_urls.add(url)
            except: continue
        proxies_list, renamed_txt, clean_ip_configs = [], [], []
        for i, url in enumerate(sorted(list(valid_urls)), 1):
            if not (proxy := self.parse_config_for_clash(url)): continue
            server_host = proxy.get('server')
            if not server_host or server_host in ['127.0.0.1', 'localhost', '0.0.0.0']: continue
            try:
                if ipaddress.ip_address(server_host).is_loopback: continue
            except: pass
            country_code = self.get_country_iso_code(server_host)
            flag = COUNTRY_FLAGS.get(country_code, '🏳️')
            proxy['name'] = f"{country_code} Config_jo-{i:02d}"
            proxies_list.append(proxy)
            name_with_flag = f"{flag} Config_jo-{i:02d}"
            
            if proxy['type'] == 'ss':
                p_copy = proxy.copy(); p_copy['name'] = name_with_flag
                final_link = self.generate_sip002_link(p_copy) or f"{url.split('#')[0]}#{name_with_flag}"
            else:
                try:
                    p_url = list(urlparse(url)); p_url[5] = name_with_flag
                    final_link = urlunparse(p_url)
                except: final_link = f"{url.split('#')[0]}#{name_with_flag}"
            renamed_txt.append(final_link)
            if is_clean_ip(server_host): clean_ip_configs.append(final_link)

        with open(OUTPUT_ORIGINAL_CONFIGS, 'w', encoding='utf-8') as f: f.write("\n".join(sorted(list(self.raw_configs))))
        with open(OUTPUT_TXT, 'w', encoding='utf-8') as f: f.write("\n".join(sorted(renamed_txt)))
        self.handle_no_cf_retention(clean_ip_configs); self.handle_weekly_file(renamed_txt)
        os.makedirs('rules', exist_ok=True)
        if proxies_list:
            clash_cfg = self.build_pro_config(proxies_list)
            if clash_cfg:
                with open(OUTPUT_YAML_PRO, 'w', encoding='utf-8') as f: yaml.dump(clash_cfg, f, allow_unicode=True, sort_keys=False, indent=2)
            with open(OUTPUT_JSON_CONFIG_JO, 'w', encoding='utf-8') as f:
                json.dump(self.build_sing_box_config(proxies_list), f, ensure_ascii=False, indent=4)
        print(f"⚙️ Total Configs Saved: {len(renamed_txt)}")

async def main():
    print("🚀 Starting config extractor..."); load_ip_data(); load_blocked_ips()
    extractor = V2RayExtractor()
    async with extractor.client:
        async for d in extractor.client.get_dialogs(): pass
        tasks = [extractor.find_raw_configs_from_chat(ch, CHANNEL_SEARCH_LIMIT) for ch in CHANNELS]
        tasks.extend(extractor.find_raw_configs_from_chat(g, GROUP_SEARCH_LIMIT) for g in GROUPS)
        if tasks: await asyncio.gather(*tasks)
    extractor.save_files()

if __name__ == "__main__":
    if all([API_ID, API_HASH, SESSION_STRING]): asyncio.run(main())
