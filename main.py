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

API_ID = int(os.environ.get("API_ID", 0))
API_HASH = os.environ.get("API_HASH", "")
SESSION_STRING = os.environ.get("SESSION_STRING", "")
CHANNELS_STR = os.environ.get('CHANNELS_LIST', "")
GROUPS_STR = os.environ.get('GROUPS_LIST', "")
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

V2RAY_PATTERNS = [
    re.compile(r'(vless:\/\/[^\s\'\"<>`|()\[\]{}]+)'), re.compile(r'(vmess:\/\/[^\s\'\"<>`|()\[\]{}]+)'),
    re.compile(r'(trojan:\/\/[^\s\'\"<>`|()\[\]{}]+)'), re.compile(r'(ss:\/\/[^\s\'\"<>`|()\[\]{}]+)'),
    re.compile(r"(hy2://[^\s'\"<>`|()\[\]{}]+)"), re.compile(r"(hysteria2://[^\s'\"<>`|()\[\]{}]+)"),
    re.compile(r"(tuic://[^\s'\"<>`|()\[\]{}]+)")
]
BASE64_PATTERN = re.compile(r"([A-Za-z0-9+/=]{50,})", re.MULTILINE)

COUNTRY_FLAGS = {'AD': '🇦🇩', 'AE': '🇦🇪', 'AF': '🇦🇫', 'AG': '🇦🇬', 'AI': '🇦🇮', 'AL': '🇦🇱', 'AM': '🇦🇲', 'AO': '🇦🇴', 'AQ': '🇦🇶', 'AR': '🇦🇷', 'AS': '🇦🇸', 'AT': '🇦🇹', 'AU': '🇦🇺', 'AW': '🇦🇼', 'AX': '🇦🇽', 'AZ': '🇦🇿', 'BA': '🇧🇦', 'BB': '🇧🇧', 'BD': '🇧🇩', 'BE': '🇧🇪', 'BF': '🇧🇫', 'BG': '🇧🇬', 'BH': '🇧🇭', 'BI': '🇧🇮', 'BJ': '🇧🇯', 'BL': '🇧🇱', 'BM': '🇧🇲', 'BN': '🇧🇳', 'BO': '🇧🇴', 'BR': '🇧🇷', 'BS': '🇧🇸', 'BT': '🇧🇹', 'BW': '🇧🇼', 'BY': '🇧🇾', 'BZ': '🇧🇿', 'CA': '🇨🇦', 'CC': '🇨🇨', 'CD': '🇨🇩', 'CF': '🇨🇫', 'CG': '🇨🇬', 'CH': '🇨🇭', 'CI': '🇨🇮', 'CK': '🇨🇰', 'CL': '🇨🇱', 'CM': '🇨🇲', 'CN': '🇨🇳', 'CO': '🇨🇴', 'CR': '🇨🇷', 'CU': '🇨🇺', 'CV': '🇨🇻', 'CW': '🇨🇼', 'CX': '🇨🇽', 'CY': '🇨🇾', 'CZ': '🇨🇿', 'DE': '🇩🇪', 'DJ': '🇩🇯', 'DK': '🇩🇰', 'DM': '🇩🇲', 'DO': '🇩🇴', 'DZ': '🇩🇿', 'EC': '🇪🇨', 'EE': '🇪🇪', 'EG': '🇪🇬', 'EH': '🇪🇭', 'ER': '🇪🇷', 'ES': '🇪🇸', 'ET': '🇪🇹', 'FI': '🇫🇮', 'FJ': '🇫🇯', 'FK': '🇫🇰', 'FM': '🇫🇲', 'FO': '🇫🇴', 'FR': '🇫🇷', 'GA': '🇬🇦', 'GB': '🇬🇬', 'GD': '🇬🇩', 'GE': '🇬🇪', 'GF': '🇬🇫', 'GG': '🇬🇬', 'GH': '🇬🇭', 'GI': '🇬🇮', 'GL': '🇬🇱', 'GM': '🇬🇲', 'GN': '🇬🇳', 'GP': '🇬🇵', 'GQ': '🇬🇶', 'GR': '🇬🇷', 'GT': '🇬🇹', 'GU': '🇬🇺', 'GW': '🇬🇼', 'GY': '🇬🇾', 'HK': '🇭🇰', 'HN': '🇭🇳', 'HR': '🇭🇷', 'HT': '🇭🇹', 'HU': '🇭🇺', 'ID': '🇮🇩', 'IE': '🇮🇪', 'IL': '🇮🇱', 'IM': '🇮🇲', 'IN': '🇮🇳', 'IO': '🇮🇴', 'IQ': '🇮🇶', 'IR': '🇮🇷', 'IS': '🇮🇸', 'IT': '🇮🇹', 'JE': '🇯🇪', 'JM': '🇯🇲', 'JO': '🇯🇴', 'JP': '🇯🇵', 'KE': '🇰🇪', 'KG': '🇰🇬', 'KH': '🇰🇭', 'KI': '🇰🇮', 'KM': '🇰🇲', 'KN': '🇰🇳', 'KP': '🇰🇵', 'KR': '🇰🇷', 'KW': '🇰🇼', 'KY': '🇰🇾', 'KZ': '🇰🇿', 'LA': '🇱🇦', 'LB': '🇱🇧', 'LC': '🇱🇨', 'LI': '🇱🇮', 'LK': '🇱🇰', 'LR': '🇱🇷', 'LS': '🇱🇸', 'LT': '🇱🇹', 'LU': '🇱🇺', 'LV': '🇱🇻', 'LY': '🇱🇾', 'MA': '🇲🇦', 'MC': '🇲🇨', 'MD': '🇲🇩', 'ME': '🇲🇪', 'MF': '🇲🇫', 'MG': '🇲🇬', 'MH': '🇲🇭', 'MK': '🇲🇰', 'ML': '🇲🇱', 'MM': '🇲🇲', 'MN': '🇲🇳', 'MO': '🇲🇴', 'MP': '🇲🇵', 'MQ': '🇲🇶', 'MR': '🇲🇷', 'MS': '🇲🇸', 'MT': '🇲🇹', 'MU': '🇲🇺', 'MV': '🇲🇻', 'MW': '🇲🇼', 'MX': '🇲🇽', 'MY': '🇲🇾', 'MZ': '🇲🇿', 'NA': '🇳🇦', 'NC': '🇳🇨', 'NE': '🇳🇪', 'NF': '🇳🇫', 'NG': '🇳🇬', 'NI': '🇳🇮', 'NL': '🇳🇱', 'NO': '🇳🇴', 'NP': '🇳🇵', 'NR': '🇳🇷', 'NU': '🇳🇺', 'NZ': '🇳🇿', 'OM': '🇴🇲', 'PA': '🇵🇦', 'PE': '🇵🇪', 'PF': '🇵🇫', 'PG': '🇵🇬', 'PH': '🇵🇭', 'PK': '🇵🇰', 'PL': '🇵🇱', 'PM': '🇵🇲', 'PN': '🇵🇳', 'PR': '🇵🇷', 'PS': '🇵🇸', 'PT': '🇵🇹', 'PW': '🇵🇼', 'PY': '🇵🇾', 'QA': '🇶🇦', 'RE': '🇷🇪', 'RO': '🇷🇴', 'RS': '🇷🇸', 'RU': '🇷🇺', 'RW': '🇷🇼', 'SA': '🇸🇦', 'SB': '🇸🇧', 'SC': '🇸🇨', 'SD': '🇸🇩', 'SE': '🇸🇪', 'SG': '🇸🇬', 'SH': '🇸🇭', 'SI': '🇸🇮', 'SK': '🇸🇰', 'SL': '🇸🇱', 'SM': '🇸🇲', 'SN': '🇸🇳', 'SO': '🇸🇴', 'SR': '🇸🇷', 'SS': '🇸🇸', 'ST': '🇸🇹', 'SV': '🇸🇻', 'SX': '🇸🇽', 'SY': '🇸🇾', 'SZ': '🇸🇿', 'TC': '🇹🇨', 'TD': '🇹🇩', 'TG': '🇹🇬', 'TH': '🇹🇭', 'TJ': '🇹🇯', 'TK': '🇹🇰', 'TL': '🇹🇱', 'TM': '🇹🇲', 'TN': '🇹🇳', 'TO': '🇹🇴', 'TR': '🇹🇷', 'TT': '🇹🇹', 'TV': '🇹🇻', 'TW': '🇹🇼', 'TZ': '🇹🇿', 'UA': '🇺🇦', 'UG': '🇺🇬', 'US': '🇺🇸', 'UY': '🇺🇾', 'UZ': '🇺🇿', 'VA': '🇻🇦', 'VC': '🇻🇨', 'VE': '🇻🇪', 'VG': '🇻🇬', 'VI': '🇻🇮', 'VN': '🇻🇳', 'VU': '🇻🇺', 'WF': '🇼🇫', 'WS': '🇼🇸', 'YE': '🇾🇪', 'YT': '🇾🇹', 'ZA': '🇿🇦', 'ZM': '🇿🇲', 'ZW': '🇿🇼'}

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
    ch_list = [ch.strip() for ch in CHANNELS_STR.split(',')] if CHANNELS_STR else []
    gr_list = []
    if GROUPS_STR:
        try: gr_list = [int(g.strip()) for g in GROUPS_STR.split(',')]
        except ValueError: pass
    return ch_list, gr_list

CHANNELS, GROUPS = process_lists()

class V2RayExtractor:
    def __init__(self):
        self.raw_configs: Set[str] = set()
        self.client = Client("my_account", api_id=API_ID, api_hash=API_HASH, session_string=SESSION_STRING)
        self._country_cache: Dict[str, str] = {}

    def get_country_iso_code(self, host: str) -> str:
        if not host or not GEOIP_READER: return "N/A"
        if host in self._country_cache: return self._country_cache[host]
        try:
            addr = host
            try: socket.inet_aton(host)
            except:
                try: addr = socket.gethostbyname(host)
                except: return "N/A"
            res = GEOIP_READER.country(addr)
            iso = res.country.iso_code or "N/A"
            self._country_cache[host] = iso
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
        p = urlparse(url); q = {k: v[0] for k, v in parse_qs(p.query).items()}
        def fix_b64(s): return s.replace(' ', '+') if s else s
        pbk = fix_b64(q.get('pbk') or q.get('pk'))
        reality = {'public-key': pbk} if q.get('security') == 'reality' and pbk else None
        if reality and q.get('sid'): reality['short-id'] = q.get('sid')
        raw_h = q.get('host') or q.get('sni') or p.hostname
        ws_h = raw_h.split(',')[0].strip() if raw_h else p.hostname
        ws_opts = {'path': q.get('path', '/'), 'headers': {'Host': ws_h}} if q.get('type') == 'ws' else None
        return {'name': unquote(p.fragment or ''), 'type': 'vless', 'server': p.hostname, 'port': p.port or 443, 'uuid': p.username, 'udp': True, 'tls': q.get('security') in ['tls', 'reality'], 'flow': q.get('flow'), 'client-fingerprint': q.get('fp'), 'network': q.get('type', 'tcp'), 'servername': q.get('sni'), 'ws-opts': ws_opts, 'reality-opts': reality}

    def parse_trojan(self, url: str) -> Optional[Dict[str, Any]]:
        p = urlparse(url); q = {k: v[0] for k, v in parse_qs(p.query).items()}
        raw_h = q.get('host') or q.get('sni') or p.hostname
        ws_h = raw_h.split(',')[0].strip() if raw_h else p.hostname
        ws_opts = {'path': q.get('path', '/'), 'headers': {'Host': ws_h}} if q.get('type')=='ws' else None
        return {'name': unquote(p.fragment or ''), 'type': 'trojan', 'server': p.hostname, 'port': p.port or 443, 'password': p.username, 'udp': True, 'sni': q.get('sni'), 'network': q.get('type', 'tcp'), 'ws-opts': ws_opts, 'client-fingerprint': q.get('fp')}

    def parse_shadowsocks(self, url: str) -> Optional[Dict[str, Any]]:
        try:
            content = url[5:]; name = unquote(content.split('#', 1)[1]) if '#' in content else ''
            content = content.split('#', 1)[0]; u_b64, s_part = content.rsplit('@', 1)
            host, port = s_part.rsplit(':', 1)
            info = base64.b64decode(u_b64 + '=' * (-len(u_b64) % 4)).decode('utf-8')
            cipher, pw = info.split(':', 1)
            if cipher == 'chacha20-poly1305': cipher = 'chacha20-ietf-poly1305'
            return {'name': name, 'type': 'ss', 'server': host, 'port': int(port), 'cipher': cipher, 'password': pw, 'udp': True}
        except: return None

    def parse_hysteria2(self, url: str) -> Optional[Dict[str, Any]]:
        p = urlparse(url); q = {k: v[0] for k, v in parse_qs(p.query).items()}
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
            active = False
            async for m in self.client.get_chat_history(chat_id, limit=1):
                if m.date > (datetime.datetime.now() - datetime.timedelta(days=CHANNEL_MAX_INACTIVE_DAYS)): active = True
                break 
            if not active: return
            async for msg in self.client.get_chat_history(chat_id, limit=limit):
                if len(local_configs) >= MAX_CONFIGS_PER_SOURCE: break
                text = (msg.text or msg.caption or "")
                texts = [text]
                if msg.entities:
                    for e in msg.entities:
                        if e.type in [enums.MessageEntityType.CODE, enums.MessageEntityType.PRE]:
                            texts.append(text[e.offset : e.offset + e.length].replace('\n', '').replace(' ', ''))
                for b64 in BASE64_PATTERN.findall(text):
                    try: texts.append(base64.b64decode(b64 + '=' * 4).decode('utf-8', errors='ignore'))
                    except: pass
                for t in texts:
                    found = set()
                    for pattern in V2RAY_PATTERNS: found.update(pattern.findall(t))
                    for u in found:
                        u = u.strip()
                        if not u.startswith('vmess://') and '#' in u: u = u.split('#')[0]
                        local_configs.add(u)
                        if len(local_configs) >= MAX_CONFIGS_PER_SOURCE: break
            res = list(local_configs)[:MAX_CONFIGS_PER_SOURCE]
            print(f"   ✅ Fetched {len(res)} configs from {chat_id}")
            self.raw_configs.update(res)
        except FloodWait as e:
            await asyncio.sleep(e.value + 2); await self.find_raw_configs_from_chat(chat_id, limit)

    def handle_weekly_file(self, new_configs: List[str]):
        now = datetime.datetime.now(); hist = {}
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, 'r') as f: hist = json.load(f)
        new_h = {k: v for k, v in hist.items() if datetime.datetime.fromisoformat(v['date']) > (now - datetime.timedelta(days=7))}
        for c in new_configs:
            base = c.split('#')[0]
            if base not in new_h: new_h[base] = {"link": c, "date": now.isoformat()}
        with open(HISTORY_FILE, 'w') as f: json.dump(new_h, f, indent=2)
        lns = [v['link'] for v in new_h.values()]
        with open(WEEKLY_FILE, 'w', encoding='utf-8') as f: f.write("\n".join(sorted(lns)))
        print(f"📅 7-Day Weekly: Total {len(lns)} configs.")

    def handle_no_cf_retention(self, new_configs: List[str]):
        now = datetime.datetime.now(); hist = {}
        if os.path.exists(NO_CF_HISTORY_FILE):
            with open(NO_CF_HISTORY_FILE, 'r') as f: hist = json.load(f)
        new_h = {k: v for k, v in hist.items() if datetime.datetime.fromisoformat(v['date']) > (now - datetime.timedelta(hours=72))}
        for c in new_configs:
            p = self.parse_config_for_clash(c)
            if p:
                uid = str(p.get('uuid') or p.get('password') or c.split('#')[0])
                if uid not in new_h: new_h[uid] = {"link": c, "date": now.isoformat()}
        with open(NO_CF_HISTORY_FILE, 'w') as f: json.dump(new_h, f, indent=2)
        lns = [v['link'] for v in new_h.values()]
        with open(OUTPUT_NO_CF, 'w', encoding='utf-8') as f: f.write("\n".join(sorted(lns)))
        print(f"⏱️ 72h Retention: Total {len(lns)} configs.")

    def build_pro_config(self, proxies):
        clean_p, clean_n, seen = [], [], set()
        for p in proxies:
            if p.get('type') in ['vless', 'vmess', 'tuic'] and not p.get('uuid'): continue
            if p.get('type') == 'trojan' and not p.get('password'): continue
            srv = p.get('server', '').lower()
            if not srv or any(x in srv for x in ['update', 'subscription', 'dayyyy']) or len(srv) > 60: continue
            
            net = p.get('network', 'tcp')
            if net not in ['tcp', 'ws', 'grpc', 'h2']: p['network'] = 'tcp'
            
            sni = p.get('servername') or p.get('sni')
            if sni and re.search(r'[^\w\.\-]', sni): p['servername'] = p['sni'] = p['server']
            if p.get('ws-opts') and not p['ws-opts']['headers'].get('Host'):
                p['ws-opts']['headers']['Host'] = p['server']
            
            if p.get('reality-opts') and len(p['reality-opts'].get('public-key', '')) < 43: continue
            if p.get('network') in ['xhttp', 'httpupgrade']: continue
            
            name = p['name']; count = 1; orig = name
            while name in seen:
                name = f"{orig}_{count}"; count += 1
            p['name'] = name; seen.add(name)
            clean_p.append({k: v for k, v in p.items() if v is not None and v != ''})
            clean_n.append(name)
        if not clean_p: return {}
        return {
            'mixed-port': 7890, 'ipv6': True, 'allow-lan': False, 'tcp-concurrent': True,
            'log-level': 'warning', 'mode': 'rule', 'external-controller': '127.0.0.1:9090',
            'dns': {
                'enable': True, 'ipv6': True, 'listen': '127.0.0.1:1053', 'enhanced-mode': 'redir-host',
                'nameserver': ['https://8.8.8.8/dns-query#✅ Selector'],
                'proxy-server-nameserver': ['8.8.8.8#DIRECT'], 'direct-nameserver': ['8.8.8.8#DIRECT'],
                'nameserver-policy': {
                    'rule-set:openai': '178.22.122.100#DIRECT',
                    'rule-set:googleai': '178.22.122.100#DIRECT',
                    'rule-set:microsoft': '178.22.122.100#DIRECT',
                    'rule-set:ir': '8.8.8.8#DIRECT'
                }
            },
            'tun': {
                'enable': True, 'stack': 'mixed', 'auto-route': True, 'strict-route': True,
                'auto-detect-interface': True, 'dns-hijack': ['any:53', 'tcp://any:53'], 'mtu': 9000
            },
            'sniffer': {
                'enable': True, 'force-dns-mapping': True, 'parse-pure-ip': True, 'override-destination': True,
                'sniff': {
                    'HTTP': {'ports': [80, 8080, 8880, 2052, 2082, 2086, 2095]},
                    'TLS': {'ports': [443, 8443, 2053, 2083, 2087, 2096]}
                }
            },
            'proxies': clean_p,
            'proxy-groups': [
                {'name': '✅ Selector', 'type': 'select', 'proxies': ['💥 Best Ping 🚀', 'DIRECT', *clean_n]},
                {'name': '💥 Best Ping 🚀', 'type': 'url-test', 'proxies': clean_n, 'url': 'https://www.gstatic.com/generate_204', 'interval': 30, 'tolerance': 50}
            ],
            'rule-providers': {
                'ir': {'type': 'http', 'behavior': 'domain', 'format': 'text', 'url': "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ir.txt", 'path': './ruleset/ir.txt', 'interval': 86400},
                'ir-cidr': {'type': 'http', 'behavior': 'ipcidr', 'format': 'text', 'url': "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ircidr.txt", 'path': './ruleset/ir-cidr.txt', 'interval': 86400},
                'openai': {'type': 'http', 'behavior': 'domain', 'format': 'yaml', 'url': "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/openai.yaml", 'path': './ruleset/openai.yaml', 'interval': 86400},
                'googleai': {'type': 'http', 'behavior': 'domain', 'format': 'yaml', 'url': "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/google-deepmind.yaml", 'path': './ruleset/googleai.yaml', 'interval': 86400},
                'microsoft': {'type': 'http', 'behavior': 'domain', 'format': 'yaml', 'url': "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/microsoft.yaml", 'path': './ruleset/microsoft.yaml', 'interval': 86400}
            },
            'rules': [
                'GEOIP,lan,DIRECT,no-resolve', 'NETWORK,udp,REJECT',
                'RULE-SET,ir,DIRECT', 'RULE-SET,openai,DIRECT', 'RULE-SET,googleai,DIRECT',
                'RULE-SET,microsoft,DIRECT', 'RULE-SET,ir-cidr,DIRECT', 'MATCH,✅ Selector'
            ]
        }

    def build_sing_box_config(self, proxies: List[Dict[str, Any]]) -> Dict[str, Any]:
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
        valid_u = set()
        for u in self.raw_configs:
            try:
                p = urlparse(u)
                if p.hostname in ['127.0.0.1', 'localhost', '0.0.0.0']: continue
                valid_u.add(u)
            except: continue
        p_list, ren_txt, clean_ip = [], [], []
        for i, u in enumerate(sorted(list(valid_u)), 1):
            if not (proxy := self.parse_config_for_clash(u)): continue
            srv = proxy.get('server')
            if not srv or srv in ['127.0.0.1', 'localhost', '0.0.0.0']: continue
            try:
                if ipaddress.ip_address(srv).is_loopback: continue
            except: pass
            iso = self.get_country_iso_code(srv); flag = COUNTRY_FLAGS.get(iso, '🏳️')
            proxy['name'] = f"{iso} 🍁Config_jo-{i:02d}"
            p_list.append(proxy); name_f = f"{flag} 🍁Config_jo-{i:02d}"
            if proxy['type'] == 'ss':
                cp = proxy.copy(); cp['name'] = name_f
                final = self.generate_sip002_link(cp) or f"{u.split('#')[0]}#{name_f}"
            else:
                try:
                    p_u = list(urlparse(u)); p_u[5] = name_f; final = urlunparse(p_u)
                except: final = f"{u.split('#')[0]}#{name_f}"
            ren_txt.append(final)
            if is_clean_ip(srv): clean_ip.append(final)
        with open(OUTPUT_ORIGINAL_CONFIGS, 'w', encoding='utf-8') as f: f.write("\n".join(sorted(list(self.raw_configs))))
        with open(OUTPUT_TXT, 'w', encoding='utf-8') as f: f.write("\n".join(sorted(ren_txt)))
        self.handle_no_cf_retention(clean_ip); self.handle_weekly_file(ren_txt)
        os.makedirs('ruleset', exist_ok=True)
        if p_list:
            c_cfg = self.build_pro_config(p_list)
            if c_cfg:
                with open(OUTPUT_YAML_PRO, 'w', encoding='utf-8') as f: yaml.dump(c_cfg, f, allow_unicode=True, sort_keys=False, indent=2)
            with open(OUTPUT_JSON_CONFIG_JO, 'w', encoding='utf-8') as f:
                json.dump(self.build_sing_box_config(p_list), f, ensure_ascii=False, indent=4)
        print(f"⚙️ Total Configs Saved: {len(ren_txt)}")

async def main():
    print("🚀 Starting config extractor..."); load_ip_data(); load_blocked_ips()
    ext = V2RayExtractor()
    async with ext.client:
        async for d in ext.client.get_dialogs(): pass
        tasks = [ext.find_raw_configs_from_chat(ch, CHANNEL_SEARCH_LIMIT) for ch in CHANNELS]
        tasks.extend(ext.find_raw_configs_from_chat(g, GROUP_SEARCH_LIMIT) for g in GROUPS)
        if tasks: await asyncio.gather(*tasks)
    ext.save_files()

if __name__ == "__main__":
    if all([API_ID, API_HASH, SESSION_STRING]): asyncio.run(main())
