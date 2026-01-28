import re
import asyncio
import base64
import json
import yaml
import os
import datetime
from urllib.parse import urlparse, parse_qs, unquote, urlunparse
from pyrogram import Client, enums
from pyrogram.errors import FloodWait
from typing import Optional, Dict, Any, Set, List
import socket
import geoip2.database

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

WEEKLY_FILE = "conf-week.txt"
HISTORY_FILE = "conf-week-history.json"
GEOIP_DATABASE_PATH = 'dbip-country-lite.mmdb'

CHANNEL_MAX_INACTIVE_DAYS = 4

V2RAY_PATTERNS = [
    re.compile(r'(vless:\/\/[^\s\'\"<>`]+)'), re.compile(r'(vmess:\/\/[^\s\'\"<>`]+)'),
    re.compile(r'(trojan:\/\/[^\s\'\"<>`]+)'), re.compile(r'(ss:\/\/[^\s\'\"<>`]+)'),
    re.compile(r"(hy2://[^\s'\"<>`]+)"), re.compile(r"(hysteria2://[^\s'\"<>`]+)"),
    re.compile(r"(tuic://[^\s'\"<>`]+)")
]
BASE64_PATTERN = re.compile(r"([A-Za-z0-9+/=]{50,})", re.MULTILINE)

COUNTRY_FLAGS = {
    'AD': '🇦🇩', 'AE': '🇦🇪', 'AF': '🇦🇫', 'AG': '🇦🇬', 'AI': '🇦🇮', 'AL': '🇦🇱', 'AM': '🇦🇲', 'AO': '🇦🇴', 'AQ': '🇦🇶', 'AR': '🇦🇷', 'AS': '🇦🇸', 'AT': '🇦🇹', 'AU': '🇦🇺', 'AW': '🇦🇼', 'AX': '🇦🇽', 'AZ': '🇦🇿', 'BA': '🇧🇦', 'BB': '🇧🇧', 'BD': '🇧🇩', 'BE': '🇧🇪', 'BF': '🇧🇫', 'BG': '🇧🇬', 'BH': '🇧🇭', 'BI': '🇧🇮', 'BJ': '🇧🇯', 'BL': '🇧🇱', 'BM': '🇧🇲', 'BN': '🇧🇳', 'BO': '🇧🇴', 'BR': '🇧🇷', 'BS': '🇧🇸', 'BT': '🇧🇹', 'BW': '🇧🇼', 'BY': '🇧🇾', 'BZ': '🇧🇿', 'CA': '🇨🇦', 'CC': '🇨🇨', 'CD': '🇨🇩', 'CF': '🇨🇫', 'CG': '🇨🇬', 'CH': '🇨🇭', 'CI': '🇨🇮', 'CK': '🇨🇰', 'CL': '🇨🇱', 'CM': '🇨🇲', 'CN': '🇨🇳', 'CO': '🇨🇴', 'CR': '🇨🇷', 'CU': '🇨🇺', 'CV': '🇨🇻', 'CW': '🇨🇼', 'CX': '🇨🇽', 'CY': '🇨🇾', 'CZ': '🇨🇿', 'DE': '🇩🇪', 'DJ': '🇩🇯', 'DK': '🇩🇰', 'DM': '🇩🇲', 'DO': '🇩🇴', 'DZ': '🇩🇿', 'EC': '🇪🇨', 'EE': '🇪🇪', 'EG': '🇪🇬', 'EH': '🇪🇭', 'ER': '🇪🇷', 'ES': '🇪🇸', 'ET': '🇪🇹', 'FI': '🇫🇮', 'FJ': '🇫🇯', 'FK': '🇫🇰', 'FM': '🇫🇲', 'FO': '🇫🇴', 'FR': '🇫🇷', 'GA': '🇬🇦', 'GB': '🇬🇬', 'GD': '🇬🇩', 'GE': '🇬🇪', 'GF': '🇬🇫', 'GG': '🇬🇬', 'GH': '🇬🇭', 'GI': '🇬🇮', 'GL': '🇬🇱', 'GM': '🇬🇲', 'GN': '🇬🇳', 'GP': '🇬🇵', 'GQ': '🇬🇶', 'GR': '🇬🇷', 'GT': '🇬🇹', 'GU': '🇬🇺', 'GW': '🇬🇼', 'GY': '🇬🇾', 'HK': '🇭🇰', 'HN': '🇭🇳', 'HR': '🇭🇷', 'HT': '🇭🇹', 'HU': '🇭🇺', 'ID': '🇮🇩', 'IE': '🇮🇪', 'IL': '🇮🇱', 'IM': '🇮🇲', 'IN': '🇮🇳', 'IO': '🇮🇴', 'IQ': '🇮🇶', 'IR': '🇮🇷', 'IS': '🇮🇸', 'IT': '🇮🇹', 'JE': '🇯🇪', 'JM': '🇯🇲', 'JO': '🇯🇴', 'JP': '🇯🇵', 'KE': '🇰🇪', 'KG': '🇰🇬', 'KH': '🇰🇭', 'KI': '🇰🇮', 'KM': '🇰🇲', 'KN': '🇰🇳', 'KP': '🇰🇵', 'KR': '🇰🇷', 'KW': '🇰🇼', 'KY': '🇰🇾', 'KZ': '🇰🇿', 'LA': '🇱🇦', 'LB': '🇱🇧', 'LC': '🇱🇨', 'LI': '🇱🇮', 'LK': '🇱🇰', 'LR': '🇱🇷', 'LS': '🇱🇸', 'LT': '🇱🇹', 'LU': '🇱🇺', 'LV': '🇱🇻', 'LY': '🇱🇾', 'MA': '🇲🇦', 'MC': '🇲🇨', 'MD': '🇲🇩', 'ME': '🇲🇪', 'MF': '🇲🇫', 'MG': '🇲🇬', 'MH': '🇲🇭', 'MK': '🇲🇰', 'ML': '🇲🇱', 'MM': '🇲🇲', 'MN': '🇲🇳', 'MO': '🇲🇴', 'MP': '🇲🇵', 'MQ': '🇲🇶', 'MR': '🇲🇷', 'MS': '🇲🇸', 'MT': '🇲🇹', 'MU': '🇲🇺', 'MV': '🇲🇻', 'MW': '🇲🇼', 'MX': '🇲🇽', 'MY': '🇲🇾', 'MZ': '🇲🇿', 'NA': '🇳🇦', 'NC': '🇳🇨', 'NE': '🇳🇪', 'NF': '🇳🇫', 'NG': '🇳🇬', 'NI': '🇳🇮', 'NL': '🇳🇱', 'NO': '🇳🇴', 'NP': '🇳🇵', 'NR': '🇳🇷', 'NU': '🇳🇺', 'NZ': '🇳🇿', 'OM': '🇴🇲', 'PA': '🇵🇦', 'PE': '🇵🇪', 'PF': '🇵🇫', 'PG': '🇵🇬', 'PH': '🇵🇭', 'PK': '🇵🇰', 'PL': '🇵🇱', 'PM': '🇵🇲', 'PN': '🇵🇳', 'PR': '🇵🇷', 'PS': '🇵🇸', 'PT': '🇵🇹', 'PW': '🇵🇼', 'PY': 'PY', 'QA': '🇶🇦', 'RE': '🇷🇪', 'RO': '🇷🇴', 'RS': '🇷🇸', 'RU': '🇷🇺', 'RW': '🇷🇼', 'SA': '🇸🇦', 'SB': '🇸🇧', 'SC': '🇸🇨', 'SD': '🇸🇩', 'SE': '🇸🇪', 'SG': '🇸🇬', 'SH': '🇸🇭', 'SI': '🇸🇮', 'SK': '🇸🇰', 'SL': '🇸🇱', 'SM': '🇸🇲', 'SN': '🇸🇳', 'SO': '🇸🇴', 'SR': '🇸🇷', 'SS': '🇸🇸', 'ST': '🇸🇹', 'SV': '🇸🇻', 'SX': '🇸🇽', 'SY': '🇸🇾', 'SZ': '🇸🇿', 'TC': '🇹🇨', 'TD': '🇹🇩', 'TG': '🇹🇬', 'TH': '🇹🇭', 'TJ': '🇹🇭', 'TK': '🇹🇰', 'TL': '🇹🇱', 'TM': '🇹🇲', 'TN': '🇹🇳', 'TO': '🇹🇴', 'TR': '🇹🇷', 'TT': '🇹🇹', 'TV': '🇹🇻', 'TW': '🇹🇼', 'TZ': '🇹🇿', 'UA': '🇺🇦', 'UG': '🇺🇬', 'US': '🇺🇸', 'UY': '🇺🇾', 'UZ': '🇺🇿', 'VA': '🇻🇦', 'VC': '🇻🇨', 'VE': '🇻🇪', 'VG': '🇻🇬', 'VI': '🇻🇮', 'VN': '🇻🇳', 'VU': '🇻🇺', 'WF': '🇼🇫', 'WS': '🇼🇸', 'YE': '🇾🇪', 'YT': '🇾🇹', 'ZA': '🇿🇦', 'ZM': '🇿🇲', 'ZW': '🇿🇼'
}

GEOIP_READER = None

def load_ip_data():
    global GEOIP_READER
    try:
        GEOIP_READER = geoip2.database.Reader(GEOIP_DATABASE_PATH)
    except: pass

def process_lists():
    channels = [ch.strip() for ch in CHANNELS_STR.split(',')] if CHANNELS_STR else []
    groups = []
    if GROUPS_STR:
        try:
            groups = [int(g.strip()) for g in GROUPS_STR.split(',')]
        except ValueError: pass
    return channels, groups

CHANNELS, GROUPS = process_lists()

class V2RayExtractor:
    def __init__(self):
        self.raw_configs: Set[str] = set()
        self.client = Client("my_account", api_id=API_ID, api_hash=API_HASH, session_string=SESSION_STRING)

    def get_country_iso_code(self, hostname: str) -> str:
        if not hostname or not GEOIP_READER: return "N/A"
        try:
            ip_address = hostname
            try: socket.inet_aton(hostname)
            except: ip_address = socket.gethostbyname(hostname)
            return GEOIP_READER.country(ip_address).country.iso_code or "N/A"
        except: return "N/A"

    def _is_valid_shadowsocks(self, ss_url: str) -> bool:
        try:
            if '@' in ss_url:
                parts = ss_url.split('@')
                if len(parts) >= 2: return True
            return False
        except: return False

    def _correct_config_type(self, config_url: str) -> str:
        if config_url.startswith('ss://') and 'v=2' in config_url: return config_url.replace('ss://', 'vmess://', 1)
        return config_url

    def _validate_config_type(self, config_url: str) -> bool:
        try:
            if config_url.startswith('vless://'): return True
            elif config_url.startswith('vmess://'):
                decoded_str = base64.b64decode(config_url[8:] + '=' * 4).decode('utf-8')
                config = json.loads(decoded_str)
                return bool(config.get('add') and config.get('id'))
            elif config_url.startswith('trojan://'): return True
            elif config_url.startswith('ss://'): return self._is_valid_shadowsocks(config_url)
            return True
        except: return False

    def parse_config_for_clash(self, config_url: str) -> Optional[Dict[str, Any]]:
        parsers = {'vmess://': self.parse_vmess, 'vless://': self.parse_vless, 'trojan://': self.parse_trojan, 'ss://': self.parse_shadowsocks, 'hysteria2://': self.parse_hysteria2, 'hy2://': self.parse_hysteria2, 'tuic://': self.parse_tuic}
        for prefix, parser in parsers.items():
            if config_url.startswith(prefix):
                try: return parser(config_url)
                except: return None
        return None

    def parse_vmess(self, vmess_url: str) -> Optional[Dict[str, Any]]:
        decoded_str = base64.b64decode(vmess_url[8:] + '=' * 4).decode('utf-8')
        c = json.loads(decoded_str)
        ws_opts = {'path': c.get('path', '/'), 'headers': {'Host': c.get('host', '')}} if c.get('net') == 'ws' else None
        return {'name': c.get('ps', ''), 'type': 'vmess', 'server': c.get('add'), 'port': int(c.get('port', 443)), 'uuid': c.get('id'), 'alterId': int(c.get('aid', 0)), 'cipher': c.get('scy', 'auto'), 'tls': c.get('tls')=='tls', 'network': c.get('net', 'tcp'), 'udp': True, 'ws-opts': ws_opts, 'servername': c.get('sni', c.get('host'))}

    def parse_vless(self, vless_url: str) -> Optional[Dict[str, Any]]:
        p, q = urlparse(vless_url), parse_qs(urlparse(vless_url).query)
        ws_opts = {'path': q.get('path', ['/'])[0], 'headers': {'Host': q.get('host', [''])[0]}} if q.get('type', [''])[0] == 'ws' else None
        reality_opts = {'public-key': q.get('pbk', [''])[0], 'short-id': q.get('sid', [''])[0]} if q.get('security', [''])[0] == 'reality' else None
        return {'name': unquote(p.fragment or ''), 'type': 'vless', 'server': p.hostname, 'port': p.port or 443, 'uuid': p.username, 'udp': True, 'tls': q.get('security', [''])[0] in ['tls', 'reality'], 'network': q.get('type', ['tcp'])[0], 'servername': q.get('sni', [None])[0], 'ws-opts': ws_opts, 'reality-opts': reality_opts}

    def parse_trojan(self, trojan_url: str) -> Optional[Dict[str, Any]]:
        p, q = urlparse(trojan_url), parse_qs(urlparse(trojan_url).query)
        return {'name': unquote(p.fragment or ''), 'type': 'trojan', 'server': p.hostname, 'port': p.port or 443, 'password': p.username, 'udp': True, 'sni': q.get('sni', [p.hostname])[0]}

    def parse_shadowsocks(self, ss_url: str) -> Optional[Dict[str, Any]]:
        try:
            content = ss_url[5:].split('#')[0]
            if '@' not in content: return None
            userinfo_b64, server_part = content.rsplit('@', 1)
            userinfo = base64.b64decode(userinfo_b64 + '='*4).decode('utf-8')
            cipher, password = userinfo.split(':', 1)
            host, port = server_part.rsplit(':', 1)
            return {'name': unquote(urlparse(ss_url).fragment or ''), 'type': 'ss', 'server': host, 'port': int(port), 'cipher': cipher, 'password': password, 'udp': True}
        except: return None

    def parse_hysteria2(self, hy2_url: str) -> Optional[Dict[str, Any]]:
        p, q = urlparse(hy2_url), parse_qs(urlparse(hy2_url).query)
        return {'name': unquote(p.fragment or ''), 'type': 'hysteria2', 'server': p.hostname, 'port': p.port or 443, 'auth': p.username, 'sni': q.get('sni', [p.hostname])[0]}

    def parse_tuic(self, tuic_url: str) -> Optional[Dict[str, Any]]:
        p, q = urlparse(tuic_url), parse_qs(urlparse(tuic_url).query)
        return {'name': unquote(p.fragment or ''), 'type': 'tuic', 'server': p.hostname, 'port': p.port or 443, 'uuid': p.username, 'password': q.get('password', [''])[0], 'udp': True, 'sni': q.get('sni', [p.hostname])[0]}

    def extract_configs_from_text(self, text: str) -> Set[str]:
        found = set()
        for pattern in V2RAY_PATTERNS:
            found.update(pattern.findall(text))
        return {corrected for url in found if (corrected := self._correct_config_type(url.strip())) and self._validate_config_type(corrected)}

    async def find_raw_configs_from_chat(self, chat_id: int, limit: int, retries: int = 3):
        local_configs = set()
        try:
            is_active = False
            async for last_msg in self.client.get_chat_history(chat_id, limit=1):
                if last_msg.date > (datetime.datetime.now() - datetime.timedelta(days=CHANNEL_MAX_INACTIVE_DAYS)):
                    is_active = True
                break 

            if not is_active: return

            async for message in self.client.get_chat_history(chat_id, limit=limit):
                # گرفتن متن به صورت‌های مختلف برای اطمینان از اسکن کوت‌ها
                raw_text = message.text or message.caption or ""
                
                # روش تهاجمی: حذف تمام کاراکترهای مخفی و اینترها برای پیدا کردن لینک‌های شکسته شده در کوت
                dense_text = raw_text.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')
                
                texts_to_scan = [raw_text, dense_text]
                
                # اسکن انتیتی‌ها به روش امن
                if message.entities:
                    for ent in message.entities:
                        # استخراج متن بر اساس افست تلگرام
                        start, length = ent.offset, ent.length
                        # استفاده از اسلایس برای گرفتن محتوای کوت
                        segment = raw_text[start : start + length]
                        if segment:
                            texts_to_scan.append(segment)
                            texts_to_scan.append(segment.replace('\n', '').replace(' ', ''))

                # اسکن بیس 64
                for b64_str in BASE64_PATTERN.findall(raw_text):
                    try:
                        decoded = base64.b64decode(b64_str + '=' * 4).decode('utf-8', errors='ignore')
                        texts_to_scan.append(decoded)
                    except: continue
                
                for text in texts_to_scan:
                    if text: local_configs.update(self.extract_configs_from_text(text))
            
            self.raw_configs.update(local_configs)
        except FloodWait as e:
            if retries > 0:
                await asyncio.sleep(e.value + 1)
                await self.find_raw_configs_from_chat(chat_id, limit, retries - 1)
        except: pass

    def build_pro_config(self, proxies, proxy_names):
        # فیلتر فیلدهای حیاتی برای جلوگیری از ارور کلش
        clean_proxies = []
        clean_names = []
        for p in proxies:
            if p.get('type') in ['vless', 'vmess', 'tuic'] and not p.get('uuid'): continue
            if p.get('type') == 'trojan' and not p.get('password'): continue
            if not p.get('server') or not p.get('port'): continue
            clean_proxies.append(p)
            clean_names.append(p['name'])

        return {
            'port': 7890, 'socks-port': 7891, 'allow-lan': True, 'mode': 'rule', 'proxies': clean_proxies,
            'proxy-groups': [
                {'name': 'PROXY', 'type': 'select', 'proxies': ['⚡ Auto-Select', 'DIRECT', *clean_names]},
                {'name': '⚡ Auto-Select', 'type': 'url-test', 'proxies': clean_names, 'url': 'http://www.gstatic.com/generate_204', 'interval': 300},
            ],
            'rules': ['MATCH,PROXY']
        }

    def save_files(self):
        proxies_clash, final_txt = [], []
        for i, url in enumerate(sorted(list(self.raw_configs)), 1):
            if not (proxy := self.parse_config_for_clash(url)): continue
            host = proxy.get('server')
            code = self.get_country_iso_code(host)
            flag = COUNTRY_FLAGS.get(code, '🏳️')
            proxy['name'] = f"{code} Config_jo-{i:02d}"
            proxies_clash.append(proxy)
            final_txt.append(f"{url.split('#')[0]}#{flag} Config_jo-{i:02d}")

        with open(OUTPUT_TXT, 'w', encoding='utf-8') as f: f.write("\n".join(final_txt))
        with open(OUTPUT_YAML_PRO, 'w', encoding='utf-8') as f:
            yaml.dump(self.build_pro_config(proxies_clash, []), f, allow_unicode=True, sort_keys=False)

        # آپدیت سیستم هفتگی
        history = {}
        if os.path.exists(HISTORY_FILE):
            try:
                with open(HISTORY_FILE, 'r') as f: history = json.load(f)
            except: pass
        now = datetime.datetime.now()
        new_history = {k: v for k, v in history.items() if datetime.datetime.fromisoformat(v['date']) > (now - datetime.timedelta(days=7))}
        for cfg in final_txt:
            base = cfg.split('#')[0]
            if base not in new_history: new_history[base] = {"link": cfg, "date": now.isoformat()}
        with open(HISTORY_FILE, 'w') as f: json.dump(new_history, f, indent=2)
        with open(WEEKLY_FILE, 'w', encoding='utf-8') as f: f.write("\n".join([m['link'] for m in new_history.values()]))

async def main():
    load_ip_data()
    extractor = V2RayExtractor()
    async with extractor.client:
        tasks = [extractor.find_raw_configs_from_chat(c, CHANNEL_SEARCH_LIMIT) for c in CHANNELS]
        await asyncio.gather(*tasks)
    extractor.save_files()

if __name__ == "__main__":
    asyncio.run(main())
