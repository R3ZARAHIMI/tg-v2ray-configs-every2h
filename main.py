import re, asyncio, base64, json, yaml, os, datetime, ipaddress, socket, geoip2.database
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

OUTPUT_YAML_PRO, OUTPUT_TXT = "Config-jo.yaml", "Config_jo.txt"
OUTPUT_JSON_CONFIG_JO = "Config_jo.json"
OUTPUT_ORIGINAL_CONFIGS = "Original-Configs.txt"
OUTPUT_NO_CF = "Config_no_cf.txt"
HISTORY_FILE, NO_CF_HISTORY_FILE = "conf-week-history.json", "no_cf_history.json"
WEEKLY_FILE, BLOCKED_IPS_FILE = "conf-week.txt", "blocked_ips.txt"
GEOIP_DATABASE_PATH = 'dbip-country-lite.mmdb'
CHANNEL_MAX_INACTIVE_DAYS = 4

V2RAY_PATTERNS = [re.compile(r'(vless:\/\/[^\s\'\"<>`]+)'), re.compile(r'(vmess:\/\/[^\s\'\"<>`]+)'), re.compile(r'(trojan:\/\/[^\s\'\"<>`]+)'), re.compile(r'(ss:\/\/[^\s\'\"<>`]+)'), re.compile(r"(hy2://[^\s'\"<>`]+)"), re.compile(r"(hysteria2://[^\s'\"<>`]+)"), re.compile(r"(tuic://[^\s'\"<>`]+)")]
BASE64_PATTERN = re.compile(r"([A-Za-z0-9+/=]{50,})", re.MULTILINE)
COUNTRY_FLAGS = {'AD': '🇦🇩', 'AE': '🇦🇪', 'AF': '🇦🇫', 'AG': '🇦🇬', 'AI': '🇦🇮', 'AL': '🇦🇱', 'AM': '🇦🇲', 'AO': '🇦🇴', 'AQ': '🇦🇶', 'AR': '🇦🇷', 'AS': '🇦🇸', 'AT': '🇦🇹', 'AU': '🇦🇺', 'AW': '🇦🇼', 'AX': '🇦🇽', 'AZ': '🇦🇿', 'BA': '🇧🇦', 'BB': '🇧🇧', 'BD': '🇧🇩', 'BE': '🇧🇪', 'BF': '🇧🇫', 'BG': '🇧🇬', 'BH': '🇧🇭', 'BI': '🇧🇮', 'BJ': '🇧🇯', 'BL': '🇧🇱', 'BM': '🇧🇲', 'BN': '🇧🇳', 'BO': '🇧🇴', 'BR': '🇧🇷', 'BS': '🇧🇸', 'BT': '🇧🇹', 'BW': '🇧🇼', 'BY': '🇧🇾', 'BZ': '🇧🇿', 'CA': '🇨🇦', 'CC': '🇨🇨', 'CD': '🇨🇩', 'CF': '🇨🇫', 'CG': '🇨🇬', 'CH': '🇨🇭', 'CI': '🇨🇮', 'CK': '🇨🇰', 'CL': '🇨🇱', 'CM': '🇨🇲', 'CN': '🇨🇳', 'CO': '🇨🇴', 'CR': '🇨🇷', 'CU': '🇨🇺', 'CV': '🇨🇻', 'CW': '🇨🇼', 'CX': '🇨🇽', 'CY': '🇨🇾', 'CZ': '🇨🇿', 'DE': '🇩🇪', 'DJ': '🇩🇯', 'DK': '🇩🇰', 'DM': '🇩🇲', 'DO': '🇩🇴', 'DZ': '🇩🇿', 'EC': '🇪🇨', 'EE': '🇪🇪', 'EG': '🇪🇬', 'EH': '🇪🇭', 'ER': '🇪🇷', 'ES': '🇪🇸', 'ET': '🇪🇹', 'FI': '🇫🇮', 'FJ': '🇫🇯', 'FK': '🇫🇰', 'FM': '🇫🇲', 'FO': '🇫🇴', 'FR': '🇫🇷', 'GA': '🇬🇦', 'GB': '🇬🇬', 'GD': '🇬🇩', 'GE': '🇬🇪', 'GF': '🇬🇫', 'GG': '🇬🇬', 'GH': '🇬🇭', 'GI': '🇬🇮', 'GL': '🇬🇱', 'GM': '🇬🇲', 'GN': '🇬🇳', 'GP': '🇬🇵', 'GQ': '🇬🇶', 'GR': '🇬🇷', 'GT': '🇬🇹', 'GU': '🇬🇺', 'GW': '🇬🇼', 'GY': '🇬🇾', 'HK': '🇭🇰', 'HN': '🇭🇳', 'HR': '🇭🇷', 'HT': '🇭🇹', 'HU': '🇭🇺', 'ID': '🇮🇩', 'IE': '🇮🇪', 'IL': '🇮🇱', 'IM': '🇮🇲', 'IN': '🇮🇳', 'IO': '🇮🇴', 'IQ': '🇮🇶', 'IR': '🇮🇷', 'IS': '🇮🇸', 'IT': '🇮🇹', 'JE': '🇯🇪', 'JM': '🇯🇲', 'JO': '🇯🇴', 'JP': '🇯🇵', 'KE': '🇰🇪', 'KG': '🇰🇬', 'KH': '🇰🇭', 'KI': '🇰🇮', 'KM': '🇰🇲', 'KN': '🇰🇳', 'KP': '🇰🇵', 'KR': '🇰🇷', 'KW': '🇰🇼', 'KY': '🇰🇾', 'KZ': '🇰🇿', 'LA': '🇱🇦', 'LB': '🇱🇧', 'LC': '🇱🇨', 'LI': '🇱🇮', 'LK': '🇱🇰', 'LR': '🇱🇷', 'LS': '🇱🇸', 'LT': '🇱🇹', 'LU': '🇱🇺', 'LV': '🇱🇻', 'LY': '🇱🇾', 'MA': '🇲🇦', 'MC': '🇲🇨', 'MD': '🇲🇩', 'ME': '🇲🇪', 'MF': '🇲🇫', 'MG': '🇲🇬', 'MH': '🇲🇭', 'MK': '🇲🇰', 'ML': '🇲🇱', 'MM': '🇲🇲', 'MN': '🇲🇳', 'MO': '🇲🇴', 'MP': '🇲🇵', 'MQ': '🇲🇶', 'MR': '🇲🇷', 'MS': '🇲🇸', 'MT': '🇲🇹', 'MU': '🇲🇺', 'MV': '🇲🇻', 'MW': '🇲🇼', 'MX': '🇲🇽', 'MY': '🇲🇾', 'MZ': '🇲🇿', 'NA': '🇳🇦', 'NC': '🇳🇨', 'NE': '🇳🇪', 'NF': '🇳🇫', 'NG': '🇳🇬', 'NI': '🇳🇮', 'NL': '🇳🇱', 'NO': '🇳🇴', 'NP': '🇳🇵', 'NR': '🇳🇷', 'NU': '🇳🇺', 'NZ': '🇳🇿', 'OM': '🇴🇲', 'PA': '🇵🇦', 'PE': '🇵🇪', 'PF': '🇵🇫', 'PG': '🇵🇬', 'PH': '🇵🇭', 'PK': '🇵🇰', 'PL': '🇵🇱', 'PM': '🇵🇲', 'PN': '🇵🇳', 'PR': '🇵🇷', 'PS': '🇵🇸', 'PT': '🇵🇹', 'PW': '🇵🇼', 'PY': '🇵🇾', 'QA': '🇶🇦', 'RE': '🇷🇪', 'RO': '🇷🇴', 'RS': '🇷🇸', 'RU': '🇷🇺', 'RW': '🇷🇼', 'SA': '🇸🇦', 'SB': '🇸🇧', 'SC': '🇸🇨', 'SD': '🇸🇩', 'SE': '🇸🇪', 'SG': '🇸🇬', 'SH': '🇸🇭', 'SI': '🇸🇮', 'SK': '🇸🇰', 'SL': '🇸🇱', 'SM': '🇸🇲', 'SN': '🇸🇳', 'SO': '🇸🇴', 'SR': '🇸🇷', 'SS': '🇸🇸', 'ST': '🇸🇹', 'SV': '🇸🇻', 'SX': '🇸🇽', 'SY': '🇸🇾', 'SZ': '🇸🇿', 'TC': '🇹🇨', 'TD': '🇹🇩', 'TG': '🇹🇬', 'TH': '🇹🇭', 'TJ': '🇹🇯', 'TK': '🇹🇰', 'TL': '🇹🇱', 'TM': '🇹🇲', 'TN': '🇹🇳', 'TO': '🇹🇴', 'TR': '🇹🇷', 'TT': '🇹🇹', 'TV': '🇹🇻', 'TW': '🇹🇼', 'TZ': '🇹🇿', 'UA': '🇺🇦', 'UG': '🇺🇬', 'US': '🇺🇸', 'UY': '🇺🇾', 'UZ': '🇺🇿', 'VA': '🇻🇦', 'VC': '🇻🇨', 'VE': '🇻🇪', 'VG': '🇻🇬', 'VI': '🇻🇮', 'VN': '🇻🇳', 'VU': '🇻🇺', 'WF': '🇼🇫', 'WS': '🇼🇸', 'YE': '🇾🇪', 'YT': '🇾🇹', 'ZA': '🇿🇦', 'ZM': '🇿🇲', 'ZW': '🇿🇼'}

GEOIP_READER = None
BLOCKED_NETWORKS = []

def load_ip_data():
    global GEOIP_READER
    try: GEOIP_READER = geoip2.database.Reader(GEOIP_DATABASE_PATH)
    except: pass

def load_blocked_ips():
    global BLOCKED_NETWORKS
    if os.path.exists(BLOCKED_IPS_FILE):
        try:
            with open(BLOCKED_IPS_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        try: BLOCKED_NETWORKS.append(ipaddress.ip_network(line, strict=False))
                        except: pass
        except: pass

def is_clean_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        for network in BLOCKED_NETWORKS:
            if ip in network: return False 
        return True 
    except: return False 

def process_lists():
    channels = [ch.strip() for ch in CHANNELS_STR.split(',')] if CHANNELS_STR else []
    groups = []
    if GROUPS_STR:
        try: groups = [int(g.strip()) for g in GROUPS_STR.split(',')]
        except: pass
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

    def _correct_config_type(self, config_url: str) -> str:
        if config_url.startswith('ss://') and 'v=2' in config_url: return config_url.replace('ss://', 'vmess://', 1)
        return config_url

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
        return {'name': unquote(p.fragment or ''), 'type': 'trojan', 'server': p.hostname, 'port': p.port or 443, 'password': p.username, 'udp': True, 'sni': q.get('sni', [None])[0]}

    def parse_shadowsocks(self, ss_url: str) -> Optional[Dict[str, Any]]:
        try:
            content = ss_url[5:]
            name = unquote(content.split('#', 1)[1]) if '#' in content else ''
            content = content.split('#', 1)[0] if '#' in content else content
            userinfo_b64, server_part = content.rsplit('@', 1)
            server_host, port = server_part.rsplit(':', 1)
            userinfo = base64.b64decode(userinfo_b64 + '=' * (-len(userinfo_b64) % 4)).decode('utf-8')
            cipher, password = userinfo.split(':', 1)
            return {'name': name, 'type': 'ss', 'server': server_host, 'port': int(port), 'cipher': cipher, 'password': password, 'udp': True}
        except: return None

    def parse_hysteria2(self, hy2_url: str) -> Optional[Dict[str, Any]]:
        p, q = urlparse(hy2_url), parse_qs(urlparse(hy2_url).query)
        return {'name': unquote(p.fragment or ''), 'type': 'hysteria2', 'server': p.hostname, 'port': p.port or 443, 'auth': p.username, 'sni': q.get('sni', [p.hostname])[0], 'skip-cert-verify': q.get('insecure', ['0'])[0]=='1'}

    def parse_tuic(self, tuic_url: str) -> Optional[Dict[str, Any]]:
        p, q = urlparse(tuic_url), parse_qs(urlparse(tuic_url).query)
        return {'name': unquote(p.fragment or ''), 'type': 'tuic', 'server': p.hostname, 'port': p.port or 443, 'uuid': p.username, 'password': q.get('password', [''])[0], 'udp': True, 'sni': q.get('sni', [p.hostname])[0], 'skip-cert-verify': q.get('allow_insecure', ['0'])[0]=='1'}

    def convert_to_singbox_outbound(self, proxy: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not proxy: return None
        t = proxy['type']
        out = {'type': t if t!='ss' else 'shadowsocks', 'tag': proxy['name'], 'server': proxy['server'], 'server_port': proxy['port']}
        if t=='vmess': out.update({'uuid': proxy['uuid'], 'alter_id': proxy['alterId'], 'security': proxy['cipher'], 'tls': {'enabled': True, 'server_name': proxy['servername']} if proxy.get('tls') else None})
        if t=='vless': out.update({'uuid': proxy['uuid'], 'tls': {'enabled': True, 'server_name': proxy['servername'], 'reality': {'enabled': True, 'public_key': proxy.get('reality-opts',{}).get('public-key'), 'short_id': proxy.get('reality-opts',{}).get('short-id')} if proxy.get('reality-opts') else None} if proxy.get('tls') else None})
        if t=='trojan': out.update({'password': proxy['password'], 'tls': {'enabled': True, 'server_name': proxy.get('sni')}})
        if t=='ss': out.update({'method': proxy['cipher'], 'password': proxy['password']})
        if t in ['hysteria2','tuic']: out.update({'password': proxy.get('auth') or proxy.get('password'), 'tls': {'enabled': True, 'server_name': proxy['sni'], 'insecure': proxy.get('skip-cert-verify')}})
        if proxy.get('ws-opts'): out['transport'] = {'type': 'ws', 'path': proxy['ws-opts']['path'], 'headers': proxy['ws-opts']['headers']}
        return out

    async def find_raw_configs_from_chat(self, chat_id: int, limit: int):
        try:
            async for message in self.client.get_chat_history(chat_id, limit=limit):
                text = message.text or message.caption or ""
                for pattern in V2RAY_PATTERNS:
                    for url in pattern.findall(text):
                        url = url.strip()
                        if not url.startswith('vmess://') and '#' in url: url = url.split('#')[0]
                        if corrected := self._correct_config_type(url): self.raw_configs.add(corrected)
        except FloodWait as e: await asyncio.sleep(e.value + 2)
        except: pass

    def handle_retention(self, links: List[str], file: str, hist_file: str, hours: int = 168):
        now, cutoff = datetime.datetime.now(), datetime.datetime.now() - datetime.timedelta(hours=hours)
        history = {}
        if os.path.exists(hist_file):
            try:
                with open(hist_file, 'r') as f: history = json.load(f)
            except: pass
        new_history = {k: v for k, v in history.items() if datetime.datetime.fromisoformat(v['date']) > cutoff}
        for cfg in links:
            base = cfg.split('#')[0]
            if base not in new_history: new_history[base] = {"link": cfg, "date": now.isoformat()}
        with open(hist_file, 'w') as f: json.dump(new_history, f, indent=2)
        with open(file, 'w', encoding='utf-8') as f: f.write("\n".join(sorted([m['link'] for m in new_history.values()])))

    def save_files(self):
        if not self.raw_configs: return
        proxies_list, renamed_txt, clean_ip_links = [], [], []
        for i, url in enumerate(sorted(list(self.raw_configs)), 1):
            if not (p := self.parse_config_for_clash(url)): continue
            code = self.get_country_iso_code(p.get('server'))
            p['name'] = f"{code} Config_jo-{i:02d}"
            proxies_list.append(p)
            name_with_flag = f"{COUNTRY_FLAGS.get(code, '🏳️')} Config_jo-{i:02d}"
            final_link = urlunparse(list(urlparse(url))[:5] + [name_with_flag]) if p['type'] != 'ss' else f"{url.split('#')[0]}#{name_with_flag}"
            renamed_txt.append(final_link)
            if is_clean_ip(p.get('server')): clean_ip_links.append(final_link)

        with open(OUTPUT_ORIGINAL_CONFIGS, 'w', encoding='utf-8') as f: f.write("\n".join(sorted(list(self.raw_configs))))
        with open(OUTPUT_TXT, 'w', encoding='utf-8') as f: f.write("\n".join(sorted(renamed_txt)))
        self.handle_retention(renamed_txt, WEEKLY_FILE, HISTORY_FILE)
        self.handle_retention(clean_ip_links, OUTPUT_NO_CF, NO_CF_HISTORY_FILE, 72)
        
        if proxies_list:
            clash_cfg = self.build_pro_config(proxies_list)
            with open(OUTPUT_YAML_PRO, 'w', encoding='utf-8') as f: yaml.dump(clash_cfg, f, allow_unicode=True, sort_keys=False, indent=2)
            with open(OUTPUT_JSON_CONFIG_JO, 'w', encoding='utf-8') as f: json.dump(self.build_sing_box_config(proxies_list), f, ensure_ascii=False, indent=4)

    def build_pro_config(self, proxies):
        clean_p, clean_n, seen = [], [], set()
        for p in proxies:
            if p.get('network') in ['xhttp', 'httpupgrade']: continue
            if p.get('type') in ['vless', 'vmess', 'tuic'] and not p.get('uuid'): continue
            if p.get('type') == 'trojan' and not p.get('password'): continue
            sni = p.get('servername') or p.get('sni')
            if not sni and (p.get('tls') or p.get('type') == 'trojan'): p['servername'] = p['sni'] = 'www.google.com'
            p_clean = {k: v for k, v in p.items() if v is not None and v != ''}
            name = p_clean.get('name', 'Proxy')
            counter = 1
            original_name = name
            while name in seen:
                name = f"{original_name}_{counter}"; counter += 1
            p_clean['name'] = name; seen.add(name); clean_p.append(p_clean); clean_n.append(name)

        return {
            'port': 7890, 'socks-port': 7891, 'allow-lan': False, 'mode': 'rule', 'log-level': 'warning', 'ipv6': False,
            'external-controller': '127.0.0.1:9090',
            'dns': {
                'enable': True,
                'respect-rules': True,
                'use-system-hosts': False,
                'listen': '127.0.0.1:1053',  # پورت فیکس شده طبق دستور
                'ipv6': True,
                'nameserver': ['https://8.8.8.8/dns-query#✅ Selector'],
                'proxy-server-nameserver': ['8.8.8.8#DIRECT'],
                'direct-nameserver': ['8.8.8.8#DIRECT'],
                'direct-nameserver-follow-policy': True,
                'nameserver-policy': {
                    'rule-set:openai': '178.22.122.100#DIRECT',
                    'rule-set:ir': '8.8.8.8#DIRECT'
                },
                'enhanced-mode': 'fake-ip', # یا redir-host بسته به نیاز، fake-ip معمولاً سریعتر است
                'fake-ip-range': '198.18.0.1/16'
            },
            'proxies': clean_p,
            'proxy-groups': [
                {'name': '✅ Selector', 'type': 'select', 'proxies': ['⚡ Auto-Select', 'DIRECT', *clean_n]},
                {'name': '⚡ Auto-Select', 'type': 'url-test', 'proxies': clean_n, 'url': 'http://www.gstatic.com/generate_204', 'interval': 300},
                {'name': '🇮🇷 Iran', 'type': 'select', 'proxies': ['DIRECT', '✅ Selector']},
                {'name': '🛑 Block-Ads', 'type': 'select', 'proxies': ['REJECT', 'DIRECT']}
            ],
            # الگوی مسیریابی دقیق طبق فایل ارسالی شما
            'rule-providers': {
                'ir': {'type': 'http', 'format': 'text', 'behavior': 'domain', 'path': './ruleset/ir.txt', 'interval': 86400, 'url': 'https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ir.txt'},
                'ir-cidr': {'type': 'http', 'format': 'text', 'behavior': 'ipcidr', 'path': './ruleset/ir-cidr.txt', 'interval': 86400, 'url': 'https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ircidr.txt'},
                'openai': {'type': 'http', 'format': 'yaml', 'behavior': 'domain', 'path': './ruleset/openai.yaml', 'interval': 86400, 'url': 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/openai.yaml'}
            },
            'rules': [
                'RULE-SET,openai,✅ Selector',
                'RULE-SET,ir,🇮🇷 Iran',
                'RULE-SET,ir-cidr,🇮🇷 Iran',
                'GEOIP,IR,🇮🇷 Iran',
                'MATCH,✅ Selector'
            ]
        }

    def build_sing_box_config(self, proxies):
        outbounds = [p for p in (self.convert_to_singbox_outbound(proxy) for proxy in proxies) if p]
        tags = [p['tag'] for p in outbounds]
        return {"log": {"level": "warn", "timestamp": True}, "dns": {"servers": [{"tag": "dns_proxy", "address": "https://dns.google/dns-query", "detour": "PROXY"}, {"tag": "dns_direct", "address": "1.1.1.1"}], "rules": [{"outbound": "PROXY", "server": "dns_proxy"}, {"rule_set": ["geosite-ir", "geoip-ir"], "server": "dns_direct"}, {"domain_suffix": ".ir", "server": "dns_direct"}], "final": "dns_direct", "strategy": "ipv4_only"}, "inbounds": [{"type": "mixed", "listen": "0.0.0.0", "listen_port": 2080, "sniff": True}], "outbounds": [{"type": "direct", "tag": "direct"}, {"type": "block", "tag": "block"}, {"type": "dns", "tag": "dns-out"}, *outbounds, {"type": "selector", "tag": "PROXY", "outbounds": ["auto", *tags], "default": "auto"}, {"type": "urltest", "tag": "auto", "outbounds": tags, "url": "http://www.gstatic.com/generate_204", "interval": "5m"}], "route": {"rule_set": [{"tag": "geosite-ir", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/Chocolate4U/Iran-sing-box-rules@rule-set/geosite-ir.srs", "download_detour": "direct"}, {"tag": "geoip-ir", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/Chocolate4U/Iran-sing-box-rules@rule-set/geoip-ir.srs", "download_detour": "direct"}], "rules": [{"protocol": "dns", "outbound": "dns-out"}, {"rule_set": ["geosite-ir", "geoip-ir"], "outbound": "direct"}, {"ip_is_private": True, "outbound": "direct"}], "final": "PROXY"}}

async def main():
    load_ip_data(); load_blocked_ips()
    ex = V2RayExtractor()
    async with ex.client:
        tasks = [ex.find_raw_configs_from_chat(ch, CHANNEL_SEARCH_LIMIT) for ch in CHANNELS]
        tasks += [ex.find_raw_configs_from_chat(g, GROUP_SEARCH_LIMIT) for g in GROUPS]
        if tasks: await asyncio.gather(*tasks)
    ex.save_files()

if __name__ == "__main__":
    if all([API_ID, API_HASH, SESSION_STRING]): asyncio.run(main())
