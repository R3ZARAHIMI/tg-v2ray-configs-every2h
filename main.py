import re
import asyncio
import base64
import json
import yaml
import os
import uuid
from urllib.parse import urlparse, parse_qs, unquote
from pyrogram import Client
from pyrogram.errors import FloodWait
from typing import Optional, Dict, Any, Set, List

# =================================================================================
# بخش تنظیمات و ثابت‌ها
# =================================================================================

# خواندن متغیرهای محیطی
API_ID = int(os.environ.get("API_ID"))
API_HASH = os.environ.get("API_HASH")
SESSION_STRING = os.environ.get("SESSION_STRING")
CHANNELS_STR = os.environ.get('CHANNELS_LIST')
GROUPS_STR = os.environ.get('GROUPS_LIST')
CHANNEL_SEARCH_LIMIT = int(os.environ.get('CHANNEL_SEARCH_LIMIT', 5))
GROUP_SEARCH_LIMIT = int(os.environ.get('GROUP_SEARCH_LIMIT', 600))

# تعریف نام فایل‌های خروجی
OUTPUT_YAML_PRO = "Config-jo.yaml"      # نسخه حرفه‌ای
OUTPUT_YAML_LITE = "Config-Lite.yaml"     # نسخه سازگار برای بعضی کلاینت‌های کلش 
OUTPUT_TXT = "Config_jo.txt"              # لیست خام کانفیگ‌ها

# الگوهای Regex برای یافتن انواع کانفیگ
V2RAY_PATTERNS = [
    re.compile(r'(vless:\/\/[^\s\'\"<>`]+)'),
    re.compile(r'(vmess:\/\/[^\s\'\"<>`]+)'),
    re.compile(r'(trojan:\/\/[^\s\'\"<>`]+)'),
    re.compile(r'(ss:\/\/[^\s\'\"<>`]+)'),
    re.compile(r"(hy2://[^\s'\"<>`]+)"),
    re.compile(r"(hysteria2://[^\s'\"<>`]+)"),
    re.compile(r"(tuic://[^\s'\"<>`]+)")
]

BASE64_PATTERN = re.compile(r"([A-Za-z0-9+/=]{50,})", re.MULTILINE)

def process_lists():
    """خواندن و پردازش لیست کانال‌ها و گروه‌ها از متغیرهای محیطی"""
    channels = [ch.strip() for ch in CHANNELS_STR.split(',')] if CHANNELS_STR else []
    if channels: print(f"✅ {len(channels)} کانال از سکرت‌ها خوانده شد.")
    else: print("⚠️ هشدار: سکرت CHANNELS_LIST پیدا نشد یا خالی است.")

    groups = []
    if GROUPS_STR:
        try:
            groups = [int(g.strip()) for g in GROUPS_STR.split(',')]
            print(f"✅ {len(groups)} گروه از سکرت‌ها خوانده شد.")
        except ValueError: print("❌ خطا: سکرت GROUPS_LIST باید فقط شامل آیدی‌های عددی باشد.")
    else: print("⚠️ هشدار: سکرت GROUPS_LIST خالی است.")
    return channels, groups

CHANNELS, GROUPS = process_lists()

class V2RayExtractor:
    def __init__(self):
        self.raw_configs: Set[str] = set()
        self.client = Client("my_account", api_id=API_ID, api_hash=API_HASH, session_string=SESSION_STRING)

    @staticmethod
    def _generate_unique_name(original_name: str, prefix: str = "config") -> str:
        if not original_name: return f"{prefix}-{str(uuid.uuid4())[:8]}"
        cleaned_name = re.sub(r'[^\w\s\-\_\u0600-\u06FF]', '', original_name).replace(' ', '_').strip('_-')
        if not cleaned_name: return f"{prefix}-{str(uuid.uuid4())[:8]}"
        return f"{cleaned_name}-{str(uuid.uuid4())[:4]}"

    def _is_valid_shadowsocks(self, ss_url: str) -> bool:
        try:
            parsed = urlparse(ss_url)
            if not parsed.hostname or not parsed.username: return False
            uuid_pattern = r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'
            if re.search(uuid_pattern, parsed.username): return False
            try:
                decoded_user = base64.b64decode(parsed.username + '=' * (-len(parsed.username) % 4)).decode('utf-8')
                if ':' not in decoded_user: return False
            except:
                if ':' not in parsed.username: return False
            return True
        except: return False

    def _correct_config_type(self, config_url: str) -> str:
        try:
            if config_url.startswith('ss://'):
                parsed = urlparse(config_url)
                uuid_pattern = r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'
                if parsed.username and re.match(uuid_pattern, parsed.username):
                    return config_url.replace('ss://', 'vless://', 1)
                if parsed.username:
                    try:
                        decoded = base64.b64decode(parsed.username + '=' * (-len(parsed.username) % 4)).decode('utf-8')
                        json_data = json.loads(decoded)
                        if 'v' in json_data and json_data.get('v') == '2':
                            return config_url.replace('ss://', 'vmess://', 1)
                    except: pass
            return config_url
        except: return config_url

    def _validate_config_type(self, config_url: str) -> bool:
        try:
            if config_url.startswith('vless://'):
                return bool(urlparse(config_url).hostname and urlparse(config_url).username)
            elif config_url.startswith('vmess://'):
                encoded_data = config_url.split("://")[1]
                decoded_str = base64.b64decode(encoded_data + '=' * (-len(encoded_data) % 4)).decode('utf-8')
                config = json.loads(decoded_str)
                return bool(config.get('add') and config.get('id'))
            elif config_url.startswith('trojan://'):
                return bool(urlparse(config_url).hostname and urlparse(config_url).username)
            elif config_url.startswith('ss://'):
                return self._is_valid_shadowsocks(config_url)
            return True
        except: return False

    def parse_config_for_clash(self, config_url: str) -> Optional[Dict[str, Any]]:
        try:
            if config_url.startswith('vmess://'): return self.parse_vmess(config_url)
            elif config_url.startswith('vless://'): return self.parse_vless(config_url)
            elif config_url.startswith('trojan://'): return self.parse_trojan(config_url)
            elif config_url.startswith('ss://'): return self.parse_shadowsocks(config_url)
            elif config_url.startswith(('hysteria2://', 'hy2://')): return self.parse_hysteria2(config_url)
            elif config_url.startswith('tuic://'): return self.parse_tuic(config_url)
            return None
        except Exception as e:
            print(f"❌ خطا در پارس کردن کانفیگ {config_url[:50]}...: {e}")
            return None

    def parse_vmess(self, vmess_url: str) -> Optional[Dict[str, Any]]:
        try:
            encoded_data = vmess_url.split("://")[1]
            decoded_str = base64.b64decode(encoded_data + '=' * (-len(encoded_data) % 4)).decode('utf-8')
            config = json.loads(decoded_str)
            original_name = config.get('ps', '')
            ws_opts = None
            if config.get('net') == 'ws':
                host_header = config.get('host', '').strip() or config.get('add', '').strip()
                if host_header: ws_opts = {'path': config.get('path', '/'), 'headers': {'Host': host_header}}
            return {'name': self._generate_unique_name(original_name, "vmess"), 'type': 'vmess', 'server': config.get('add'), 'port': int(config.get('port', 443)), 'uuid': config.get('id'), 'alterId': int(config.get('aid', 0)), 'cipher': config.get('scy', 'auto'), 'tls': config.get('tls') == 'tls', 'network': config.get('net', 'tcp'), 'udp': True, 'ws-opts': ws_opts}
        except Exception as e:
            print(f"❌ خطا در پارس vmess: {e}")
            return None

    def parse_vless(self, vless_url: str) -> Optional[Dict[str, Any]]:
        try:
            parsed = urlparse(vless_url)
            query = parse_qs(parsed.query)
            original_name = unquote(parsed.fragment) if parsed.fragment else ''
            ws_opts, reality_opts = None, None
            if query.get('type', [''])[0] == 'ws':
                host_header = query.get('host', [''])[0].strip() or query.get('sni', [''])[0].strip() or parsed.hostname
                if host_header: ws_opts = {'path': query.get('path', ['/'])[0], 'headers': {'Host': host_header}}
            if query.get('security', [''])[0] == 'reality':
                pbk = query.get('pbk', [None])[0]
                if pbk: reality_opts = {'public-key': pbk, 'short-id': query.get('sid', [''])[0]}
            return {'name': self._generate_unique_name(original_name, "vless"), 'type': 'vless', 'server': parsed.hostname, 'port': parsed.port or 443, 'uuid': parsed.username, 'udp': True, 'tls': query.get('security', [''])[0] in ['tls', 'reality'], 'network': query.get('type', ['tcp'])[0], 'servername': query.get('sni', [None])[0], 'ws-opts': ws_opts, 'reality-opts': reality_opts}
        except Exception as e:
            print(f"❌ خطا در پارس vless: {e}")
            return None

    def parse_trojan(self, trojan_url: str) -> Optional[Dict[str, Any]]:
        try:
            parsed = urlparse(trojan_url)
            query = parse_qs(parsed.query)
            original_name = unquote(parsed.fragment) if parsed.fragment else ''
            sni = query.get('peer', [None])[0] or query.get('sni', [None])[0] or parsed.hostname
            return {'name': self._generate_unique_name(original_name, "trojan"), 'type': 'trojan', 'server': parsed.hostname, 'port': parsed.port or 443, 'password': parsed.username, 'udp': True, 'sni': sni}
        except Exception as e:
            print(f"❌ خطا در پارس trojan: {e}")
            return None

    def parse_shadowsocks(self, ss_url: str) -> Optional[Dict[str, Any]]:
        try:
            parsed = urlparse(ss_url)
            original_name = unquote(parsed.fragment) if parsed.fragment else ''
            user_info = ''
            if '@' in parsed.netloc:
                user_info_part = parsed.netloc.split('@')[0]
                try: user_info = base64.b64decode(user_info_part + '=' * (4 - len(user_info_part) % 4)).decode('utf-8')
                except: user_info = unquote(user_info_part)
            cipher, password = user_info.split(':', 1) if ':' in user_info else (None, None)
            if cipher and password:
                return {'name': self._generate_unique_name(original_name, 'ss'), 'type': 'ss', 'server': parsed.hostname, 'port': parsed.port, 'cipher': cipher, 'password': password, 'udp': True}
            return None
        except Exception as e:
            print(f"❌ خطا در پارس shadowsocks: {e}")
            return None

    def parse_hysteria2(self, hy2_url: str) -> Optional[Dict[str, Any]]:
        try:
            parsed = urlparse(hy2_url)
            query = parse_qs(parsed.query)
            original_name = unquote(parsed.fragment) if parsed.fragment else ''
            return {'name': self._generate_unique_name(original_name, "hysteria2"), 'type': 'hysteria2', 'server': parsed.hostname, 'port': parsed.port or 443, 'auth': parsed.username, 'up': query.get('up', ['100 Mbps'])[0], 'down': query.get('down', ['100 Mbps'])[0], 'obfs': query.get('obfs', [''])[0] or None, 'sni': query.get('sni', [parsed.hostname])[0], 'skip-cert-verify': query.get('insecure', ['false'])[0].lower() == 'true'}
        except Exception as e:
            print(f"❌ خطا در پارس hysteria2: {e}")
            return None

    def parse_tuic(self, tuic_url: str) -> Optional[Dict[str, Any]]:
        try:
            parsed = urlparse(tuic_url)
            query = parse_qs(parsed.query)
            original_name = unquote(parsed.fragment) if parsed.fragment else ''
            return {'name': self._generate_unique_name(original_name, "tuic"), 'type': 'tuic', 'server': parsed.hostname, 'port': parsed.port or 443, 'uuid': parsed.username, 'password': query.get('password', [''])[0], 'udp': True, 'sni': query.get('sni', [parsed.hostname])[0], 'skip-cert-verify': query.get('allow_insecure', ['false'])[0].lower() == 'true'}
        except Exception as e:
            print(f"❌ خطا در پارس tuic: {e}")
            return None

    def extract_configs_from_text(self, text: str) -> Set[str]:
        found_configs = set()
        potential_configs = set()
        for pattern in V2RAY_PATTERNS:
            potential_configs.update(pattern.findall(text))
        for config_url in potential_configs:
            corrected_config = self._correct_config_type(config_url.strip())
            if corrected_config and self._validate_config_type(corrected_config):
                found_configs.add(corrected_config)
        return found_configs

    async def find_raw_configs_from_chat(self, chat_id: int, limit: int, retries: int = 3):
        try:
            print(f"🔍 جستجو در چت {chat_id} (محدودیت: {limit} پیام)...")
            async for message in self.client.get_chat_history(chat_id, limit=limit):
                text_to_check = message.text or message.caption
                if not text_to_check: continue
                texts_to_scan = [text_to_check]
                potential_b64 = BASE64_PATTERN.findall(text_to_check)
                for b64_str in potential_b64:
                    try:
                        decoded_text = base64.b64decode(b64_str + '=' * (-len(b64_str) % 4)).decode('utf-8', errors='ignore')
                        texts_to_scan.append(decoded_text)
                    except Exception: continue
                for text in texts_to_scan:
                    found_configs = self.extract_configs_from_text(text)
                    self.raw_configs.update(found_configs)
        except FloodWait as e:
            if retries <= 0:
                print(f"❌ حداکثر تعداد تلاش‌ها برای چت {chat_id} به پایان رسید.")
                return
            wait_time = min(e.value * (4 - retries), 300)
            print(f"⏳ صبر برای {wait_time} ثانیه (تلاش {4 - retries} از ۳)...")
            await asyncio.sleep(wait_time)
            await self.find_raw_configs_from_chat(chat_id, limit, retries - 1)
        except Exception as e:
            print(f"❌ خطا در زمان اسکن چت {chat_id}: {e}")

    def save_files(self):
        print("\n" + "="*40)
        print("⚙️ شروع پردازش و ساخت فایل‌های کانفیگ...")

        if not self.raw_configs:
            print("⚠️ هیچ کانفیگی در چت‌ها یافت نشد. فایل‌های خروجی خالی خواهند بود.")
            for f in [OUTPUT_YAML_PRO, OUTPUT_YAML_LITE, OUTPUT_TXT]: open(f, "w").close()
            return

        print(f"⚙️ پردازش {len(self.raw_configs)} کانفیگ یافت شده...")
        proxies_list, parse_errors = [], 0
        
        valid_configs = set()
        for url in self.raw_configs:
            try:
                # فیلتر اول: حذف کانفیگ‌های تست سرعت
                hostname = urlparse(url).hostname
                if hostname and 'speedtest' in hostname.lower():
                    continue

                # فیلتر دوم: حذف کانفیگ‌های VLESS بدون امنیت (TLS/REALITY)
                if url.startswith('vless://'):
                    query = parse_qs(urlparse(url).query)
                    if query.get('security', ['none'])[0] == 'none':
                        continue
                
                valid_configs.add(url)
            except Exception:
                pass

        for url in valid_configs:
            proxy = self.parse_config_for_clash(url)
            if proxy:
                proxies_list.append(proxy)
            else:
                parse_errors += 1

        if parse_errors > 0:
            print(f"⚠️ {parse_errors} کانفیگ به دلیل خطا در پارسینگ نادیده گرفته شد.")

        if not proxies_list:
            print("⚠️ هیچ کانفیگ معتبری برای ساخت فایل‌ها پیدا نشد.")
            for f in [OUTPUT_YAML_PRO, OUTPUT_YAML_LITE, OUTPUT_TXT]: open(f, "w").close()
            return
            
        print(f"👍 {len(proxies_list)} کانفیگ معتبر برای فایل نهایی یافت شد.")
        all_proxy_names = [p['name'] for p in proxies_list]

        # مرحله ۲: ساخت و ذخیره فایل حرفه‌ای (Pro)
        try:
            os.makedirs('rules', exist_ok=True)
            pro_config = self.build_pro_config(proxies_list, all_proxy_names)
            with open(OUTPUT_YAML_PRO, 'w', encoding='utf-8') as f:
                yaml.dump(pro_config, f, allow_unicode=True, sort_keys=False, indent=2, width=1000)
            print(f"✅ فایل حرفه‌ای {OUTPUT_YAML_PRO} با موفقیت ساخته شد.")
        except Exception as e:
            print(f"❌ خطا در ساخت فایل حرفه‌ای: {e}")

        # مرحله ۳: ساخت و ذخیره فایل سازگار (Lite)
        try:
            lite_config = self.build_lite_config(proxies_list, all_proxy_names)
            with open(OUTPUT_YAML_LITE, 'w', encoding='utf-8') as f:
                yaml.dump(lite_config, f, allow_unicode=True, sort_keys=False, indent=2, width=1000)
            print(f"✅ فایل سازگار {OUTPUT_YAML_LITE} (برای ClashMI) با موفقیت ساخته شد.")
        except Exception as e:
            print(f"❌ خطا در ساخت فایل سازگار: {e}")

        # مرحله ۴: ذخیره فایل متنی
        with open(OUTPUT_TXT, 'w', encoding='utf-8') as f:
            f.write("\n".join(sorted(list(valid_configs))))
        print(f"✅ فایل متنی {OUTPUT_TXT} با موفقیت ذخیره شد.")

    def build_pro_config(self, proxies, proxy_names):
        """ساخت کانفیگ حرفه‌ای با قابلیت‌های پیشرفته"""
        return {
            'port': int(os.environ.get('CLASH_PORT', 7890)),
            'socks-port': int(os.environ.get('CLASH_SOCKS_PORT', 7891)),
            'allow-lan': os.environ.get('CLASH_ALLOW_LAN', 'true').lower() == 'true',
            'mode': 'rule',
            'log-level': 'info',
            'external-controller': '127.0.0.1:9090',
            'dns': {
                'enable': True,
                'listen': '0.0.0.0:53',
                'default-nameserver': ['8.8.8.8', '1.1.1.1'],
                'enhanced-mode': 'fake-ip',
                'fake-ip-range': '198.18.0.1/16',
                'fallback': ['https://dns.google/dns-query', 'https://cloudflare-dns.com/dns-query'],
                'fallback-filter': {'geoip': True, 'ipcidr': ['240.0.0.0/4', '0.0.0.0/32']}
            },
            'proxies': proxies,
            'proxy-groups': [
                {'name': 'PROXY', 'type': 'select', 'proxies': ['⚡ Auto-Select', 'DIRECT', *proxy_names]},
                {'name': '⚡ Auto-Select', 'type': 'url-test', 'proxies': proxy_names, 'url': 'http://www.gstatic.com/generate_204', 'interval': 300},
                {'name': '🇮🇷 Iran', 'type': 'select', 'proxies': ['DIRECT', 'PROXY']},
                {'name': '🛑 Block-Ads', 'type': 'select', 'proxies': ['REJECT', 'DIRECT']}
            ],
            'rule-providers': {
                'iran_domains': {'type': 'http', 'behavior': 'domain', 'url': "https://raw.githubusercontent.com/bootmortis/iran-clash-rules/main/iran-domains.txt", 'path': './rules/iran_domains.txt', 'interval': 86400},
                'blocked_domains': {'type': 'http', 'behavior': 'domain', 'url': "https://raw.githubusercontent.com/bootmortis/iran-clash-rules/main/blocked-domains.txt", 'path': './rules/blocked_domains.txt', 'interval': 86400},
                'ad_domains': {'type': 'http', 'behavior': 'domain', 'url': "https://raw.githubusercontent.com/bootmortis/iran-clash-rules/main/ad-domains.txt", 'path': './rules/ad_domains.txt', 'interval': 86400}
            },
            'rules': [
                'RULE-SET,ad_domains,🛑 Block-Ads',
                'RULE-SET,blocked_domains,PROXY',
                'RULE-SET,iran_domains,🇮🇷 Iran',
                'GEOIP,IR,🇮🇷 Iran',
                'MATCH,PROXY'
            ]
        }

    def build_lite_config(self, proxies, proxy_names):
        """ساخت کانفیگ ساده و سازگار برای کلاینت‌های قدیمی"""
        return {
            'port': 7890,
            'socks-port': 7891,
            'allow-lan': True,
            'mode': 'rule',
            'log-level': 'info',
            'external-controller': '127.0.0.1:9090',
            'dns': {
                'enable': True,
                'listen': '0.0.0.0:53',
                'nameserver': ['8.8.8.8', '1.1.1.1']
            },
            'proxies': proxies,
            'proxy-groups': [
                {'name': 'PROXY', 'type': 'select', 'proxies': ['⚡ Auto-Select', 'DIRECT', *proxy_names]},
                {'name': '⚡ Auto-Select', 'type': 'url-test', 'proxies': proxy_names, 'url': 'http://www.gstatic.com/generate_204', 'interval': 300}
            ],
            'rules': [
                'DOMAIN-SUFFIX,ir,DIRECT',
                'GEOIP,IR,DIRECT',
                'MATCH,PROXY'
            ]
        }


async def main():
    print("🚀 شروع برنامه استخراج کانفیگ...")
    extractor = V2RayExtractor()
    async with extractor.client:
        tasks = [extractor.find_raw_configs_from_chat(channel, CHANNEL_SEARCH_LIMIT) for channel in CHANNELS]
        tasks.extend(extractor.find_raw_configs_from_chat(group, GROUP_SEARCH_LIMIT) for group in GROUPS)
        if tasks:
            await asyncio.gather(*tasks)
        else:
            print("❌ هیچ کانال یا گروهی برای جستجو تعریف نشده است.")
    extractor.save_files()
    print("\n✨ تمام عملیات با موفقیت به پایان رسید!")

if __name__ == "__main__":
    if not all([API_ID, API_HASH, SESSION_STRING]):
        print("❌ خطا: یک یا چند مورد از سکرت‌های ضروری (API_ID, API_HASH, SESSION_STRING) تنظیم نشده است.")
    else:
        asyncio.run(main())
