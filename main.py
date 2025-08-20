import re
import asyncio
import base64
import json
import yaml
import os
import uuid
from urllib.parse import urlparse, parse_qs, unquote
import ipaddress
from pyrogram import Client
from pyrogram.errors import FloodWait
from typing import Optional, Dict, Any, Set, List

# =================================================================================
# بخش تنظیمات و ثابت‌ها
# =================================================================================
CLOUDFLARE_IPV4_RANGES = [
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
    '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
    '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '172.64.0.0/13', '131.0.72.0/22'
]

API_ID = int(os.environ.get("API_ID"))
API_HASH = os.environ.get("API_HASH")
SESSION_STRING = os.environ.get("SESSION_STRING")
CHANNELS_STR = os.environ.get('CHANNELS_LIST')
GROUPS_STR = os.environ.get('GROUPS_LIST')
CHANNEL_SEARCH_LIMIT = int(os.environ.get('CHANNEL_SEARCH_LIMIT', 200)) # مقدار پیش‌فرض افزایش یافت
GROUP_SEARCH_LIMIT = int(os.environ.get('GROUP_SEARCH_LIMIT', 600))
OUTPUT_YAML = "Config-jo.yaml"
OUTPUT_TXT = "Config_jo.txt"

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
        self.cf_networks = [ipaddress.ip_network(r) for r in CLOUDFLARE_IPV4_RANGES]

    def _is_cloudflare_ip(self, ip_str: str) -> bool:
        """بررسی می‌کند آیا یک IP در محدوده کلادفلر است یا خیر."""
        try:
            ip = ipaddress.ip_address(ip_str)
            if not ip.is_global or ip.version != 4:
                return False
            for network in self.cf_networks:
                if ip in network:
                    return True
            return False
        except ValueError:
            return False

    @staticmethod
    def _generate_unique_name(original_name: str, prefix: str = "config") -> str:
        if not original_name:
            return f"{prefix}-{str(uuid.uuid4())[:8]}"
        cleaned_name = re.sub(r'[^\w\s\-\_\u0600-\u06FF]', '', original_name).replace(' ', '_').strip('_-')
        if not cleaned_name:
            return f"{prefix}-{str(uuid.uuid4())[:8]}"
        return f"{cleaned_name}-{str(uuid.uuid4())[:4]}"

    def _is_valid_shadowsocks(self, ss_url: str) -> bool:
        """بررسی می‌کند که آیا URL واقعاً shadowsocks است یا خیر."""
        try:
            parsed = urlparse(ss_url)
            if not parsed.hostname or not parsed.username:
                return False

            uuid_pattern = r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'
            if re.search(uuid_pattern, parsed.username):
                return False

            try:
                decoded_user = base64.b64decode(parsed.username + '=' * (-len(parsed.username) % 4)).decode('utf-8')
                if ':' not in decoded_user:
                    return False
            except:
                if ':' not in parsed.username:
                    return False

            return True
        except:
            return False

    def _correct_config_type(self, config_url: str) -> str:
        """تصحیح نوع کانفیگ در صورت اشتباه بودن."""
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
                    except:
                        pass

            return config_url
        except:
            return config_url

    def _validate_config_type(self, config_url: str) -> bool:
        """اعتبارسنجی نوع کانفیگ برای اطمینان از تشخیص صحیح."""
        try:
            if config_url.startswith('vless://'):
                parsed = urlparse(config_url)
                return bool(parsed.hostname and parsed.username)

            elif config_url.startswith('vmess://'):
                encoded_data = config_url.split("://")[1]
                decoded_str = base64.b64decode(encoded_data + '=' * (-len(encoded_data) % 4)).decode('utf-8')
                config = json.loads(decoded_str)
                return bool(config.get('add') and config.get('id'))

            elif config_url.startswith('trojan://'):
                parsed = urlparse(config_url)
                return bool(parsed.hostname and parsed.username)

            elif config_url.startswith('ss://'):
                return self._is_valid_shadowsocks(config_url)

            return True
        except:
            return False

    def parse_config_for_clash(self, config_url: str) -> Optional[Dict[str, Any]]:
        try:
            if config_url.startswith('vmess://'):
                return self.parse_vmess(config_url)
            elif config_url.startswith('vless://'):
                return self.parse_vless(config_url)
            elif config_url.startswith('trojan://'):
                return self.parse_trojan(config_url)
            elif config_url.startswith('ss://'):
                return self.parse_shadowsocks(config_url)
            elif config_url.startswith(('hysteria2://', 'hy2://')):
                return self.parse_hysteria2(config_url)
            elif config_url.startswith('tuic://'):
                return self.parse_tuic(config_url)
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
                if host_header:
                    ws_opts = {'path': config.get('path', '/'), 'headers': {'Host': host_header}}

            return {
                'name': self._generate_unique_name(original_name, "vmess"),
                'type': 'vmess',
                'server': config.get('add'),
                'port': int(config.get('port', 443)),
                'uuid': config.get('id'),
                'alterId': int(config.get('aid', 0)),
                'cipher': config.get('scy', 'auto'),
                'tls': config.get('tls') == 'tls',
                'network': config.get('net', 'tcp'),
                'udp': True,
                'ws-opts': ws_opts
            }
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
                if host_header:
                    ws_opts = {'path': query.get('path', ['/'])[0], 'headers': {'Host': host_header}}

            if query.get('security', [''])[0] == 'reality':
                pbk = query.get('pbk', [None])[0]
                if pbk:
                    reality_opts = {'public-key': pbk, 'short-id': query.get('sid', [''])[0]}

            return {
                'name': self._generate_unique_name(original_name, "vless"),
                'type': 'vless',
                'server': parsed.hostname,
                'port': parsed.port or 443,
                'uuid': parsed.username,
                'udp': True,
                'tls': query.get('security', [''])[0] in ['tls', 'reality'],
                'network': query.get('type', ['tcp'])[0],
                'servername': query.get('sni', [None])[0],
                'ws-opts': ws_opts,
                'reality-opts': reality_opts
            }
        except Exception as e:
            print(f"❌ خطا در پارس vless: {e}")
            return None

    def parse_trojan(self, trojan_url: str) -> Optional[Dict[str, Any]]:
        try:
            parsed = urlparse(trojan_url)
            query = parse_qs(parsed.query)
            original_name = unquote(parsed.fragment) if parsed.fragment else ''
            sni = query.get('peer', [None])[0] or query.get('sni', [None])[0] or parsed.hostname

            return {
                'name': self._generate_unique_name(original_name, "trojan"),
                'type': 'trojan',
                'server': parsed.hostname,
                'port': parsed.port or 443,
                'password': parsed.username,
                'udp': True,
                'sni': sni
            }
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
                try:
                    user_info = base64.b64decode(user_info_part + '=' * (4 - len(user_info_part) % 4)).decode('utf-8')
                except:
                    user_info = unquote(user_info_part)

            cipher, password = user_info.split(':', 1) if ':' in user_info else (None, None)

            if cipher and password:
                return {
                    'name': self._generate_unique_name(original_name, 'ss'),
                    'type': 'ss',
                    'server': parsed.hostname,
                    'port': parsed.port,
                    'cipher': cipher,
                    'password': password,
                    'udp': True
                }
            return None
        except Exception as e:
            print(f"❌ خطا در پارس shadowsocks: {e}")
            return None

    def parse_hysteria2(self, hy2_url: str) -> Optional[Dict[str, Any]]:
        try:
            parsed = urlparse(hy2_url)
            query = parse_qs(parsed.query)
            original_name = unquote(parsed.fragment) if parsed.fragment else ''

            return {
                'name': self._generate_unique_name(original_name, "hysteria2"),
                'type': 'hysteria2',
                'server': parsed.hostname,
                'port': parsed.port or 443,
                'auth': parsed.username,
                'up': query.get('up', ['100 Mbps'])[0],
                'down': query.get('down', ['100 Mbps'])[0],
                'obfs': query.get('obfs', [''])[0] or None,
                'sni': query.get('sni', [parsed.hostname])[0],
                'skip-cert-verify': query.get('insecure', ['false'])[0].lower() == 'true',
            }
        except Exception as e:
            print(f"❌ خطا در پارس hysteria2: {e}")
            return None

    def parse_tuic(self, tuic_url: str) -> Optional[Dict[str, Any]]:
        try:
            parsed = urlparse(tuic_url)
            query = parse_qs(parsed.query)
            original_name = unquote(parsed.fragment) if parsed.fragment else ''

            return {
                'name': self._generate_unique_name(original_name, "tuic"),
                'type': 'tuic',
                'server': parsed.hostname,
                'port': parsed.port or 443,
                'uuid': parsed.username,
                'password': query.get('password', [''])[0],
                'udp': True,
                'sni': query.get('sni', [parsed.hostname])[0],
                'skip-cert-verify': query.get('allow_insecure', ['false'])[0].lower() == 'true',
            }
        except Exception as e:
            print(f"❌ خطا در پارس tuic: {e}")
            return None

    def extract_configs_from_text(self, text: str) -> Set[str]:
        """استخراج کانفیگ‌ها از متن با تصحیح نوع کانفیگ‌های اشتباه"""
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
                if not text_to_check:
                    continue

                texts_to_scan = [text_to_check]
                potential_b64 = BASE64_PATTERN.findall(text_to_check)
                for b64_str in potential_b64:
                    try:
                        decoded_text = base64.b64decode(b64_str + '=' * (-len(b64_str) % 4)).decode('utf-8', errors='ignore')
                        texts_to_scan.append(decoded_text)
                    except Exception:
                        continue

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

        # مرحله ۱: جدا کردن کانفیگ‌های کلودفلر از غیر کلودفلر
        # =======================================================
        print(f"⚙️ پردازش و جداسازی {len(self.raw_configs)} کانفیگ یافت شده...")
        direct_proxies = []
        cf_proxies = []
        parse_errors = 0

        # به جای حذف کامل، کانفیگ‌ها را دسته‌بندی می‌کنیم
        # ابتدا کانفیگ‌های اسپیدتست را حذف می‌کنیم ولی کلودفلر را نگه می‌داریم
        configs_to_process = set()
        for url in self.raw_configs:
            try:
                hostname = urlparse(url).hostname
                if hostname and 'speedtest.net' in hostname.lower():
                    continue
                if url.startswith('vmess://'):
                    encoded_data = url.split("://")[1]
                    decoded_str = base64.b64decode(encoded_data + '=' * (-len(encoded_data) % 4)).decode('utf-8', errors='ignore')
                    config = json.loads(decoded_str)
                    if 'speedtest.net' in config.get('add', '').lower():
                        continue
                configs_to_process.add(url)
            except:
                configs_to_process.add(url)

        for url in configs_to_process:
            proxy = self.parse_config_for_clash(url)
            if proxy is None:
                parse_errors += 1
                continue

            server_address = proxy.get('server', '')
            if self._is_cloudflare_ip(server_address):
                cf_proxies.append(proxy)
            else:
                direct_proxies.append(proxy)

        if parse_errors > 0:
            print(f"⚠️ {parse_errors} کانفیگ به دلیل خطا در پارسینگ نادیده گرفته شد.")

        print(f"👍 {len(direct_proxies)} کانفیگ مستقیم و {len(cf_proxies)} کانفیگ کلودفلر یافت شد.")

        # اگر هیچ کانفیگی پیدا نشد، فایل‌ها را خالی می‌سازیم
        if not direct_proxies and not cf_proxies:
            print(f"⚠️ هیچ کانفیگ معتبری برای ساخت فایل‌ها پیدا نشد.")
            open(OUTPUT_YAML, "w").close()
            open(OUTPUT_TXT, "w").close()
            return

        # مرحله ۲: ساخت ساختار YAML با گروه‌ها و قوانین هوشمند
        # =========================================================
        all_proxies = direct_proxies + cf_proxies
        direct_proxy_names = [p['name'] for p in direct_proxies]
        cf_proxy_names = [p['name'] for p in cf_proxies]
        all_proxy_names = direct_proxy_names + cf_proxy_names

        clash_port = int(os.environ.get('CLASH_PORT', 7890))
        clash_socks_port = int(os.environ.get('CLASH_SOCKS_PORT', 7891))
        allow_lan = os.environ.get('CLASH_ALLOW_LAN', 'True').lower() == 'true'
        log_level = os.environ.get('CLASH_LOG_LEVEL', 'info')
        dns_server = os.environ.get('CLASH_DNS_SERVER', '8.8.8.8,1.1.1.1').split(',')
        fallback_dns = os.environ.get('CLASH_FALLBACK_DNS', 'https://cloudflare-dns.com/dns-query,https://dns.google/dns-query').split(',')

        clash_config_base = {
            'port': clash_port,
            'socks-port': clash_socks_port,
            'allow-lan': allow_lan,
            'mode': 'rule',
            'log-level': log_level,
            'external-controller': '127.0.0.1:9090',
            'dns': { 'enable': True, 'listen': '0.0.0.0:53', 'default-nameserver': dns_server, 'enhanced-mode': 'fake-ip', 'fake-ip-range': '198.18.0.1/16', 'fallback': fallback_dns, 'fallback-filter': {'geoip': True, 'ipcidr': ['240.0.0.0/4']}},
            'proxies': all_proxies,
            'proxy-groups': [
                {
                    'name': 'PROXY',
                    'type': 'select',
                    'proxies': ['✅ CF-Access (Auto)', '♻️ All-Auto', 'DIRECT', *all_proxy_names]
                },
                {
                    'name': '✅ CF-Access (Auto)',
                    'type': 'url-test',
                    'proxies': direct_proxy_names if direct_proxy_names else ['DIRECT'],
                    'url': 'http://www.gstatic.com/generate_204',
                    'interval': 300
                },
                {
                    'name': '♻️ All-Auto',
                    'type': 'url-test',
                    'proxies': all_proxy_names,
                    'url': 'http://www.gstatic.com/generate_204',
                    'interval': 300
                }
            ],
            'rules': [
                # قانون هوشمند: اگر مقصد یکی از IPهای کلودفلر بود، از گروه CF-Access استفاده کن
                'IP-CIDR,173.245.48.0/20,✅ CF-Access (Auto)',
                'IP-CIDR,103.21.244.0/22,✅ CF-Access (Auto)',
                'IP-CIDR,103.22.200.0/22,✅ CF-Access (Auto)',
                'IP-CIDR,103.31.4.0/22,✅ CF-Access (Auto)',
                'IP-CIDR,141.101.64.0/18,✅ CF-Access (Auto)',
                'IP-CIDR,108.162.192.0/18,✅ CF-Access (Auto)',
                'IP-CIDR,190.93.240.0/20,✅ CF-Access (Auto)',
                'IP-CIDR,188.114.96.0/20,✅ CF-Access (Auto)',
                'IP-CIDR,197.234.240.0/22,✅ CF-Access (Auto)',
                'IP-CIDR,198.41.128.0/17,✅ CF-Access (Auto)',
                'IP-CIDR,162.158.0.0/15,✅ CF-Access (Auto)',
                'IP-CIDR,104.16.0.0/13,✅ CF-Access (Auto)',
                'IP-CIDR,172.64.0.0/13,✅ CF-Access (Auto)',
                'IP-CIDR,131.0.72.0/22,✅ CF-Access (Auto)',
                # قوانین دیگر
                'GEOIP,IR,DIRECT',
                'MATCH,PROXY'
            ]
        }
        
        # اگر هیچ پروکسی مستقیمی پیدا نشد، به کاربر اطلاع بده
        if not direct_proxy_names:
            print("⚠️ هشدار: هیچ کانفیگ با IP مستقیم یافت نشد. گروه CF-Access فقط شامل DIRECT خواهد بود.")

        with open(OUTPUT_YAML, 'w', encoding='utf-8') as f:
            yaml.dump(clash_config_base, f, allow_unicode=True, sort_keys=False, indent=2, width=1000)

        print(f"✅ فایل هوشمند {OUTPUT_YAML} با موفقیت ذخیره شد.")

        # فایل متنی را با کانفیگ‌های پردازش شده ذخیره می‌کنیم
        with open(OUTPUT_TXT, 'w', encoding='utf-8') as f:
            f.write("\n".join(sorted(list(configs_to_process))))
        print(f"✅ فایل متنی {OUTPUT_TXT} با موفقیت ذخیره شد.")

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
