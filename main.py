# -*- coding: utf-8 -*-

import re
import asyncio
import base64
import json
import yaml
import os
import uuid
from urllib.parse import urlparse, parse_qs, unquote
import ipaddress # کتابخانه جدید برای کار با آدرس‌های IP

# Pyrogram imports
from pyrogram import Client
from pyrogram.errors import FloodWait

# =================================================================================
# بخش تنظیمات و ثابت‌ها
# =================================================================================

# --- لیست محدوده‌های IP کلادفلر (IPv4) ---
# منبع: https://www.cloudflare.com/ips/
CLOUDFLARE_IPV4_RANGES = [
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
    '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
    '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '172.64.0.0/13', '131.0.72.0/22'
]

# --- خواندن سکرت‌ها از محیط ---
try:
    API_ID = int(os.environ.get("API_ID"))
except (ValueError, TypeError):
    print("❌ خطا: سکرت API_ID تعریف نشده یا مقدار آن عدد صحیح نیست.")
    exit(1)

API_HASH = os.environ.get("API_HASH")
SESSION_STRING = os.environ.get("SESSION_STRING")
CHANNELS_STR = os.environ.get('CHANNELS_LIST')
GROUPS_STR = os.environ.get('GROUPS_LIST')
CHANNEL_SEARCH_LIMIT = 5
GROUP_SEARCH_LIMIT = 600
OUTPUT_YAML = "Config-jo.yaml"
OUTPUT_TXT = "Config_jo.txt"
OUTPUT_ORIGINAL_TXT = "Original-Configs.txt" # <-- فایل جدید برای کانفیگ‌های اصلی

# =================================================================================
# توابع و کلاس‌های اصلی برنامه
# =================================================================================

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

# تغییر ترتیب regex patterns - vless باید قبل از ss باشد
V2RAY_PATTERNS = [
    re.compile(r'(vless:\/\/[^\s\'\"<>`]+)'),  # vless قبل از ss
    re.compile(r'(vmess:\/\/[^\s\'\"<>`]+)'),
    re.compile(r'(trojan:\/\/[^\s\'\"<>`]+)'),
    re.compile(r'(ss:\/\/[^\s\'\"<>`]+)'),     # ss بعد از vless
    re.compile(r"(hy2://[^\s'\"<>`]+)"),
    re.compile(r"(hysteria2://[^\s'\"<>`]+)"),
    re.compile(r"(tuic://[^\s'\"<>`]+)")
]
BASE64_PATTERN = re.compile(r"([A-Za-z0-9+/=]{50,})", re.MULTILINE)

# --- تابع جدید فقط برای تغییر نام کانفیگ خام ---
def rename_config_remark(config_url, new_name):
    """کانفیگ خام را می‌گیرد و نام (remark) آن را تغییر می‌دهد."""
    new_name_encoded = new_name.replace(" ", "%20")
    if config_url.startswith('vmess://'):
        try:
            b64_data = config_url.split("://")[1]
            decoded_str = base64.b64decode(b64_data + '=' * (-len(b64_data) % 4)).decode('utf-8')
            config_json = json.loads(decoded_str)
            config_json['ps'] = new_name
            new_b64_data = base64.b64encode(json.dumps(config_json, separators=(',', ':')).encode('utf-8')).decode('utf-8')
            return f"vmess://{new_b64_data}"
        except Exception:
            return f"{config_url.split('#')[0]}#{new_name_encoded}"
    else:
        base_url = config_url.split('#')[0]
        return f"{base_url}#{new_name_encoded}"


class V2RayExtractor:
    def __init__(self):
        self.raw_configs = set()
        self.client = Client("my_account", api_id=API_ID, api_hash=API_HASH, session_string=SESSION_STRING)
        # برای سرعت بیشتر، محدوده‌های IP را یک بار در ابتدا پردازش می‌کنیم
        self.cf_networks = [ipaddress.ip_network(r) for r in CLOUDFLARE_IPV4_RANGES]

    def _is_cloudflare_ip(self, ip_str):
        """بررسی می‌کند آیا یک IP در محدوده کلادفلر است یا خیر."""
        try:
            ip = ipaddress.ip_address(ip_str)
            # فقط IP های عمومی و از نوع IPv4 را بررسی می‌کنیم
            if not ip.is_global or ip.version != 4:
                return False
            for network in self.cf_networks:
                if ip in network:
                    return True
            return False
        except ValueError:
            # اگر ورودی یک دامنه باشد و نه IP، خطا می‌دهد که یعنی IP کلادفلر نیست
            return False

    def _is_unwanted_config(self, config_url):
        """
        تابع فیلتر جامع: کانفیگ‌های اسپیدتست و کلادفلر را شناسایی می‌کند.
        """
        try:
            hostname = ''
            if config_url.startswith('vmess://'):
                encoded_data = config_url.split("://")[1]
                decoded_str = base64.b64decode(encoded_data + '=' * (-len(encoded_data) % 4)).decode('utf-8')
                config = json.loads(decoded_str)
                hostname = config.get('add', '')
            elif config_url.startswith(('vless://', 'trojan://', 'ss://')):
                parsed = urlparse(config_url)
                hostname = parsed.hostname

            if not hostname:
                return False
            
            # شرط اول: بررسی اسپیدتست
            if 'speedtest.net' in hostname.lower():
                return True
            
            # شرط دوم: بررسی IP کلادفلر
            if self._is_cloudflare_ip(hostname):
                return True

            return False
        except Exception:
            return False

    @staticmethod
    def _generate_unique_name(original_name, prefix="config"):
        if not original_name: return f"{prefix}-{str(uuid.uuid4())[:8]}"
        cleaned_name = re.sub(r'[^\w\s\-\_\u0600-\u06FF]', '', original_name).replace(' ', '_').strip('_-')
        if not cleaned_name: return f"{prefix}-{str(uuid.uuid4())[:8]}"
        return f"{cleaned_name}-{str(uuid.uuid4())[:4]}"

    def parse_config_for_clash(self, config_url):
        try:
            if config_url.startswith('vmess://'): return self.parse_vmess(config_url)
            elif config_url.startswith('vless://'): return self.parse_vless(config_url)
            elif config_url.startswith('trojan://'): return self.parse_trojan(config_url)
            elif config_url.startswith('ss://'): return self.parse_shadowsocks(config_url)
            return None
        except Exception as e:
            print(f"❌ خطا در پارس کردن کانفیگ {config_url[:50]}...: {e}")
            return None

    def parse_vmess(self, vmess_url):
        try:
            encoded_data = vmess_url.split("://")[1]
            decoded_str = base64.b64decode(encoded_data + '=' * (-len(encoded_data) % 4)).decode('utf-8')
            config = json.loads(decoded_str)
            original_name = config.get('ps', '')
            ws_opts = None
            if config.get('net') == 'ws':
                host_header = config.get('host', '').strip() or config.get('add', '').strip()
                if host_header: ws_opts = {'path': config.get('path', '/'), 'headers': {'Host': host_header}}
            
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

    def parse_vless(self, vless_url):
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

    def parse_trojan(self, trojan_url):
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
    
    def parse_shadowsocks(self, ss_url):
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

    def extract_configs_from_text(self, text):
        """استخراج کانفیگ‌ها از متن با تصحیح نوع کانفیگ‌های اشتباه"""
        found_configs = set()
        
        # ابتدا تمام کانفیگ‌های ممکن را پیدا کنیم
        potential_configs = set()
        
        for pattern in V2RAY_PATTERNS:
            matches = pattern.findall(text)
            for match in matches:
                potential_configs.add(match.strip())
        
        # حالا هر کانفیگ را بررسی و در صورت لزوم تصحیح می‌کنیم
        for config_url in potential_configs:
            corrected_config = self._correct_config_type(config_url)
            if corrected_config and self._validate_config_type(corrected_config):
                found_configs.add(corrected_config)
                    
        return found_configs

    def _correct_config_type(self, config_url):
        """تصحیح نوع کانفیگ در صورت اشتباه بودن"""
        try:
            if config_url.startswith('ss://'):
                # بررسی اینکه آیا واقعاً shadowsocks است یا خیر
                parsed = urlparse(config_url)
                
                # اگر UUID pattern دارد، احتمالاً vless است
                uuid_pattern = r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'
                if parsed.username and re.match(uuid_pattern, parsed.username):
                    # تبدیل ss:// به vless://
                    corrected_url = config_url.replace('ss://', 'vless://', 1)
                    return corrected_url
                
                # اگر base64 decoded شده JSON باشد، vmess است
                if parsed.username:
                    try:
                        decoded = base64.b64decode(parsed.username + '=' * (-len(parsed.username) % 4)).decode('utf-8')
                        json_data = json.loads(decoded)
                        if 'v' in json_data and json_data.get('v') == '2':
                            # این یک vmess config است
                            corrected_url = config_url.replace('ss://', 'vmess://', 1)
                            return corrected_url
                    except:
                        pass
                
                # اگر هیچ کدام از شرایط بالا برقرار نبود، shadowsocks واقعی است
                return config_url
            
            return config_url
        except:
            return config_url

    def _validate_config_type(self, config_url):
        """اعتبارسنجی نوع کانفیگ برای اطمینان از تشخیص صحیح"""
        try:
            if config_url.startswith('vless://'):
                # بررسی ساختار vless
                parsed = urlparse(config_url)
                return bool(parsed.hostname and parsed.username)
            elif config_url.startswith('vmess://'):
                # بررسی ساختار vmess
                encoded_data = config_url.split("://")[1]
                decoded_str = base64.b64decode(encoded_data + '=' * (-len(encoded_data) % 4)).decode('utf-8')
                config = json.loads(decoded_str)
                return bool(config.get('add') and config.get('id'))
            elif config_url.startswith('trojan://'):
                # بررسی ساختار trojan
                parsed = urlparse(config_url)
                return bool(parsed.hostname and parsed.username)
            elif config_url.startswith('ss://'):
                # بررسی دقیق‌تر برای shadowsocks
                return self._is_valid_shadowsocks(config_url)
            return True
        except:
            return False

    def _is_valid_shadowsocks(self, ss_url):
        """بررسی می‌کند که آیا URL واقعاً shadowsocks است یا خیر"""
        try:
            parsed = urlparse(ss_url)
            
            # اگر UUID pattern دارد، احتمالاً vless یا vmess است
            uuid_pattern = r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'
            if re.search(uuid_pattern, parsed.username if parsed.username else ''):
                return False
            
            # اگر base64 decoded شده JSON باشد، vmess است
            if parsed.username:
                try:
                    decoded = base64.b64decode(parsed.username + '=' * (-len(parsed.username) % 4)).decode('utf-8')
                    json.loads(decoded)  # اگر JSON باشد، vmess است
                    return False
                except:
                    pass
            
            # بررسی کلی ساختار shadowsocks
            if not parsed.hostname:
                return False
                
            # shadowsocks معمولاً cipher:password format دارد
            if parsed.username and ':' not in parsed.username:
                # اگر username وجود دارد ولی cipher:password format ندارد، مشکوک است
                # مگر اینکه base64 encoded باشد
                try:
                    decoded_user = base64.b64decode(parsed.username + '=' * (-len(parsed.username) % 4)).decode('utf-8')
                    if ':' not in decoded_user:
                        return False
                except:
                    return False
            
            return True
        except:
            return False

    async def find_raw_configs_from_chat(self, chat_id, limit):
        try:
            print(f"🔍 جستجو در چت {chat_id} (محدودیت: {limit} پیام)...")
            async for message in self.client.get_chat_history(chat_id, limit=limit):
                if not message.text: continue
                
                texts_to_scan = [message.text]
                
                # بررسی base64 های احتمالی
                potential_b64 = BASE64_PATTERN.findall(message.text)
                for b64_str in potential_b64:
                    try:
                        decoded_text = base64.b64decode(b64_str + '=' * (-len(b64_str) % 4)).decode('utf-8', errors='ignore')
                        texts_to_scan.append(decoded_text)
                    except Exception: 
                        continue
                
                # استخراج کانفیگ از هر متن
                for text in texts_to_scan:
                    found_configs = self.extract_configs_from_text(text)
                    self.raw_configs.update(found_configs)
                    
        except FloodWait as e:
            print(f"⏳ به دلیل محدودیت تلگرام، برای چت {chat_id} به مدت {e.value} ثانیه صبر می‌کنیم.")
            await asyncio.sleep(e.value)
            await self.find_raw_configs_from_chat(chat_id, limit)
        except Exception as e: 
            print(f"❌ خطا در زمان اسکن چت {chat_id}: {e}")

    def save_files(self):
        print("\n" + "="*40)
        
        print(f"⚙️ فیلتر کردن کانفیگ‌های ناخواسته (Speedtest و Cloudflare) از مجموع {len(self.raw_configs)} کانفیگ...")
        filtered_configs = {config for config in self.raw_configs if not self._is_unwanted_config(config)}
        
        removed_count = len(self.raw_configs) - len(filtered_configs)
        if removed_count > 0:
            print(f"👍 {removed_count} کانفیگ ناخواسته حذف شد.")
        
        # نمایش آمار به تفکیک نوع کانفیگ
        config_types = {'vless': 0, 'vmess': 0, 'trojan': 0, 'ss': 0, 'other': 0}
        for config in filtered_configs:
            if config.startswith('vless://'):
                config_types['vless'] += 1
            elif config.startswith('vmess://'):
                config_types['vmess'] += 1
            elif config.startswith('trojan://'):
                config_types['trojan'] += 1
            elif config.startswith('ss://'):
                config_types['ss'] += 1
            else:
                config_types['other'] += 1
        
        print(f"📊 آمار کانفیگ‌های یافت شده:")
        for config_type, count in config_types.items():
            if count > 0:
                print(f"   - {config_type.upper()}: {count}")

        # --- شروع تغییرات ---

        # 1. ذخیره فایل با نام اصلی
        print(f"\n📝 ذخیره {len(filtered_configs)} کانفیگ با نام اصلی در فایل {OUTPUT_ORIGINAL_TXT}...")
        if filtered_configs:
            with open(OUTPUT_ORIGINAL_TXT, 'w', encoding='utf-8') as f:
                f.write("\n".join(sorted(list(filtered_configs))))
            print(f"✅ فایل {OUTPUT_ORIGINAL_TXT} با موفقیت ذخیره شد.")

        # 2. ایجاد لیست جدید با نام‌های تغییر یافته
        print("✏️ تغییر نام کانفیگ‌ها برای فایل‌های خروجی...")
        sorted_configs = sorted(list(filtered_configs))
        renamed_configs = [rename_config_remark(conf, f"R3za-@v2rayww3-{i:03}") for i, conf in enumerate(sorted_configs, 1)]

        # 3. ذخیره فایل متنی با نام‌های جدید
        print(f"📝 ذخیره {len(renamed_configs)} کانفیگ نهایی در فایل {OUTPUT_TXT}...")
        if renamed_configs:
            with open(OUTPUT_TXT, 'w', encoding='utf-8') as f:
                f.write("\n".join(renamed_configs))
            print("✅ فایل متنی با موفقیت ذخیره شد.")
        else:
            print("⚠️ هیچ کانفیگ خامی برای ذخیره باقی نماند.")

        print(f"\n⚙️ پردازش کانفیگ‌ها برای فایل کلش ({OUTPUT_YAML})...")
        clash_proxies = []
        parse_errors = 0
        
        # 4. استفاده از لیست تغییر نام یافته برای ساخت فایل کلش
        for url in renamed_configs:
            proxy = self.parse_config_for_clash(url)
            if proxy is not None:
                clash_proxies.append(proxy)
            else:
                parse_errors += 1
        
        # --- پایان تغییرات ---

        if parse_errors > 0:
            print(f"⚠️ {parse_errors} کانفیگ به دلیل خطا در پارسینگ نادیده گرفته شد.")

        if not clash_proxies:
            print(f"⚠️ هیچ کانفیگ معتبری برای Clash پیدا نشد. فایل {OUTPUT_YAML} خالی خواهد بود.")
            open(OUTPUT_YAML, "w").close()
            return
            
        print(f"👍 {len(clash_proxies)} کانفیگ معتبر برای Clash پیدا شد.")
        proxy_names = [p['name'] for p in clash_proxies]
        
        clash_config_base = {
            'port': 7890, 
            'socks-port': 7891, 
            'allow-lan': True, 
            'mode': 'rule',
            'log-level': 'info', 
            'external-controller': '127.0.0.1:9090',
            'dns': {
                'enable': True, 
                'listen': '0.0.0.0:53', 
                'default-nameserver': ['8.8.8.8', '1.1.1.1'], 
                'enhanced-mode': 'fake-ip', 
                'fake-ip-range': '198.18.0.1/16', 
                'fallback': ['https://cloudflare-dns.com/dns-query', 'https://dns.google/dns-query'], 
                'fallback-filter': {
                    'geoip': True, 
                    'ipcidr': ['240.0.0.0/4']
                }
            },
            'proxies': clash_proxies,
            'proxy-groups': [
                {
                    'name': 'PROXY', 
                    'type': 'select', 
                    'proxies': ['AUTO', 'DIRECT', *proxy_names]
                }, 
                {
                    'name': 'AUTO', 
                    'type': 'url-test', 
                    'proxies': proxy_names, 
                    'url': 'http://www.gstatic.com/generate_204', 
                    'interval': 300
                }
            ],
            'rules': [
                'DOMAIN-SUFFIX,local,DIRECT', 
                'IP-CIDR,127.0.0.0/8,DIRECT', 
                'IP-CIDR,192.168.0.0/16,DIRECT', 
                'IP-CIDR,172.16.0.0/12,DIRECT', 
                'IP-CIDR,10.0.0.0/8,DIRECT', 
                'GEOIP,IR,DIRECT', 
                'MATCH,PROXY'
            ]
        }
        
        with open(OUTPUT_YAML, 'w', encoding='utf-8') as f:
            yaml.dump(clash_config_base, f, allow_unicode=True, sort_keys=False, indent=2, width=1000)
        print(f"✅ فایل {OUTPUT_YAML} با موفقیت ذخیره شد.")

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
