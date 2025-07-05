import re
import asyncio
import base64
import json
import yaml
import os
import uuid
from urllib.parse import urlparse, parse_qs

# Pyrogram imports
from pyrogram import Client
from pyrogram.errors import FloodWait, RPCError

# --- تنظیمات عمومی ---

# اطلاعات API تلگرام (از GitHub Secrets خوانده می‌شود)
API_ID = int(os.environ.get("API_ID"))
API_HASH = os.environ.get("API_HASH")

# نام فایل سشن برای Pyrogram (باید با نامی که در GitHub Secret ذخیره کرده‌اید مطابقت داشته باشد)
# این نام باید دقیقاً با نام فایل سشن محلی شما (مثلاً v2rayTrack.session) مطابقت داشته باشد، اما بدون پسوند .session
SESSION_NAME = "my_account"

# کانال‌هایی که باید اسکن شوند
CHANNELS = [
    "@SRCVPN",
    "@sezar_sec",
    "@Anty_Filter",
    "@proxy_kafee",
    "@vpns"
]

# خروجی‌ها
OUTPUT_YAML = "Config-jo.yaml"  # خروجی به فرمت YAML برای Clash
OUTPUT_TXT = "Config_jo.txt"    # خروجی به فرمت متنی ساده

# الگوهای شناسایی کانفیگ‌ها (این‌ها کانفیگ‌های URL را شناسایی می‌کنند)
V2RAY_PATTERNS = [
    re.compile(r"(vless://[^\s]+)"),
    re.compile(r"(vmess://[^\s]+)"),
    re.compile(r"(trojan://[^\s]+)"),
    re.compile(r"(ss://[^\s]+)"),
    re.compile(r"(hy2://[^\s]+)"),
    re.compile(r"(hysteria://[^\s]+)"),
    re.compile(r"(tuic://[^\s]+)")
]

# تنظیمات پروکسی (اختیاری) - برای GitHub Actions معمولاً غیرفعال است
# اگر به پروکسی نیاز دارید (مثلاً برای دور زدن فیلترینگ تلگرام در خود GitHub Actions)،
# باید یک پروکسی واقعی و قابل دسترس از خارج داشته باشید و تنظیمات آن را اینجا قرار دهید.
# در غیر این صورت، این را None بگذارید یا کامنت کنید.
GLOBAL_PROXY_SETTINGS = None

# --- کلاس V2RayExtractor برای تعامل با تلگرام و ذخیره‌سازی ---
class V2RayExtractor:
    def __init__(self):
        self.found_configs = set() # مجموعه ای از کانفیگ‌های URL پیدا شده (رشته‌های خام)
        self.parsed_clash_configs = [] # لیست کانفیگ‌ها بعد از تجزیه برای فرمت Clash (دیکشنری‌ها)

        # مقداردهی Client برای User Client
        self.client = Client(
            SESSION_NAME,
            api_id=API_ID,
            api_hash=API_HASH,
            # bot_token=BOT_TOKEN, # این خط باید حذف یا کامنت شود زیرا ما از User Client استفاده می‌کنیم
            **({"proxy": GLOBAL_PROXY_SETTINGS} if GLOBAL_PROXY_SETTINGS else {})
        )

    # توابع تجزیه کانفیگ‌ها را اینجا نگه می‌داریم زیرا برای تبدیل به فرمت Clash نیاز هستند
    def parse_config(self, config_url):
        """تجزیه و تحلیل کانفیگ برای استخراج اطلاعات اتصال برای Clash"""
        try:
            if config_url.startswith('vmess://'):
                return self.parse_vmess(config_url)
            elif config_url.startswith('vless://'):
                return self.parse_vless(config_url)
            elif config_url.startswith('trojan://'):
                return self.parse_trojan(config_url)
            elif config_url.startswith('ss://'):
                return self.parse_shadowsocks(config_url)
            elif config_url.startswith('hy2://') or config_url.startswith('hysteria://'):
                return self.parse_hysteria(config_url)
            elif config_url.startswith('tuic://'):
                return self.parse_tuic(config_url)
            else:
                return None
        except Exception as e:
            # print(f"❌ خطا در تجزیه کانفیگ ({config_url[:50]}...): {str(e)}") # برای کاهش لاگ‌ها
            return None

    def parse_vmess(self, vmess_url):
        try:
            encoded_data = vmess_url.replace('vmess://', '')
            padding = len(encoded_data) % 4
            if padding:
                encoded_data += '=' * (4 - padding)

            decoded_data = base64.b64decode(encoded_data).decode('utf-8')
            config = json.loads(decoded_data)

            clash_config = {
                'name': config.get('ps', f"vmess-{str(uuid.uuid4())[:8]}"),
                'type': 'vmess',
                'server': config.get('add'),
                'port': int(config.get('port', 443)),
                'uuid': config.get('id'),
                'alterId': int(config.get('aid', 0)),
                'cipher': config.get('scy', 'auto'),
                'tls': config.get('tls') == 'tls',
                'skip-cert-verify': False,
                'network': config.get('net', 'tcp'),
                'udp': True
            }

            if clash_config['network'] == 'ws':
                clash_config['ws-opts'] = {
                    'path': config.get('path', '/'),
                    'headers': {'Host': config.get('host', '')} if config.get('host') else {}
                }
            if clash_config['network'] == 'h2':
                clash_config['h2-opts'] = {
                    'path': config.get('path', '/'),
                    'host': [config.get('host', '')] if config.get('host') else []
                }
            if clash_config['network'] == 'grpc':
                clash_config['grpc-opts'] = {
                    'grpc-service-name': config.get('path', '')
                }
            return clash_config
        except Exception as e:
            # print(f"❌ خطا در تجزیه VMess ({vmess_url[:50]}...): {str(e)}")
            return None

    def parse_vless(self, vless_url):
        try:
            parsed = urlparse(vless_url)
            query = parse_qs(parsed.query)

            clash_config = {
                'name': parse_qs(parsed.fragment).get('', [f"vless-{str(uuid.uuid4())[:8]}"])[0],
                'type': 'vless',
                'server': parsed.hostname,
                'port': parsed.port or 443,
                'uuid': parsed.username,
                'tls': query.get('security', [''])[0] == 'tls',
                'skip-cert-verify': False,
                'udp': True,
                'network': query.get('type', ['tcp'])[0],
                'servername': query.get('sni', [''])[0]
            }

            if 'flow' in query:
                clash_config['flow'] = query['flow'][0]
            if clash_config['network'] == 'ws':
                clash_config['ws-opts'] = {
                    'path': query.get('path', ['/'])[0],
                    'headers': {'Host': query.get('host', [''])[0]} if query.get('host') else {}
                }
            if clash_config['network'] == 'h2':
                clash_config['h2-opts'] = {
                    'path': query.get('path', ['/'])[0],
                    'host': [query.get('host', [''])[0]] if query.get('host') else []
                }
            if clash_config['network'] == 'grpc':
                clash_config['grpc-opts'] = {
                    'grpc-service-name': query.get('serviceName', [''])[0]
                }
            return clash_config
        except Exception as e:
            # print(f"❌ خطا در تجزیه VLESS ({vless_url[:50]}...): {str(e)}")
            return None

    def parse_trojan(self, trojan_url):
        try:
            parsed = urlparse(trojan_url)
            query = parse_qs(parsed.query)

            return {
                'name': parsed.fragment or f"trojan-{str(uuid.uuid4())[:8]}",
                'type': 'trojan',
                'server': parsed.hostname,
                'port': parsed.port or 443,
                'password': parsed.username,
                'sni': query.get('sni', [''])[0],
                'skip-cert-verify': False,
                'udp': True,
                'network': query.get('type', ['tcp'])[0],
                'alpn': query.get('alpn', [''])[0].split(',') if query.get('alpn') else None
            }
        except Exception as e:
            # print(f"❌ خطا در تجزیه Trojan ({trojan_url[:50]}...): {str(e)}")
            return None

    def parse_shadowsocks(self, ss_url):
        try:
            if '@' in ss_url:
                method_password, server_info = ss_url.replace('ss://', '').split('@')
                padding = len(method_password) % 4
                if padding:
                    method_password += '=' * (4 - padding)

                method_password = base64.b64decode(method_password).decode('utf-8')
                method, password = method_password.split(':', 1)
                host, port = server_info.split(':')

                return {
                    'name': f"ss-{str(uuid.uuid4())[:8]}",
                    'type': 'ss',
                    'server': host,
                    'port': int(port),
                    'password': password,
                    'cipher': method,
                    'udp': True
                }
        except Exception as e:
            # print(f"❌ خطا در تجزیه Shadowsocks ({ss_url[:50]}...): {str(e)}")
            return None

    def parse_hysteria(self, hysteria_url):
        try:
            parsed = urlparse(hysteria_url)
            query = parse_qs(parsed.query)

            return {
                'name': parsed.fragment or f"hysteria-{str(uuid.uuid4())[:8]}",
                'type': 'hysteria',
                'server': parsed.hostname,
                'port': parsed.port or 443,
                'auth_str': parsed.username,
                'obfs': query.get('obfsParam', [''])[0],
                'protocol': query.get('protocol', ['udp'])[0],
                'up_mbps': int(query.get('upmbps', ['10'])[0]),
                'down_mbps': int(query.get('downmbps', ['50'])[0]),
                'sni': query.get('peer', [''])[0],
                'skip-cert-verify': False,
                'alpn': query.get('alpn', [''])[0].split(',') if query.get('alpn') else None
            }
        except Exception as e:
            # print(f"❌ خطا در تجزیه Hysteria ({hysteria_url[:50]}...): {str(e)}")
            return None

    def parse_tuic(self, tuic_url):
        try:
            parsed = urlparse(tuic_url)
            query = parse_qs(parsed.query)

            return {
                'name': parsed.fragment or f"tuic-{str(uuid.uuid4())[:8]}",
                'type': 'tuic',
                'server': parsed.hostname,
                'port': parsed.port or 443,
                'uuid': parsed.username,
                'password': query.get('password', [''])[0],
                'sni': query.get('sni', [''])[0],
                'udp-relay-mode': query.get('udp-relay-mode', ['native'])[0],
                'skip-cert-verify': False,
                'alpn': query.get('alpn', [''])[0].split(',') if query.get('alpn') else None
            }
        except Exception as e:
            # print(f"❌ خطا در تجزیه TUIC ({tuic_url[:50]}...): {str(e)}")
            return None

    async def check_channel(self, channel):
        """بررسی یک کانال تلگرام برای استخراج کانفیگ"""
        try:
            print(f"🔍 در حال بررسی کانال {channel}...")
            # از get_chat_history برای گرفتن پیام‌ها استفاده می‌کنیم.
            # چون این یک User Client است، باید به تاریخچه دسترسی داشته باشد.
            # limit=100 به معنای بررسی 100 پیام آخر است. می‌توانید آن را افزایش دهید.
            async for message in self.client.get_chat_history(channel, limit=15):
                if not message.text:
                    continue

                for pattern in V2RAY_PATTERNS:
                    matches = pattern.findall(message.text)
                    for config_url in matches: # نام متغیر به config_url تغییر یافت
                        if config_url not in self.found_configs:
                            self.found_configs.add(config_url)
                            print(f"✅ کانفیگ جدید یافت شد از {channel}: {config_url[:60]}...")
                            # بلافاصله پس از یافتن، آن را تجزیه و به لیست Clash اضافه می‌کنیم
                            clash_format = self.parse_config(config_url)
                            if clash_format:
                                self.parsed_clash_configs.append(clash_format)

        except FloodWait as e:
            print(f"⏳ نیاز به انتظار {e.value} ثانیه (محدودیت تلگرام) برای کانال {channel}")
            await asyncio.sleep(e.value)
            await self.check_channel(channel) # دوباره امتحان کن
        except RPCError as e: # برای خطاهای خاص Pyrogram (مثلاً Peer Flood)
            print(f"❌ خطای RPC در کانال {channel}: {e.MESSAGE} (کد: {e.CODE})")
            # اگر این خطا "The method can't be used by bots" باشد، یعنی سشن شما User نیست.
            # باید مجدداً سشن را به صورت User Client ایجاد و Base64 کنید.
        except Exception as e:
            print(f"❌ خطای عمومی در کانال {channel}: {str(e)}")


    async def extract_configs(self):
        """اتصال به تلگرام و استخراج کانفیگ‌ها از تمام کانال‌ها"""
        print("Connecting to Telegram as User Client...")
        try:
            async with self.client:
                print("Successfully connected to Telegram.")
                tasks = [self.check_channel(channel) for channel in CHANNELS]
                await asyncio.gather(*tasks)
        except Exception as e:
            print(f"🔴 خطای اتصال به تلگرام یا استخراج کانفیگ: {str(e)}")
            print("لطفاً مطمئن شوید:")
            print("1. Secret PYROGRAM_SESSION در GitHub Secrets به درستی و کامل Base64 شده است.")
            print(f"2. SESSION_NAME در main.py (فعلاً '{SESSION_NAME}') دقیقاً با نام فایل سشن شما (بدون پسوند) مطابقت دارد.")
            print("3. API_ID و API_HASH در GitHub Secrets صحیح هستند.")
            # اگر به این بخش رسید، یعنی اتصال به تلگرام ناموفق بوده، پس ادامه کار معنی ندارد
            self.found_configs.clear() # برای اطمینان از اینکه configs خالی باشند
            self.parsed_clash_configs.clear() # خالی کردن لیست Clash configs نیز


    async def save_configs(self):
        """ذخیره تمام کانفیگ‌های پیدا شده به هر دو فرمت YAML و TXT (بدون تست)"""
        if not self.found_configs:
            print("⚠️ هیچ کانفیگی یافت نشد یا خطا در استخراج کانفیگ‌ها.")
            # ایجاد فایل‌های خالی برای جلوگیری از خطای "No such file or directory" در Git
            open(OUTPUT_YAML, "w").close()
            open(OUTPUT_TXT, "w").close()
            print(f"فایل‌های خالی {OUTPUT_YAML} و {OUTPUT_TXT} ایجاد شدند.")
            return

        print(f"\n💾 شروع ذخیره {len(self.found_configs)} کانفیگ پیدا شده...")

        # ذخیره به فرمت YAML برای Clash
        clash_config_output = {
            'proxies': self.parsed_clash_configs, # استفاده مستقیم از لیست تجزیه شده
            'proxy-groups': [
                {
                    'name': '🚀 Auto Select',
                    'type': 'url-test',
                    'proxies': [cfg['name'] for cfg in self.parsed_clash_configs if 'name' in cfg], # استفاده از نام‌های کانفیگ‌ها
                    'url': 'http://www.gstatic.com/generate_204',
                    'interval': 300
                },
                {
                    'name': '🔮 Proxy',
                    'type': 'select',
                    'proxies': ['🚀 Auto Select', 'DIRECT']
                },
                {
                    'name': '🎯 Domestic',
                    'type': 'select',
                    'proxies': ['DIRECT']
                }
            ],
            'rules': [
                'DOMAIN-SUFFIX,ir,🎯 Domestic',
                'GEOIP,IR,🎯 Domestic',
                'MATCH,🔮 Proxy'
            ]
        }

        # ذخیره فایل YAML
        try:
            with open(OUTPUT_YAML, "w", encoding="utf-8") as f:
                yaml.dump(clash_config_output, f, allow_unicode=True, sort_keys=False)
            print(f"🎉 {len(self.parsed_clash_configs)} کانفیگ در {OUTPUT_YAML} ذخیره شد.")
        except Exception as e:
            print(f"❌ خطا در ذخیره فایل YAML: {str(e)}")

        # ذخیره به فرمت متنی ساده
        raw_configs_output = list(self.found_configs) # همه کانفیگ‌های پیدا شده (URLs)
        try:
            with open(OUTPUT_TXT, "w", encoding="utf-8") as f:
                f.write("\n".join(raw_configs_output))
            print(f"🎉 {len(self.found_configs)} کانفیگ در {OUTPUT_TXT} ذخیره شد.")
        except Exception as e:
            print(f"❌ خطا در ذخیره فایل TXT: {str(e)}")

        # نمایش جزئیات کانفیگ‌های پیدا شده
        print(f"\n📋 لیستی از کانفیگ‌های پیدا شده (10 مورد اول):")
        for i, config_info in enumerate(self.parsed_clash_configs[:10], 1): # نمایش 10 مورد اول از Clash Format
            if config_info:
                print(f"{i}. {config_info.get('name', 'N/A')} ({config_info.get('type', 'N/A')}) - {config_info.get('server', 'N/A')}:{config_info.get('port', 'N/A')}")
            else:
                # این حالت نباید رخ دهد اگر parse_config به درستی کار کند
                print(f"{i}. (کانفیگ نامعتبر)")


async def main():
    print("🚀 شروع استخراج کانفیگ‌های V2Ray...")
    print("=" * 60)

    extractor = V2RayExtractor()

    await extractor.extract_configs() # استخراج کانفیگ‌ها

    # حالا بدون تست، مستقیماً به مرحله ذخیره‌سازی می‌رویم
    await extractor.save_configs()

    print("=" * 60)
    print("✨ اتمام کار!")

if __name__ == "__main__":
    asyncio.run(main())