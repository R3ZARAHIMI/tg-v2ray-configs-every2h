import re
import asyncio
import base64
import json
import yaml
import os
import uuid
from urllib.parse import urlparse, parse_qs, unquote, urlunparse
from pyrogram import Client
from pyrogram.errors import FloodWait
from pyrogram.enums import MessageEntityType
from typing import Optional, Dict, Any, Set, List

# =================================================================================
# Settings and Constants Section
# =================================================================================

# Reading environment variables
API_ID = int(os.environ.get("API_ID"))
API_HASH = os.environ.get("API_HASH")
SESSION_STRING = os.environ.get("SESSION_STRING")
CHANNELS_STR = os.environ.get('CHANNELS_LIST')
GROUPS_STR = os.environ.get('GROUPS_LIST')
CHANNEL_SEARCH_LIMIT = int(os.environ.get('CHANNEL_SEARCH_LIMIT', 50)) # Increased default for better searching
GROUP_SEARCH_LIMIT = int(os.environ.get('GROUP_SEARCH_LIMIT', 600))

# Defining output file names
OUTPUT_YAML_PRO = "Config-jo.yaml"
OUTPUT_TXT = "Config_jo.txt"
OUTPUT_JSON_CONFIG_JO = "Config_jo.json"
OUTPUT_ORIGINAL_CONFIGS = "Original-Configs.txt"

# Regex patterns for finding various config types
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
    """Read and process the list of channels and groups from environment variables"""
    channels = [ch.strip() for ch in CHANNELS_STR.split(',')] if CHANNELS_STR else []
    if channels: print(f"✅ {len(channels)} channels read from secrets.")
    else: print("⚠️ Warning: CHANNELS_LIST secret not found or is empty.")

    groups = []
    if GROUPS_STR:
        try:
            groups = [int(g.strip()) for g in GROUPS_STR.split(',')]
            print(f"✅ {len(groups)} groups read from secrets.")
        except ValueError: print("❌ Error: GROUPS_LIST secret must only contain numeric IDs.")
    else: print("⚠️ Warning: GROUPS_LIST secret is empty.")
    return channels, groups

CHANNELS, GROUPS = process_lists()

class V2RayExtractor:
    def __init__(self):
        self.raw_configs: Set[str] = set()
        self.client = Client("my_account", api_id=API_ID, api_hash=API_HASH, session_string=SESSION_STRING)

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
        # This function remains the same as the original, just ensure it handles all types
        try:
            if config_url.startswith('vmess://'): return self.parse_vmess(config_url)
            elif config_url.startswith('vless://'): return self.parse_vless(config_url)
            elif config_url.startswith('trojan://'): return self.parse_trojan(config_url)
            elif config_url.startswith('ss://'): return self.parse_shadowsocks(config_url)
            elif config_url.startswith(('hysteria2://', 'hy2://')): return self.parse_hysteria2(config_url)
            elif config_url.startswith('tuic://'): return self.parse_tuic(config_url)
            return None
        except Exception as e:
            print(f"❌ Error parsing config {config_url[:50]}...: {e}")
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
            return {'name': original_name, 'type': 'vmess', 'server': config.get('add'), 'port': int(config.get('port', 443)), 'uuid': config.get('id'), 'alterId': int(config.get('aid', 0)), 'cipher': config.get('scy', 'auto'), 'tls': config.get('tls') == 'tls', 'network': config.get('net', 'tcp'), 'udp': True, 'ws-opts': ws_opts}
        except Exception as e:
            # print(f"❌ Error parsing vmess: {e}")
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
            is_tls = query.get('security', [''])[0] in ['tls', 'reality']
            return {'name': original_name, 'type': 'vless', 'server': parsed.hostname, 'port': parsed.port or 443, 'uuid': parsed.username, 'udp': True, 'tls': is_tls, 'network': query.get('type', ['tcp'])[0], 'servername': query.get('sni', [None])[0], 'ws-opts': ws_opts, 'reality-opts': reality_opts}
        except Exception as e:
            # print(f"❌ Error parsing vless: {e}")
            return None

    def parse_trojan(self, trojan_url: str) -> Optional[Dict[str, Any]]:
        try:
            parsed = urlparse(trojan_url)
            query = parse_qs(parsed.query)
            original_name = unquote(parsed.fragment) if parsed.fragment else ''
            sni = query.get('peer', [None])[0] or query.get('sni', [None])[0] or parsed.hostname
            return {'name': original_name, 'type': 'trojan', 'server': parsed.hostname, 'port': parsed.port or 443, 'password': parsed.username, 'udp': True, 'sni': sni}
        except Exception as e:
            # print(f"❌ Error parsing trojan: {e}")
            return None

    def parse_shadowsocks(self, ss_url: str) -> Optional[Dict[str, Any]]:
        try:
            parsed = urlparse(ss_url)
            original_name = unquote(parsed.fragment) if parsed.fragment else ''
            user_info_part = parsed.netloc.split('@')[0]
            try:
                user_info = base64.b64decode(user_info_part + '=' * (4 - len(user_info_part) % 4)).decode('utf-8')
            except:
                user_info = unquote(user_info_part)
            cipher, password = user_info.split(':', 1)
            return {'name': original_name, 'type': 'ss', 'server': parsed.hostname, 'port': parsed.port, 'cipher': cipher, 'password': password, 'udp': True}
        except Exception as e:
            # print(f"❌ Error parsing shadowsocks: {e}")
            return None

    def parse_hysteria2(self, hy2_url: str) -> Optional[Dict[str, Any]]:
        try:
            parsed = urlparse(hy2_url)
            query = parse_qs(parsed.query)
            original_name = unquote(parsed.fragment) if parsed.fragment else ''
            return {'name': original_name, 'type': 'hysteria2', 'server': parsed.hostname, 'port': parsed.port or 443, 'auth': parsed.username, 'up': query.get('up', ['100 Mbps'])[0], 'down': query.get('down', ['100 Mbps'])[0], 'obfs': query.get('obfs', [None])[0], 'sni': query.get('sni', [parsed.hostname])[0], 'skip-cert-verify': query.get('insecure', ['0'])[0] == '1'}
        except Exception as e:
            # print(f"❌ Error parsing hysteria2: {e}")
            return None
    
    def parse_tuic(self, tuic_url: str) -> Optional[Dict[str, Any]]:
        try:
            parsed = urlparse(tuic_url)
            query = parse_qs(parsed.query)
            original_name = unquote(parsed.fragment) if parsed.fragment else ''
            return {'name': original_name, 'type': 'tuic', 'server': parsed.hostname, 'port': parsed.port or 443, 'uuid': parsed.username, 'password': query.get('password', [''])[0], 'udp': True, 'sni': query.get('sni', [parsed.hostname])[0], 'skip-cert-verify': query.get('allow_insecure', ['0'])[0] == '1'}
        except Exception as e:
            # print(f"❌ Error parsing tuic: {e}")
            return None

    def convert_to_singbox_outbound(self, proxy: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        # This function also remains mostly the same
        # Small fixes for robustness
        try:
            ptype = proxy.get('type')
            if not ptype: return None
            sb_type = 'shadowsocks' if ptype == 'ss' else ptype
            server = proxy.get('server')
            if not server:
                return None
            try: port = int(proxy.get('port') or 443)
            except (ValueError, TypeError): port = 443
            tag = proxy.get('name') or f"{ptype}-{server}:{port}"
            out: Dict[str, Any] = {"type": sb_type, "tag": tag, "server": server, "server_port": port}
            uuid_re = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
            
            if ptype == 'vless':
                uid = proxy.get('uuid')
                if not uid or not uuid_re.match(str(uid)): return None
                out.update({"uuid": uid, "flow": proxy.get('flow', '')})
                if proxy.get('tls'):
                    out['tls'] = {"enabled": True, "server_name": proxy.get('servername')}
                    ro = proxy.get('reality-opts')
                    if ro and ro.get('public-key'):
                        out['tls'].setdefault('utls', {"enabled": True, "fingerprint": "chrome"})
                        out['tls']['reality'] = {"enabled": True, "public_key": ro.get('public-key'), "short_id": ro.get('short-id')}
                else:
                    out['tls'] = {"enabled": False}

                if proxy.get('network') == 'ws' and proxy.get('ws-opts'):
                    ws = proxy.get('ws-opts') or {}
                    headers = {}
                    host = (ws.get('headers') or {}).get('Host')
                    if host: headers['Host'] = host
                    out['transport'] = {"type": "ws", "path": ws.get('path', '/'), "headers": headers}

            elif ptype == 'vmess':
                uid = proxy.get('uuid')
                if not uid: return None # VMess UUID can be non-standard
                try: alter_id = int(proxy.get('alterId') or 0)
                except (ValueError, TypeError): alter_id = 0
                security = (proxy.get('cipher') or 'auto').lower()
                out.update({"uuid": uid, "alter_id": alter_id, "security": security})
                if proxy.get('tls'):
                    out['tls'] = {"enabled": True, "server_name": proxy.get('servername')}
                if proxy.get('network') == 'ws' and proxy.get('ws-opts'):
                    ws = proxy.get('ws-opts') or {}
                    headers = {}
                    host = (ws.get('headers') or {}).get('Host')
                    if host: headers['Host'] = host
                    out['transport'] = {"type": "ws", "path": ws.get('path', '/'), "headers": headers}

            elif ptype == 'trojan':
                pw = proxy.get('password')
                if not pw: return None
                out.update({"password": pw})
                sni = proxy.get('sni') or proxy.get('servername')
                out['tls'] = {"enabled": True, "server_name": sni}

            elif ptype == 'ss':
                method = proxy.get('cipher')
                pw = proxy.get('password')
                if not method or not pw: return None
                out.update({"method": method, "password": pw})

            else:
                return None

            return out
        except Exception as e:
            # print(f"❌ Error converting to Sing-box for {proxy.get('name')}: {e}")
            return None

    def extract_configs_from_text(self, text: str) -> Set[str]:
        found_configs = set()
        for pattern in V2RAY_PATTERNS:
            found_configs.update(pattern.findall(text))
        
        final_configs = set()
        for config_url in found_configs:
            stripped_config = config_url.strip().replace("`", "")
            if self._validate_config_type(stripped_config):
                final_configs.add(self._correct_config_type(stripped_config))
        return final_configs

    async def find_raw_configs_from_chat(self, chat_id: Any, limit: int, retries: int = 3):
        try:
            print(f"🔍 Searching in chat '{chat_id}' (limit: {limit} messages)...")
            message_count = 0
            async for message in self.client.get_chat_history(chat_id, limit=limit):
                message_count += 1
                texts_to_scan = []
                text_to_check = message.text or message.caption

                if not text_to_check:
                    continue

                texts_to_scan.append(text_to_check)
                if message.entities:
                    for entity in message.entities:
                        if entity.type in (MessageEntityType.PRE, MessageEntityType.CODE):
                            code_text = text_to_check[entity.offset : entity.offset + entity.length]
                            texts_to_scan.append(code_text)
                
                potential_b64 = BASE64_PATTERN.findall(text_to_check)
                for b64_str in potential_b64:
                    try:
                        decoded_text = base64.b64decode(b64_str + '=' * (-len(b64_str) % 4)).decode('utf-8', errors='ignore')
                        texts_to_scan.append(decoded_text)
                    except Exception:
                        continue
                
                initial_config_count = len(self.raw_configs)
                for text in texts_to_scan:
                    found_configs = self.extract_configs_from_text(text)
                    self.raw_configs.update(found_configs)

                new_configs_found = len(self.raw_configs) - initial_config_count
                if new_configs_found > 0:
                    print(f"    ✅ Found {new_configs_found} new config(s) in message {message.id}!")
            
            print(f"➡️ Finished searching '{chat_id}'. Processed {message_count} messages.")
            if message_count == 0:
                print(f"    ⚠️ WARNING: No messages were found for chat '{chat_id}'. Check if the ID/username is correct and if you have joined it.")

        except FloodWait as e:
            if retries <= 0:
                print(f"❌ Max retries reached for chat {chat_id}.")
                return
            wait_time = e.value + 5
            print(f"⏳ Flood wait. Waiting for {wait_time} seconds...")
            await asyncio.sleep(wait_time)
            await self.find_raw_configs_from_chat(chat_id, limit, retries - 1)
        except Exception as e:
            print(f"❌ An unexpected error occurred while scanning chat '{chat_id}': {e}")
            print("    - This might be due to an incorrect chat ID (e.g., using a username for a private channel) or not being a member of the channel/group.")

    def save_files(self):
        print("\n" + "="*40)
        print("⚙️ Starting to process and build config files...")

        if not self.raw_configs:
            print("⚠️ No configs found in any of the chats. Output files will be empty.")
            for f in [OUTPUT_YAML_PRO, OUTPUT_TXT, OUTPUT_JSON_CONFIG_JO, OUTPUT_ORIGINAL_CONFIGS]:
                with open(f, "w") as file:
                    pass # Create empty files
            return

        print(f"⚙️ Processing {len(self.raw_configs)} unique raw configs...")
        proxies_list_clash, parse_errors = [], 0
        
        original_configs_to_save = []
        renamed_txt_configs = []
        config_counter = 1
        
        for url in sorted(list(self.raw_configs)):
            proxy = self.parse_config_for_clash(url)
            if proxy:
                original_configs_to_save.append(url)
                new_name = f"Config_jo-{config_counter:02d}"
                proxy['name'] = new_name
                proxies_list_clash.append(proxy)
                try:
                    parsed_url = list(urlparse(url))
                    parsed_url[5] = new_name
                    new_url = urlunparse(parsed_url)
                    renamed_txt_configs.append(new_url)
                except Exception:
                    base_url = url.split('#')[0]
                    renamed_txt_configs.append(f"{base_url}#{new_name}")
                config_counter += 1
            else:
                parse_errors += 1

        if parse_errors > 0:
            print(f"⚠️ {parse_errors} configs were ignored due to parsing errors.")
        if not proxies_list_clash:
            print("⚠️ No valid configs could be parsed to build files.")
            for f in [OUTPUT_YAML_PRO, OUTPUT_TXT, OUTPUT_JSON_CONFIG_JO, OUTPUT_ORIGINAL_CONFIGS]:
                with open(f, "w") as file:
                    pass
            return
            
        print(f"👍 {len(proxies_list_clash)} valid configs will be saved.")
        all_proxy_names = [p['name'] for p in proxies_list_clash]

        # Build and save Pro file
        try:
            os.makedirs('rules', exist_ok=True)
            pro_config = self.build_pro_config(proxies_list_clash, all_proxy_names)
            with open(OUTPUT_YAML_PRO, 'w', encoding='utf-8') as f:
                yaml.dump(pro_config, f, allow_unicode=True, sort_keys=False, indent=2, width=1000)
            print(f"✅ Pro file {OUTPUT_YAML_PRO} created successfully.")
        except Exception as e:
            print(f"❌ Error creating pro file: {e}")

        # Build and save Sing-box file
        try:
            singbox_config = self.build_sing_box_config(proxies_list_clash)
            with open(OUTPUT_JSON_CONFIG_JO, 'w', encoding='utf-8') as f:
                json.dump(singbox_config, f, ensure_ascii=False, indent=4)
            print(f"✅ Sing-box file {OUTPUT_JSON_CONFIG_JO} created successfully.")
        except Exception as e:
            print(f"❌ Error creating Sing-box file: {e}")
        
        # Save text file with new names
        with open(OUTPUT_TXT, 'w', encoding='utf-8') as f:
            f.write("\n".join(sorted(renamed_txt_configs)))
        print(f"✅ Text file {OUTPUT_TXT} saved successfully.")

        # Save original configs file
        with open(OUTPUT_ORIGINAL_CONFIGS, 'w', encoding='utf-8') as f:
            f.write("\n".join(sorted(original_configs_to_save)))
        print(f"✅ Original configs file {OUTPUT_ORIGINAL_CONFIGS} saved successfully.")

    def build_pro_config(self, proxies, proxy_names):
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

    def build_sing_box_config(self, proxies_clash: List[Dict[str, Any]]) -> Dict[str, Any]:
        outbounds = []
        for proxy in proxies_clash:
            sb_outbound = self.convert_to_singbox_outbound(proxy)
            if sb_outbound: outbounds.append(sb_outbound)
        proxy_tags = [p['tag'] for p in outbounds]
        return {
            "log": {"level": "warn", "timestamp": True},
            "dns": {
                "servers": [
                    {"tag": "dns_proxy", "address": "https://dns.google/dns-query", "detour": "PROXY"},
                    {"tag": "dns_direct", "address": "1.1.1.1"}
                ],
                "rules": [
                    {"outbound": "PROXY", "server": "dns_proxy"},
                    {"rule_set": ["geosite-ir", "geoip-ir"], "server": "dns_direct"},
                    {"domain_suffix": ".ir", "server": "dns_direct"}
                ],
                "final": "dns_direct",
                "strategy": "ipv4_only"
            },
            "inbounds": [{"type": "mixed", "listen": "0.0.0.0", "listen_port": 2080, "sniff": True}],
            "outbounds": [
                {"type": "direct", "tag": "direct"},
                {"type": "block", "tag": "block"},
                {"type": "dns", "tag": "dns-out"},
                *outbounds,
                {"type": "selector", "tag": "PROXY", "outbounds": ["auto", *proxy_tags], "default": "auto"},
                {"type": "urltest", "tag": "auto", "outbounds": proxy_tags, "url": "http://www.gstatic.com/generate_204", "interval": "5m"}
            ],
            "route": {
                "rule_set": [
                    {"tag": "geosite-ir", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/Chocolate4U/Iran-sing-box-rules@rule-set/geosite-ir.srs", "download_detour": "direct"},
                    {"tag": "geoip-ir", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/Chocolate4U/Iran-sing-box-rules@rule-set/geoip-ir.srs", "download_detour": "direct"}
                ],
                "rules": [
                    {"protocol": "dns", "outbound": "dns-out"},
                    {"rule_set": ["geosite-ir", "geoip-ir"], "outbound": "direct"},
                    {"ip_is_private": True, "outbound": "direct"}
                ],
                "final": "PROXY"
            }
        }

async def main():
    print("🚀 Starting config extractor...")
    extractor = V2RayExtractor()
    async with extractor.client:
        tasks = [extractor.find_raw_configs_from_chat(channel, CHANNEL_SEARCH_LIMIT) for channel in CHANNELS]
        tasks.extend(extractor.find_raw_configs_from_chat(group, GROUP_SEARCH_LIMIT) for group in GROUPS)
        if tasks:
            await asyncio.gather(*tasks)
        else:
            print("❌ No channels or groups defined for searching.")
    extractor.save_files()
    print("\n✨ All operations completed successfully!")

if __name__ == "__main__":
    if not all([API_ID, API_HASH, SESSION_STRING]):
        print("❌ Error: One or more required secrets (API_ID, API_HASH, SESSION_STRING) are not set.")
    else:
        asyncio.run(main())
