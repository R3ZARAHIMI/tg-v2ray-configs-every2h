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
CHANNEL_SEARCH_LIMIT = int(os.environ.get('CHANNEL_SEARCH_LIMIT', 50))
GROUP_SEARCH_LIMIT = int(os.environ.get('GROUP_SEARCH_LIMIT', 600))

# Defining output file names
OUTPUT_YAML_PRO = "Config-jo.yaml"
OUTPUT_TXT = "Config_jo.txt"
OUTPUT_JSON_CONFIG_JO = "Config_jo.json"
OUTPUT_ORIGINAL_CONFIGS = "Original-Configs.txt"

# Regex patterns for finding various config types
V2RAY_PATTERNS = [
    re.compile(r'vless:\/\/[^\s\'\"<>`]+'),
    re.compile(r'vmess:\/\/[^\s\'\"<>`]+'),
    re.compile(r'trojan:\/\/[^\s\'\"<>`]+'),
    re.compile(r'ss:\/\/[^\s\'\"<>`]+'),
    re.compile(r"hy2:\/\/[^\s'\"<>`]+"),
    re.compile(r"hysteria2:\/\/[^\s'\"<>`]+"),
    re.compile(r"tuic:\/\/[^\s'\"<>`]+")
]

def process_lists():
    """Read and process the list of channels and groups from environment variables"""
    channels_list = [ch.strip() for ch in CHANNELS_STR.split(',') if ch.strip()] if CHANNELS_STR else []
    channels = [int(ch) if ch.lstrip('-').isdigit() else ch for ch in channels_list]
    if channels: print(f"✅ {len(channels)} channels read from secrets.")
    else: print("⚠️ Warning: CHANNELS_LIST secret is empty.")

    groups_list = [g.strip() for g in GROUPS_STR.split(',') if g.strip()] if GROUPS_STR else []
    groups = [int(g) if g.lstrip('-').isdigit() else g for g in groups_list]
    if groups: print(f"✅ {len(groups)} groups read from secrets.")
    else: print("⚠️ Warning: GROUPS_LIST secret is empty.")
    return channels, groups

CHANNELS, GROUPS = process_lists()

class V2RayExtractor:
    def __init__(self):
        self.raw_configs: Set[str] = set()
        self.client = Client("my_account", api_id=API_ID, api_hash=API_HASH, session_string=SESSION_STRING)

    def extract_configs_from_text(self, text: str) -> Set[str]:
        found_configs = set()
        for pattern in V2RAY_PATTERNS:
            found_configs.update(pattern.findall(text))
        return {config.strip().replace("`", "").replace("'", "").replace('"', '') for config in found_configs}

    async def find_raw_configs_from_chat(self, chat_id: Any, limit: int):
        try:
            print(f"INFO: 🔍 Searching in chat '{chat_id}' (limit: {limit})...")
            message_count = 0
            async for message in self.client.get_chat_history(chat_id, limit=limit):
                message_count += 1
                
                # --- NEW RELIABLE EXTRACTION LOGIC ---
                # Convert the entire message object to a string to capture all text
                full_message_text = str(message)
                
                initial_count = len(self.raw_configs)
                found = self.extract_configs_from_text(full_message_text)
                
                if found:
                    self.raw_configs.update(found)
                    newly_found = len(self.raw_configs) - initial_count
                    if newly_found > 0:
                        print(f"    ✅ SUCCESS: Found {newly_found} config(s) in message ID: {message.id}!")
            
            print(f"INFO: ➡️ Finished searching '{chat_id}'. Processed {message_count} messages.")
            if message_count == 0:
                print(f"    ⚠️ WARNING: No messages were found for chat '{chat_id}'. Check ID/username and membership.")

        except FloodWait as e:
            print(f"⏳ FLOOD WAIT: Waiting for {e.value + 5} seconds...")
            await asyncio.sleep(e.value + 5)
        except Exception as e:
            print(f"❌ ERROR scanning chat '{chat_id}': {e}")

    def save_files(self):
        print("\n" + "="*40)
        print("⚙️ Starting to process and build config files...")

        if not self.raw_configs:
            print("⚠️ No configs found. Output files will be empty.")
            open(OUTPUT_ORIGINAL_CONFIGS, "w").close()
            return
            
        print(f"👍 {len(self.raw_configs)} unique configs found. Saving...")
        
        with open(OUTPUT_ORIGINAL_CONFIGS, 'w', encoding='utf-8') as f:
            f.write("\n".join(sorted(list(self.raw_configs))))
        print(f"✅ Original configs file '{OUTPUT_ORIGINAL_CONFIGS}' saved successfully.")
        # The rest of the file generation is omitted for simplicity,
        # focusing on the main goal: finding and saving the raw configs.

async def main():
    print("🚀 Starting config extractor...")
    extractor = V2RayExtractor()
    async with extractor.client:
        tasks = []
        if CHANNELS:
            tasks.extend([extractor.find_raw_configs_from_chat(ch, CHANNEL_SEARCH_LIMIT) for ch in CHANNELS])
        if GROUPS:
             tasks.extend([extractor.find_raw_configs_from_chat(g, GROUP_SEARCH_LIMIT) for g in GROUPS])
        
        if tasks:
            await asyncio.gather(*tasks)
        else:
            print("❌ No channels or groups defined for searching.")
    
    extractor.save_files()
    print("\n✨ All operations completed successfully!")

if __name__ == "__main__":
    if not all([API_ID, API_HASH, SESSION_STRING]):
        print("❌ Error: Required secrets (API_ID, API_HASH, SESSION_STRING) are not set.")
    else:
        asyncio.run(main())
