import requests
import json
import ipaddress
import os
import hashlib
import pickle
from datetime import datetime, timedelta
from urllib.parse import urlparse
import re
import base64
import uuid

class GeoIPClassifier:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        self.country_codes = [
            'US', 'DE', 'FR', 'NL', 'GB', 'CA', 'JP', 'SG', 'KR', 'AU',
            'IT', 'ES', 'SE', 'CH', 'NO', 'FI', 'DK', 'BE', 'AT', 'PL',
            'CZ', 'IE', 'IL', 'TR', 'AE', 'SA', 'IN', 'BR', 'MX', 'ZA'
        ]
        
        self.geoip_data = {}
        self.cache_dir = 'configs/geoip_cache'
        self.cache_file = f'{self.cache_dir}/geoip_data.pkl'
        self.last_update_file = f'{self.cache_dir}/last_update.txt'
        
        os.makedirs(self.cache_dir, exist_ok=True)
        self.load_geoip_data()
    
    def load_geoip_data(self):
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'rb') as f:
                    self.geoip_data = pickle.load(f)
                print(f"✓ GeoIP data loaded from cache: {len(self.geoip_data)} countries")
        except:
            self.geoip_data = {}
    
    def save_geoip_data(self):
        try:
            with open(self.cache_file, 'wb') as f:
                pickle.dump(self.geoip_data, f)
            
            with open(self.last_update_file, 'w') as f:
                f.write(datetime.now().isoformat())
        except:
            pass
    
    def should_update_geoip(self):
        if not os.path.exists(self.last_update_file):
            return True
        
        try:
            with open(self.last_update_file, 'r') as f:
                last_update = datetime.fromisoformat(f.read().strip())
            
            if datetime.now() - last_update > timedelta(days=7):
                return True
        except:
            return True
        
        return False
    
    def fetch_country_cidrs(self, country_code):
        urls = [
            f"https://raw.githubusercontent.com/v2fly/geoip/release/text/{country_code}.txt",
            f"https://cdn.jsdelivr.net/gh/v2fly/geoip@release/text/{country_code}.txt"
        ]
        
        for url in urls:
            try:
                response = self.session.get(url, timeout=10)
                if response.status_code == 200:
                    cidrs = []
                    for line in response.text.strip().split('\n'):
                        line = line.strip()
                        if line and not line.startswith('#'):
                            try:
                                ipaddress.ip_network(line)
                                cidrs.append(line)
                            except:
                                continue
                    return cidrs
            except:
                continue
        
        return []
    
    def update_geoip_database(self):
        if not self.should_update_geoip():
            print("✓ GeoIP database is up to date (last update < 7 days)")
            return
        
        print("⟳ Updating GeoIP database from v2fly/geoip...")
        
        for i, country in enumerate(self.country_codes, 1):
            print(f"  [{i}/{len(self.country_codes)}] Fetching {country}...")
            cidrs = self.fetch_country_cidrs(country)
            if cidrs:
                networks = []
                for cidr in cidrs:
                    try:
                        networks.append(ipaddress.ip_network(cidr))
                    except:
                        continue
                
                self.geoip_data[country] = {
                    'cidrs': cidrs,
                    'networks': networks,
                    'updated': datetime.now().isoformat()
                }
                print(f"    ✓ {len(cidrs)} CIDRs loaded")
        
        self.save_geoip_data()
        print(f"✓ GeoIP database updated: {len(self.geoip_data)} countries")
    
    def extract_ip_from_config(self, config_str):
        if config_str.startswith('vmess://'):
            try:
                base64_part = config_str[8:]
                if len(base64_part) % 4 != 0:
                    base64_part += '=' * (4 - len(base64_part) % 4)
                decoded = json.loads(base64.b64decode(base64_part).decode('utf-8'))
                return decoded.get('add', '')
            except:
                return ''
        
        elif config_str.startswith('vless://') or config_str.startswith('trojan://'):
            try:
                parsed = urlparse(config_str)
                hostname = parsed.hostname or parsed.netloc.split('@')[-1].split(':')[0]
                return hostname
            except:
                return ''
        
        elif config_str.startswith('ss://'):
            try:
                if '@' in config_str:
                    server_part = config_str.split('@')[1].split('#')[0]
                    if ':' in server_part:
                        return server_part.split(':')[0]
            except:
                return ''
        
        elif config_str.startswith('hysteria2://') or config_str.startswith('hy2://'):
            try:
                parsed = urlparse(config_str)
                return parsed.hostname or ''
            except:
                return ''
        
        elif config_str.startswith('tuic://'):
            try:
                parsed = urlparse(config_str)
                hostname = parsed.hostname or parsed.netloc.split('%')[0].split('@')[-1].split(':')[0]
                return hostname
            except:
                return ''
        
        elif config_str.startswith('wireguard://'):
            try:
                parsed = urlparse(config_str)
                return parsed.hostname or ''
            except:
                return ''
        
        return ''
    
    def is_valid_ip(self, ip_str):
        try:
            ipaddress.ip_address(ip_str)
            return True
        except:
            return False
    
    def classify_ip(self, ip_str):
        if not self.is_valid_ip(ip_str):
            return 'UNKNOWN'
        
        try:
            ip = ipaddress.ip_address(ip_str)
            
            for country, data in self.geoip_data.items():
                for network in data.get('networks', []):
                    if ip in network:
                        return country
            
            return 'OTHER'
        except:
            return 'ERROR'
    
    def classify_configs(self, configs):
        classified = {}
        
        for config in configs:
            ip = self.extract_ip_from_config(config)
            if ip:
                country = self.classify_ip(ip)
            else:
                country = 'UNKNOWN'
            
            if country not in classified:
                classified[country] = []
            
            classified[country].append(config)
        
        return classified
    
    def categorize_by_protocol(self, configs):
        categories = {
            'vmess': [], 'vless': [], 'trojan': [], 'shadowsocks': [],
            'hysteria': [], 'hysteria2': [], 'tuic': [], 'wireguard': [], 'other': []
        }
        
        for config in configs:
            if config.startswith('vmess://'):
                categories['vmess'].append(config)
            elif config.startswith('vless://'):
                categories['vless'].append(config)
            elif config.startswith('trojan://'):
                categories['trojan'].append(config)
            elif config.startswith('ss://'):
                categories['shadowsocks'].append(config)
            elif config.startswith('hysteria2://') or config.startswith('hy2://'):
                categories['hysteria2'].append(config)
            elif config.startswith('hysteria://'):
                categories['hysteria'].append(config)
            elif config.startswith('tuic://'):
                categories['tuic'].append(config)
            elif config.startswith('wireguard://'):
                categories['wireguard'].append(config)
            else:
                categories['other'].append(config)
        
        return categories
    
    def save_country_configs(self, country, protocol_configs, all_configs):
        country_dir = f'configs/country/{country}'
        os.makedirs(country_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        for protocol, configs in protocol_configs.items():
            if configs:
                filename = f"{country_dir}/{protocol}.txt"
                content = f"# {country} {protocol.upper()} Configurations\n"
                content += f"# Updated: {timestamp}\n"
                content += f"# Count: {len(configs)}\n\n"
                content += "\n".join(configs)
                
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(content)
        
        if all_configs:
            filename = f"{country_dir}/all.txt"
            content = f"# All {country} Configurations\n"
            content += f"# Updated: {timestamp}\n"
            content += f"# Total Count: {len(all_configs)}\n\n"
            content += "\n".join(all_configs)
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(content)
        
        meta = {
            'country': country,
            'last_update': timestamp,
            'total_configs': len(all_configs),
            'protocols': {p: len(c) for p, c in protocol_configs.items() if c},
            'source': 'GeoIP Classification from v2fly/geoip'
        }
        
        with open(f"{country_dir}/meta.json", 'w', encoding='utf-8') as f:
            json.dump(meta, f, ensure_ascii=False, indent=2)
    
    def process_all_combined_configs(self):
        combined_file = 'configs/combined/all.txt'
        
        if not os.path.exists(combined_file):
            print("❌ No combined configs found")
            return {}
        
        configs = []
        with open(combined_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    configs.append(line)
        
        print(f"⟳ Classifying {len(configs)} configs by country...")
        
        classified = self.classify_configs(configs)
        
        total_classified = 0
        for country, country_configs in classified.items():
            if country not in ['UNKNOWN', 'OTHER', 'ERROR']:
                protocol_categories = self.categorize_by_protocol(country_configs)
                self.save_country_configs(country, protocol_categories, country_configs)
                total_classified += len(country_configs)
                print(f"  ✓ {country}: {len(country_configs)} configs")
        
        print(f"✓ Classification complete: {total_classified} configs mapped to {len([c for c in classified if c not in ['UNKNOWN', 'OTHER', 'ERROR']])} countries")
        
        return classified

def main():
    print("=" * 60)
    print("ARISTA GEOIP CLASSIFIER")
    print("=" * 60)
    
    try:
        classifier = GeoIPClassifier()
        classifier.update_geoip_database()
        classified = classifier.process_all_combined_configs()
        
        print("\n✅ CLASSIFICATION COMPLETE")
        print(f"Total countries with configs: {len([c for c in classified if c not in ['UNKNOWN', 'OTHER', 'ERROR']])}")
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}")

if __name__ == "__main__":
    main()
