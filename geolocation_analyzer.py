import os
import json
import socket
import ipaddress
import base64
from datetime import datetime
from urllib.parse import urlparse
import geoip2.database
import geoip2.errors

class GeolocationAnalyzer:
    def __init__(self):
        self.db_path = 'GeoIP'
        self.country_db = None
        self.asn_db = None
        self.city_db = None
        self.load_databases()
        
        self.protocol_mapping = {
            'vmess': self.extract_vmess_ip,
            'vless': self.extract_vless_ip,
            'trojan': self.extract_trojan_ip,
            'ss': self.extract_ss_ip,
            'hysteria2': self.extract_hysteria_ip,
            'hy2': self.extract_hysteria_ip,
            'hysteria': self.extract_hysteria_ip,
            'tuic': self.extract_tuic_ip,
            'wireguard': self.extract_wireguard_ip
        }
        
        self.cdn_domains = {
            'cloudflare.com': 'CLOUDFLARE',
            'cdn.cloudflare.net': 'CLOUDFLARE',
            'cdn77.com': 'CDN77',
            'akamai.net': 'AKAMAI',
            'akamaiedge.net': 'AKAMAI',
            'fastly.net': 'FASTLY',
            'amazonaws.com': 'AWS',
            'cloudfront.net': 'CLOUDFRONT',
            'googleusercontent.com': 'GOOGLE',
            'stackpathcdn.com': 'STACKPATH',
            'azure.com': 'MICROSOFT',
            'azureedge.net': 'MICROSOFT'
        }
    
    def load_databases(self):
        try:
            country_path = os.path.join(self.db_path, 'GeoLite2-Country.mmdb')
            asn_path = os.path.join(self.db_path, 'GeoLite2-ASN.mmdb')
            city_path = os.path.join(self.db_path, 'GeoLite2-City.mmdb')
            
            if os.path.exists(country_path):
                self.country_db = geoip2.database.Reader(country_path)
            
            if os.path.exists(asn_path):
                self.asn_db = geoip2.database.Reader(asn_path)
            
            if os.path.exists(city_path):
                self.city_db = geoip2.database.Reader(city_path)
                
        except Exception as e:
            print(f"Error loading GeoIP databases: {e}")
    
    def is_valid_ip(self, host):
        try:
            ipaddress.ip_address(host)
            return True
        except:
            return False
    
    def resolve_domain(self, domain):
        try:
            return socket.gethostbyname(domain)
        except:
            return None
    
    def detect_cdn(self, domain):
        domain_lower = domain.lower()
        for cdn_domain, cdn_name in self.cdn_domains.items():
            if cdn_domain in domain_lower or domain_lower.endswith(cdn_domain):
                return cdn_name
        return None
    
    def get_ip_geolocation(self, ip_address):
        result = {
            'ip': ip_address,
            'country_code': 'XX',
            'country_name': 'Unknown',
            'continent': 'Unknown',
            'asn': None,
            'as_org': None,
            'city': None,
            'is_cdn': False,
            'cdn_provider': None,
            'is_iranian': False
        }
        
        try:
            if self.country_db:
                country_response = self.country_db.country(ip_address)
                result['country_code'] = country_response.country.iso_code or 'XX'
                result['country_name'] = country_response.country.name or 'Unknown'
                result['continent'] = country_response.continent.name or 'Unknown'
                result['is_iranian'] = (result['country_code'] == 'IR')
            
            if self.asn_db:
                asn_response = self.asn_db.asn(ip_address)
                result['asn'] = asn_response.autonomous_system_number
                result['as_org'] = asn_response.autonomous_system_organization
            
            if self.city_db:
                city_response = self.city_db.city(ip_address)
                result['city'] = city_response.city.name
            
        except geoip2.errors.AddressNotFoundError:
            pass
        except Exception as e:
            pass
        
        return result
    
    def extract_vmess_ip(self, config_str):
        try:
            base64_part = config_str[8:]
            if len(base64_part) % 4 != 0:
                base64_part += '=' * (4 - len(base64_part) % 4)
            decoded = json.loads(base64.b64decode(base64_part).decode('utf-8'))
            host = decoded.get('add', '')
            port = decoded.get('port', '')
            return host, port, 'vmess'
        except:
            return None, None, None
    
    def extract_vless_ip(self, config_str):
        try:
            if config_str.startswith('vless://'):
                config_str = config_str[8:]
            
            if '@' in config_str:
                host_part = config_str.split('@')[1]
                if ':' in host_part:
                    host = host_part.split(':')[0]
                    port = host_part.split(':')[1].split('#')[0].split('?')[0]
                    return host, port, 'vless'
        except:
            pass
        return None, None, None
    
    def extract_trojan_ip(self, config_str):
        try:
            if config_str.startswith('trojan://'):
                config_str = config_str[9:]
            
            if '@' in config_str:
                host_part = config_str.split('@')[1]
                if ':' in host_part:
                    host = host_part.split(':')[0]
                    port = host_part.split(':')[1].split('#')[0].split('?')[0]
                    return host, port, 'trojan'
        except:
            pass
        return None, None, None
    
    def extract_ss_ip(self, config_str):
        try:
            if config_str.startswith('ss://'):
                config_str = config_str[5:]
            
            if '@' in config_str:
                host_part = config_str.split('@')[1]
                if ':' in host_part:
                    host = host_part.split(':')[0]
                    port = host_part.split(':')[1].split('#')[0].split('?')[0]
                    return host, port, 'ss'
        except:
            pass
        return None, None, None
    
    def extract_hysteria_ip(self, config_str):
        try:
            if config_str.startswith('hysteria2://') or config_str.startswith('hy2://'):
                config_str = config_str.split('://')[1]
            elif config_str.startswith('hysteria://'):
                config_str = config_str[11:]
            
            if '@' in config_str:
                host_part = config_str.split('@')[1]
                if ':' in host_part:
                    host = host_part.split(':')[0]
                    port = host_part.split(':')[1].split('#')[0].split('?')[0]
                    return host, port, 'hysteria2'
        except:
            pass
        return None, None, None
    
    def extract_tuic_ip(self, config_str):
        try:
            if config_str.startswith('tuic://'):
                config_str = config_str[7:]
            
            if '@' in config_str:
                host_part = config_str.split('@')[1]
                if ':' in host_part:
                    host = host_part.split(':')[0]
                    port = host_part.split(':')[1].split('#')[0].split('?')[0]
                    return host, port, 'tuic'
        except:
            pass
        return None, None, None
    
    def extract_wireguard_ip(self, config_str):
        try:
            if config_str.startswith('wireguard://'):
                config_str = config_str[12:]
            
            if '@' in config_str:
                host_part = config_str.split('@')[1]
                if ':' in host_part:
                    host = host_part.split(':')[0]
                    port = host_part.split(':')[1].split('#')[0].split('?')[0]
                    return host, port, 'wireguard'
        except:
            pass
        return None, None, None
    
    def analyze_config(self, config_str):
        result = {
            'config': config_str,
            'protocol': None,
            'host': None,
            'port': None,
            'ip_address': None,
            'is_ip': False,
            'cdn_detected': None,
            'geolocation': None,
            'analysis_error': None
        }
        
        try:
            for protocol_prefix in self.protocol_mapping.keys():
                if config_str.startswith(protocol_prefix + '://') or (protocol_prefix == 'hy2' and config_str.startswith('hy2://')):
                    extract_func = self.protocol_mapping.get(protocol_prefix)
                    if extract_func:
                        host, port, protocol = extract_func(config_str)
                        result['host'] = host
                        result['port'] = port
                        result['protocol'] = protocol or protocol_prefix
                        break
            
            if not result['host']:
                result['analysis_error'] = 'Host not extractable'
                return result
            
            if self.is_valid_ip(result['host']):
                result['is_ip'] = True
                result['ip_address'] = result['host']
                result['cdn_detected'] = None
            else:
                result['is_ip'] = False
                result['cdn_detected'] = self.detect_cdn(result['host'])
                resolved_ip = self.resolve_domain(result['host'])
                if resolved_ip:
                    result['ip_address'] = resolved_ip
                    result['resolved_domain'] = result['host']
            
            if result['ip_address']:
                result['geolocation'] = self.get_ip_geolocation(result['ip_address'])
                
        except Exception as e:
            result['analysis_error'] = str(e)
        
        return result
    
    def process_configs(self, configs):
        analyzed = []
        country_map = {}
        protocol_country_map = {}
        
        for config in configs:
            analysis = self.analyze_config(config)
            analyzed.append(analysis)
            
            if analysis['geolocation']:
                country_code = analysis['geolocation']['country_code']
                protocol = analysis['protocol']
                
                if country_code not in country_map:
                    country_map[country_code] = []
                
                country_map[country_code].append(analysis)
                
                if country_code not in protocol_country_map:
                    protocol_country_map[country_code] = {}
                
                if protocol not in protocol_country_map[country_code]:
                    protocol_country_map[country_code][protocol] = []
                
                protocol_country_map[country_code][protocol].append(config)
        
        return analyzed, country_map, protocol_country_map
    
    def save_country_configs(self, country_map, protocol_country_map):
        os.makedirs('configs/country', exist_ok=True)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        total_countries = 0
        total_configs = 0
        
        for country_code, configs in country_map.items():
            if country_code == 'XX' or not configs:
                continue
            
            country_dir = f'configs/country/{country_code}'
            os.makedirs(country_dir, exist_ok=True)
            
            all_configs = []
            
            for protocol in ['vmess', 'vless', 'trojan', 'ss', 'hysteria2', 'hysteria', 'tuic', 'wireguard', 'other']:
                protocol_configs = []
                
                if country_code in protocol_country_map and protocol in protocol_country_map[country_code]:
                    protocol_configs = protocol_country_map[country_code][protocol]
                
                if protocol_configs:
                    filename = f"{country_dir}/{protocol}.txt"
                    content = f"# {country_code} {protocol.upper()} Configurations\n"
                    content += f"# Updated: {timestamp}\n"
                    content += f"# Count: {len(protocol_configs)}\n"
                    content += "# Geolocated by MaxMind GeoLite2\n\n"
                    content += "\n".join(protocol_configs)
                    
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write(content)
                    
                    all_configs.extend(protocol_configs)
            
            if all_configs:
                filename = f"{country_dir}/all.txt"
                content = f"# All {country_code} Configurations\n"
                content += f"# Updated: {timestamp}\n"
                content += f"# Total Count: {len(all_configs)}\n"
                content += "# Geolocated by MaxMind GeoLite2\n\n"
                content += "\n".join(all_configs)
                
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                meta_info = {
                    'country_code': country_code,
                    'total_configs': len(all_configs),
                    'protocols': {},
                    'last_update': timestamp,
                    'total_iranian_configs': len([c for c in configs if c['geolocation'] and c['geolocation'].get('is_iranian')])
                }
                
                for protocol in ['vmess', 'vless', 'trojan', 'ss', 'hysteria2', 'hysteria', 'tuic', 'wireguard', 'other']:
                    if country_code in protocol_country_map and protocol in protocol_country_map[country_code]:
                        meta_info['protocols'][protocol] = len(protocol_country_map[country_code][protocol])
                    else:
                        meta_info['protocols'][protocol] = 0
                
                with open(f"{country_dir}/meta.json", 'w', encoding='utf-8') as f:
                    json.dump(meta_info, f, ensure_ascii=False, indent=2)
            
            total_countries += 1
            total_configs += len(all_configs)
        
        return total_countries, total_configs
    
    def generate_report(self, country_map, total_processed):
        print("=" * 60)
        print("GEOLOCATION ANALYSIS REPORT")
        print("=" * 60)
        print(f"Total configs analyzed: {total_processed}")
        print(f"Countries detected: {len([c for c in country_map.keys() if c != 'XX'])}")
        print("\n📊 Configs per country:")
        
        sorted_countries = sorted([(c, len(configs)) for c, configs in country_map.items() if c != 'XX'], key=lambda x: x[1], reverse=True)
        
        for country_code, count in sorted_countries[:20]:
            iran_flag = "🇮🇷" if country_code == 'IR' else ""
            print(f"  {country_code} {iran_flag}: {count} configs")
        
        if 'XX' in country_map:
            print(f"\n⚠️ Unknown location: {len(country_map['XX'])} configs")
        
        print("=" * 60)

def main():
    print("=" * 60)
    print("ARISTA GEOLOCATION ANALYZER")
    print("=" * 60)
    
    analyzer = GeolocationAnalyzer()
    
    combined_configs_path = 'configs/combined/all.txt'
    
    if not os.path.exists(combined_configs_path):
        print("Combined configs not found. Please run combine_configs.py first.")
        return
    
    configs = []
    with open(combined_configs_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                configs.append(line)
    
    print(f"Loaded {len(configs)} configs for geolocation analysis")
    print("Analyzing IP addresses and detecting service locations...\n")
    
    analyzed, country_map, protocol_country_map = analyzer.process_configs(configs)
    
    total_countries, total_configs = analyzer.save_country_configs(country_map, protocol_country_map)
    
    analyzer.generate_report(country_map, len(configs))
    
    print(f"\n✅ GEOLOCATION COMPLETE")
    print(f"Configs saved in configs/country/:")
    print(f"  • {total_countries} country directories")
    print(f"  • {total_configs} geolocated configs")
    print(f"  • meta.json files with detailed statistics")
    print("=" * 60)

if __name__ == "__main__":
    main()
