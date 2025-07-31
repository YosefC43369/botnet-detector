import socket
import threading
import time
import json
import logging
import argparse
import subprocess
import sys
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import re
import hashlib
import psutil
import requests
from urllib.parse import urlparse
from scapy.all import sniff, IP, TCP, UDP, DNS, ICMP, sr1
import whois
import dns.resolver

# logging settings
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('botnet_detection.log'),
        logging.StreamHandler()
    ]
)

class BotnetDetector:
    def __init__(self, target_website=None):
        self.target_website = target_website
        self.suspicious_ips = set()
        self.connection_counts = defaultdict(int)
        self.dns_queries = defaultdict(list)
        self.port_scans = defaultdict(set)
        self.ddos_patterns = defaultdict(list)
        self.bot_signatures = []
        self.target_ip = None
        
        # Kali Linux tools paths
        self.tools = {
            'nmap': '/usr/bin/nmap',
            'hping3': '/usr/sbin/hping3',
            'dig': '/usr/bin/dig',
            'curl': '/usr/bin/curl'
        }
        
        self.c2_domains = [
            'malicious-c2.com',
            'botnet-control.net',
            'evil-command.org',
            'mirai-c2.net'
        ]
        
        self.suspicious_ports = {
            1337, 31337, 12345, 54321, 9999, 6666, 4444, 8080, 3128
        }
        
        self.detection_threshold = {
            'connection_rate': 100,
            'dns_queries': 50,
            'port_scan': 20,
            'ddos_requests': 1000,  # requests per minute
            'bot_requests': 50      # suspicious requests per minute
        }
        
        self.start_time = datetime.now()
        
        # Initialize target website analysis
        if self.target_website:
            self.initialize_target_analysis()
    def initialize_target_analysis(self):
        """เตรียมข้อมูลสำหรับวิเคราะห์เว็บไซต์เป้าหมาย"""
        try:
            parsed_url = urlparse(self.target_website)
            domain = parsed_url.netloc or parsed_url.path
            
            # Resolve target IP
            self.target_ip = socket.gethostbyname(domain)
            logging.info(f"Target website: {self.target_website} -> {self.target_ip}")
            
            # Get website info
            self.get_website_info(domain)
            
        except Exception as e:
            logging.error(f"Error initializing target analysis: {e}")
            
    def get_website_info(self, domain):
        """รวบรวมข้อมูลเว็บไซต์"""
        try:
            # WHOIS lookup
            try:
                w = whois.whois(domain)
                logging.info(f"Domain registrar: {w.registrar}")
                logging.info(f"Creation date: {w.creation_date}")
            except Exception as e:
                logging.warning(f"WHOIS lookup failed: {e}")
                
        except Exception as e:
            logging.error(f"Error getting website info: {e}")
            
    def scan_target_infrastructure(self):
        """สแกนโครงสร้างเครือข่ายของเป้าหมาย"""
        if not self.target_ip:
            return
        
        print(f"🔍 Scanning target infrastructure: {self.target_ip}")
        
        # Port scan with nmap
        self.nmap_scan()
        
        # Check for common botnet indicators
        self.check_botnet_indicators()
        
        # Analyze HTTP headers
        self.analyze_http_headers()
        
    def nmap_scan(self):
        """ใช้ nmap สแกน ports และ services"""
        try:
            if not self.check_tool_availability('nmap'):
                return
            
            cmd = [
                'nmap', '-sS', '-O', '-sV', '-A',
                '--script=http-enum,http-headers,http-methods',
                '-p', '1-1000',
                self.target_ip
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                logging.info("Nmap scan completed")
                self.analyze_nmap_results(result.stdout)
            else:
                logging.error(f"Error running nmap: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            logging.warning("Nmap scan timed out")
        except Exception as e:
            logging.error(f"Error running nmap: {e}")
            
    def analyze_nmap_results(self, nmap_output):
        """วิเคราะห์ผลลัพธ์จาก nmap"""
        lines = nmap_output.split('\n')
        
        # Look for suspicious services
        suspicious_services = ['backdoor', 'trojan', 'malware', 'botnet']
        
        for line in lines:
            line_lower = line.lower()
            for service in suspicious_services:
                if service in line_lower:
                    logging.warning(f"Suspicious services detected: {line.strip()}")
                    
                # Check for uncommon ports
                if '/tcp' in line and 'open' in line:
                    try:
                        port = int(line.split('/')[0])
                        if port in self.suspicious_ports:
                            logging.warning(f"Suspicious port open: {port}")
                    except:
                        pass
                    
    def check_botnet_indicators(self):
        """ตรวจสอบสัญญาณของบ็อตเน็ต"""
        indicators = []
        
        # Check for IRC botnet (common ports 6667, 6668, 6669)
        irc_ports = [6667, 6668, 6669]
        for port in irc_ports:
            if self.check_port_open(self.target_ip, port):
                indicators.append(f"IRC port {port} open - possible IRC botnet")
                
        if self.check_port_open(self.target_ip, 80) or self.check_port_open(self.target_ip, 8080):
            indicators.extend(self.check_http_botnet_patterns())
            
        # Check for HTTP botnet (port 80, 8080 with suspicious patterns)
        if self.check_port_open(self.target_ip, 80) or self.check_port_open(self.target_ip, 8080):
            indicators.extend(self.check_http_botnet_patterns())
            
        # Check for P2P botnet indicators
        p2p_ports = [4444, 5555, 7777, 8888, 9999]
        open_p2p_ports = [port for port in p2p_ports if self.check_port_open(self.target_ip, port)]
        if len(open_p2p_ports) > 2:
            indicators.append(f"Multiple P2P ports open: {open_p2p_ports}")
            
        if indicators:
            logging.warning("Botnet indicators found:")
            for indicator in indicators:
                logging.warning(f"  - {indicators}")
                
        return indicators
    
    def check_port_open(self, ip, port, timeout=3):
        """ตรวจสอบว่า port เปิดอยู่หรือไม่"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
        
    def check_http_botnet_patterns(self):
        """ตรวจสอบ HTTP patterns ที่เป็นลักษณะของ botnet"""
        patterns = []
        
        try:
            # Test common botnet panel paths
            botnet_paths = [
                '/panel/', '/admin/', '/bot/', 'control/',
                '/gate.php', '/panel.php', '/admin.php',
                '/stats.php', '/logs.php'
            ]
            
            for path in botnet_paths:
                url = f"http://{self.target_ip}{path}"
                try:
                    response = requests.get(url, timeout=5, allow_redirects=False)
                    if response.status_code == 200:
                        # Check for botnet panel indicators in content
                        content = response.text.lower()
                        botnet_keywords = ['bot count', 'infected', 'zombie', 'command', 'panel']
                        
                        for keyword in botnet_keywords:
                            if keyword in content:
                                patterns.append(f"Botnet panel found at {path}")
                                break
                            
                except requests.RequestException:
                    pass
                
        except Exception as e:
            logging.error(f"Error checking HTTP botnet patterns: {e}")
            
        return patterns
    
    def analyze_http_headers(self):
        """วิเคราะห์ HTTP headers เพื่อหา botnet indicators"""
        try:
            url = f"http://{self.target_ip}"
            response = requests.get(url, timeout=10)
            
            headers = response.headers
            
            # Check for suspicious headers
            suspicious_headers = {
                'server': ['botnet', 'malware', 'trojan'],
                'x-powered-by': ['bot', 'panel'],
                'x-bot-version': None,  # Any value is suspicious
                'x-admin-panel': None
            }
            
            for header, suspicious_values in suspicious_headers.items():
                if header in headers:
                    header_value = headers[header].lower()
                    
                    if suspicious_values is None:
                        logging.warning(f"Suspicious header found: {header}: {headers[header]}")
                    else:
                        for suspicious in suspicious_values:
                            if suspicious in header_value:
                                logging.warning(f"Suspicious header value: {header}: {headers[header]}")
                                break
                            
        except Exception as e:
            logging.warning(f"Could not analyze HTTP headers: {e}")
            
    def monitor_ddos_attacks(self):
        """ตรวจสอบ DDoS attacks ที่มุ่งเป้าไปยังเว็บไซต์"""
        if not self.target_ip:
            return
        
        print(f"🛡️ Monitoring DDoS attacks against {self.target_ip}")
        
        # Start packet capture focused on target
        try:
            filter_str = f"host {self.target_ip}"
            sniff(
                filter=filter_str,
                prn=self.analyze_ddos_packet,
                timeout=60,
                store=False
            )
        except Exception as e:
            logging.error(f"Error monitoring DDoS: {e}")
            
    def analyze_ddos_packet(self, packet):
        """วิเคราะห์ packets เพื่อหา DDoS patterns"""
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # Focus on traffic to target
                if dst_ip == self.target_ip:
                    current_time = datetime.now()
                    self.ddos_patterns[src_ip].append(current_time)
                    
                    # Check for high request rate from single IP
                    recent_requests = [
                        req_time for req_time in self.ddos_patterns[src_ip]
                        if (current_time - req_time).total_seconds() < 60
                    ]
                    
                    if len(recent_requests) > self.detection_threshold['ddos_requests']:
                        self.flag_suspicious_ip(src_ip, f"DDoS attack detected - {len(recent_requests)} requests/minute")
                        
                    # Check for SYN flood
                    if TCP in packet and packet[TCP].flags == 2:    # SYN flag
                        syn_requests = [
                            req_time for req_time in self.ddos_patterns[src_ip]
                            if (current_time - req_time).total_seconds() < 10
                        ]
                        if len(syn_requests) > 100:
                            self.flag_suspicious_ip(src_ip, "SYN flood attack detected")
                            
        except Exception as e:
            logging.error(f"Error analyzing DDoS packet: {e}")
            
    def detect_bot_traffic_patterns(self):
        """ตรวจจับ traffic patterns ที่เป็นลักษณะของ bot"""
        print("🤖 Analyzing bot traffic patterns...")
        
        # Monitor HTTP requests to target
        self.monitor_http_bot_patterns()
        
        # Check for coordinated attacks
        self.detect_coordinated_attacks()
        
    def monitor_http_patterns(self):
        """ตรวจสอบ HTTP request patterns ของ bots"""
        if not self.target_ip:
            return
        
        try:
            # Simulate monitoring by making test requests and analyzing responses
            bot_indicators = []
            
            response_times = []
            for _ in range(5):
                start_time = time.time()
                try:
                    requests.get(f"http://{self.target_ip}", timeout=10)
                    response_time = time.time() - start_time
                    response_times.append(response_time)
                except:
                    response_times.append(10)
                time.sleep(1)
                
            avg_response_time = sum(response_times) / len(response_times)
            if avg_response_time > 5:
                bot_indicators.append(f"Slow response time: {avg_response_time:.2f}s (possible DDoS)")
                
            # Check for rate limiting response
            try:
                response = requests.get(f"http://{self.target_ip}")
                if response.status_code == 429:
                    bot_indicators.append("Rate limiting detected (429 Too Many Requests)")
                elif response.status_code == 503:
                    bot_indicators.append("Service unavailable (503) - possible overload")
            except:
                pass
            
            if bot_indicators:
                logging.warning("Bot traffic indicators:")
                for indicator in bot_indicators:
                    logging.warning(f"  - {indicator}")
                    
        except Exception as e:
            logging.error(f"Error monitoring HTTP bot patterns: {e}")
            
    def detect_coordinated_attacks(self):
        """ตรวจจับการโจมตีแบบประสาน"""
        if len(self.suspicious_ips) > 5:
            logging.warning(f"Multiple suspicious IPs detected: {len(self.suspicious_ips)}")
            logging.warning("Possible coordinated botnet attack")
            
            # Check if attacks are synchronized
            attack_times = []
            for ip in self.suspicious_ips:
                if ip in self.ddos_patterns:
                    attack_times.extend(self.ddos_patterns[ip])
                    
            if len(attack_times) > 10:
                # Time check clustering
                attack_times.sort()
                time_diffs = [
                    (attack_times[i+1] - attack_times[i]).total_seconds()
                    for i in range(len(attack_times)-1)
                ]
                
                avg_time_diff = sum(time_diffs) / len(time_diffs)
                if avg_time_diff < 1:   # Less than 1 second apart
                    logging.warning("Highly synchronized attack pattern detected")
                    
    def check_tool_availability(self, tool):
        """ตรวจสอบว่า tool มีอยู้ในระบบหรือไม่"""
        if tool in self.tools:
            if subprocess.shutil.which(self.tools[tool]) or subprocess.shutil.which(tool):
                return True
            logging.warning(f"Tool {tool} not available")
            return False
            """วิเคราะห์แต่ละ packet"""
            try:
                if IP in packet:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    
                    # ตรวจสอบ TCP connections
                    if TCP in packet:
                        self.analyze_tcp_connection(src_ip, dst_ip, packet[TCP])
                        
                    # ตรวจสอบ DNS queries
                    if DNS in packet:
                        self.analyze_dns_query(src_ip, packet[DNS])
                        
            except Exception as e:
                logging.error(f"Error analyzing packet: {e}")
                
    def analyze_tcp_connection(self, src_ip, dst_ip, tcp_layer):
        """TCP connections analyze"""
        dst_port = tcp_layer.dport
        
        self.connection_counts[src_ip] += 1
        
        if dst_port in self.suspicious_ports:
            self.flag_suspicious_ip(src_ip, f"Connection to suspicious port {dst_port}")
            
        # ตรวจสอบ port scanning
        self.port_scans[src_ip].add(dst_port)
        if len(self.port_scans[src_ip]) > self.detection_threshold['port_scan']:
            self.flag_suspicious_ip(src_ip, "Port scanning detected")
            
    def analyze_dns_query(self, src_ip, dns_layer):
        """DNS queries analyze"""
        if dns_layer.qr == 0:   # DNS query
            query_name = dns_layer.qd.qname.decode('utf-8').rstrip('.')
            self.dns_queries[src_ip].append(query_name)
            
            # ตรวจสอบ C&C domains
            for c2_domain in self.c2_domains:
                if c2_domain in query_name:
                    self.flag_suspicious_ip(src_ip, f"DNS query to C&C domain: {query_name}")
                    
            # ตรวจสอบ DGA patterns
            if self.is_dga_domain(query_name):
                self.flag_suspicious_ip(src_ip, f"Possible DGA domain: {query_name}")
                
    def is_dga_domain(self, domain):
        """ตรวจสอบว่าเป็น DGA domain หรือไม่"""
        # ตรวจสอบ patterns ของ DGA
        domain_parts = domain.split('.')
        if len(domain_parts) < 2:
            return False
        
        subdomain = domain_parts[0]
        
        if len(subdomain) > 20:
            return True
        
        # ตรวจสอบ entropy
        entropy = self.calculate_entropy(subdomain)
        if entropy > 4.0:
            return True
        
        # ตรวจสอบ consonant-vowel ratio
        vowels = 'aeiou'
        consonants = sum(1 for c in subdomain.lower() if c.isalpha() and c not in vowels)
        vowel_count = sum(1 for c in subdomain.lower() if c in vowels)
        
        if vowel_count > 0 and consonants / vowel_count > 3:
            return True
        
        return False
    
    def calculate_entropy(self, string):
        """คำนวณ entropy ของ string"""
        if not string:
            return 0
        
        counts = Counter(string)
        length = len(string)
        entropy = 0
        
        for count in counts.values():
            p = count / length
            if p > 0:
                entropy -= p * (p ** 0.5)   # Simplified entropy calculation
                
        return entropy
    
    def flag_suspicious_ip(self, ip, reason):
        """ทำเครื่องหมาย IP ที่น่าสงสัย"""
        if ip not in self.suspicious_ips:
            self.suspicious_ips.add(ip)
            logging.warning(f"SUSPICIOUS IP DETECTED: {ip} - {reason}")
            self.take_action(ip, reason)
            
    def take_action(self, ip, reason):
        """ดำเนินการเมื่อพบ IP ที่น่าสงสัย"""
        # บันทึกข้อมูล
        alert = {
            'timestamp': datetime.now().isoformat(),
            'ip': ip,
            'reason': reason,
            'action': 'flagged'
        }
        
        # บันทึกลงไฟล์
        with open('suspicious_ips.json', 'a') as f:
            f.write(json.dumps(alert) + '\n')
            
        # ส่งแจ้งเตือน (สามารถเพิ่ม email หรือ webhook ได้)
        print(f"🚨 ALERT: {ip} flagged for {reason}")
        
    def monitor_system_processes(self):
        """ตรวจสอบ processes ที่น่าสงสัย"""
        suspicious_process_names = [
            'botnet', 'malware', 'trojan', 'keylogger',
            'backdoor', 'rootkit', 'spyware'
        ]
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                proc_name = proc.info['name'].lower()
                cmdline = ' '.join(proc.info['cmdline'] or []).lower()
                
                for suspicious in suspicious_process_names:
                    if suspicious in proc_name or suspicious in cmdline:
                        logging.warning(f"Suspicious process detected: {proc.info}")
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            
    def check_network_connectons(self):
        """ตรวจสอบ network connections"""
        connections = psutil.net_connections(kind='iter')
        
        for conn in connections:
            if conn.raddr:  # มี remote address
                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port
                
                # ตรวจสอบ suspicious ports
                if remote_port in self.suspicious_ports:
                    logging.warning(f"Connection to suspicious port: {remote_ip}:{remote_port}")
                    
    def analyze_traffic_patterns(self):
        """วิเคราะห์ patterns ของ traffic"""
        current_time = datetime.now()
        
        for ip, count in self.connection_counts.items():
            # ตรวจสอบ connection rate
            time_diff = (current_time - self.start_time).total_seconds() / 60
            if time_diff > 0:
                rate = count / time_diff
                if rate > self.detection_threshold['connection_rate']:
                    self.flag_suspicious_ip(ip, f"High connection rate: {rate:.2f}/min")
                    
        for ip, queries in self.dns_queries.items():
            # ตรวจสอบ DNS query rate
            time_diff = (current_time - self.start_time).total_seconds() / 60
            if time_diff > 0:
                rate = len(queries) / time_diff
                if rate > self.detection_threshold['dns_queries']:
                    self.flag_suspicious_ip(ip, f"High DNS query rate: {rate:.2f}/min")
                    
    def generate_report(self):
        """สร้างรายงาน"""
        report = {
            'scan_duration': str(datetime.now() - self.start_time),
            'target_website': self.target_website,
            'target_ip': self.target_ip,
            'suspicious_ips_count': len(self.suspicious_ips),
            'suspicious_ips': list(self.suspicious_ips),
            'total_connections': sum(self.connection_counts.values()),
            'total_dns_queries': sum(len(queries) for queries in self.dns_queries.values()),
            'ddos_sources': len([ip for ip in self.ddos_patterns if len(self.ddos_patterns[ip]) > 10]),
            'botnet_indicators': []
        }
        
        print("\n" + "="*60)
        print("🔍 BOTNET DETECTION REPORT")
        print("="*60)
        print(f"Scan Duration: {report['scan_duration']}")
        if self.target_website:
            print(f"Target Website: {report['target_website']} ({report['target_ip']})")
            print(f"Suspicious IPs Found: {report['suspicious_ips_count']}")
        print(f"Total Connections Monitored: {report['total_connections']}")
        print(f"Total DNS Queries: {report['total_dns_queries']}")
        print(f"Potential DDoS Sources: {report['ddos_sources']}")
        
        if self.suspicious_ips:
            print("\n🚨 SUSPICIOUS IPs:")
            for ip in self.suspicious_ips:
                print(f"    - {ip}")
                
        # Additional website-specific analysis
        if self.target_website:
            print(f"\n🌐 WEBSITE ANALYSIS ({self.target_website}):")
            if self.target_ip:
                print(f"    - Target IP: {self.target_ip}")
                
                # Check if target IP is in suspicious list
                if self.target_ip in self.suspicious_ips:
                    print("  - ⚠️  Target website IP flagged as suspicious!")
                else:
                    print("  - ✅ Target website IP appears clean")
                    
        # Save detailed report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f'botnet_report_{timestamp}.json'
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
            
        print(f"\n📄 Detailed report saved to: {report_file}")
        return report
    
    def start_website_monitoring(self, duration=600):   # 10 minute
        """F*ck u Scambodian"""
        if not self.target_website:
            print("❌ No target website specified")
            return
        
        print(f"🎯 Starting website-focused botnet detection...")
        print(f"Target: {self.target_website}")
        print(f"Duration: {duration} seconds")
        print("="*50)
        
        # Phase 1: Infrastructure scanning
        print("\n📡 Phase 1: Infrastructure Analysis")
        self.scan_target_infrastructure()
        
        # Phase 2: Traffic monitoring
        print("\n🌊 Phase 2: Traffic Monitoring")
        monitor_thread = threading.Thread(
            target=self.monitor_ddos_attacks
        )
        monitor_thread.daemon = True
        monitor_thread.start()
        
        # Phase 3: Bot pattern detection
        print("\n🤖 Phase 3: Bot Pattern Detection")
        pattern_thread = threading.Thread(
            target=self.detect_bot_traffic_patterns
        )
        pattern_thread.daemon = True
        pattern_thread.start()
        
         # Phase 4: General monitoring
        print("\n🔍 Phase 4: General Network Monitoring")
        capture_thread = threading.Thread(
            target=self.start_packet_capture,
            args=(duration,)
        )
        capture_thread.daemon = True
        capture_thread.start()
        
        # Continue monitoring
        end_time = time.time() + duration
        while time.time() < end_time:
            self.monitor_system_processes()
            self.check_network_connectons()
            self.analyze_traffic_patterns()
            time.sleep(15)
            
        # Wait for threads to complete
        for thread in [monitor_thread, pattern_thread, capture_thread]:
            thread.join(timeout=5)
            
        return self.generate_report()
    
    def start_monitoring(self, duration=300):   # 5 minute
        """เขมรหัวควย"""
        print(f"Starting botnet detection for {duration} seconds...")
        
        # เริ่ม packet capture ใน thread แยก นะจ๊ะ
        capture_thread = threading.Thread(
            target=self.start_packet_capture,
            args=(duration,)
        )
        capture_thread.daemon = True
        capture_thread.start()
        
        # ตรวจสอบ system processes และ connections
        end_time = time.time() + duration
        while time.time() < end_time:
            self.monitor_system_processes()
            self.check_network_connectons()
            self.analyze_traffic_patterns()
            time.sleep(10)
            
        capture_thread.join(timeout=5)
        
        self.generate_report()
        
    def start_packet_capture(self, duration):
        """เขมรยอดนักเคลม"""
        try:
            print("Starting packet capture...")
            sniff(
                prn=self.analyze_packet,
                timeout=duration,
                store=False
            )
        except Exception as e:
            logging.error(f"Error in packet capture: {e}")
            print("Note: Packet capture requires administrator/root privileges")
            
def main():
    """Function หลัก"""
    parser = argparse.ArgumentParser(
        description='🔍 Advanced Botnet Detection Script for Kali Linux',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # General botnet detection
  python3 botnet_detector.py --mode general --duration 300
  
  # Website-specific analysis
  python3 botnet_detector.py --mode website --target https://example.com --duration 600
  
  # Quick infrastructure scan
  python3 botnet_detector.py --mode scan --target example.com
        """
    )
    
    parser.add_argument(
        '--mode', 
        choices=['general', 'website', 'scan'], 
        default='general',
        help='Detection mode: general monitoring, website analysis, or quick scan'
    )
    
    parser.add_argument(
        '--target', 
        help='Target website URL or domain for analysis'
    )
    
    parser.add_argument(
        '--duration', 
        type=int, 
        default=300,
        help='Monitoring duration in seconds (default: 300)'
    )
    
    parser.add_argument(
        '--output', 
        help='Output directory for reports (default: current directory)'
    )
    
    parser.add_argument(
        '--verbose', '-v', 
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    print("🔍 Advanced Botnet Detection Script for Kali Linux")
    print("=" * 55)
    print("⚠️  Note: Some features require root privileges")
    print("📍 Optimized for Kali Linux environment\n")
    
    # Validate target for website/scan modes
    if args.mode in ['website', 'scan'] and not args.target:
        print("❌ Error: --target is required for website and scan modes")
        sys.exit(1)
    
    # Initialize detector
    detector = BotnetDetector(target_website=args.target)
    
    try:
        if args.mode == 'general':
            print("🌐 Starting general botnet detection...")
            detector.start_monitoring(duration=args.duration)
            
        elif args.mode == 'website':
            print(f"🎯 Starting website-specific analysis for: {args.target}")
            detector.start_website_monitoring(duration=args.duration)
            
        elif args.mode == 'scan':
            print(f"⚡ Quick infrastructure scan for: {args.target}")
            detector.scan_target_infrastructure()
            detector.generate_report()
            
    except KeyboardInterrupt:
        print("\n⏹️  Stopping botnet detection...")
        detector.generate_report()
    except PermissionError:
        print("❌ Permission denied. Please run with sudo for full functionality:")
        print("   sudo python3 botnet_detector.py [options]")
    except Exception as e:
        logging.error(f"Error in main execution: {e}")
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()