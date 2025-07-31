<img width="210" height="31" alt="image" src="https://github.com/user-attachments/assets/7e87754c-5c53-4d59-9f76-db938a20f3e3" /># botnet-detector

🔍 Advanced Botnet Detection Script
Advanced network security tool สำหรับตรวจจับและวิเคราะห์กิจกรรมของ botnet บน Kali Linux

** โปรเจกต์นี้เป็นสคริปต์ที่ถูกใช้จริงในสงครามระหว่าง ไทย-กัมพูชา เมื่อแฮ็กเกอร์กัมพูชาใช้ botnet ในการโจมตีเว็บไซต์ราชการของไทย ทางผู้เขียนได้สร้างสคริปต์สำหรับตรวจจับ botnet และบล็อก ip ที่มาจากฝั่งกัมพูขา และได้มีการปรับปรุงตัวสคริปต์จนครบถ้วนสมบูรณ์

🎯 ความสามารถหลัก
- วิเคราะห์ Network Traffic - ตรวจสอบ TCP connections และ DNS queries
- ตรวจจับ DGA Domains - หา domains ที่สร้างด้วย Domain Generation Algorithm
- Monitor System Processes - ตรวจสอบ processes ที่น่าสงสัย
- Port Scan Detection - ตรวจจับการ scan ports
- C&C Communication - หาการเชื่อมต่อกับ Command & Control servers
- Website-Specific Analysis - วิเคราะห์เว็บไซต์เฉพาะเพื่อหา botnet indicators
- DDoS Attack Detection - ตรวจจับการโจมตี DDoS

🛠️ การติดตั้ง
ความต้องการระบบ
- Kali Linux (แนะนำ)
- Python 3.7+
- Root privileges (สำหรับ packet capture)

# Dependencies
```bash
# อัปเดท system
$ sudo apt update

# ติดตั้ง Python packages
$ pip3 install -r requirements.txt

# ตรวจสอบ tools ที่จำเป็น (มักมีอยู่แล้วใน Kali)
$ which nmap hping3 dig curl
```
# Clone Repository

```bash
$ git clone https://github.com/yourusername/botnet-detector.git
$ cd botnet-detector
$ chmod +x botnet_detector.py
```

# 🚀 การใช้งาน

## 1. General Monitoring (ตรวจสอบทั่วไป)

```bash
# ตรวจสอบ botnet ทั่วไป 5 นาที
$ sudo python3 botnet_detector.py --mode general --duration 300

# ตรวจสอบแบบ verbose
$ sudo python3 botnet_detector.py --mode general --duration 600 --verbose
```

## 2. Website Analysis (วิเคราะห์เว็บไซต์เฉพาะ)

```bash
# วิเคราะห์เว็บไซต์เป้าหมาย
$ sudo python3 botnet_detector.py --mode website --target https://kuyscambodia.com --duration 600

# ตรวจสอบเว็บไซต์ที่สงสัยว่าถูกโจมตี
$ sudo python3 botnet_detector.py --mode website --target vulnerable-site.com --duration 900
```

## 3. Quick Infrastructure Scan (สแกนโครงสร้างเร็ว)

```bash
# สแกนโครงสร้างเครือข่ายอย่างรวดเร็ว
$ sudo python3 botnet_detector.py --mode scan --target suspicious-domain.com

# สแกนหลาย domains
for domain in site1.com site2.com site3.com; do
    sudo python3 botnet_detector.py --mode scan --target $domain
done
```

# 🔍 สิ่งที่สคริปต์จะตรวจสอบ

Infrastructure Analysis

- Port scanning (nmap integration)
- Service fingerprinting
- DNS record analysis
- WHOIS information
- Suspicious open ports (IRC, P2P, backdoor ports)

Botnet Indicators

- IRC botnet ports (6667, 6668, 6669)
- HTTP botnet panels (/panel/, /admin/, /gate.php)
- P2P botnet communications
- Command & Control server connections
- Domain Generation Algorithm (DGA) domains

Attack Detection

- DDoS attack patterns
- SYN flood attacks
- Coordinated botnet attacks
- High request rate anomalies
- Bot traffic signatures

HTTP Analysis

- Response time analysis
- Rate limiting detection (429, 503 errors)
- Suspicious HTTP headers
- Botnet panel keywords detection

# 📊 Output Files

- `botnet_detection.log` - การบันทึกรายละเอียด
- `suspicious_ips.json` - รายชื่อ IP ที่น่าสงสัย
- `botnet_report_YYYYMMDD_HHMMSS.json` - รายงานสรุป

# 🎯 Use Cases

## 1. Website Owner Protection

```bash
# ตรวจสอบเว็บไซต์ของคุณเองว่าถูกโจมตีหรือไม่
$ sudo python3 botnet_detector.py --mode website --target https://cambodiahuakuy.com --duration 1800
```

## 2. Security Research

```bash
# วิเคราะห์เว็บไซต์ที่สงสัยว่าเป็น C&C server
$ sudo python3 botnet_detector.py --mode scan --target suspicious-c2-server.com
```

## 3. Network Monitoring

```bash
# ตรวจสอบ network traffic ใน environment
$ sudo python3 botnet_detector.py --mode general --duration 3600 --verbose
```

# ⚙️ Configuration

สามารถปรับแต่งค่าต่าง ๆ ในไฟล์:

```python
# ปรับ detection thresholds
self.detection_threshold = {
    'connection_rate': 100,    # connections/minute
    'dns_queries': 50,         # queries/minute  
    'port_scan': 20,           # ports scanned
    'ddos_requests': 1000,     # requests/minute
    'bot_requests': 50         # suspicious requests/minute
}

# เพิ่ม C&C domains
self.c2_domains.extend([
    'your-known-c2.com',
    'malware-panel.net'
])
```

# ⚠️ ข้อควรระวัง

- Legal Usage : ใช้เฉพาะกับเว็บไซต์ที่คุณมีสิทธิ์หรือได้รับอนุญาต
- Root Privileges : จำเป็นต้องใช้ sudo สำหรับ packet capture
- Network Impact : การสแกนอาจส่งผลต่อ network performance
- False Positives : ตรวจสอบผลลัพธ์อย่างระมัดระวัง

# 🔧 Advanced Features

- Real-time packet analysis
- Machine learning-based DGA detection
- Integration with threat intelligence feeds
- Custom alert systems
- Network forensics capabilities

# ⚠️ Disclaimer: เครื่องมือนี้สำหรับการใช้งานด้านการป้องกันและการศึกษาเท่านั้น ผู้ใช้ต้องรับผิดชอบในการใช้งานอย่างถูกกฎหมายและจริยธรรม

![botnet_detect2](https://github.com/user-attachments/assets/860dd1a3-48d7-4ca9-81e1-8a9f2635b443)
![botnet_detect3](https://github.com/user-attachments/assets/3d09dd1e-6047-4af6-9634-32f67782d4bd)
![botnet_detect 1](https://github.com/user-attachments/assets/c4c4abf2-51ce-4fff-a9fe-bdb28c07373d)
