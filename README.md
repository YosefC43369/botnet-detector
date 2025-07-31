# botnet-detector

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
