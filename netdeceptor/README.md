<p align="center">
  <img src="assets/logo.png" alt="NetDeceptor Desktop Logo" width="180">
</p>

<h1 align="center">NetDeceptor Desktop</h1>
<p align="center"><b>Enterprise Honeypot & Threat Inspector</b></p>
# NetDeceptor

NetDeceptor can run either as a desktop dashboard or as a foreground headless
honeypot process. The headless mode does not require PyQt6.

## Project layout

- `app.py` is the backward-compatible launcher.
- `netdeceptor/config.py` loads and validates application settings.
- `netdeceptor/database.py` stores events and verifies the hash chain.
- `netdeceptor/services.py` contains classification, notifications, rate limiting,
  geolocation, and firewall-defense helpers.
- `netdeceptor/engine.py` runs the asyncio honeypot and traffic simulator.
- `netdeceptor/reports.py` exports CSV, JSON, and optional PDF reports.
- `netdeceptor/dashboard.py` contains the desktop UI and its Python/JavaScript bridge.
- `netdeceptor/cli.py` selects desktop or headless startup.
- `netdeceptor/compat.py` provides shared paths, standard-library imports, and
  optional PyQt compatibility for headless installs.

## Headless mode

Run from the project directory:

```powershell
python app.py --headless
```

The process listens on the enabled ports in `netdeceptor_config.json`, writes
events to `netdeceptor.db`, and exits cleanly when it receives Ctrl+C or a
termination signal. Paths can be overridden:

```powershell
python app.py --headless --config C:\NetDeceptor\config.json --db C:\NetDeceptor\events.db
```

On Linux, run the same foreground command under a supervisor such as systemd.
On Windows, use an approved service wrapper or supervisor; this script does not
install itself as a Windows Service.

The default bind address is `127.0.0.1`. Only change it to a network interface
address in an isolated, authorized test environment, and restrict inbound and
outbound traffic with host and network firewalls. Ports below 1024 may require
elevated privileges or may already be in use. Firewall blocking remains in
dry-run mode by default.

Use `python app.py --help` to see command-line options. Omitting `--headless`
continues to launch the desktop application.

## 🖥️ หน้าต่างการใช้งานและฟีเจอร์หลัก (Pages & Features)

โปรเจค **NetDeceptor** ถูกออกแบบมาด้วยหน้าจอแดชบอร์ดสไตล์ Dark SOC ที่มีความทันสมัยและใช้งานง่าย โดยแบ่งสัดส่วนการทำงานออกเป็นหน้าหลักต่างๆ ดังนี้:

### 1. Onboarding Wizard (วิซาร์ดแนะนำการใช้งานเบื้องต้น)
<p align="center">
  <img src="assets/wizard.png" alt="NetDeceptor Wizard" width="600">
</p>

- ปรากฏขึ้นมาอัตโนมัติเมื่อเริ่มใช้งานโปรแกรมครั้งแรก เพื่อแนะนำแนวคิดของฮันนีพอต (Honeypot) ใน 5 ขั้นตอนสั้นๆ
- ช่วยให้ผู้ใช้งานเข้าใจระบบการทำงาน การจำแนกประเภทการโจมตี การบันทึก Log ป้องกันการปลอมแปลง และระบบแจ้งเตือนภัยคุกคามได้อย่างรวดเร็ว

### 2. Dashboard (หน้าแดชบอร์ดหลัก)
- **Overview Metrics:** แสดงตัวชี้วัดสำคัญ เช่น จำนวนพอร์ตกับดักที่เปิดใช้งาน, จำนวนการโจมตีทั้งหมด, พอร์ตเป้าหมายยอดนิยม และ IP ล่าสุดของผู้บุกรุก
- **Timeline Chart:** กราฟแสดงสถิติการโจมตีย้อนหลัง 60 นาทีแบบเรียลไทม์
- **Network Mesh Visualizer:** แผนภาพอนิมชันจำลองเครือข่ายและการเชื่อมต่อของผู้บุกรุก
- **Telemetry Feed:** ฟีดแสดงข้อมูล Log การโจมตีสดๆ ที่ดึงมาจากฐานข้อมูล SQLite

### 3. Trap Config (หน้าตั้งค่าพอร์ตกับดัก)
- อนุญาตให้ผู้ใช้เปิด/ปิดพอร์ตกับดัก (เช่น FTP บนพอร์ต 21, SSH บนพอร์ต 22, HTTP บนพอร์ต 80 และ RDP บนพอร์ต 3389) ได้แบบไดนามิก
- สามารถแก้ไขข้อความ **Banner** ที่จะส่งไปล่อลวงผู้บุกรุกได้ทันทีโดยไม่ต้องรีสตาร์ตโปรแกรม และเลือกตั้งค่า Bind Address ได้ตามต้องการ

### 4. Alerts (หน้าตั้งค่าการแจ้งเตือน)
- ตั้งค่าการส่งข้อความแจ้งเตือนภัยคุกคามแบบเรียลไทม์ไปยังมือถือผ่าน **Telegram Bot** และ **LINE Messaging API**
- กำหนดระดับความรุนแรงขั้นต่ำในการแจ้งเตือน (เช่น เฉพาะ HIGH หรือทุกระดับ) พร้อมระบบหน่วงเวลา (Cooldown) ป้องกันการแจ้งเตือนรัวเกินไป

### 5. Defense (หน้าจัดการระบบป้องกันเชิงรุก)
- **Active Defense:** ควบคุมระบบบล็อก IP อันตรายที่ไฟร์วอลล์ของระบบปฏิบัติการอัตโนมัติ (รองรับ Windows Firewall ผ่าน `netsh` และ Linux ผ่าน `iptables`) พร้อมโหมดทดสอบ (Dry-run)
- **Rate Limiting:** ป้องกันการโจมตีแบบ DoS/Flood ด้วยระบบ Token Bucket ควบคุมอัตราการเชื่อมต่อต่อ IP
- **Blocked IPs Table:** ตารางแสดงรายชื่อ IP ที่ถูกบล็อก พร้อมปุ่มปลดบล็อก (Unblock) หรือเพิ่มเข้าสู่รายการยกเว้น (Whitelist)

### 6. Reports (หน้ารายงานความปลอดภัย)
- รองรับการส่งออกรายงานสรุปผลการตรวจสอบความปลอดภัยเป็นไฟล์ **PDF, CSV และ JSON** ตามช่วงเวลาที่ต้องการ (24 ชั่วโมง, 7 วัน, 30 วัน หรือทั้งหมด)
- **Log Integrity Verification:** ระบบตรวจสอบความสมบูรณ์ของ Log ด้วย **SHA-256 Hash Chain** เพื่อพิสูจน์ว่าข้อมูลในฐานข้อมูลไม่เคยถูกแก้ไขหรือลบย้อนหลัง

### 7. Simulator (หน้าตัวจำลองการโจมตี)
- มีชุดสถานการณ์จำลองการโจมตีในตัว (เช่น Port Scan, SSH Brute-force, SQL Injection, Log4Shell, DoS Flood)
- ทำหน้าที่ส่งทราฟฟิกจำลองเข้าพอร์ตของตัวเองเพื่อทดสอบปฏิกิริยาของระบบตั้งแต่การกรอง การบันทึก ไปจนถึงการแจ้งเตือน พร้อมหน้าจอเทอร์มินัลจำลองแสดงผลแบบสดๆ

### 8. Help (หน้าช่วยเหลือและตรวจสอบระบบ)
- **Interactive Flow Visualizer:** จำลองการไหลของข้อมูลผ่านกลไกต่างๆ ของระบบทีละขั้นตอน เพื่อให้อาจารย์หรือผู้ใช้งานเข้าใจสถาปัตยกรรมเชิงลึก
- **Self-Check Checklist:** ตรวจสอบความพร้อมของระบบ (ฐานข้อมูล, สิทธิ์ Admin, โทเคนแจ้งเตือน, ฟอนต์ PDF ฯลฯ) พร้อมคำแนะนำแนวทางแก้ไขเมื่อเกิดข้อผิดพลาด