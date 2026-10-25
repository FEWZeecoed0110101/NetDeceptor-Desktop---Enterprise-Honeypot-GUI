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
NetDeceptor สามารถรันได้ทั้งในรูปแบบแดชบอร์ดเดสก์ท็อป (Desktop Dashboard) หรือเป็นกระบวนการฮันนีพอตแบบไม่มีหน้าจอ (Headless Honeypot) เบื้องหน้า โดยโหมด Headless นี้ไม่จำเป็นต้องใช้ PyQt6

โหมด Headless (Headless mode)
รันจากไดเรกทอรีโปรเจกต์:

PowerShell
python app.py --headless
กระบวนการนี้จะรอรับการเชื่อมต่อบนพอร์ตที่เปิดใช้งานในไฟล์ netdeceptor_config.json บันทึกเหตุการณ์ลงใน netdeceptor.db และปิดการทำงานอย่างเรียบร้อยเมื่อได้รับคำสั่ง Ctrl+C หรือสัญญาณยุติการทำงาน โดยสามารถระบุเส้นทาง (Path) ใหม่ได้:

PowerShell
python app.py --headless --config C:\NetDeceptor\config.json --db C:\NetDeceptor\events.db
บน Linux ให้รันคำสั่งเบื้องหน้าเดียวกันนี้ภายใต้ตัวจัดการกระบวนการ (Supervisor) เช่น systemd ส่วนบน Windows ให้ใช้ตัวห่อหุ้มบริการ (Service wrapper) หรือตัวจัดการที่ได้รับอนุมัติ เนื่องจากสคริปต์นี้ไม่ได้ติดตั้งตัวเองเป็น Windows Service

ที่อยู่ Bind เริ่มต้นคือ 127.0.0.1 ควรเปลี่ยนเป็นที่อยู่ของอินเทอร์เฟซเครือข่ายเฉพาะในสภาพแวดล้อมทดสอบที่แยกต่างหากและได้รับอนุญาตแล้วเท่านั้น พร้อมทั้งจำกัดการรับส่งข้อมูลขาเข้าและขาออกด้วยไฟร์วอลล์ของโฮสต์และเครือข่าย พอร์ตที่ต่ำกว่า 1024 อาจต้องใช้สิทธิ์ระดับสูงหรืออาจถูกใช้งานอยู่แล้ว การบล็อกผ่านไฟร์วอลล์จะยังคงอยู่ในโหมดจำลอง (Dry-run) ตามค่าเริ่มต้น
ภาพรวมโปรเจค (Overview)NetDeceptor คือระบบ Enterprise Honeypot และ Threat Inspector (ระบบฮันนีพอตและตรวจสอบภัยคุกคามทางไซเบอร์ระดับองค์กร) ที่พัฒนาขึ้นด้วยภาษา Python (ใช้ AsyncIO เพื่อประสิทธิภาพสูง) โดยทำหน้าที่เป็น "กับดัก" เพื่อล่อลวง ตรวจจับ และบันทึกพฤติกรรมของผู้บุกรุกที่พยายามเข้ามาโจมตีระบบเครือข่าย   2. แนวคิดการทำงาน (How It Works)เปิดพอร์ตล่อลวง (Trap Ports): จำลองบริการยอดนิยมที่มักตกเป็นเป้าหมาย เช่น FTP (พอร์ต 21), SSH (พอร์ต 22), HTTP (พอร์ต 80), SMB และ RDP (พอร์ต 3389) พร้อมส่งป้ายต้อนรับ (Banner) หลอกๆ เพื่อให้ผู้โจมตีตายใจ   ดักจับและวิเคราะห์ (Capture & Classify): เมื่อมีผู้โจมตีส่ง Payload หรือพยายามเจาะระบบเข้ามา ระบบจะใช้ Regex Signatures และกฎพฤติกรรมเพื่อจำแนกประเภทการโจมตี (เช่น SQL Injection, Brute-force, Port Scan, DoS) พร้อมคำนวณคะแนนภัยคุกคาม (Threat Score 0–100)   3. ฟีเจอร์เด่นที่น่าสนใจ (Key Features for Presentation)🔒 Log ป้องกันการปลอมแปลง (Tamper-Evident Log): ข้อมูลการโจมตีจะถูกบันทึกลงฐานข้อมูล SQLite และร้อยเรียงกันด้วย SHA-256 Hash Chain ทำให้หากมีใครแอบแก้หรือลบ Log ย้อนหลัง ระบบจะตรวจพบความผิดปกติได้ทันที   🛡️ ระบบป้องกันเชิงรุก (Active Defense): สามารถสั่งบล็อก IP ของผู้โจมตีที่ไฟร์วอลล์ของระบบปฏิบัติการอัตโนมัติ (รองรับ Windows Firewall ผ่าน netsh และ Linux ผ่าน iptables) โดยมีโหมดทดสอบ (Dry-run) ป้องกันการบล็อกผิดพลาด   📱 แจ้งเตือนภัยแบบเรียลไทม์ (Real-time Alerts): ส่งข้อความแจ้งเตือนเข้ามือถือทันทีผ่าน Telegram Bot หรือ LINE Messaging API เมื่อตรวจพบการโจมตีระดับสูง   🌍 ระบุพิกัดประเทศ (Offline GeoIP): ตรวจสอบประเทศต้นทางของผู้โจมตีแบบออฟไลน์ด้วยฐานข้อมูล MaxMind GeoLite2   📊 แดชบอร์ดและรายงานครบวงจร (Dashboard & Reports): มีหน้าจอ GUI สไตล์ Dark SOC ที่สร้างด้วย PyQt6 และ WebEngine พร้อมฟังก์ชันส่งออกรายงานความปลอดภัยเป็นไฟล์ PDF, CSV และ JSON สำหรับผู้บริหาร   4. สถาปัตยกรรมทางเทคโนโลยี (Tech Stack)Backend: Python (AsyncIO สำหรับจัดการเน็ตเวิร์กพร้อมกันหลายๆ พอร์ต, SQLite สำหรับจัดการข้อมูล)   Frontend / GUI: PyQt6, QWebChannel ร่วมกับ HTML5, Tailwind CSS และ JavaScript สำหรับแสดงผล Dashboard แบบเรียลไทม์   Reporting: ReportLab (สำหรับสร้างรายงาน PDF ภาษาไทย)   

# 🛡️ NetDeceptor Desktop (Enterprise Honeypot & Threat Inspector)

ระบบฮันนีพอตและตรวจสอบภัยคุกคามทางไซเบอร์แบบครบวงจร พัฒนาด้วยภาษา Python และ PyQt6 สำหรับตรวจจับและวิเคราะห์พฤติกรรมการโจมตีในระบบเครือข่าย

## 🚀 Key Features
- **Multi-Service Traps:** จำลองพอร์ตยอดนิยม (FTP, SSH, HTTP, RDP) พร้อมแบนเนอร์ล่อลวง
- **Tamper-Evident Logs:** ระบบบันทึก Log ป้องกันการแก้ไขด้วย SHA-256 Hash Chain
- **Active Defense:** ระบบบล็อก IP ผู้โจมตีอัตโนมัติที่ระดับ Firewall (Windows/Linux)
- **Real-time Alerts:** แจ้งเตือนเหตุการณ์ผ่าน Telegram และ LINE API
- **Modern GUI Dashboard:** หน้าจอควบคุมสไตล์ SOC สวยงามและใช้งานง่าย

## 📦 Installation & Quick Start
1. Clone repository:
   ```bash
   git clone [https://github.com/FEWZeecoed0110101/NetDeceptor-Desktop---Enterprise-Honeypot-GUI.git](https://github.com/FEWZeecoed0110101/NetDeceptor-Desktop---Enterprise-Honeypot-GUI.git)
Install dependencies:

Bash
pip install -r requirements.txt
Run the application:

Bash
python app.py

---

### 2. ตั้งค่าช่อง "About" (แถบขวาบนของหน้าเว็บ GitHub)
คลิกที่รูปเฟือง ⚙️ ตรงมุมขวาบนของกล่อง About แล้วปรับแก้ข้อมูลให้ดูเป็นทางการและสื่อถึงทักษะทางเทคนิค:
* **Description:** เปลี่ยนจากข้อความเล่นๆ เป็นคำอธิบายเชิงวิชาการหรือโปรเจค เช่น:
  > *"An enterprise-grade Python AsyncIO honeypot and threat intelligence dashboard featuring a PyQt6 user interface, active firewall defense, and cryptographic log verification."*
* **Website:** ถ้ามีเว็บเดโมหรือวิดีโอพรีเซนต์ใน YouTube ให้ใส่ลิงก์ไว้ตรงนี้ได้เลย

---

### 3. ใส่ Topics / Tags (ป้ายกำกับโปรเจค)
ในกล่อง About เดียวกัน ให้ใส่แท็กคำค้นหา (Topics) เพื่อให้อาจารย์หรือระบบค้นหาเจอโปรเจคเราได้ง่ายขึ้น เช่น:
* `python`
* `cybersecurity`
* `honeypot`
* `pyqt6`
* `network-security`
* `asyncio`
* `tcas-portfolio`

---

### 4. เพิ่มรูปภาพ Screenshots ของโปรแกรม
* แคปเจอร์หน้าจอแดชบอร์ดสวยๆ ของโปรแกรม NetDeceptor
* อัปโหลดรูปนั้นเข้าไปใน GitHub (ลากไฟล์รูปมาวางตอน Edit README หรือสร้างโฟลเดอร์ `assets/` เก็บไว้) แล้วดึงลิงก์มาแสดงใน README เพื่อให้หน้าพอร์ตดูมีชีวิตชีวาและน่าเชื่อถือขึ้นทันที

---

### 5. เพิ่มไฟล์ `LICENSE`
* กดปุ่ม **Add file** -> **Create new file** ในหน้าแรกของ Repo ตั้งชื่อว่า `LICENSE`
* กดเลือก Template เป็น **MIT License** (เป็นสากลและนิยมใช้กันทั่วไป) แล้วกด Commit เพื่อแสดงว่าโปรเจคนี้เปิดให้ศึกษาและเป็นระเบียบเรียบร้อย

การแต่ง GitHub ให้เนี้ยบแบบนี้จะช่วยเสริมพอร์ตคอมพิวเตอร์/วิศวกรรมคอมพิวเตอร์ของคุณให้ดูโดดเด่นและแสดงถึงศั
