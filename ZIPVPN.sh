#!/bin/bash
# MULTI PLUS VPN - ZIVPN UDP + Web Panel (Admin + Reseller) - FULL (Ubuntu 20.04/22.04 Compatible)
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

ZIVPN_BIN="/usr/local/bin/zivpn"
ZIVPN_DIR="/etc/zivpn"
ZIVPN_CFG="${ZIVPN_DIR}/config.json"
ZIVPN_SVC="zivpn.service"

ADMIN_DIR="/opt/zivpn-admin"
APP_PY="${ADMIN_DIR}/app.py"
VENV="${ADMIN_DIR}/venv"
ENV_FILE="${ADMIN_DIR}/.env"
PANEL_SVC="zivpn-admin.service"

MAINT_PY="${ADMIN_DIR}/maint.py"
MAINT_SVC="zivpn-maint.service"
MAINT_TIMER="zivpn-maint.timer"

echo "==> Updating packages..."
apt-get update -y >/dev/null
apt-get upgrade -y >/dev/null
apt-get install -y python3-venv python3-pip openssl ufw curl jq wget zip unzip iptables >/dev/null

echo "==> Installing ZIVPN binary..."
systemctl stop ${ZIVPN_SVC} 2>/dev/null || true
wget -q https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64 -O "${ZIVPN_BIN}"
chmod +x "${ZIVPN_BIN}"

mkdir -p "${ZIVPN_DIR}"

cat > "${ZIVPN_CFG}" <<'JSON'
{
  "listen": ":5667",
  "cert": "/etc/zivpn/zivpn.crt",
  "key": "/etc/zivpn/zivpn.key",
  "obfs": "zivpn",
  "auth": {"mode": "passwords", "config": ["zi"]},
  "config": ["zi"]
}
JSON

echo "==> Generating TLS certificate..."
openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
  -subj "/C=US/ST=CA/L=LA/O=ZIVPN/CN=zivpn" \
  -keyout "${ZIVPN_DIR}/zivpn.key" -out "${ZIVPN_DIR}/zivpn.crt" >/dev/null 2>&1

cat >/etc/systemd/system/${ZIVPN_SVC} <<'EOF'
[Unit]
Description=ZIVPN UDP Server
After=network.target

[Service]
ExecStart=/usr/local/bin/zivpn server -c /etc/zivpn/config.json
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ${ZIVPN_SVC}

echo "==> Setting up NAT + Firewall..."
IFC=$(ip -4 route ls | awk '/default/ {print $5; exit}' || true)
IFC=${IFC:-eth0}
iptables -t nat -C PREROUTING -i "$IFC" -p udp --dport 6000:19999 -j REDIRECT --to-ports 5667 2>/dev/null || \

# --- Compat patch (main.sh): allow required ports in INPUT (idempotent) ---
if ! iptables -C INPUT -p udp --dport 5667 -j ACCEPT 2>/dev/null; then
  iptables -I INPUT -p udp --dport 5667 -j ACCEPT
fi
if ! iptables -C INPUT -p tcp --dport 8088 -j ACCEPT 2>/dev/null; then
  iptables -I INPUT -p tcp --dport 8088 -j ACCEPT
fi

if ! iptables -t nat -C PREROUTING -p udp --dport 6000:19999 -j REDIRECT --to-ports 5667 2>/dev/null; then
  iptables -t nat -A PREROUTING -p udp --dport 6000:19999 -j REDIRECT --to-ports 5667
fi

if command -v ufw >/dev/null 2>&1; then
  ufw allow 5667/udp >/dev/null 2>&1 || true

# --- Compat patch (main.sh): persist firewall rules if possible ---
if command -v netfilter-persistent >/dev/null 2>&1; then
  netfilter-persistent save >/dev/null 2>&1 || true
  netfilter-persistent reload >/dev/null 2>&1 || true
elif [ -d /etc/iptables ]; then
  iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
fi

  ufw allow 8088/tcp >/dev/null 2>&1 || true
fi

echo "==> Setting up Web Panel..."
mkdir -p "${ADMIN_DIR}"
python3 -m venv "${VENV}"
"${VENV}/bin/pip" install --upgrade pip >/dev/null 2>&1 || true
"${VENV}/bin/pip" install flask waitress >/dev/null

read -rp "Panel name [default: MULTI PLUS VPN]: " PANEL_NAME
PANEL_NAME=${PANEL_NAME:-MULTI PLUS VPN}

read -rp "Admin username [default: admin]: " ADMIN_USER
ADMIN_USER=${ADMIN_USER:-admin}

read -rp "Admin password [default: change-me]: " ADMIN_PASSWORD
ADMIN_PASSWORD=${ADMIN_PASSWORD:-change-me}

read -rp "Panel port [default: 8088]: " PANEL_PORT
PANEL_PORT=${PANEL_PORT:-8088}

read -rp "Bandwidth interface (eth0/ens3) [default: auto]: " BW_IFACE
BW_IFACE=${BW_IFACE:-}

WA_NUMBER="6287873951705"

cat > "${ENV_FILE}" <<EOF
PANEL_NAME=${PANEL_NAME}
ADMIN_USER=${ADMIN_USER}
ADMIN_PASSWORD=${ADMIN_PASSWORD}
BIND_HOST=0.0.0.0
BIND_PORT=${PANEL_PORT}
ZIVPN_CONFIG=${ZIVPN_CFG}
ZIVPN_SERVICE=${ZIVPN_SVC}
BW_IFACE=${BW_IFACE}
WA_NUMBER=${WA_NUMBER}
EOF

cat > "${APP_PY}" <<'PY'
#!/usr/bin/env python3
import os, json, sqlite3, tempfile, subprocess, time, zipfile, io
from subprocess import DEVNULL
from datetime import datetime, timedelta
from flask import Flask, request, redirect, url_for, session, render_template_string, flash, jsonify, send_file

DB="/var/lib/zivpn-admin/zivpn.db"
os.makedirs("/var/lib/zivpn-admin", exist_ok=True)

ZIVPN_CFG=os.getenv("ZIVPN_CONFIG","/etc/zivpn/config.json")
ZIVPN_SVC=os.getenv("ZIVPN_SERVICE","zivpn.service")

PANEL_NAME=os.getenv("PANEL_NAME","MULTI PLUS VPN")
ADMIN_USER=os.getenv("ADMIN_USER","admin")
ADMIN_PASS=os.getenv("ADMIN_PASSWORD","change-me")
WA_NUMBER=os.getenv("WA_NUMBER","6287873951705")

BW_IFACE=os.getenv("BW_IFACE","").strip()
_bw_prev = {}

app=Flask(__name__)
app.secret_key=os.urandom(24)

def db():
    c=sqlite3.connect(DB)
    c.row_factory=sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL;")
    c.execute("PRAGMA synchronous=NORMAL;")
    return c

def init_db():
    with db() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS resellers(
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            max_users INTEGER DEFAULT 0,
            expires_at TEXT DEFAULT '',
            created_at TEXT
        )""")
        con.execute("""CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            expires_at TEXT,
            reseller_id INTEGER DEFAULT NULL,
            created_at TEXT,
            FOREIGN KEY(reseller_id) REFERENCES resellers(id)
        )""")
init_db()

def migrate_db():
    with db() as con:
        cols = [r[1] for r in con.execute("PRAGMA table_info(resellers)")]
        if "max_users" not in cols:
            con.execute("ALTER TABLE resellers ADD COLUMN max_users INTEGER DEFAULT 0")
        if "expires_at" not in cols:
            con.execute("ALTER TABLE resellers ADD COLUMN expires_at TEXT DEFAULT ''")
migrate_db()

def now_utc():
    return datetime.utcnow()

def now_utc_str():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

def now_local_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def _safe(s, maxlen=60):
    s = (s or "").strip()
    return s[:maxlen]

def _shell(cmd):
    try:
        return subprocess.check_output(cmd, stderr=DEVNULL).decode().strip()
    except Exception:
        return ""

def vps_ip():
    ip=_shell(["hostname","-I"]).split()
    return ip[0] if ip else request.host.split(":")[0]

def _parse_dt(s):
    s=(s or "").strip()
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
    except Exception:
        pass
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return None

def _reseller_active(expires_at_text):
    dt=_parse_dt(expires_at_text)
    if dt is None:
        return True  # kosong = unlimited
    return dt > datetime.utcnow()

def sync_config():
    with db() as con:
        pw=[r[0] for r in con.execute("SELECT DISTINCT password FROM users WHERE expires_at > ?", (now_utc_str(),))]
    if not pw:
        pw=["zi"]
    cfg={}
    try:
        cfg=json.load(open(ZIVPN_CFG))
    except Exception:
        pass
    cfg.setdefault("auth",{})["mode"]="passwords"
    cfg["auth"]["config"]=pw
    cfg["config"]=pw
    with tempfile.NamedTemporaryFile("w",delete=False) as f:
        json.dump(cfg,f,indent=2)
        tmp=f.name
    os.replace(tmp, ZIVPN_CFG)
    subprocess.Popen(["systemctl","restart",ZIVPN_SVC], stdout=DEVNULL, stderr=DEVNULL)

def purge_expired_users():
    with db() as con:
        con.execute("DELETE FROM users WHERE expires_at <= ?", (now_utc_str(),))
    sync_config()

def login_required(role=None):
    def deco(fn):
        def w(*a, **kw):
            if not session.get("ok"):
                return redirect(url_for("login"))
            if role and session.get("role") != role:
                return redirect(url_for("dash"))
            return fn(*a, **kw)
        w.__name__ = fn.__name__
        return w
    return deco

def admin_required(fn): return login_required("admin")(fn)
def reseller_required(fn): return login_required("reseller")(fn)

def logs():
    return _shell(["journalctl","-u",ZIVPN_SVC,"--since","-20min","-o","cat"]).lower()

def fmt_left(td):
    if td is None:
        return "-"
    if td.total_seconds() <= 0:
        return "0s"
    s=int(td.total_seconds())
    d=s//86400; s%=86400
    h=s//3600; s%=3600
    m=s//60; s%=60
    if d>0: return "%dd %dh"%(d,h)
    if h>0: return "%dh %dm"%(h,m)
    return "%dm %ds"%(m,s)

def user_rows_for_admin():
    log=logs()
    out=[]
    with db() as con:
        for r in con.execute("""SELECT u.*, r.username AS reseller_name
                                FROM users u
                                LEFT JOIN resellers r ON r.id=u.reseller_id
                                ORDER BY u.id DESC"""):
            dt=_parse_dt(r["expires_at"]); expired = (dt is not None and dt <= now_utc())
            online = (not expired) and (r["password"].lower() in log)
            left=None
            try:
                left=datetime.fromisoformat(r["expires_at"]) - now_utc()
            except Exception:
                left=None
            out.append({
                "id": r["id"],
                "username": r["username"],
                "password": r["password"],
                "expires_at": r["expires_at"],
                "expired": expired,
                "online": online,
                "left_str": fmt_left(left),
                "reseller_name": r["reseller_name"] or "-"
            })
    return out

def user_rows_for_reseller(reseller_id):
    log=logs()
    out=[]
    with db() as con:
        for r in con.execute("SELECT * FROM users WHERE reseller_id=? ORDER BY id DESC",(reseller_id,)):
            dt=_parse_dt(r["expires_at"]); expired = (dt is not None and dt <= now_utc())
            online = (not expired) and (r["password"].lower() in log)
            left=None
            try:
                left=datetime.fromisoformat(r["expires_at"]) - now_utc()
            except Exception:
                left=None
            out.append({
                "id": r["id"],
                "username": r["username"],
                "password": r["password"],
                "expires_at": r["expires_at"],
                "expired": expired,
                "online": online,
                "left_str": fmt_left(left)
            })
    return out

def reseller_list():
    out=[]
    with db() as con:
        for r in con.execute("SELECT * FROM resellers ORDER BY id DESC"):
            rid=int(r["id"])
            used = con.execute("SELECT COUNT(*) FROM users WHERE reseller_id=?", (rid,)).fetchone()[0]
            mx = int(r["max_users"] or 0)
            left = "-" if mx == 0 else str(max(0, mx - used))
            exp=(r["expires_at"] or "").strip()
            active=_reseller_active(exp)
            left_time="-"
            if exp:
                dt=_parse_dt(exp)
                if dt:
                    left_time=fmt_left(dt - datetime.utcnow())
            base=dict(r)
            extra={"used": used, "left_quota": left, "active": active, "left_time": left_time}
            out.append({**base, **extra})
    return out

# ---------- Bandwidth realtime ----------
def _default_iface():
    out=_shell(["ip","-4","route","ls"])
    for line in out.splitlines():
        if line.startswith("default "):
            p=line.split()
            if len(p)>=5:
                return p[4]
    return "eth0"

def _read_proc_net_dev():
    data={}
    try:
        with open("/proc/net/dev","r",encoding="utf-8",errors="ignore") as f:
            lines=f.read().splitlines()
        for ln in lines[2:]:
            if ":" not in ln: continue
            iface, rest = ln.split(":",1)
            iface=iface.strip()
            parts=rest.split()
            if len(parts) < 16: continue
            rx=int(parts[0]); tx=int(parts[8])
            data[iface]=(rx,tx)
    except Exception:
        return {}
    return data

def _human_gb(n):
    n=float(max(0,n))
    return "%.2f GB"%(n/(1024**3))

def get_bw_snapshot():
    iface = BW_IFACE or _default_iface()
    dev=_read_proc_net_dev()
    if iface not in dev:
        for k in dev.keys():
            if k!="lo":
                iface=k
                break
    now_ts=time.time()
    rx,tx=dev.get(iface,(0,0))
    prev=_bw_prev.get(iface)
    rx_mbps=tx_mbps=0.0
    if prev:
        pts, prx, ptx = prev
        dt=max(0.25, now_ts-pts)
        rx_mbps=((rx-prx)*8.0)/dt/1_000_000.0
        tx_mbps=((tx-ptx)*8.0)/dt/1_000_000.0
    _bw_prev[iface]=(now_ts,rx,tx)
    return {
        "iface": iface,
        "rx_mbps": max(0.0, round(rx_mbps, 3)),
        "tx_mbps": max(0.0, round(tx_mbps, 3)),
        "rx_total_h": _human_gb(rx),
        "tx_total_h": _human_gb(tx),
        "ts": int(now_ts)
    }

@app.route("/api/bw")
@login_required()
def api_bw():
    return jsonify(get_bw_snapshot())

# ---------- System stats ----------
def get_mem_cpu():
    mem=_shell(["bash","-lc","free -m | awk '/Mem:/ {print $3\" \"$2}'"])
    used_mb,total_mb=(0,0)
    try:
        u,t=mem.split()
        used_mb=int(u); total_mb=int(t)
    except Exception:
        pass
    ram_pct= (used_mb/total_mb*100.0) if total_mb>0 else 0.0
    cpu=_shell(["bash","-lc","LC_ALL=C top -bn1 | awk -F',' '/Cpu\\(s\\)/{print 100-$4}' | awk '{printf \"%.1f\", $1}'"])
    try:
        cpu_pct=float(cpu)
    except Exception:
        cpu_pct=0.0
    return {
        "cpu_pct": cpu_pct,
        "ram_pct": round(ram_pct, 1),
        "ram_used": used_mb,
        "ram_total": total_mb
    }

@app.route("/api/sys")
@login_required()
def api_sys():
    return jsonify(get_mem_cpu())

# ---------- Backup & Restore ----------
@app.route("/backup")
@admin_required
def backup():
    mem=io.BytesIO()
    with zipfile.ZipFile(mem, "w", compression=zipfile.ZIP_DEFLATED) as z:
        try: z.write(DB, arcname="zivpn.db")
        except Exception: pass
        try: z.write(ZIVPN_CFG, arcname="config.json")
        except Exception: pass
    mem.seek(0)
    fn="zivpn-backup-%s.zip"%(datetime.now().strftime("%Y%m%d-%H%M%S"))
    return send_file(mem, as_attachment=True, download_name=fn, mimetype="application/zip")

@app.route("/restore", methods=["POST"])
@admin_required
def restore():
    f=request.files.get("file")
    if not f:
        flash("Restore gagal: file kosong"); return redirect(url_for("dash"))
    data=f.read()
    mem=io.BytesIO(data)
    try:
        with zipfile.ZipFile(mem,"r") as z:
            if "zivpn.db" in z.namelist():
                z.extract("zivpn.db", "/tmp")
                os.replace("/tmp/zivpn.db", DB)
            if "config.json" in z.namelist():
                z.extract("config.json", "/tmp")
                os.replace("/tmp/config.json", ZIVPN_CFG)
    except Exception as e:
        flash("Restore gagal: %s"%e)
        return redirect(url_for("dash"))
    subprocess.Popen(["systemctl","restart",ZIVPN_SVC], stdout=DEVNULL, stderr=DEVNULL)
    flash("Restore sukses. Service direstart.")
    return redirect(url_for("dash"))

# ---------- Templates ----------
LOGIN_TPL = r'''<!doctype html>
<html><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{{panel_name}} - Login</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
:root{color-scheme:dark}
body{background: radial-gradient(1100px 600px at 20% 10%, rgba(16,185,129,.22), transparent 55%),
             radial-gradient(900px 500px at 80% 30%, rgba(59,130,246,.18), transparent 60%),
             radial-gradient(900px 600px at 50% 90%, rgba(168,85,247,.16), transparent 60%),
             linear-gradient(135deg, #030614, #060b18, #040812);}
.glass{background: rgba(255,255,255,.06); border:1px solid rgba(255,255,255,.10);
       backdrop-filter: blur(18px); -webkit-backdrop-filter: blur(18px);
       box-shadow: 0 18px 80px rgba(0,0,0,.60);}
.btn-gloss{position:relative; overflow:hidden}
.btn-gloss:before{content:""; position:absolute; inset:-50%;
background: radial-gradient(circle at 25% 25%, rgba(255,255,255,.42), rgba(255,255,255,0) 48%);
transform: rotate(12deg); pointer-events:none;}
.muted{color: rgba(226,232,240,.70)}
</style></head>
<body class="min-h-screen grid place-items-center text-slate-100">
<div class="w-[360px] max-w-[92vw] glass rounded-3xl p-6">
  <div class="text-xl font-extrabold">ADMIN LOGIN</div>
  <div class="text-sm muted">{{panel_name}}</div>
  {% with msgs = get_flashed_messages() %}
  {% if msgs %}
    <div class="mt-3 text-sm text-rose-200 bg-rose-500/10 border border-rose-500/20 rounded-xl p-2">{{ msgs[0] }}</div>
  {% endif %}
  {% endwith %}
  <form method="post" action="/login" class="mt-4 space-y-3">
    <input name="u" placeholder="Admin username" class="w-full rounded-2xl p-3 bg-white/10 border border-white/10 outline-none placeholder:text-white/40">
    <input name="p" type="password" placeholder="Admin password" class="w-full rounded-2xl p-3 bg-white/10 border border-white/10 outline-none placeholder:text-white/40">
    <button class="w-full btn-gloss rounded-2xl py-3 font-semibold bg-gradient-to-r from-emerald-500 via-emerald-600 to-teal-500 hover:brightness-110">Login Admin</button>
  </form>
  <div class="mt-4 text-center text-sm muted">
    <a href="/reseller/login" class="hover:text-white">Login Reseller</a>
  </div>
</div></body></html>'''

RESELLER_LOGIN_TPL = r'''<!doctype html>
<html><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{{panel_name}} - Reseller Login</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
:root{color-scheme:dark}
body{background: radial-gradient(1100px 600px at 20% 10%, rgba(16,185,129,.18), transparent 55%),
             radial-gradient(900px 500px at 80% 30%, rgba(59,130,246,.16), transparent 60%),
             radial-gradient(900px 600px at 50% 90%, rgba(168,85,247,.14), transparent 60%),
             linear-gradient(135deg, #030614, #060b18, #040812);}
.glass{background: rgba(255,255,255,.06); border:1px solid rgba(255,255,255,.10);
       backdrop-filter: blur(18px); -webkit-backdrop-filter: blur(18px);
       box-shadow: 0 18px 80px rgba(0,0,0,.60);}
.btn-gloss{position:relative; overflow:hidden}
.btn-gloss:before{content:""; position:absolute; inset:-50%;
background: radial-gradient(circle at 25% 25%, rgba(255,255,255,.42), rgba(255,255,255,0) 48%);
transform: rotate(12deg); pointer-events:none;}
.muted{color: rgba(226,232,240,.70)}
</style></head>
<body class="min-h-screen grid place-items-center text-slate-100">
<div class="w-[360px] max-w-[92vw] glass rounded-3xl p-6">
  <div class="text-xl font-extrabold">RESELLER LOGIN</div>
  <div class="text-sm muted">{{panel_name}}</div>
  {% with msgs = get_flashed_messages() %}
  {% if msgs %}
    <div class="mt-3 text-sm text-rose-200 bg-rose-500/10 border border-rose-500/20 rounded-xl p-2">{{ msgs[0] }}</div>
  {% endif %}
  {% endwith %}
  <form method="post" action="/reseller/login" class="mt-4 space-y-3">
    <input name="u" placeholder="Reseller username" class="w-full rounded-2xl p-3 bg-white/10 border border-white/10 outline-none placeholder:text-white/40">
    <input name="p" type="password" placeholder="Reseller password" class="w-full rounded-2xl p-3 bg-white/10 border border-white/10 outline-none placeholder:text-white/40">
    <button class="w-full btn-gloss rounded-2xl py-3 font-semibold bg-gradient-to-r from-sky-500 via-blue-600 to-indigo-500 hover:brightness-110">Login Reseller</button>
  </form>
  <div class="mt-4 text-center text-sm muted space-y-1">
    <a href="/login" class="hover:text-white block">Login Admin</a>
    <div class="text-xs">Daftar reseller WA: <span class="text-white font-semibold">{{wa}}</span></div>
  </div>
</div></body></html>'''

COMMON_STYLE = r'''
<style>
:root{color-scheme:dark}
body{background: radial-gradient(1100px 600px at 18% 10%, rgba(16,185,129,.22), transparent 55%),
             radial-gradient(900px 500px at 82% 30%, rgba(59,130,246,.18), transparent 60%),
             radial-gradient(900px 600px at 50% 90%, rgba(168,85,247,.16), transparent 60%),
             linear-gradient(135deg, #030614, #060b18, #040812);}
.glass{background: rgba(255,255,255,.06); border:1px solid rgba(255,255,255,.10);
       backdrop-filter: blur(18px); -webkit-backdrop-filter: blur(18px);
       box-shadow: 0 18px 80px rgba(0,0,0,.60);}
.soft{background: rgba(255,255,255,.04); border:1px solid rgba(255,255,255,.08);}
.btn-gloss{position:relative; overflow:hidden}
.btn-gloss:before{content:""; position:absolute; inset:-55%;
background: radial-gradient(circle at 25% 25%, rgba(255,255,255,.42), rgba(255,255,255,0) 48%);
transform: rotate(12deg); pointer-events:none;}
.muted{color: rgba(226,232,240,.70)}
.tiny{font-size:12px}
.chip{font-family: ui-monospace, SFMono-Regular, Menlo, monospace;}

.qbtn{border:1px solid rgba(255,255,255,.12); color:#fff}
.q1d{background: linear-gradient(90deg, rgba(16,185,129,.85), rgba(5,150,105,.85));}
.q7d{background: linear-gradient(90deg, rgba(59,130,246,.85), rgba(37,99,235,.85));}
.q15d{background: linear-gradient(90deg, rgba(168,85,247,.85), rgba(126,34,206,.85));}
.q30d{background: linear-gradient(90deg, rgba(245,158,11,.85), rgba(217,119,6,.85));}
.qnow{background: linear-gradient(90deg, rgba(244,63,94,.80), rgba(236,72,153,.80));}
.qclr{background: linear-gradient(90deg, rgba(100,116,139,.75), rgba(30,41,59,.75));}

/* Flatpickr LIGHT THEME */
.flatpickr-calendar{
  background: rgba(255,255,255,.92) !important;
  color:#0f172a !important;
  border:1px solid rgba(15,23,42,.18) !important;
  box-shadow:0 18px 60px rgba(0,0,0,.35) !important;
}
.flatpickr-months .flatpickr-month,
.flatpickr-current-month,
.flatpickr-weekday,
.flatpickr-day { color:#0f172a !important; }
.flatpickr-day:hover{ background: rgba(16,185,129,.15) !important; }
.flatpickr-day.selected,
.flatpickr-day.startRange,
.flatpickr-day.endRange{
  background:#10b981 !important; border-color:#10b981 !important; color:white !important;
}
.flatpickr-time input{ color:#0f172a !important; }
.flatpickr-confirm{
  background:#10b981 !important; color:#fff !important; border-radius:10px !important;
}
</style>
'''

COMMON_JS = r'''
<script>
function fmt2(n){return n.toString().padStart(2,'0')}
function copyText(text, btn){
  const ok=()=>{ if(btn){ const old=btn.innerText; btn.innerText='OK'; btn.disabled=true;
    setTimeout(()=>{btn.innerText=old; btn.disabled=false;},700);} }
  if (navigator.clipboard && window.isSecureContext){
    navigator.clipboard.writeText(text).then(ok).catch(()=>fallbackCopy(text, ok));
  } else fallbackCopy(text, ok);
}
function fallbackCopy(text, cb){
  const ta=document.createElement('textarea');
  ta.value=text; ta.style.position='fixed'; ta.style.opacity='0';
  document.body.appendChild(ta); ta.focus(); ta.select();
  try{ document.execCommand('copy'); }catch(e){}
  document.body.removeChild(ta); cb && cb();
}

async function refreshBW(){
  try{
    const r=await fetch('/api/bw',{cache:'no-store'});
    const j=await r.json();
    const el=(id)=>document.getElementById(id);
    if(el('bw-iface')) el('bw-iface').textContent=j.iface||'-';
    if(el('rx')) el('rx').textContent=(j.rx_mbps||0).toFixed(2);
    if(el('tx')) el('tx').textContent=(j.tx_mbps||0).toFixed(2);
    if(el('rxTot')) el('rxTot').textContent=j.rx_total_h||'-';
    if(el('txTot')) el('txTot').textContent=j.tx_total_h||'-';
  }catch(e){}
}
async function refreshSYS(){
  try{
    const r=await fetch('/api/sys',{cache:'no-store'});
    const j=await r.json();
    const el=(id)=>document.getElementById(id);
    if(el('cpu')) el('cpu').textContent=(j.cpu_pct||0).toFixed(1)+'%';
    if(el('ram')) el('ram').textContent=(j.ram_pct||0).toFixed(1)+'%';
    if(el('ramUsed')) el('ramUsed').textContent=(j.ram_used||0)+'MB / '+(j.ram_total||0)+'MB';
  }catch(e){}
}

function initPicker(inputId){
  const input=document.getElementById(inputId);
  if(!input) return;
  let prevVal="";
  function addCancel(fp){
    const okBtn = fp.calendarContainer.querySelector(".flatpickr-confirm");
    if(!okBtn) return;
    const cancel=document.createElement("button");
    cancel.type="button";
    cancel.className="flatpickr-confirm";
    cancel.style.marginLeft="8px";
    cancel.textContent="Batal";
    cancel.addEventListener("click", ()=>{
      fp.setDate(prevVal, true);
      fp.close();
    });
    okBtn.parentNode.appendChild(cancel);
  }
  flatpickr("#"+inputId, {
    disableMobile:true,
    enableTime:true,
    enableSeconds:true,
    dateFormat:"Y-m-d H:i:S",
    time_24hr:true,
    allowInput:true,
    clickOpens:true,
    plugins: [new confirmDatePlugin({ confirmText:"OK", showAlways:true })],
    onOpen: (selectedDates, dateStr, fp)=>{ prevVal = fp.input.value || ""; },
    onReady: (selectedDates, dateStr, fp)=>{ addCancel(fp); }
  });
}

window.addEventListener('load', ()=>{
  refreshBW(); refreshSYS();
  setInterval(refreshBW, 1000);
  setInterval(refreshSYS, 2000);

  initPicker("expires_at");
  initPicker("reseller_expires_at");

  const setExp=(mins)=>{
    const el=document.getElementById('expires_at');
    if(!el) return;
    const d=new Date(Date.now()+mins*60*1000);
    const s=d.getFullYear()+"-"+fmt2(d.getMonth()+1)+"-"+fmt2(d.getDate())+" "+fmt2(d.getHours())+":"+fmt2(d.getMinutes())+":"+fmt2(d.getSeconds());
    el.value=s;
  }
  const bind=(id, fn)=>{ const b=document.getElementById(id); if(b) b.onclick=fn; }
  bind('b1d', ()=>setExp(1440));
  bind('b7d', ()=>setExp(10080));
  bind('b15d', ()=>setExp(21600));
  bind('b30d', ()=>setExp(43200));
  bind('bnow', ()=>setExp(10));
  bind('bclear', ()=>{ const el=document.getElementById('expires_at'); if(el) el.value=""; });
});
</script>
'''

COLORED_BOXES = r'''
<section class="grid grid-cols-1 sm:grid-cols-2 gap-3">
  <div class="glass rounded-3xl p-4 border-2 border-amber-400/60">
    <div class="muted text-sm">CPU Usage</div>
    <div class="text-3xl font-extrabold text-amber-300 mt-1" id="cpu">0.0%</div>
  </div>
  <div class="glass rounded-3xl p-4 border-2 border-violet-400/60">
    <div class="muted text-sm">RAM Usage</div>
    <div class="text-3xl font-extrabold text-violet-300 mt-1" id="ram">0.0%</div>
    <div class="tiny muted" id="ramUsed">-</div>
  </div>
  <div class="glass rounded-3xl p-4 border-2 border-emerald-400/60">
    <div class="muted text-sm">Download</div>
    <div class="text-3xl font-extrabold text-emerald-300 mt-1"><span id="rx">0.00</span> Mbps</div>
    <div class="tiny muted">Total: <b class="text-white" id="rxTot">-</b></div>
  </div>
  <div class="glass rounded-3xl p-4 border-2 border-sky-400/60">
    <div class="muted text-sm">Upload</div>
    <div class="text-3xl font-extrabold text-sky-300 mt-1"><span id="tx">0.00</span> Mbps</div>
    <div class="tiny muted">Total: <b class="text-white" id="txTot">-</b></div>
  </div>
  <div class="glass rounded-3xl p-4 sm:col-span-2 border-2 border-slate-300/40">
    <div class="muted text-sm">Bandwidth Interface</div>
    <div class="text-xl font-bold mt-1"><span id="bw-iface">-</span></div>
    <div class="tiny muted mt-1">Realtime monitoring</div>
  </div>
</section>
'''

DASH_TPL = r'''<!doctype html>
<html><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{{panel_name}} - Admin</title>
<script src="https://cdn.tailwindcss.com"></script>

<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/flatpickr/dist/flatpickr.min.css">
<script src="https://cdn.jsdelivr.net/npm/flatpickr"></script>
<script src="https://cdn.jsdelivr.net/npm/flatpickr/dist/plugins/confirmDate/confirmDate.js"></script>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/flatpickr/dist/plugins/confirmDate/confirmDate.css">

''' + COMMON_STYLE + COMMON_JS + r'''
</head>
<body class="min-h-screen text-slate-100">
<main class="max-w-3xl mx-auto px-3 sm:px-4 py-3 sm:py-4 space-y-3 sm:space-y-4">

  <section class="glass rounded-3xl p-5">
    <div class="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-3">
      <div class="min-w-0">
        <div class="text-2xl sm:text-3xl font-extrabold tracking-tight leading-tight">{{panel_name}}</div>
        <div class="mt-2 text-sm muted">Role: <b class="text-white">admin</b></div>
        <div class="mt-1 text-sm muted">Server time: <b class="text-white">{{server_time}}</b> - VPS: <b class="text-white">{{ip}}</b></div>
      </div>

      <div class="flex flex-col gap-2 w-full sm:w-auto">
        <a class="btn-gloss rounded-2xl px-4 py-2 text-sm font-semibold bg-gradient-to-r from-emerald-500 to-teal-500 hover:brightness-110" href="/backup">Backup</a>

        <form method="post" action="/restore" enctype="multipart/form-data" class="soft rounded-2xl p-2">
          <input type="file" name="file" accept=".zip" class="tiny muted w-full">
          <button class="mt-2 w-full btn-gloss rounded-xl py-2 text-sm font-semibold bg-gradient-to-r from-sky-500 to-indigo-500 hover:brightness-110">Restore</button>
        </form>

        <form method="post" action="/purge" onsubmit="return confirm('Purge expired users?')">
          <button class="w-full btn-gloss rounded-2xl px-4 py-2 text-sm font-semibold bg-gradient-to-r from-slate-600 to-slate-800 hover:brightness-110">Purge Expired</button>
        </form>

        <a class="btn-gloss rounded-2xl px-4 py-2 text-sm font-semibold bg-gradient-to-r from-rose-500 to-pink-600 hover:brightness-110" href="/logout">Logout</a>
      </div>
    </div>
  </section>

  {% with msgs=get_flashed_messages() %}
  {% if msgs %}
    <section class="glass rounded-3xl p-4 text-sm whitespace-pre-wrap">{{msgs[0]}}</section>
  {% endif %}
  {% endwith %}

  ''' + COLORED_BOXES + r'''

  <section class="glass rounded-3xl p-4">
    <div class="text-xl font-bold">Add User (Admin)</div>
    <form method="post" action="/admin/user/create" class="mt-3 space-y-3">
      <input name="username" placeholder="Username" class="w-full rounded-2xl p-3 bg-white/10 border border-white/10 outline-none placeholder:text-white/40">
      <input name="password" placeholder="Password" class="w-full rounded-2xl p-3 bg-white/10 border border-white/10 outline-none placeholder:text-white/40">

      <div class="grid grid-cols-2 gap-2">
        <button type="button" id="b1d" class="btn-gloss qbtn q1d rounded-2xl py-2 text-sm">1d</button>
        <button type="button" id="b7d" class="btn-gloss qbtn q7d rounded-2xl py-2 text-sm">7d</button>
        <button type="button" id="b15d" class="btn-gloss qbtn q15d rounded-2xl py-2 text-sm">15d</button>
        <button type="button" id="b30d" class="btn-gloss qbtn q30d rounded-2xl py-2 text-sm">30d</button>
      </div>
      <div class="grid grid-cols-2 gap-2">
        <button type="button" id="bnow" class="btn-gloss qbtn qnow rounded-2xl py-2 text-sm">Now</button>
        <button type="button" id="bclear" class="btn-gloss qbtn qclr rounded-2xl py-2 text-sm">Clear</button>
      </div>

      <input id="expires_at" name="expires_at" value="{{default_exp}}" placeholder="YYYY-MM-DD HH:MM:SS"
        class="w-full rounded-2xl p-3 bg-white/10 border border-white/10 outline-none placeholder:text-white/40">

      <select name="reseller_id" class="w-full rounded-2xl p-3 bg-white/10 border border-white/10 outline-none">
        <option value="">Owner: Admin (no reseller)</option>
        {% for rr in resellers %}
          <option value="{{rr['id']}}">Owner: {{rr['username']}}</option>
        {% endfor %}
      </select>

      <button class="w-full btn-gloss rounded-2xl py-3 font-semibold bg-gradient-to-r from-emerald-500 to-teal-500 hover:brightness-110">Create User</button>
      <div class="tiny muted">1 User For 1 Device</div>
    </form>
  </section>

  <section class="glass rounded-3xl p-4">
    <div class="text-xl font-bold">Reseller</div>
    <form method="post" action="/admin/reseller/create" class="mt-3 space-y-3">
      <input name="username" placeholder="Username reseller" class="w-full rounded-2xl p-3 bg-white/10 border border-white/10 outline-none placeholder:text-white/40">
      <input name="password" placeholder="Password reseller (kosong = auto)" class="w-full rounded-2xl p-3 bg-white/10 border border-white/10 outline-none placeholder:text-white/40">
      <input name="max_users" placeholder="Max users reseller (0 = unlimited)" class="w-full rounded-2xl p-3 bg-white/10 border border-white/10 outline-none placeholder:text-white/40">
      <input id="reseller_expires_at" name="expires_at" placeholder="Expired reseller (kosong = unlimited) YYYY-MM-DD HH:MM:SS"
        class="w-full rounded-2xl p-3 bg-white/10 border border-white/10 outline-none placeholder:text-white/40">
      <button class="w-full btn-gloss rounded-2xl py-3 font-semibold bg-gradient-to-r from-sky-500 via-blue-600 to-indigo-500 hover:brightness-110">Buat Reseller</button>
      <div class="tiny muted">Daftar reseller WA: <b class="text-white">{{wa}}</b></div>
    </form>

    <div class="mt-4 soft rounded-2xl p-3">
      <div class="font-semibold mb-2">List Reseller</div>
      {% if resellers|length == 0 %}
        <div class="muted text-sm">Belum ada reseller.</div>
      {% else %}
        <div class="space-y-2">
          {% for rr in resellers %}
            <div class="soft rounded-xl p-3">
              <div class="flex items-start justify-between gap-2">
                <div class="min-w-0">
                  <div class="font-semibold truncate">{{rr['username']}}</div>
                  <div class="tiny muted">Created: {{rr['created_at']}}</div>
                  <div class="tiny muted">
                    Quota: <b class="text-white">{{ rr['max_users'] if rr['max_users'] else 'unlimited' }}</b>
                    - Used: <b class="text-white">{{ rr['used'] }}</b>
                    - Left: <b class="text-white">{{ rr['left_quota'] }}</b>
                  </div>
                  <div class="tiny muted">
                    Expired: <b class="text-white">{{ rr['expires_at'] if rr['expires_at'] else 'unlimited' }}</b>
                    - Left: <b class="text-white">{{ rr['left_time'] }}</b>
                  </div>
                </div>
                <div class="flex flex-col gap-2 items-end">
                  {% if rr['active'] %}
                    <span class="text-emerald-300 tiny px-3 py-1 rounded-full soft">ACTIVE</span>
                  {% else %}
                    <span class="text-rose-300 tiny px-3 py-1 rounded-full soft">EXPIRED</span>
                  {% endif %}
                  <div class="flex items-center gap-2">
                    <code class="chip px-2 py-1 rounded-lg bg-white/10 border border-white/10">{{rr['password']}}</code>
                    <button type="button" onclick="copyText('{{rr['password']}}', this)" class="btn-gloss soft rounded-xl px-3 py-2 text-sm">Copy</button>
                  </div>
                  <button type="button" class="btn-gloss soft rounded-xl px-3 py-2 text-sm"
                    onclick="document.getElementById('edit-rs-{{rr['id']}}').classList.toggle('hidden')">Edit</button>
                  <form method="post" action="/admin/reseller/delete/{{rr['id']}}" onsubmit="return confirm('Hapus reseller {{rr['username']}} dan SEMUA user-nya?')" class="w-full">
                    <button class="btn-gloss rounded-xl px-3 py-2 text-sm font-semibold bg-gradient-to-r from-rose-500 to-pink-600 hover:brightness-110 w-full">Delete</button>
                  </form>
                </div>
              </div>

              <div id="edit-rs-{{rr['id']}}" class="hidden mt-3 soft rounded-2xl p-3">
                <form method="post" action="/admin/reseller/update/{{rr['id']}}" class="space-y-2">
                  <input name="password" value="{{rr['password']}}" placeholder="Password reseller"
                    class="w-full rounded-2xl p-3 bg-white/10 border border-white/10 outline-none placeholder:text-white/40">
                  <input name="max_users" value="{{rr['max_users']}}" placeholder="Max users reseller (0=unlimited)"
                    class="w-full rounded-2xl p-3 bg-white/10 border border-white/10 outline-none placeholder:text-white/40">
                  <input name="expires_at" value="{{rr['expires_at']}}" placeholder="Expired reseller (kosong = unlimited) YYYY-MM-DD HH:MM:SS"
                    class="w-full rounded-2xl p-3 bg-white/10 border border-white/10 outline-none placeholder:text-white/40">
                  <button class="w-full btn-gloss rounded-2xl py-3 font-semibold bg-gradient-to-r from-emerald-500 to-teal-500 hover:brightness-110">Save Reseller</button>
                </form>
              </div>

            </div>
          {% endfor %}
        </div>
      {% endif %}
    </div>
  </section>

  <section class="glass rounded-3xl p-4">
    <div class="text-xl font-bold">User List</div>
    <div class="mt-3 space-y-2">
      {% if rows|length == 0 %}
        <div class="muted">No users.</div>
      {% endif %}
      {% for r in rows %}
        <div class="soft rounded-2xl p-3">
          <div class="flex items-center justify-between gap-2">
            <div class="min-w-0">
              <div class="font-semibold truncate">{{r['username']}}</div>
              <div class="tiny muted">
                Owner: <b class="text-white">{{r['reseller_name']}}</b>
                - Exp: <b class="text-white">{{r['expires_at']}}</b>
                - Left: <b class="text-white">{{r['left_str']}}</b>
              </div>
            </div>
            <div class="flex items-center gap-2">
              {% if not r['expired'] %}
                <span class="text-emerald-300 tiny px-3 py-1 rounded-full soft">ACTIVE</span>
              {% else %}
                <span class="muted tiny px-3 py-1 rounded-full soft">EXPIRED</span>
              {% endif %}
            </div>
          </div>

          <div class="mt-2 flex items-center justify-between gap-2">
            <div class="flex items-center gap-2">
              <code class="chip px-2 py-1 rounded-lg bg-white/10 border border-white/10">{{r['password']}}</code>
              <button type="button" onclick="copyText('{{r['password']}}', this)" class="btn-gloss soft rounded-xl px-3 py-2 text-sm">Copy</button>
            </div>
            <div class="flex items-center gap-2">
              <button type="button" class="btn-gloss soft rounded-xl px-4 py-2 text-sm"
                onclick="document.getElementById('edit-{{r['id']}}').classList.toggle('hidden')">Edit</button>

              <form method="post" action="/admin/user/delete/{{r['id']}}" onsubmit="return confirm('Delete {{r['username']}} ?')">
                <button class="btn-gloss rounded-xl px-4 py-2 text-sm font-semibold bg-gradient-to-r from-rose-500 to-pink-600 hover:brightness-110">Delete</button>
              </form>
            </div>
          </div>

          <div id="edit-{{r['id']}}" class="hidden mt-3 soft rounded-2xl p-3">
            <form method="post" action="/admin/user/update/{{r['id']}}" class="space-y-2">
              <input name="password" value="{{r['password']}}" placeholder="Password"
                class="w-full rounded-2xl p-3 bg-white/10 border border-white/10 outline-none placeholder:text-white/40">
              <input name="expires_at" value="{{r['expires_at']}}" placeholder="YYYY-MM-DD HH:MM:SS"
                class="w-full rounded-2xl p-3 bg-white/10 border border-white/10 outline-none placeholder:text-white/40">
              <select name="reseller_id" class="w-full rounded-2xl p-3 bg-white/10 border border-white/10 outline-none">
                <option value="">Owner: Admin</option>
                {% for rr in resellers %}
                  <option value="{{rr['id']}}">Owner: {{rr['username']}}</option>
                {% endfor %}
              </select>
              <button class="w-full btn-gloss rounded-2xl py-3 font-semibold bg-gradient-to-r from-emerald-500 to-teal-500 hover:brightness-110">Save</button>
            </form>
          </div>
        </div>
      {% endfor %}
    </div>
  </section>

</main>
</body></html>'''

RESELLER_DASH_TPL = r'''<!doctype html>
<html><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{{panel_name}} - Reseller</title>
<script src="https://cdn.tailwindcss.com"></script>

<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/flatpickr/dist/flatpickr.min.css">
<script src="https://cdn.jsdelivr.net/npm/flatpickr"></script>
<script src="https://cdn.jsdelivr.net/npm/flatpickr/dist/plugins/confirmDate/confirmDate.js"></script>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/flatpickr/dist/plugins/confirmDate/confirmDate.css">

''' + COMMON_STYLE + COMMON_JS + r'''
</head>
<body class="min-h-screen text-slate-100">
<main class="max-w-3xl mx-auto px-3 sm:px-4 py-3 sm:py-4 space-y-3 sm:space-y-4">

  <section class="glass rounded-3xl p-5">
    <div class="flex items-start justify-between gap-3">
      <div class="min-w-0">
        <div class="text-2xl font-extrabold tracking-tight leading-tight">{{panel_name}}</div>
        <div class="mt-2 text-sm muted">Role: <b class="text-white">reseller</b> - Login: <b class="text-white">{{reseller_name}}</b></div>
        <div class="mt-1 text-sm muted">VPS: <b class="text-white">{{ip}}</b></div>
      </div>
      <a class="btn-gloss rounded-2xl px-4 py-2 text-sm font-semibold bg-gradient-to-r from-rose-500 to-pink-600 hover:brightness-110" href="/logout">Logout</a>
    </div>
  </section>

  ''' + COLORED_BOXES + r'''

  {% with msgs=get_flashed_messages() %}
  {% if msgs %}
    <section class="glass rounded-3xl p-4 text-sm whitespace-pre-wrap">{{msgs[0]}}</section>
  {% endif %}
  {% endwith %}

  <section class="glass rounded-3xl p-4">
    <div class="text-xl font-bold">Add User (Reseller)</div>
    <form method="post" action="/reseller/user/create" class="mt-3 space-y-3">
      <input name="username" placeholder="Username" class="w-full rounded-2xl p-3 bg-white/10 border border-white/10 outline-none placeholder:text-white/40">
      <input name="password" placeholder="Password" class="w-full rounded-2xl p-3 bg-white/10 border border-white/10 outline-none placeholder:text-white/40">

      <div class="grid grid-cols-2 gap-2">
        <button type="button" id="b1d" class="btn-gloss qbtn q1d rounded-2xl py-2 text-sm">1d</button>
        <button type="button" id="b7d" class="btn-gloss qbtn q7d rounded-2xl py-2 text-sm">7d</button>
        <button type="button" id="b15d" class="btn-gloss qbtn q15d rounded-2xl py-2 text-sm">15d</button>
        <button type="button" id="b30d" class="btn-gloss qbtn q30d rounded-2xl py-2 text-sm">30d</button>
      </div>
      <div class="grid grid-cols-2 gap-2">
        <button type="button" id="bnow" class="btn-gloss qbtn qnow rounded-2xl py-2 text-sm">Trial 10 Menit</button>
        <button type="button" id="bclear" class="btn-gloss qbtn qclr rounded-2xl py-2 text-sm">Clear</button>
      </div>

      <input id="expires_at" name="expires_at" value="{{default_exp}}" placeholder="YYYY-MM-DD HH:MM:SS"
        class="w-full rounded-2xl p-3 bg-white/10 border border-white/10 outline-none placeholder:text-white/40">

      <button class="w-full btn-gloss rounded-2xl py-3 font-semibold bg-gradient-to-r from-sky-500 via-blue-600 to-indigo-500 hover:brightness-110">Create User</button>
      <div class="tiny muted">1 User For 1 Device</div>
    </form>
  </section>

  <section class="glass rounded-3xl p-4">
    <div class="text-xl font-bold">My Users</div>
    <div class="mt-3 space-y-2">
      {% if rows|length == 0 %}
        <div class="muted">No users.</div>
      {% endif %}
      {% for r in rows %}
        <div class="soft rounded-2xl p-3">
          <div class="flex items-center justify-between gap-2">
            <div class="min-w-0">
              <div class="font-semibold truncate">{{r['username']}}</div>
              <div class="tiny muted">Exp: <b class="text-white">{{r['expires_at']}}</b> - Left: <b class="text-white">{{r['left_str']}}</b></div>
            </div>
            <div>
              {% if not r['expired'] %}
                <span class="text-emerald-300 tiny px-3 py-1 rounded-full soft">ACTIVE</span>
              {% else %}
                <span class="muted tiny px-3 py-1 rounded-full soft">EXPIRED</span>
              {% endif %}
            </div>
          </div>
          <div class="mt-2 flex items-center justify-between gap-2">
            <div class="flex items-center gap-2">
              <code class="chip px-2 py-1 rounded-lg bg-white/10 border border-white/10">{{r['password']}}</code>
              <button type="button" onclick="copyText('{{r['password']}}', this)" class="btn-gloss soft rounded-xl px-3 py-2 text-sm">Copy</button>
            </div>

            <form method="post" action="/reseller/user/delete/{{r['id']}}" onsubmit="return confirm('Delete {{r['username']}} ?')">
              <button class="btn-gloss rounded-xl px-4 py-2 text-sm font-semibold bg-gradient-to-r from-rose-500 to-pink-600 hover:brightness-110">Delete</button>
            </form>
          </div>
        </div>
      {% endfor %}
    </div>
  </section>

</main>
</body></html>'''

# ---------- Auth Routes ----------
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        if request.form.get("u")==ADMIN_USER and request.form.get("p")==ADMIN_PASS:
            session["ok"]=True
            session["role"]="admin"
            session["rid"]=None
            return redirect(url_for("dash"))
        flash("Invalid admin credentials")
    return render_template_string(LOGIN_TPL, panel_name=PANEL_NAME)

@app.route("/reseller/login", methods=["GET","POST"])
def reseller_login():
    if request.method=="POST":
        u=_safe(request.form.get("u"))
        p=_safe(request.form.get("p"))
        with db() as con:
            r=con.execute("SELECT * FROM resellers WHERE username=? AND password=?", (u,p)).fetchone()
        if r:
            exp=(r["expires_at"] or "").strip()
            if exp and not _reseller_active(exp):
                flash("Reseller expired. Hubungi admin.")
                return redirect(url_for("reseller_login"))
            session["ok"]=True
            session["role"]="reseller"
            session["rid"]=int(r["id"])
            return redirect(url_for("reseller_dash"))
        flash("Invalid reseller credentials")
    return render_template_string(RESELLER_LOGIN_TPL, panel_name=PANEL_NAME, wa=WA_NUMBER)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------- Pages ----------
@app.route("/")
@login_required()
def dash():
    if session.get("role")=="reseller":
        return redirect(url_for("reseller_dash"))
    ip=vps_ip()
    rows=user_rows_for_admin()
    default_exp=(datetime.now()+timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
    return render_template_string(
        DASH_TPL,
        panel_name=PANEL_NAME,
        server_time=now_local_str(),
        ip=ip,
        rows=rows,
        default_exp=default_exp,
        resellers=reseller_list(),
        wa=WA_NUMBER
    )

@app.route("/reseller")
@reseller_required
def reseller_dash():
    ip=vps_ip()
    rid=int(session.get("rid") or 0)
    with db() as con:
        rr=con.execute("SELECT * FROM resellers WHERE id=?", (rid,)).fetchone()
    reseller_name = rr["username"] if rr else "reseller"
    rows=user_rows_for_reseller(rid)
    default_exp=(datetime.now()+timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
    return render_template_string(
        RESELLER_DASH_TPL,
        panel_name=PANEL_NAME,
        ip=ip,
        reseller_name=reseller_name,
        rows=rows,
        default_exp=default_exp
    )

# ---------- Admin user actions ----------
@app.route("/admin/user/create", methods=["POST"])
@admin_required
def admin_user_create():
    u=_safe(request.form.get("username"))
    p=_safe(request.form.get("password"))
    exp=_safe(request.form.get("expires_at"), maxlen=32)
    reseller_id=request.form.get("reseller_id") or None

    if not u or not p or not exp:
        flash("Create user gagal: isi username, password, expiry")
        return redirect(url_for("dash"))
    try:
        datetime.strptime(exp, "%Y-%m-%d %H:%M:%S")
    except Exception:
        flash("Format expiry salah. Pakai: YYYY-MM-DD HH:MM:SS")
        return redirect(url_for("dash"))

    rid=None
    if reseller_id:
        try: rid=int(reseller_id)
        except Exception: rid=None

    with db() as con:
        con.execute("""INSERT INTO users(username,password,expires_at,reseller_id,created_at)
                       VALUES(?,?,?,?,?)
                       ON CONFLICT(username) DO UPDATE SET password=?, expires_at=?, reseller_id=?""",
                    (u,p,exp,rid,now_utc().isoformat(),p,exp,rid))
    sync_config()
    flash("Create Account Done\nIP : %s\nUser : %s\nPassword : %s\nExpired : %s\n1 User For 1 Device"%(vps_ip(),u,p,exp))
    return redirect(url_for("dash"))

@app.route("/admin/user/update/<int:uid>", methods=["POST"])
@admin_required
def admin_user_update(uid):
    p=_safe(request.form.get("password"))
    exp=_safe(request.form.get("expires_at"), maxlen=32)
    reseller_id=request.form.get("reseller_id") or None
    if not p or not exp:
        flash("Update gagal: password & expiry wajib")
        return redirect(url_for("dash"))
    try:
        datetime.strptime(exp, "%Y-%m-%d %H:%M:%S")
    except Exception:
        flash("Format expiry salah. Pakai: YYYY-MM-DD HH:MM:SS")
        return redirect(url_for("dash"))
    rid=None
    if reseller_id:
        try: rid=int(reseller_id)
        except Exception: rid=None
    with db() as con:
        con.execute("UPDATE users SET password=?, expires_at=?, reseller_id=? WHERE id=?",
                    (p, exp, rid, uid))
    sync_config()
    flash("User updated.")
    return redirect(url_for("dash"))

@app.route("/admin/user/delete/<int:uid>", methods=["POST"])
@admin_required
def admin_user_delete(uid):
    with db() as con:
        con.execute("DELETE FROM users WHERE id=?", (uid,))
    sync_config()
    flash("User deleted.")
    return redirect(url_for("dash"))

# ---------- Admin reseller actions ----------
@app.route("/admin/reseller/create", methods=["POST"])
@admin_required
def admin_reseller_create():
    u=_safe(request.form.get("username"))
    p=_safe(request.form.get("password"))
    mx_raw=_safe(request.form.get("max_users"), maxlen=12)
    exp=_safe(request.form.get("expires_at"), maxlen=32)

    if not u:
        flash("Buat reseller gagal: username kosong")
        return redirect(url_for("dash"))
    if not p:
        p = "rs%s"%(int(time.time())%1000000)

    try:
        mx=int(mx_raw) if mx_raw else 0
        if mx < 0: mx=0
    except Exception:
        mx=0

    if exp:
        try:
            datetime.strptime(exp, "%Y-%m-%d %H:%M:%S")
        except Exception:
            flash("Format expiry reseller salah. Pakai: YYYY-MM-DD HH:MM:SS (atau kosong)")
            return redirect(url_for("dash"))

    with db() as con:
        con.execute("""INSERT INTO resellers(username,password,max_users,expires_at,created_at)
                       VALUES(?,?,?,?,?)
                       ON CONFLICT(username) DO UPDATE SET password=?, max_users=?, expires_at=?""",
                    (u,p,mx,exp,now_local_str(),p,mx,exp))
    flash("Reseller dibuat / diupdate.")
    return redirect(url_for("dash"))

@app.route("/admin/reseller/update/<int:rid>", methods=["POST"])
@admin_required
def admin_reseller_update(rid):
    p=_safe(request.form.get("password"))
    mx_raw=_safe(request.form.get("max_users"), maxlen=12)
    exp=_safe(request.form.get("expires_at"), maxlen=32)

    if not p:
        flash("Update reseller gagal: password wajib")
        return redirect(url_for("dash"))

    try:
        mx=int(mx_raw) if mx_raw else 0
        if mx < 0: mx=0
    except Exception:
        mx=0

    if exp:
        try:
            datetime.strptime(exp, "%Y-%m-%d %H:%M:%S")
        except Exception:
            flash("Format expiry reseller salah. Pakai: YYYY-MM-DD HH:MM:SS (atau kosong)")
            return redirect(url_for("dash"))

    with db() as con:
        con.execute("UPDATE resellers SET password=?, max_users=?, expires_at=? WHERE id=?",
                    (p,mx,exp,rid))
    flash("Reseller updated.")
    return redirect(url_for("dash"))

@app.route("/purge", methods=["POST"])
@admin_required
def purge():
    purge_expired_users()
    flash("Expired users purged + config synced.")
    return redirect(url_for("dash"))

# ---------- Reseller create user (quota + expiry check) ----------
@app.route("/reseller/user/create", methods=["POST"])
@reseller_required
def reseller_user_create():
    rid=int(session.get("rid") or 0)

    with db() as con:
        rr = con.execute("SELECT * FROM resellers WHERE id=?", (rid,)).fetchone()
        if rr:
            exp=(rr["expires_at"] or "").strip()
            if exp and not _reseller_active(exp):
                flash("Reseller expired. Tidak bisa create user.")
                return redirect(url_for("reseller_dash"))

            mx=int(rr["max_users"] or 0)
            if mx > 0:
                used = con.execute("SELECT COUNT(*) FROM users WHERE reseller_id=?", (rid,)).fetchone()[0]
                if used >= mx:
                    flash("Quota reseller habis. Max %d user."%mx)
                    return redirect(url_for("reseller_dash"))

    u=_safe(request.form.get("username"))
    p=_safe(request.form.get("password"))
    exp=_safe(request.form.get("expires_at"), maxlen=32)

    if not u or not p or not exp:
        flash("Create user gagal: isi username, password, expiry")
        return redirect(url_for("reseller_dash"))
    try:
        datetime.strptime(exp, "%Y-%m-%d %H:%M:%S")
    except Exception:
        flash("Format expiry salah. Pakai: YYYY-MM-DD HH:MM:SS")
        return redirect(url_for("reseller_dash"))

    with db() as con:
        con.execute("""INSERT INTO users(username,password,expires_at,reseller_id,created_at)
                       VALUES(?,?,?,?,?)
                       ON CONFLICT(username) DO UPDATE SET password=?, expires_at=?, reseller_id=?""",
                    (u,p,exp,rid,now_utc().isoformat(),p,exp,rid))

    sync_config()
    flash("Create Account Done\nIP : %s\nUser : %s\nPassword : %s\nExpired : %s\n1 User For 1 Device"%(vps_ip(),u,p,exp))
    return redirect(url_for("reseller_dash"))


@app.route("/reseller/user/delete/<int:uid>", methods=["POST"])
@reseller_required
def reseller_user_delete(uid):
    rid=int(session.get("rid") or 0)
    with db() as con:
        owned = con.execute("SELECT id FROM users WHERE id=? AND reseller_id=?", (uid, rid)).fetchone()
        if not owned:
            flash("Delete gagal: user bukan milik reseller ini.")
            return redirect(url_for("reseller_dash"))
        con.execute("DELETE FROM users WHERE id=? AND reseller_id=?", (uid, rid))
    sync_config()
    flash("User deleted.")
    return redirect(url_for("reseller_dash"))


@app.route("/admin/reseller/delete/<int:rid>", methods=["POST"])
@admin_required
def admin_reseller_delete(rid):
    # hapus reseller + semua user miliknya
    with db() as con:
        con.execute("DELETE FROM users WHERE reseller_id=?", (rid,))
        con.execute("DELETE FROM resellers WHERE id=?", (rid,))
    sync_config()
    flash("Reseller dan semua user-nya berhasil dihapus.")
    return redirect(url_for("dash"))


if __name__=="__main__":
    from waitress import serve
    serve(app, host=os.getenv("BIND_HOST","0.0.0.0"), port=int(os.getenv("BIND_PORT","8088")))
PY

# Maintenance script (auto purge expired users + sync)
cat > "${MAINT_PY}" <<'PY'
import os, sqlite3, json, tempfile, subprocess
from datetime import datetime
from subprocess import DEVNULL

DB="/var/lib/zivpn-admin/zivpn.db"
CFG=os.getenv("ZIVPN_CONFIG","/etc/zivpn/config.json")
SVC=os.getenv("ZIVPN_SERVICE","zivpn.service")

def now_iso():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

def sync():
    with sqlite3.connect(DB) as con:
        pw=[r[0] for r in con.execute("SELECT DISTINCT password FROM users WHERE expires_at > ?", (now_iso(),))]
    if not pw:
        pw=["zi"]
    cfg={}
    try:
        cfg=json.load(open(CFG))
    except Exception:
        pass
    cfg.setdefault("auth",{})["mode"]="passwords"
    cfg["auth"]["config"]=pw
    cfg["config"]=pw
    with tempfile.NamedTemporaryFile("w",delete=False) as f:
        json.dump(cfg,f,indent=2); tmp=f.name
    os.replace(tmp, CFG)
    subprocess.Popen(["systemctl","restart",SVC], stdout=DEVNULL, stderr=DEVNULL)

def purge_users():
    with sqlite3.connect(DB) as con:
        con.execute("DELETE FROM users WHERE expires_at <= ?", (now_iso(),))
    sync()

if __name__=="__main__":
    purge_users()
PY

chmod +x "${APP_PY}" "${MAINT_PY}"

cat >/etc/systemd/system/${PANEL_SVC} <<EOF
[Unit]
Description=ZIVPN Web Panel (Admin+Reseller)
After=network.target

[Service]
EnvironmentFile=${ENV_FILE}
WorkingDirectory=${ADMIN_DIR}
ExecStart=${VENV}/bin/python ${APP_PY}
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

cat >/etc/systemd/system/${MAINT_SVC} <<EOF
[Unit]
Description=ZIVPN Maintenance (Purge Expired + Sync)

[Service]
EnvironmentFile=${ENV_FILE}
WorkingDirectory=${ADMIN_DIR}
ExecStart=${VENV}/bin/python ${MAINT_PY}
User=root
EOF

cat >/etc/systemd/system/${MAINT_TIMER} <<'EOF'
[Unit]
Description=Run ZIVPN maintenance every 10 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=10min
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now ${PANEL_SVC}
systemctl enable --now ${MAINT_TIMER}

IP=$(hostname -I | awk '{print $1}')
echo
echo "INSTALL COMPLETE"
echo "Open Admin    : http://${IP}:${PANEL_PORT}/login"
echo "Open Reseller : http://${IP}:${PANEL_PORT}/reseller/login"
echo "UDP Port      : 5667 (NAT 6000-19999 -> 5667)"
echo "Auto purge expired users: every 10 minutes"
echo "======================================"
