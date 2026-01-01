cat > zi.sh <<'BASH'
#!/bin/bash
# MULTI PLUS VPN - ZIVPN UDP + Admin/Reseller Web Panel (1 FILE INSTALLER)
# Rebuild: Stable + Glossy UI + Backup/Restore + Reseller Separation + Auto Purge Expired

set -euo pipefail

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
export DEBIAN_FRONTEND=noninteractive
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

# NAT / firewall
IFC=$(ip -4 route ls | awk '/default/ {print $5; exit}' || true)
IFC=${IFC:-eth0}
iptables -t nat -C PREROUTING -i "$IFC" -p udp --dport 6000:19999 -j DNAT --to-destination :5667 2>/dev/null || \
iptables -t nat -A PREROUTING -i "$IFC" -p udp --dport 6000:19999 -j DNAT --to-destination :5667

ufw allow 5667/udp >/dev/null 2>&1 || true
ufw allow 8088/tcp >/dev/null 2>&1 || true

echo "==> Setting up Web Panel (Admin + Reseller)..."
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

def now():
    return datetime.utcnow()

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

def server_time_str():
    # show server local time (system)
    try:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "-"

def sync_config():
    with db() as con:
        pw=[r[0] for r in con.execute("SELECT DISTINCT password FROM users WHERE expires_at > ?", (now().isoformat(),))]
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

def purge_expired():
    with db() as con:
        con.execute("DELETE FROM users WHERE expires_at <= ?", (now().isoformat(),))
    sync_config()

def get_role():
    return session.get("role")  # "admin" or "reseller"

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

def reseller_required(fn):
    return login_required("reseller")(fn)

def admin_required(fn):
    return login_required("admin")(fn)

def logs():
    return _shell(["journalctl","-u",ZIVPN_SVC,"--since","-20min","-o","cat"]).lower()

def user_rows_for_admin():
    log=logs()
    out=[]
    with db() as con:
        for r in con.execute("""SELECT u.*, r.username AS reseller_name
                                FROM users u
                                LEFT JOIN resellers r ON r.id=u.reseller_id
                                ORDER BY u.id DESC"""):
            expired = r["expires_at"] <= now().isoformat()
            online = (not expired) and (r["password"].lower() in log)
            left = None
            try:
                left = datetime.fromisoformat(r["expires_at"]) - now()
            except Exception:
                left = None
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

def user_rows_for_reseller(reseller_id:int):
    log=logs()
    out=[]
    with db() as con:
        for r in con.execute("""SELECT * FROM users WHERE reseller_id=? ORDER BY id DESC""",(reseller_id,)):
            expired = r["expires_at"] <= now().isoformat()
            online = (not expired) and (r["password"].lower() in log)
            left = None
            try:
                left = datetime.fromisoformat(r["expires_at"]) - now()
            except Exception:
                left = None
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
    with db() as con:
        return list(con.execute("SELECT * FROM resellers ORDER BY id DESC"))

def fmt_left(td):
    if td is None:
        return "-"
    if td.total_seconds() <= 0:
        return "0s"
    s=int(td.total_seconds())
    d=s//86400; s%=86400
    h=s//3600; s%=3600
    m=s//60; s%=60
    if d>0:
        return f"{d}d {h}h"
    if h>0:
        return f"{h}h {m}m"
    return f"{m}m {s}s"

# ---------- Bandwidth realtime (from /proc/net/dev) ----------
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

def _human_gb(n:int)->str:
    n=float(max(0,n))
    return f"{(n/(1024**3)):.2f} GB"

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
    # CPU: read /proc/stat delta
    try:
        # simple 1-sample using uptime + /proc/stat not perfect, but ok
        load=_shell(["bash","-lc","awk '{print $1}' /proc/loadavg"])
    except Exception:
        load="0"
    # RAM
    mem=_shell(["bash","-lc","free -m | awk '/Mem:/ {print $3\" \"$2}'"])
    used_mb,total_mb=(0,0)
    try:
        u,t=mem.split()
        used_mb=int(u); total_mb=int(t)
    except Exception:
        pass
    ram_pct= (used_mb/total_mb*100.0) if total_mb>0 else 0.0
    # CPU % from top (fast)
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
    # zip: db + config
    mem=io.BytesIO()
    with zipfile.ZipFile(mem, "w", compression=zipfile.ZIP_DEFLATED) as z:
        try:
            z.write(DB, arcname="zivpn.db")
        except Exception:
            pass
        try:
            z.write(ZIVPN_CFG, arcname="config.json")
        except Exception:
            pass
    mem.seek(0)
    fn=f"zivpn-backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}.zip"
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
        flash(f"Restore gagal: {e}")
        return redirect(url_for("dash"))
    subprocess.Popen(["systemctl","restart",ZIVPN_SVC], stdout=DEVNULL, stderr=DEVNULL)
    flash("Restore sukses. Service direstart.")
    return redirect(url_for("dash"))

# ---------- Login ----------
LOGIN_TPL = r'''<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{{panel_name}} - Login</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
  :root{color-scheme:dark}
  body{background: radial-gradient(1100px 600px at 20% 10%, rgba(16,185,129,.22), transparent 55%),
                 radial-gradient(900px 500px at 80% 30%, rgba(59,130,246,.18), transparent 60%),
                 radial-gradient(900px 600px at 50% 90%, rgba(168,85,247,.16), transparent 60%),
                 linear-gradient(135deg, #030614, #060b18, #040812);}
  .glass{background: rgba(255,255,255,.06); border:1px solid rgba(255,255,255,.10); backdrop-filter: blur(18px);
         -webkit-backdrop-filter: blur(18px); box-shadow: 0 18px 80px rgba(0,0,0,.60);}
  .btn-gloss{position:relative; overflow:hidden}
  .btn-gloss:before{content:""; position:absolute; inset:-50%;
    background: radial-gradient(circle at 25% 25%, rgba(255,255,255,.42), rgba(255,255,255,0) 48%);
    transform: rotate(12deg); pointer-events:none;}
  .muted{color: rgba(226,232,240,.70)}
</style>
</head>
<body class="min-h-screen grid place-items-center text-slate-100">
  <div class="w-[360px] max-w-[92vw] glass rounded-3xl p-6">
    <div class="flex items-center gap-3">
      <div class="w-12 h-12 grid place-items-center rounded-2xl bg-white/10 border border-white/10">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="currentColor" class="text-emerald-300">
          <path d="M12 12c2.8 0 5-2.7 5-6s-2.2-6-5-6-5 2.7-5 6 2.2 6 5 6zm0 2c-4.4 0-8 2.2-8 5v3h16v-3c0-2.8-3.6-5-8-5z"/>
        </svg>
      </div>
      <div class="leading-tight">
        <div class="text-xl font-extrabold tracking-tight">ADMIN LOGIN</div>
        <div class="text-sm muted">{{panel_name}}</div>
      </div>
    </div>

    {% with msgs = get_flashed_messages() %}
    {% if msgs %}
      <div class="mt-3 text-sm text-rose-200 bg-rose-500/10 border border-rose-500/20 rounded-xl p-2">
        {{ msgs[0] }}
      </div>
    {% endif %}
    {% endwith %}

    <form method="post" action="/login" class="mt-4 space-y-3">
      <input name="u" placeholder="Admin username"
        class="w-full rounded-2xl p-3 bg-white/10 border border-white/10 outline-none focus:ring-2 focus:ring-emerald-500 placeholder:text-white/40">
      <input name="p" type="password" placeholder="Admin password"
        class="w-full rounded-2xl p-3 bg-white/10 border border-white/10 outline-none focus:ring-2 focus:ring-emerald-500 placeholder:text-white/40">
      <button class="w-full btn-gloss rounded-2xl py-3 font-semibold bg-gradient-to-r from-emerald-500 via-emerald-600 to-teal-500 hover:brightness-110">
        Login Admin
      </button>
    </form>

    <div class="mt-4 text-center text-sm muted">
      <a href="/reseller/login" class="hover:text-white">Login Reseller</a>
    </div>
  </div>
</body>
</html>'''

RESELLER_LOGIN_TPL = r'''<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{{panel_name}} - Reseller Login</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
  :root{color-scheme:dark}
  body{background: radial-gradient(1100px 600px at 20% 10%, rgba(16,185,129,.18), transparent 55%),
                 radial-gradient(900px 500px at 80% 30%, rgba(59,130,246,.16), transparent 60%),
                 radial-gradient(900px 600px at 50% 90%, rgba(168,85,247,.14), transparent 60%),
                 linear-gradient(135deg, #030614, #060b18, #040812);}
  .glass{background: rgba(255,255,255,.06); border:1px solid rgba(255,255,255,.10); backdrop-filter: blur(18px);
         -webkit-backdrop-filter: blur(18px); box-shadow: 0 18px 80px rgba(0,0,0,.60);}
  .btn-gloss{position:relative; overflow:hidden}
  .btn-gloss:before{content:""; position:absolute; inset:-50%;
    background: radial-gradient(circle at 25% 25%, rgba(255,255,255,.42), rgba(255,255,255,0) 48%);
    transform: rotate(12deg); pointer-events:none;}
  .muted{color: rgba(226,232,240,.70)}
</style>
</head>
<body class="min-h-screen grid place-items-center text-slate-100">
  <div class="w-[360px] max-w-[92vw] glass rounded-3xl p-6">
    <div class="flex items-center gap-3">
      <div class="w-12 h-12 grid place-items-center rounded-2xl bg-white/10 border border-white/10">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="currentColor" class="text-sky-300">
          <path d="M12 1l9 4v6c0 5-3.8 9.7-9 11-5.2-1.3-9-6-9-11V5l9-4z"/>
        </svg>
      </div>
      <div class="leading-tight">
        <div class="text-xl font-extrabold tracking-tight">RESELLER LOGIN</div>
        <div class="text-sm muted">{{panel_name}}</div>
      </div>
    </div>

    {% with msgs = get_flashed_messages() %}
    {% if msgs %}
      <div class="mt-3 text-sm text-rose-200 bg-rose-500/10 border border-rose-500/20 rounded-xl p-2">
        {{ msgs[0] }}
      </div>
    {% endif %}
    {% endwith %}

    <form method="post" action="/reseller/login" class="mt-4 space-y-3">
      <input name="u" placeholder="Reseller username"
        class="w-full rounded-2xl p-3 bg-white/10 border border-white/10 outline-none focus:ring-2 focus:ring-sky-500 placeholder:text-white/40">
      <input name="p" type="password" placeholder="Reseller password"
        class="w-full rounded-2xl p-3 bg-white/10 border border-white/10 outline-none focus:ring-2 focus:ring-sky-500 placeholder:text-white/40">
      <button class="w-full btn-gloss rounded-2xl py-3 font-semibold bg-gradient-to-r from-sky-500 via-blue-600 to-indigo-500 hover:brightness-110">
        Login Reseller
      </button>
    </form>

    <div class="mt-4 text-center text-sm muted space-y-1">
      <a href="/login" class="hover:text-white block">Login Admin</a>
      <div class="text-xs">
        Daftar reseller WA: <span class="text-white font-semibold">{{wa}}</span>
      </div>
    </div>
  </div>
</body>
</html>'''

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

# ---------- DASHBOARD (ADMIN) ----------
DASH_TPL = r'''<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{{panel_name}} - Admin</title>
<script src="https://cdn.tailwindcss.com"></script>

<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/flatpickr/dist/flatpickr.min.css">
<script src="https://cdn.jsdelivr.net/npm/flatpickr"></script>

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
  .flatpickr-calendar{background:#0b1224;border:1px solid rgba(255,255,255,.10); box-shadow:0 18px 60px rgba(0,0,0,.55)}
  .flatpickr-time input{color:#fff}
  .flatpickr-day{color:#cbd5e1}
  .flatpickr-day.selected{background:#10b981;border-color:#10b981}
</style>

<script>
function fmt2(n){return n.toString().padStart(2,'0')}
function copyText(text, btn){
  // Clipboard API + fallback
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
    document.getElementById('bw-iface').textContent=j.iface||'-';
    document.getElementById('rx').textContent=(j.rx_mbps||0).toFixed(2);
    document.getElementById('tx').textContent=(j.tx_mbps||0).toFixed(2);
    document.getElementById('rxTot').textContent=j.rx_total_h||'-';
    document.getElementById('txTot').textContent=j.tx_total_h||'-';
  }catch(e){}
}
async function refreshSYS(){
  try{
    const r=await fetch('/api/sys',{cache:'no-store'});
    const j=await r.json();
    document.getElementById('cpu').textContent=(j.cpu_pct||0).toFixed(1)+'%';
    document.getElementById('ram').textContent=(j.ram_pct||0).toFixed(1)+'%';
    document.getElementById('ramUsed').textContent=(j.ram_used||0)+'MB / '+(j.ram_total||0)+'MB';
  }catch(e){}
}
setInterval(refreshBW, 1000);
setInterval(refreshSYS, 2000);
window.addEventListener('load', ()=>{
  refreshBW(); refreshSYS();
  // Flatpickr: input expiry
  flatpickr("#expires_at", {
    enableTime:true,
    dateFormat:"Y-m-d H:i:S",
    time_24hr:true,
    defaultDate: document.getElementById('expires_at').value
  });
  // quick buttons
  const setExp=(mins)=>{
    const d=new Date(Date.now()+mins*60*1000);
    const s=d.getFullYear()+"-"+fmt2(d.getMonth()+1)+"-"+fmt2(d.getDate())+" "+fmt2(d.getHours())+":"+fmt2(d.getMinutes())+":"+fmt2(d.getSeconds());
    document.getElementById('expires_at').value=s;
  }
  document.getElementById('b1d').onclick=()=>setExp(1440);
  document.getElementById('b7d').onclick=()=>setExp(10080);
  document.getElementById('b15d').onclick=()=>setExp(21600);
  document.getElementById('b30d').onclick=()=>setExp(43200);
  document.getElementById('bnow').onclick=()=>setExp(10);
  document.getElementById('bclear').onclick=()=>document.getElementById('expires_at').value="";
});
</script>
</head>

<body class="min-h-screen text-slate-100">
  <main class="max-w-3xl mx-auto px-4 py-4 space-y-4">

    <section class="glass rounded-3xl p-5">
      <div class="flex items-start justify-between gap-3">
        <div class="min-w-0">
          <div class="text-3xl font-extrabold tracking-tight leading-tight">{{panel_name}}</div>
          <div class="mt-2 flex items-center gap-2 text-sm">
            <span class="px-3 py-1 rounded-full soft">
              <span class="inline-block w-2 h-2 rounded-full bg-emerald-400 mr-2"></span>
              Role: <b>admin</b>
            </span>
          </div>
          <div class="mt-2 text-sm muted">
            Server time: <b class="text-white">{{server_time}}</b> &nbsp;•&nbsp; VPS: <b class="text-white">{{ip}}</b>
          </div>
        </div>

        <div class="flex flex-col gap-2 shrink-0">
          <a class="btn-gloss rounded-2xl px-4 py-2 text-sm font-semibold bg-gradient-to-r from-emerald-500 to-teal-500 hover:brightness-110"
             href="/backup">Backup</a>

          <form method="post" action="/restore" enctype="multipart/form-data" class="soft rounded-2xl p-2">
            <input type="file" name="file" accept=".zip" class="tiny muted w-full">
            <button class="mt-2 w-full btn-gloss rounded-xl py-2 text-sm font-semibold bg-gradient-to-r from-sky-500 to-indigo-500 hover:brightness-110">Restore</button>
          </form>

          <form method="post" action="/purge" onsubmit="return confirm('Purge expired users?')">
            <button class="w-full btn-gloss rounded-2xl px-4 py-2 text-sm font-semibold bg-gradient-to-r from-slate-600 to-slate-800 hover:brightness-110">
              Purge Expired
            </button>
          </form>

          <a class="btn-gloss rounded-2xl px-4 py-2 text-sm font-semibold bg-gradient-to-r from-rose-500 to-pink-600 hover:brightness-110"
             href="/logout">Logout</a>
        </div>
      </div>
    </section>

    {% with msgs=get_flashed_messages() %}
    {% if msgs %}
      <section class="glass rounded-3xl p-4 text-sm whitespace-pre-wrap">{{msgs[0]}}</section>
    {% endif %}
    {% endwith %}

    <section class="grid grid-cols-2 gap-3">
      <div class="glass rounded-3xl p-4">
        <div class="muted text-sm">Total Users</div>
        <div class="text-4xl font-extrabold mt-1">{{total_users}}</div>
      </div>
      <div class="glass rounded-3xl p-4">
        <div class="muted text-sm">Total Online</div>
        <div class="text-4xl font-extrabold mt-1 text-emerald-300">{{total_online}}</div>
      </div>
    </section>

    <section class="glass rounded-3xl p-4">
      <div class="flex items-center justify-between">
        <div class="text-xl font-bold">Bandwidth (<span id="bw-iface">{{iface}}</span>)</div>
        <div class="muted text-sm">Realtime</div>
      </div>
      <div class="mt-3 grid grid-cols-2 gap-3">
        <div class="soft rounded-2xl p-3">
          <div class="flex items-center gap-2 muted">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" class="text-emerald-300">
              <path d="M12 3v12l4-4 1.4 1.4L12 18l-5.4-5.6L8 11l4 4V3z"/>
            </svg>
            Download
          </div>
          <div class="text-2xl font-extrabold mt-1"><span id="rx">0.00</span> Mbps</div>
          <div class="muted text-sm">Total Download <b class="text-white" id="rxTot">-</b></div>
        </div>
        <div class="soft rounded-2xl p-3">
          <div class="flex items-center gap-2 muted">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" class="text-sky-300">
              <path d="M12 21V9l-4 4-1.4-1.4L12 6l5.4 5.6L16 13l-4-4v12z"/>
            </svg>
            Upload
          </div>
          <div class="text-2xl font-extrabold mt-1"><span id="tx">0.00</span> Mbps</div>
          <div class="muted text-sm">Total Upload <b class="text-white" id="txTot">-</b></div>
        </div>
      </div>
    </section>

    <section class="glass rounded-3xl p-4">
      <div class="text-xl font-bold">System</div>
      <div class="mt-3 grid grid-cols-2 gap-3">
        <div class="soft rounded-2xl p-3">
          <div class="flex items-center gap-2 muted">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" class="text-amber-300">
              <path d="M9 2h6v2H9V2zm7 4H8C6.3 6 5 7.3 5 9v7c0 1.7 1.3 3 3 3h8c1.7 0 3-1.3 3-3V9c0-1.7-1.3-3-3-3zm1 10c0 .6-.4 1-1 1H8c-.6 0-1-.4-1-1V9c0-.6.4-1 1-1h8c.6 0 1 .4 1 1v7z"/>
            </svg>
            CPU
          </div>
          <div class="text-2xl font-extrabold mt-1" id="cpu">0.0%</div>
        </div>
        <div class="soft rounded-2xl p-3">
          <div class="flex items-center gap-2 muted">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" class="text-violet-300">
              <path d="M3 7h18v10H3V7zm2 2v6h14V9H5zm-2 9h18v2H3v-2z"/>
            </svg>
            RAM
          </div>
          <div class="text-2xl font-extrabold mt-1" id="ram">0.0%</div>
          <div class="muted text-sm" id="ramUsed">-</div>
        </div>
      </div>
    </section>

    <!-- Admin Add User -->
    <section class="glass rounded-3xl p-4">
      <div class="text-xl font-bold">Add User (Admin)</div>
      <form method="post" action="/admin/user/create" class="mt-3 space-y-3">
        <input name="username" placeholder="Username" class="w-full rounded-2xl p-3 bg-white/10 border border-white/10 outline-none focus:ring-2 focus:ring-emerald-500 placeholder:text-white/40">
        <input name="password" placeholder="Password" class="w-full rounded-2xl p-3 bg-white/10 border border-white/10 outline-none focus:ring-2 focus:ring-emerald-500 placeholder:text-white/40">
        <div class="grid grid-cols-2 gap-2">
          <button type="button" id="b1d" class="soft rounded-2xl py-2 text-sm btn-gloss">1d</button>
          <button type="button" id="b7d" class="soft rounded-2xl py-2 text-sm btn-gloss">7d</button>
          <button type="button" id="b15d" class="soft rounded-2xl py-2 text-sm btn-gloss">15d</button>
          <button type="button" id="b30d" class="soft rounded-2xl py-2 text-sm btn-gloss">30d</button>
        </div>
        <div class="grid grid-cols-2 gap-2">
          <button type="button" id="bnow" class="soft rounded-2xl py-2 text-sm btn-gloss">Now</button>
          <button type="button" id="bclear" class="soft rounded-2xl py-2 text-sm btn-gloss">Clear</button>
        </div>
        <input id="expires_at" name="expires_at" value="{{default_exp}}" placeholder="YYYY-MM-DD HH:MM:SS"
          class="w-full rounded-2xl p-3 bg-white/10 border border-white/10 outline-none focus:ring-2 focus:ring-emerald-500 placeholder:text-white/40">
        <select name="reseller_id" class="w-full rounded-2xl p-3 bg-white/10 border border-white/10 outline-none">
          <option value="">Owner: Admin (no reseller)</option>
          {% for rr in resellers %}
            <option value="{{rr['id']}}">Owner: {{rr['username']}}</option>
          {% endfor %}
        </select>
        <button class="w-full btn-gloss rounded-2xl py-3 font-semibold bg-gradient-to-r from-emerald-500 to-teal-500 hover:brightness-110">
          Create User
        </button>
        <div class="tiny muted">1 User For 1 Device</div>
      </form>
    </section>

    <!-- Reseller Management -->
    <section class="glass rounded-3xl p-4">
      <div class="text-xl font-bold">Reseller</div>
      <form method="post" action="/admin/reseller/create" class="mt-3 space-y-3">
        <input name="username" placeholder="Username reseller" class="w-full rounded-2xl p-3 bg-white/10 border border-white/10 outline-none placeholder:text-white/40">
        <input name="password" placeholder="Password reseller (kosong = auto)" class="w-full rounded-2xl p-3 bg-white/10 border border-white/10 outline-none placeholder:text-white/40">
        <button class="w-full btn-gloss rounded-2xl py-3 font-semibold bg-gradient-to-r from-sky-500 via-blue-600 to-indigo-500 hover:brightness-110">
          Buat Reseller
        </button>
        <div class="tiny muted">Daftar reseller WA: <b class="text-white">{{wa}}</b></div>
      </form>

      <div class="mt-4 soft rounded-2xl p-3">
        <div class="font-semibold mb-2">List Reseller</div>
        {% if resellers|length == 0 %}
          <div class="muted text-sm">Belum ada reseller.</div>
        {% else %}
          <div class="space-y-2">
            {% for rr in resellers %}
              <div class="flex items-center justify-between gap-2 soft rounded-xl p-2">
                <div class="min-w-0">
                  <div class="font-semibold truncate">{{rr['username']}}</div>
                  <div class="tiny muted">Created: {{rr['created_at']}}</div>
                </div>
                <div class="flex items-center gap-2">
                  <code class="chip px-2 py-1 rounded-lg bg-white/10 border border-white/10">{{rr['password']}}</code>
                  <button type="button" onclick="copyText('{{rr['password']}}', this)" class="btn-gloss soft rounded-xl px-3 py-2 text-sm">Copy</button>
                </div>
              </div>
            {% endfor %}
          </div>
        {% endif %}
      </div>
    </section>

    <!-- Users List -->
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
                <div class="tiny muted">Owner: <b class="text-white">{{r['reseller_name']}}</b> • Exp: <b class="text-white">{{r['expires_at']}}</b> • Left: <b class="text-white">{{r['left_str']}}</b></div>
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
              <form method="post" action="/admin/user/delete/{{r['id']}}" onsubmit="return confirm('Delete {{r['username']}} ?')">
                <button class="btn-gloss rounded-xl px-4 py-2 text-sm font-semibold bg-gradient-to-r from-rose-500 to-pink-600 hover:brightness-110">Delete</button>
              </form>
            </div>
          </div>
        {% endfor %}
      </div>
    </section>

  </main>
</body>
</html>'''

# ---------- DASHBOARD (RESELLER) ----------
RESELLER_DASH_TPL = r'''<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{{panel_name}} - Reseller</title>
<script src="https://cdn.tailwindcss.com"></script>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/flatpickr/dist/flatpickr.min.css">
<script src="https://cdn.jsdelivr.net/npm/flatpickr"></script>
<style>
  :root{color-scheme:dark}
  body{background: radial-gradient(1100px 600px at 18% 10%, rgba(16,185,129,.16), transparent 55%),
                 radial-gradient(900px 500px at 82% 30%, rgba(59,130,246,.14), transparent 60%),
                 radial-gradient(900px 600px at 50% 90%, rgba(168,85,247,.12), transparent 60%),
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
  .flatpickr-calendar{background:#0b1224;border:1px solid rgba(255,255,255,.10); box-shadow:0 18px 60px rgba(0,0,0,.55)}
  .flatpickr-time input{color:#fff}
  .flatpickr-day{color:#cbd5e1}
  .flatpickr-day.selected{background:#3b82f6;border-color:#3b82f6}
</style>
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
window.addEventListener('load', ()=>{
  flatpickr("#expires_at", {
    enableTime:true, dateFormat:"Y-m-d H:i:S", time_24hr:true,
    defaultDate: document.getElementById('expires_at').value
  });
  const setExp=(mins)=>{
    const d=new Date(Date.now()+mins*60*1000);
    const s=d.getFullYear()+"-"+fmt2(d.getMonth()+1)+"-"+fmt2(d.getDate())+" "+fmt2(d.getHours())+":"+fmt2(d.getMinutes())+":"+fmt2(d.getSeconds());
    document.getElementById('expires_at').value=s;
  }
  document.getElementById('b1d').onclick=()=>setExp(1440);
  document.getElementById('b7d').onclick=()=>setExp(10080);
  document.getElementById('b15d').onclick=()=>setExp(21600);
  document.getElementById('b30d').onclick=()=>setExp(43200);
  document.getElementById('bnow').onclick=()=>setExp(10);
  document.getElementById('bclear').onclick=()=>document.getElementById('expires_at').value="";
});
</script>
</head>
<body class="min-h-screen text-slate-100">
  <main class="max-w-3xl mx-auto px-4 py-4 space-y-4">

    <section class="glass rounded-3xl p-5">
      <div class="flex items-start justify-between gap-3">
        <div class="min-w-0">
          <div class="text-2xl font-extrabold tracking-tight leading-tight">{{panel_name}}</div>
          <div class="mt-2 text-sm muted">Role: <b class="text-white">reseller</b> • Login: <b class="text-white">{{reseller_name}}</b></div>
          <div class="mt-1 text-sm muted">VPS: <b class="text-white">{{ip}}</b></div>
        </div>
        <a class="btn-gloss rounded-2xl px-4 py-2 text-sm font-semibold bg-gradient-to-r from-rose-500 to-pink-600 hover:brightness-110"
           href="/logout">Logout</a>
      </div>
    </section>

    {% with msgs=get_flashed_messages() %}
    {% if msgs %}
      <section class="glass rounded-3xl p-4 text-sm whitespace-pre-wrap">{{msgs[0]}}</section>
    {% endif %}
    {% endwith %}

    <section class="glass rounded-3xl p-4">
      <div class="text-xl font-bold">Add User (Reseller)</div>
      <form method="post" action="/reseller/user/create" class="mt-3 space-y-3">
        <input name="username" placeholder="Username" class="w-full rounded-2xl p-3 bg-white/10 border border-white/10 outline-none focus:ring-2 focus:ring-sky-500 placeholder:text-white/40">
        <input name="password" placeholder="Password" class="w-full rounded-2xl p-3 bg-white/10 border border-white/10 outline-none focus:ring-2 focus:ring-sky-500 placeholder:text-white/40">
        <div class="grid grid-cols-2 gap-2">
          <button type="button" id="b1d" class="soft rounded-2xl py-2 text-sm btn-gloss">1d</button>
          <button type="button" id="b7d" class="soft rounded-2xl py-2 text-sm btn-gloss">7d</button>
          <button type="button" id="b15d" class="soft rounded-2xl py-2 text-sm btn-gloss">15d</button>
          <button type="button" id="b30d" class="soft rounded-2xl py-2 text-sm btn-gloss">30d</button>
        </div>
        <div class="grid grid-cols-2 gap-2">
          <button type="button" id="bnow" class="soft rounded-2xl py-2 text-sm btn-gloss">Now</button>
          <button type="button" id="bclear" class="soft rounded-2xl py-2 text-sm btn-gloss">Clear</button>
        </div>
        <input id="expires_at" name="expires_at" value="{{default_exp}}" placeholder="YYYY-MM-DD HH:MM:SS"
          class="w-full rounded-2xl p-3 bg-white/10 border border-white/10 outline-none focus:ring-2 focus:ring-sky-500 placeholder:text-white/40">
        <button class="w-full btn-gloss rounded-2xl py-3 font-semibold bg-gradient-to-r from-sky-500 via-blue-600 to-indigo-500 hover:brightness-110">
          Create User
        </button>
        <div class="tiny muted">Reseller tidak bisa hapus user (view only).</div>
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
                <div class="tiny muted">Exp: <b class="text-white">{{r['expires_at']}}</b> • Left: <b class="text-white">{{r['left_str']}}</b></div>
              </div>
              <div>
                {% if not r['expired'] %}
                  <span class="text-emerald-300 tiny px-3 py-1 rounded-full soft">ACTIVE</span>
                {% else %}
                  <span class="muted tiny px-3 py-1 rounded-full soft">EXPIRED</span>
                {% endif %}
              </div>
            </div>
            <div class="mt-2 flex items-center gap-2">
              <code class="chip px-2 py-1 rounded-lg bg-white/10 border border-white/10">{{r['password']}}</code>
              <button type="button" onclick="copyText('{{r['password']}}', this)" class="btn-gloss soft rounded-xl px-3 py-2 text-sm">Copy</button>
            </div>
          </div>
        {% endfor %}
      </div>
    </section>

  </main>
</body>
</html>'''

@app.route("/")
@login_required()
def dash():
    if get_role()=="reseller":
        return redirect(url_for("reseller_dash"))
    # admin
    ip=vps_ip()
    rows=user_rows_for_admin()
    total_users=len(rows)
    total_online=sum(1 for r in rows if (not r["expired"]))
    default_exp=(datetime.now()+timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
    return render_template_string(
        DASH_TPL,
        panel_name=PANEL_NAME,
        server_time=server_time_str(),
        ip=ip,
        rows=rows,
        total_users=total_users,
        total_online=total_online,
        iface=(BW_IFACE or _default_iface()),
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

# ---------- Admin actions ----------
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
    # validate exp
    try:
        datetime.strptime(exp, "%Y-%m-%d %H:%M:%S")
    except Exception:
        flash("Format expiry salah. Pakai: YYYY-MM-DD HH:MM:SS")
        return redirect(url_for("dash"))

    rid=None
    if reseller_id:
        try:
            rid=int(reseller_id)
        except Exception:
            rid=None

    with db() as con:
        con.execute("""INSERT INTO users(username,password,expires_at,reseller_id,created_at)
                       VALUES(?,?,?,?,?)
                       ON CONFLICT(username) DO UPDATE SET password=?, expires_at=?, reseller_id=?""",
                    (u,p,exp,rid,now().isoformat(),p,exp,rid))
    sync_config()
    ip=vps_ip()
    owner = "Admin" if not rid else f"Reseller #{rid}"
    flash(f"Create Account Done\nIP : {ip}\nUser : {u}\nPassword : {p}\nExpired : {exp}\nOwner : {owner}\n1 User For 1 Device")
    return redirect(url_for("dash"))

@app.route("/admin/user/delete/<int:uid>", methods=["POST"])
@admin_required
def admin_user_delete(uid:int):
    with db() as con:
        con.execute("DELETE FROM users WHERE id=?", (uid,))
    sync_config()
    flash("User deleted.")
    return redirect(url_for("dash"))

@app.route("/admin/reseller/create", methods=["POST"])
@admin_required
def admin_reseller_create():
    u=_safe(request.form.get("username"))
    p=_safe(request.form.get("password"))
    if not u:
        flash("Buat reseller gagal: username kosong")
        return redirect(url_for("dash"))
    if not p:
        p = f"rs{int(time.time())%1000000}"
    with db() as con:
        con.execute("""INSERT INTO resellers(username,password,created_at)
                       VALUES(?,?,?)
                       ON CONFLICT(username) DO UPDATE SET password=?""",
                    (u,p,server_time_str(),p))
    flash(f"Reseller dibuat.\nUsername: {u}\nPassword: {p}\nDaftar reseller WA: {WA_NUMBER}")
    return redirect(url_for("dash"))

@app.route("/purge", methods=["POST"])
@admin_required
def purge():
    purge_expired()
    flash("Expired users purged + config synced.")
    return redirect(url_for("dash"))

# ---------- Reseller actions ----------
@app.route("/reseller/user/create", methods=["POST"])
@reseller_required
def reseller_user_create():
    rid=int(session.get("rid") or 0)
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
                    (u,p,exp,rid,now().isoformat(),p,exp,rid))
    sync_config()
    ip=vps_ip()
    flash(f"Create Account Done\nIP : {ip}\nUser : {u}\nPassword : {p}\nExpired : {exp}\n1 User For 1 Device")
    return redirect(url_for("reseller_dash"))

if __name__=="__main__":
    from waitress import serve
    serve(app, host=os.getenv("BIND_HOST","0.0.0.0"), port=int(os.getenv("BIND_PORT","8088")))
PY

# Maint script (auto purge expired + sync)
cat > "${MAINT_PY}" <<'PY'
import os, sqlite3, json, tempfile, subprocess
from datetime import datetime
from subprocess import DEVNULL

DB="/var/lib/zivpn-admin/zivpn.db"
CFG=os.getenv("ZIVPN_CONFIG","/etc/zivpn/config.json")
SVC=os.getenv("ZIVPN_SERVICE","zivpn.service")

def now_iso():
    return datetime.utcnow().isoformat()

def sync():
    with sqlite3.connect(DB) as con:
        pw=[r[0] for r in con.execute("SELECT DISTINCT password FROM users WHERE expires_at > ?", (now_iso(),))]
    if not pw: pw=["zi"]
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

def purge():
    with sqlite3.connect(DB) as con:
        con.execute("DELETE FROM users WHERE expires_at <= ?", (now_iso(),))
    sync()

if __name__=="__main__":
    purge()
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
echo "Open Admin : http://${IP}:${PANEL_PORT}/login"
echo "Open Reseller : http://${IP}:${PANEL_PORT}/reseller/login"
echo "UDP Port : 5667"
echo "Backup/Restore tersedia di dashboard Admin"
echo "Auto purge expired: every 10 minutes"
echo "======================================"
BASH

chmod +x zi.sh
./zi.sh
