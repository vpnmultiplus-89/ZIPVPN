#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
trap 'echo -e "\n[ERROR] Script berhenti di baris: $LINENO\n"; exit 1' ERR

wait_for_apt_lock() {
  local timeout="${1:-180}"
  local waited=0
  echo "==> Menunggu APT lock (jika ada)..."
  while fuser /var/lib/apt/lists/lock >/dev/null 2>&1 \
     || fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 \
     || fuser /var/cache/apt/archives/lock >/dev/null 2>&1; do
    if [ "$waited" -ge "$timeout" ]; then
      echo "[ERROR] APT masih terkunci setelah ${timeout}s. Coba tunggu sebentar lalu jalankan ulang."
      exit 1
    fi
    sleep 3
    waited=$((waited+3))
  done
  # recovery ringan kalau dpkg sempat ke-interrupt
  dpkg --configure -a >/dev/null 2>&1 || true
}

ZIVPN_BIN="/usr/local/bin/zivpn"
ZIVPN_DIR="/etc/zivpn"
ZIVPN_CFG="${ZIVPN_DIR}/config.json"
ZIVPN_SVC="zivpn.service"

ADMIN_DIR="/opt/zivpn-admin"
APP_PY="${ADMIN_DIR}/app.py"
SYNC_PY="${ADMIN_DIR}/sync.py"
VENV="${ADMIN_DIR}/venv"
ENV_FILE="${ADMIN_DIR}/.env"
PANEL_SVC="zivpn-admin.service"
SYNC_SVC="zivpn-sync.service"
SYNC_TIMER="zivpn-sync.timer"

echo "==> Update packages..."
wait_for_apt_lock 300
apt-get update -y
wait_for_apt_lock 300
apt-get upgrade -y

echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections || true
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections || true

apt-get install -y python3-venv python3-pip openssl ufw curl jq wget iptables-persistent sqlite3 >/dev/null

echo "==> Install ZIVPN binary..."
systemctl stop "${ZIVPN_SVC}" 2>/dev/null || true
wget -q "https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64" -O "${ZIVPN_BIN}"
chmod +x "${ZIVPN_BIN}"

mkdir -p "${ZIVPN_DIR}"
cat > "${ZIVPN_CFG}" <<'JSON'
{
  "listen": ":1433",
  "cert": "/etc/zivpn/zivpn.crt",
  "key": "/etc/zivpn/zivpn.key",
  "obfs": "zivpn",
  "auth": {"mode": "passwords", "config": ["zi"]},
  "config": ["zi"]
}
JSON

echo "==> Generate TLS cert..."
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
systemctl enable --now "${ZIVPN_SVC}"

# Detect default interface
IFC="$(ip -4 route ls 2>/dev/null | awk '/default/ {print $5; exit}' || true)"
IFC="${IFC:-}"

echo "==> NAT REDIRECT UDP 6000-19999 -> 1433..."
if [[ -n "$IFC" ]]; then
  iptables -t nat -C PREROUTING -i "$IFC" -p udp --dport 6000:19999 -j REDIRECT --to-ports 1433 2>/dev/null \
    || iptables -t nat -A PREROUTING -i "$IFC" -p udp --dport 6000:19999 -j REDIRECT --to-ports 1433
else
  iptables -t nat -C PREROUTING -p udp --dport 6000:19999 -j REDIRECT --to-ports 1433 2>/dev/null \
    || iptables -t nat -A PREROUTING -p udp --dport 6000:19999 -j REDIRECT --to-ports 1433
fi

netfilter-persistent save >/dev/null 2>&1 || true
systemctl restart netfilter-persistent >/dev/null 2>&1 || true

# UFW safe
SSH_PORT="$(ss -tlpn 2>/dev/null | awk '/sshd/ {gsub(/.*:/,"",$4); print $4; exit}' || true)"
SSH_PORT="${SSH_PORT:-22}"
ufw allow "${SSH_PORT}/tcp" >/dev/null 2>&1 || true
ufw allow OpenSSH >/dev/null 2>&1 || true
ufw allow 1433/udp >/dev/null 2>&1 || true
ufw allow 8088/tcp >/dev/null 2>&1 || true
ufw --force enable >/dev/null 2>&1 || true

echo "==> Setup Web Panel..."
mkdir -p "${ADMIN_DIR}"
python3 -m venv "${VENV}"
"${VENV}/bin/pip" install --upgrade pip >/dev/null 2>&1 || true
"${VENV}/bin/pip" install flask waitress werkzeug >/dev/null

read -rp "Admin username [default: admin]: " ADMIN_USER
ADMIN_USER=${ADMIN_USER:-admin}
read -rp "Admin password [default: change-me]: " ADMIN_PASSWORD
ADMIN_PASSWORD=${ADMIN_PASSWORD:-change-me}
read -rp "Nama Panel [default: MULTI PLUS VPN]: " PANEL_NAME
PANEL_NAME=${PANEL_NAME:-MULTI PLUS VPN}
read -rp "Bandwidth interface (eth0/ens3) [default: auto]: " BW_IFACE
BW_IFACE=${BW_IFACE:-}

SECRET_KEY="$(openssl rand -hex 32)"

cat > "${ENV_FILE}" <<EOF
ADMIN_USER=${ADMIN_USER}
ADMIN_PASSWORD=${ADMIN_PASSWORD}
PANEL_NAME=${PANEL_NAME}
SECRET_KEY=${SECRET_KEY}
BIND_HOST=0.0.0.0
BIND_PORT=8088
ZIVPN_CONFIG=${ZIVPN_CFG}
ZIVPN_SERVICE=${ZIVPN_SVC}
BW_IFACE=${BW_IFACE}
EOF
chmod 600 "${ENV_FILE}"

mkdir -p /var/lib/zivpn-admin
chmod 700 /var/lib/zivpn-admin

cat > "${APP_PY}" <<'PY'
import os, json, sqlite3, time, tempfile, tarfile, io, shutil, subprocess, secrets
from subprocess import DEVNULL
from datetime import datetime, timedelta
from flask import Flask, request, redirect, session, render_template_string, flash, jsonify, send_file
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

DB = "/var/lib/zivpn-admin/zivpn.db"
os.makedirs("/var/lib/zivpn-admin", exist_ok=True)

ZIVPN_CFG = os.getenv("ZIVPN_CONFIG", "/etc/zivpn/config.json")
ZIVPN_SVC = os.getenv("ZIVPN_SERVICE", "zivpn.service")
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASSWORD", "change-me")
PANEL_NAME = os.getenv("PANEL_NAME", "MULTI PLUS VPN")
BW_IFACE = os.getenv("BW_IFACE", "").strip()

_bw_prev = {}
_cpu_prev = None

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev")

def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con

def ensure_schema():
    with db() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            expires TEXT,
            owner TEXT
        )""")
        con.execute("""CREATE TABLE IF NOT EXISTS resellers(
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            pass_hash TEXT NOT NULL,
            is_active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT (datetime('now'))
        )""")

ensure_schema()

def login_required(f):
    @wraps(f)
    def w(*a, **kw):
        if not session.get("ok"):
            return redirect("/login")
        return f(*a, **kw)
    return w

def admin_required(f):
    @wraps(f)
    def w(*a, **kw):
        if session.get("role") != "admin":
            flash("Akses ditolak: khusus admin")
            return redirect("/")
        return f(*a, **kw)
    return w

def sync(restart=False):
    with db() as con:
        pw = [r[0] for r in con.execute("""
            SELECT DISTINCT password
            FROM users
            WHERE datetime(expires) >= datetime('now')
        """)]
    if not pw:
        pw = ["zi"]

    cfg = {}
    try:
        cfg = json.load(open(ZIVPN_CFG))
    except Exception:
        pass

    cfg.setdefault("auth", {})["mode"] = "passwords"
    cfg["auth"]["config"] = pw
    cfg["config"] = pw

    os.makedirs(os.path.dirname(ZIVPN_CFG), exist_ok=True)
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        json.dump(cfg, f, indent=2)
        tmp = f.name
    os.replace(tmp, ZIVPN_CFG)

    if restart:
        subprocess.Popen(["systemctl", "restart", ZIVPN_SVC], stdout=DEVNULL, stderr=DEVNULL)

# ---------- Bandwidth (PROC NET DEV) ----------
def _human_best(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    x = float(n)
    u = 0
    while x >= 1024 and u < len(units) - 1:
        x /= 1024.0
        u += 1
    return f"{int(x)}{units[u]}" if u == 0 else f"{x:.2f}{units[u]}"

def _read_proc_net_dev():
    data = {}
    try:
        with open("/proc/net/dev", "r", encoding="utf-8", errors="ignore") as f:
            lines = f.read().splitlines()
        for ln in lines[2:]:
            if ":" not in ln:
                continue
            iface, rest = ln.split(":", 1)
            iface = iface.strip()
            parts = rest.split()
            if len(parts) < 16:
                continue
            rx = int(parts[0]); tx = int(parts[8])
            data[iface] = (rx, tx)
    except Exception:
        return {}
    return data

def _pick_iface(dev: dict) -> str:
    if BW_IFACE and BW_IFACE in dev:
        return BW_IFACE
    for pref in ("eth0", "ens3", "ens160", "enp0s3", "enp1s0"):
        if pref in dev:
            return pref
    for k in dev.keys():
        if k != "lo":
            return k
    return "lo"

def get_bw_snapshot():
    dev = _read_proc_net_dev()
    iface = _pick_iface(dev)
    now = time.time()
    rx, tx = dev.get(iface, (0, 0))
    prev = _bw_prev.get(iface)

    rx_mbps = tx_mbps = 0.0
    if prev:
        pts, prx, ptx = prev
        dt = max(0.001, now - pts)
        rx_mbps = ((rx - prx) * 8.0) / dt / 1_000_000.0
        tx_mbps = ((tx - ptx) * 8.0) / dt / 1_000_000.0

    _bw_prev[iface] = (now, rx, tx)
    return {
        "iface": iface,
        "rx_mbps": round(max(0.0, rx_mbps), 2),
        "tx_mbps": round(max(0.0, tx_mbps), 2),
        "rx_total_h": _human_best(rx),
        "tx_total_h": _human_best(tx),
    }

@app.route("/api/bw")
@login_required
def api_bw():
    return jsonify(get_bw_snapshot())

# ---------- CPU/RAM ----------
def _read_proc_stat_cpu():
    try:
        with open("/proc/stat", "r", encoding="utf-8", errors="ignore") as f:
            first = f.readline().strip()
        parts = first.split()
        if parts[0] != "cpu":
            return None
        nums = list(map(int, parts[1:8]))
        total = sum(nums)
        idle = nums[3] + nums[4]
        return total, idle
    except Exception:
        return None

def _read_meminfo():
    total = avail = 0
    try:
        with open("/proc/meminfo", "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    total = int(line.split()[1])
                elif line.startswith("MemAvailable:"):
                    avail = int(line.split()[1])
                if total and avail:
                    break
    except Exception:
        pass
    return total, avail

def get_sys_snapshot():
    global _cpu_prev
    cpu = _read_proc_stat_cpu()
    cpu_pct = 0.0
    if cpu:
        total, idle = cpu
        if _cpu_prev:
            ptotal, pidle = _cpu_prev
            dtotal = total - ptotal
            didle = idle - pidle
            if dtotal > 0:
                cpu_pct = 100.0 * (1.0 - (didle / dtotal))
        _cpu_prev = (total, idle)

    mem_total, mem_avail = _read_meminfo()
    mem_used = max(0, mem_total - mem_avail)
    mem_pct = 0.0
    if mem_total > 0:
        mem_pct = 100.0 * (mem_used / mem_total)

    return {
        "cpu_pct": round(max(0.0, min(cpu_pct, 100.0)), 1),
        "mem_pct": round(max(0.0, min(mem_pct, 100.0)), 1),
        "mem_used_h": _human_best(mem_used * 1024),
        "mem_total_h": _human_best(mem_total * 1024),
    }

@app.route("/api/sys")
@login_required
def api_sys():
    return jsonify(get_sys_snapshot())

# ---------- Backup/Restore (admin only) ----------
def _tar_add_safe(tar: tarfile.TarFile, path: str, arcname: str):
    try:
        if os.path.exists(path):
            tar.add(path, arcname=arcname, recursive=True)
    except Exception:
        pass

@app.route("/backup", methods=["GET"])
@login_required
@admin_required
def backup():
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    fname = f"zivpn-backup-{ts}.tar.gz"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        _tar_add_safe(tar, "/var/lib/zivpn-admin", "var/lib/zivpn-admin")
        _tar_add_safe(tar, "/etc/zivpn", "etc/zivpn")
    buf.seek(0)
    return send_file(buf, as_attachment=True, download_name=fname, mimetype="application/gzip")

@app.route("/restore", methods=["GET", "POST"])
@login_required
@admin_required
def restore():
    if request.method == "GET":
        return render_template_string('''<!doctype html><html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Restore</title><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen grid place-items-center bg-gradient-to-br from-[#050914] via-[#071021] to-[#04060f] text-white">
<div class="p-6 rounded-2xl border border-white/10 bg-white/5 backdrop-blur-xl w-[380px]">
<h2 class="text-xl font-bold mb-4">Restore Backup</h2>
<form method="post" enctype="multipart/form-data" class="space-y-3">
<input type="file" name="file" required class="w-full text-sm bg-white/10 p-2 rounded-xl border border-white/10">
<label class="flex items-center gap-2 text-sm"><input type="checkbox" name="restore_db" checked> Restore Database</label>
<label class="flex items-center gap-2 text-sm"><input type="checkbox" name="restore_cfg" checked> Restore Config</label>
<button class="w-full bg-emerald-600 hover:bg-emerald-500 py-2.5 rounded-xl">Restore Now</button>
<a href="/" class="block text-center text-sm text-white/70 hover:underline">Back</a>
</form></div></body></html>''')

    f = request.files.get("file")
    if not f:
        flash("No file uploaded")
        return redirect("/")

    tmpdir = tempfile.mkdtemp(prefix="zivpn-restore-")
    try:
        tar = tarfile.open(fileobj=f.stream, mode="r:gz")
        tar.extractall(tmpdir)
        tar.close()

        if request.form.get("restore_db"):
            src = os.path.join(tmpdir, "var/lib/zivpn-admin")
            if os.path.exists(src):
                shutil.rmtree("/var/lib/zivpn-admin", ignore_errors=True)
                shutil.copytree(src, "/var/lib/zivpn-admin")

        if request.form.get("restore_cfg"):
            src = os.path.join(tmpdir, "etc/zivpn")
            if os.path.exists(src):
                shutil.rmtree("/etc/zivpn", ignore_errors=True)
                shutil.copytree(src, "/etc/zivpn")

        subprocess.call(["systemctl", "restart", ZIVPN_SVC])
        subprocess.call(["systemctl", "restart", "zivpn-admin.service"])
        flash("Restore SUCCESS")
    except Exception as e:
        flash(f"Restore FAILED: {e}")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    return redirect("/")

# ---------- Login Templates ----------
LOGIN_TPL = '''<!doctype html>
<html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{{ panel_name }}</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
.glass{background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.12);backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);box-shadow:0 22px 90px rgba(0,0,0,.65);}
</style></head>
<body class="min-h-screen grid place-items-center bg-gradient-to-br from-[#050914] via-[#071021] to-[#04060f] text-white">
<div class="w-[360px] glass p-6 rounded-2xl">
  <div class="flex items-center gap-2 mb-4">
    <div class="w-9 h-9 rounded-full bg-emerald-500/20 border border-emerald-500/30 grid place-items-center">
      <div class="w-4 h-4 rounded-full bg-emerald-400"></div>
    </div>
    <div>
      <h2 class="text-2xl font-extrabold tracking-tight">{{ panel_name }}</h2>
      <div class="text-xs text-white/70">Admin Login</div>
    </div>
  </div>

  {% with messages = get_flashed_messages() %}
    {% if messages %}
      <div class="mb-3 space-y-2">
        {% for m in messages %}
          <div class="text-xs bg-white/10 border border-white/10 rounded-xl p-2">{{m}}</div>
        {% endfor %}
      </div>
    {% endif %}
  {% endwith %}

  <form method=post class="space-y-3">
    <input name=u class="w-full p-3 rounded-xl bg-black/30 border border-white/10 outline-none" placeholder="Username admin">
    <input name=p type=password class="w-full p-3 rounded-xl bg-black/30 border border-white/10 outline-none" placeholder="Password">
    <button class="w-full bg-gradient-to-r from-emerald-500 to-sky-500 py-3 rounded-xl text-lg font-semibold">Login Admin</button>
  </form>

  <div class="mt-3 text-xs text-white/60">
    Reseller login: <a class="underline" href="/reseller">/reseller</a>
  </div>
</div></body></html>'''

RESELLER_LOGIN_TPL = '''<!doctype html>
<html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{{ panel_name }} - Reseller</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
.glass{background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.12);backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);box-shadow:0 22px 90px rgba(0,0,0,.65);}
.badge{background:linear-gradient(90deg,#a855f7,#0ea5e9,#22c55e);}
</style></head>
<body class="min-h-screen grid place-items-center bg-gradient-to-br from-[#050914] via-[#071021] to-[#04060f] text-white">
<div class="w-[360px] glass p-6 rounded-2xl">
  <div class="flex items-center gap-2 mb-4">
    <div class="w-9 h-9 rounded-full badge border border-white/10 grid place-items-center">
      <div class="w-4 h-4 rounded-full bg-white/90"></div>
    </div>
    <div>
      <h2 class="text-2xl font-extrabold tracking-tight">{{ panel_name }}</h2>
      <div class="text-xs text-white/70">Reseller Login</div>
    </div>
  </div>

  {% with messages = get_flashed_messages() %}
    {% if messages %}
      <div class="mb-3 space-y-2">
        {% for m in messages %}
          <div class="text-xs bg-white/10 border border-white/10 rounded-xl p-2">{{m}}</div>
        {% endfor %}
      </div>
    {% endif %}
  {% endwith %}

  <form method=post class="space-y-3">
    <input name=u class="w-full p-3 rounded-xl bg-black/30 border border-white/10 outline-none" placeholder="Username reseller">
    <input name=p type=password class="w-full p-3 rounded-xl bg-black/30 border border-white/10 outline-none" placeholder="Password">
    <button class="w-full bg-gradient-to-r from-purple-500 via-sky-500 to-emerald-500 py-3 rounded-xl text-lg font-semibold">Login Reseller</button>
  </form>

  <div class="mt-3 text-xs text-white/60">
    Admin login: <a class="underline" href="/login">/login</a>
  </div>
</div></body></html>'''

# ---------- Login Routes ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = (request.form.get("u") or "").strip()
        p = (request.form.get("p") or "").strip()
        if u == ADMIN_USER and p == ADMIN_PASS:
            session["ok"] = True
            session["role"] = "admin"
            session["user"] = u
            return redirect("/")
        flash("Admin only: credential salah")
    return render_template_string(LOGIN_TPL, panel_name=PANEL_NAME)

@app.route("/reseller", methods=["GET", "POST"])
def reseller_login():
    if request.method == "POST":
        u = (request.form.get("u") or "").strip()
        p = (request.form.get("p") or "").strip()
        with db() as con:
            r = con.execute("SELECT username, pass_hash, is_active FROM resellers WHERE username=?", (u,)).fetchone()
        if r and int(r["is_active"] or 0) == 1 and check_password_hash(r["pass_hash"], p):
            session["ok"] = True
            session["role"] = "reseller"
            session["user"] = u
            return redirect("/")
        flash("Reseller credentials salah / tidak aktif")
    return render_template_string(RESELLER_LOGIN_TPL, panel_name=PANEL_NAME)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

# ---------- Admin: Create Reseller ----------
@app.route("/reseller/create", methods=["POST"])
@login_required
@admin_required
def reseller_create():
    ru = (request.form.get("ru") or "").strip()
    rp = (request.form.get("rp") or "").strip()
    if not ru:
        flash("Username reseller kosong")
        return redirect("/")
    if not rp:
        rp = secrets.token_hex(4)
    ph = generate_password_hash(rp)
    try:
        with db() as con:
            con.execute("INSERT INTO resellers(username, pass_hash, is_active) VALUES(?,?,1)", (ru, ph))
        flash(f"Reseller dibuat | User: {ru} | Pass: {rp}")
    except Exception as e:
        flash(f"Gagal buat reseller: {e}")
    return redirect("/")

def _norm_expires(v: str) -> str:
    v = (v or "").strip()
    if not v:
        return ""
    v = v

    # normalize JS picker value
    v = v.replace("T", " ")
    try:
        if len(v) == 16:
            dt = datetime.strptime(v, "%Y-%m-%d %H:%M")
        else:
            dt = datetime.fromisoformat(v)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ""

# ---------- Dashboard Template (FINAL) ----------
DASH_TPL = r'''<!doctype html>
<html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{{ panel_name }}</title>
<script src="https://cdn.tailwindcss.com"></script>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/flatpickr/dist/flatpickr.min.css">
<script src="https://cdn.jsdelivr.net/npm/flatpickr"></script>
<script>
const SERVER_TS={{server_ts}}*1000; let start=Date.now();
function fmt(n){return n.toString().padStart(2,'0')}
function tick(){
  const now=SERVER_TS+(Date.now()-start); const d=new Date(now);
  const s=d.getFullYear()+"-"+fmt(d.getMonth()+1)+"-"+fmt(d.getDate())+" "+fmt(d.getHours())+":"+fmt(d.getMinutes())+":"+fmt(d.getSeconds());
  const el=document.getElementById('server-time'); if(el) el.textContent=s;
}
setInterval(tick,1000); window.addEventListener('load',tick);

function copyText(t, btn){
  function ok(){
    if(btn){
      const old = btn.innerText;
      btn.innerText='OK'; btn.disabled=true;
      setTimeout(()=>{btn.innerText=old || 'Copy'; btn.disabled=false;},900);
    }
  }
  if (navigator.clipboard && window.isSecureContext){
    navigator.clipboard.writeText(t).then(ok).catch(()=>fallback(t,ok));
  } else { fallback(t,ok); }
  function fallback(text, cb){
    const ta=document.createElement('textarea');
    ta.value=text; ta.style.position='fixed'; ta.style.left='-9999px';
    document.body.appendChild(ta); ta.focus(); ta.select();
    try{document.execCommand('copy');}catch(e){}
    document.body.removeChild(ta); cb();
  }
}

let _bwSmooth = { rx: null, tx: null };
function _smooth(prev, cur, alpha=0.35){
  cur = Number(cur||0);
  if(prev===null || prev===undefined) return cur;
  return (prev*(1-alpha)) + (cur*alpha);
}

async function refreshBW(){
  try{
    const r=await fetch('/api/bw'); const j=await r.json();
    document.getElementById('bw-if').textContent=j.iface;
    _bwSmooth.rx = _smooth(_bwSmooth.rx, j.rx_mbps);
    _bwSmooth.tx = _smooth(_bwSmooth.tx, j.tx_mbps);
    document.getElementById('bw-rx').textContent=_bwSmooth.rx.toFixed(2)+' Mbps';
    document.getElementById('bw-tx').textContent=_bwSmooth.tx.toFixed(2)+' Mbps';
    document.getElementById('bw-rxt').textContent=j.rx_total_h;
    document.getElementById('bw-txt').textContent=j.tx_total_h;
  }catch(e){}
}
async function refreshSYS(){
  try{
    const r=await fetch('/api/sys'); const j=await r.json();
    document.getElementById('cpu').textContent=j.cpu_pct+'%';
    document.getElementById('mem').textContent=j.mem_pct+'%';
    document.getElementById('memh').textContent=j.mem_used_h+' / '+j.mem_total_h;
  }catch(e){}
}
setInterval(refreshBW,1000);
setInterval(refreshSYS,1000);
window.addEventListener('load', ()=>{refreshBW(); refreshSYS();});

function parseExpToMs(expStr){
  if(!expStr) return 0;
  let s = (expStr+'').trim().replace('T',' ');
  if (s.length === 10) s = s + ' 23:59:59';
  if (s.length === 16) s = s + ':00';
  const iso = s.replace(' ', 'T') + 'Z';
  const ms = Date.parse(iso);
  return isNaN(ms) ? 0 : ms;
}
function fmtLeft(sec){
  sec = Math.max(0, Math.floor(sec));
  const d = Math.floor(sec/86400); sec%=86400;
  const h = Math.floor(sec/3600); sec%=3600;
  const m = Math.floor(sec/60); const s = sec%60;
  if(d>0) return `${d}d ${h}h ${m}m`;
  if(h>0) return `${h}h ${m}m ${s}s`;
  if(m>0) return `${m}m ${s}s`;
  return `${s}s`;
}
function updateBadges(){
  const now=SERVER_TS+(Date.now()-start);
  document.querySelectorAll('tr[data-exp]').forEach(tr=>{
    const exp=tr.dataset.exp;
    const ms=parseExpToMs(exp);
    const badge=tr.querySelector('[data-badge]');
    const left=tr.querySelector('[data-left]');
    if(!ms){ badge.textContent='N/A'; badge.className='px-2 py-1 rounded-lg text-xs bg-white/10 border border-white/10'; left.textContent='-'; return; }
    const diff=(ms-now)/1000;
    if(diff<=0){
      badge.textContent='EXPIRED';
      badge.className='px-2 py-1 rounded-lg text-xs bg-red-500/20 border border-red-400/30 text-red-200';
      left.textContent='0s';
    }else{
      badge.textContent='ACTIVE';
      badge.className='px-2 py-1 rounded-lg text-xs bg-emerald-500/20 border border-emerald-400/30 text-emerald-200';
      left.textContent=fmtLeft(diff);
    }
  });
}
setInterval(updateBadges,1000);
window.addEventListener('load', updateBadges);

// Expiry modal + OK/Apply (force flatpickr, no native Android picker)
let fpModal = null;
let fpDraft = "";

function openDateModal(){
  const modal=document.getElementById('dateModal');
  const hidden=document.getElementById('expiresPicker');
  const display=document.getElementById('expiresDisplay');
  const wrap=document.getElementById('fpInlineWrap');
  if(!modal||!hidden||!display||!wrap||!window.flatpickr) return;
  modal.classList.remove('hidden');
  if(!fpModal){
    fpModal = flatpickr(wrap, {
      inline:true,
      enableTime:true,
      time_24hr:true,
      disableMobile:true,
      dateFormat:"Y-m-d H:i",
      defaultDate: hidden.value || null,
      onChange: (sel, str)=>{ fpDraft = str; }
    });
  } else {
    fpModal.setDate(hidden.value || null, true);
  }
  fpDraft = hidden.value || (fpModal.selectedDates[0] ? fpModal.formatDate(fpModal.selectedDates[0],"Y-m-d H:i") : "");
}

function closeDateModal(){
  document.getElementById('dateModal')?.classList.add('hidden');
}

function applyDateModal(){
  const hidden=document.getElementById('expiresPicker');
  const display=document.getElementById('expiresDisplay');
  if(!hidden||!display) return;
  hidden.value = (fpDraft||"").trim();
  display.value = hidden.value;
  closeDateModal();
}

window.addEventListener('load', ()=>{
  const hidden=document.getElementById('expiresPicker');
  const display=document.getElementById('expiresDisplay');
  if(!hidden||!display) return;

  display.value = (hidden.value||"");
  display.addEventListener('click', openDateModal);

  function parseCur(){
    if(hidden.value){
      const s=hidden.value.trim();
      const p=s.split(/[- :]/);
      if(p.length>=5){
        return new Date(parseInt(p[0]),parseInt(p[1])-1,parseInt(p[2]),parseInt(p[3]),parseInt(p[4]),0);
      }
    }
    return new Date();
  }

  function setInstant(d){
    const y=d.getFullYear();
    const mo=String(d.getMonth()+1).padStart(2,'0');
    const da=String(d.getDate()).padStart(2,'0');
    const hh=String(d.getHours()).padStart(2,'0');
    const mm=String(d.getMinutes()).padStart(2,'0');
    const val = `${y}-${mo}-${da} ${hh}:${mm}`;
    fpDraft=val;
    hidden.value=val;
    display.value=val;
    if(fpModal) fpModal.setDate(val, true);
  }

  document.querySelectorAll('[data-addday],[data-now],[data-eod],[data-clear]').forEach(btn=>{
    btn.addEventListener('click', ()=>{
      let cur=parseCur();
      if(btn.dataset.addday) cur.setDate(cur.getDate()+parseInt(btn.dataset.addday,10));
      else if(btn.dataset.now) cur=new Date();
      else if(btn.dataset.eod){ cur=new Date(); cur.setHours(23,59,0,0); }
      else if(btn.dataset.clear){ fpDraft=""; hidden.value=""; display.value=""; if(fpModal) fpModal.clear(); return; }
      setInstant(cur);
    });
  });
});

</script>

<style>
.glass{background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.12);backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);box-shadow:0 22px 90px rgba(0,0,0,.65);}
.btn-gradient{background:linear-gradient(90deg,#22c55e,#0ea5e9);}
.btn-danger{background:linear-gradient(90deg,#ef4444,#f97316);}
.text-muted{color:rgba(255,255,255,.7)}

/* ===== PREMIUM COLOR CARDS + ICONS ===== */
.card-bandwidth{
  background: linear-gradient(135deg, rgba(99,102,241,.18), rgba(2,6,23,.55));
  border-left: 4px solid rgba(99,102,241,.9);
}
.card-system{
  background: linear-gradient(135deg, rgba(34,197,94,.18), rgba(2,6,23,.55));
  border-left: 4px solid rgba(34,197,94,.9);
}
.table-row:hover{
  background: rgba(255,255,255,.06);
}


/* preset buttons full color */
.preset-green{background:linear-gradient(90deg,#22c55e,#16a34a);}
.preset-blue{background:linear-gradient(90deg,#0ea5e9,#2563eb);}
.preset-purple{background:linear-gradient(90deg,#a855f7,#3b82f6);}
.preset-orange{background:linear-gradient(90deg,#f97316,#ef4444);}
.preset-dark{background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.12);}

/* Flatpickr FULL COLOR */
.flatpickr-calendar.zivpn-theme{
  border:1px solid rgba(255,255,255,.12)!important;
  border-radius:18px!important;
  overflow:hidden!important;
  background: linear-gradient(180deg, rgba(16,24,39,.95), rgba(2,6,23,.92))!important;
  box-shadow: 0 30px 120px rgba(0,0,0,.75)!important;
}
.flatpickr-calendar.zivpn-theme .flatpickr-months{
  background: linear-gradient(90deg, rgba(34,197,94,.35), rgba(14,165,233,.35), rgba(168,85,247,.35))!important;
  border-bottom:1px solid rgba(255,255,255,.10)!important;
}
.flatpickr-calendar.zivpn-theme .flatpickr-current-month,
.flatpickr-calendar.zivpn-theme .flatpickr-prev-month,
.flatpickr-calendar.zivpn-theme .flatpickr-next-month{
  color:rgba(255,255,255,.95)!important; fill:rgba(255,255,255,.95)!important;
}
.flatpickr-calendar.zivpn-theme span.flatpickr-weekday{ color:rgba(255,255,255,.75)!important; font-weight:700!important; }
.flatpickr-calendar.zivpn-theme .flatpickr-day{ color:rgba(255,255,255,.88)!important; border-radius:12px!important; }
.flatpickr-calendar.zivpn-theme .flatpickr-day.selected{ background:linear-gradient(90deg,#22c55e,#0ea5e9,#a855f7)!important; color:#071021!important; font-weight:800!important; border-color:transparent!important;}
.flatpickr-calendar.zivpn-theme .flatpickr-time{ border-top:1px solid rgba(255,255,255,.08)!important; background:rgba(255,255,255,.03)!important;}
.flatpickr-calendar.zivpn-theme .flatpickr-time input{ color:rgba(255,255,255,.95)!important; font-weight:800!important;}
</style></head>

<body class="min-h-screen bg-gradient-to-br from-[#050914] via-[#071021] to-[#04060f] text-white">
  <div class="max-w-6xl mx-auto p-4 md:p-6">
    <div class="flex flex-col md:flex-row md:items-center md:justify-between gap-3 mb-5">
      <div>
        <h1 class="text-2xl md:text-3xl font-extrabold tracking-tight">{{ panel_name }}</h1>
        <div class="text-xs text-muted mt-1">
          Role: <b>{{role}}</b> ({{who}}) &bull; Server time: <span id="server-time">...</span> &bull; VPS: {{vps_ip}}
        </div>
      </div>
      <div class="flex gap-2">
        {% if role=="admin" %}
          <a href="/backup"
             class="px-4 py-2 rounded-xl text-sm font-semibold
                    bg-gradient-to-r from-emerald-500 to-green-600
                    hover:from-emerald-400 hover:to-green-500
                    shadow-lg shadow-emerald-500/30 transition">
            <i class="fa-solid fa-database mr-1"></i> Backup
          </a>

          <a href="/restore"
             class="px-4 py-2 rounded-xl text-sm font-semibold
                    bg-gradient-to-r from-sky-500 to-blue-600
                    hover:from-sky-400 hover:to-blue-500
                    shadow-lg shadow-sky-500/30 transition">
            <i class="fa-solid fa-rotate-left mr-1"></i> Restore
          </a>
        {% endif %}
        <a href="/logout"
           class="px-4 py-2 rounded-xl text-sm font-semibold
                  bg-gradient-to-r from-red-500 to-orange-600
                  hover:from-red-400 hover:to-orange-500
                  shadow-lg shadow-red-500/30 transition">
          <i class="fa-solid fa-right-from-bracket mr-1"></i> Logout
        </a>
      </div>
    </div>

    {% with messages = get_flashed_messages() %}
      {% if messages %}
        <div class="mb-4 space-y-2">
          {% for m in messages %}
            <div class="glass rounded-2xl p-3 text-sm whitespace-pre-wrap">{{m}}</div>
          {% endfor %}
        </div>
      {% endif %}
    {% endwith %}

    <div class="grid md:grid-cols-4 gap-4 mb-5">
      <div class="glass rounded-2xl p-4">
        <div class="text-sm text-muted">Total Users{% if role=="reseller" %} (milikmu){% endif %}</div>
        <div class="text-3xl font-extrabold mt-1">{{ total_users }}</div>
      </div>
      <div class="glass rounded-2xl p-4">
        <div class="text-sm text-muted">Total Online{% if role=="reseller" %} (milikmu){% endif %}</div>
        <div class="text-3xl font-extrabold mt-1">{{ total_active }}</div>
      </div>
      <div class="glass rounded-2xl p-4 card-bandwidth">
        <div class="text-sm text-muted flex items-center gap-2"><i class="fa-solid fa-chart-line"></i><span>Bandwidth (<span id="bw-if">-</span>)</span></div>
        <div class="mt-2 text-sm flex flex-wrap items-center gap-2">
          <span class="text-muted flex items-center gap-1"><i class="fa-solid fa-download"></i>Download</span> <b id="bw-rx">-</b>
          <span class="text-white/40">&bull;</span>
          <span class="text-muted flex items-center gap-1"><i class="fa-solid fa-upload"></i>Upload</span> <b id="bw-tx">-</b>
        </div>
        <div class="mt-1 text-xs text-muted">Total Download <span id="bw-rxt">-</span> &bull; Total Upload <span id="bw-txt">-</span></div>
      </div>
      <div class="glass rounded-2xl p-4 card-system">
        <div class="text-sm text-muted flex items-center gap-2"><i class="fa-solid fa-microchip"></i><span>System</span></div>
        <div class="mt-2 text-sm flex flex-wrap items-center gap-2">
          <span class="text-muted flex items-center gap-1"><i class="fa-solid fa-gauge-high"></i>CPU</span> <b id="cpu">-</b>
          <span class="text-white/40">&bull;</span>
          <span class="text-muted flex items-center gap-1"><i class="fa-solid fa-memory"></i>RAM</span> <b id="mem">-</b>
        </div>
        <div class="mt-1 text-xs text-muted" id="memh">-</div>
      </div>
    </div>

    <div class="grid md:grid-cols-2 gap-4">
      <section class="glass rounded-2xl p-4">
        <h3 class="font-semibold text-lg mb-3">
          {% if edit_row and role=="admin" %}Edit User{% else %}Add User{% endif %}
          {% if role=="reseller" %}<span class="text-xs text-muted">(reseller hanya bisa buat user baru)</span>{% endif %}
        </h3>
        <form method="post" action="/save" class="space-y-3">
          <input name="username" value="{{ edit_row.username if edit_row else '' }}" placeholder="Username"
            class="w-full rounded-xl p-3 bg-black/30 border border-white/10 text-white outline-none">
          <input name="password" value="{{ edit_row.password if edit_row else '' }}" placeholder="Password"
            class="w-full rounded-xl p-3 bg-black/30 border border-white/10 text-white outline-none">
          <input type="hidden" id="expiresPicker" name="expires" value="{{ edit_expires if edit_expires else default_exp_dt }}">
          <input id="expiresDisplay" type="text" readonly inputmode="none" placeholder="Pilih tanggal & jam"
            class="w-full rounded-xl p-3 bg-black/30 border border-white/10 text-white outline-none cursor-pointer">
          <div class="grid grid-cols-4 gap-2">
            <button type="button" data-addday="1"  class="px-3 py-2 rounded-xl text-xs font-semibold text-white preset-green">1d</button>
            <button type="button" data-addday="7"  class="px-3 py-2 rounded-xl text-xs font-semibold text-white preset-blue">7d</button>
            <button type="button" data-addday="15" class="px-3 py-2 rounded-xl text-xs font-semibold text-white preset-purple">15d</button>
            <button type="button" data-addday="30" class="px-3 py-2 rounded-xl text-xs font-semibold text-white preset-orange">30d</button>
            <button type="button" data-now="1"    class="px-3 py-2 rounded-xl text-xs font-semibold text-white preset-dark">Now</button>
            <button type="button" data-eod="1"    class="px-3 py-2 rounded-xl text-xs font-semibold text-white preset-purple">End Day</button>
            <button type="button" data-clear="1"  class="px-3 py-2 rounded-xl text-xs font-semibold text-white preset-orange">Clear</button>
            <button type="button" onclick="openDateModal()" class="px-3 py-2 rounded-xl text-xs font-semibold text-white preset-blue">Calendar</button>
          </div>
          <button class="w-full btn-gradient py-3 rounded-xl text-lg font-semibold">
            {% if edit_row and role=="admin" %}Update User{% else %}Create User{% endif %}
          </button>
          {% if edit_row and role=="admin" %}
            <a href="/" class="block text-center text-sm text-white/70 hover:underline">Cancel Edit</a>
          {% endif %}
        </form>
      </section>

      <section class="glass rounded-2xl p-4">
        <h3 class="font-semibold text-lg mb-3">Trial Generator</h3>
        <form method="post" action="/trial" class="space-y-3">
          <input type="hidden" name="qty" value="1">
          <select name="minutes" class="w-full rounded-xl p-3 bg-black/30 border border-white/10 text-white outline-none">
            <option value="10">10 Menit</option>
            <option value="15" selected>15 Menit</option>
            <option value="20">20 Menit</option>
            <option value="30">30 Menit</option>
          </select>
          <button class="w-full btn-gradient py-3 rounded-xl text-lg font-semibold">Create Trial</button>
          <div class="text-[11px] text-muted">
            {% if role=="reseller" %}Trial tercatat sebagai <b>milik reseller</b>.{% endif %}
          </div>
        </form>

        {% if role=="admin" %}
        <div class="mt-4 border-t border-white/10 pt-4">
          <h4 class="font-semibold mb-2">Buat Akun Login Reseller</h4>
          <form method="post" action="/reseller/create" class="space-y-2">
            <input name="ru" placeholder="Username reseller"
              class="w-full rounded-xl p-3 bg-black/30 border border-white/10 text-white outline-none">
            <input name="rp" placeholder="Password reseller (kosong = auto)"
              class="w-full rounded-xl p-3 bg-black/30 border border-white/10 text-white outline-none">
            <button class="w-full btn-gradient py-3 rounded-xl text-lg font-semibold">Buat Reseller</button>
          </form>
          <div class="mt-2 text-[11px] text-muted">Password tampil sekali lewat notifikasi.</div>
        </div>
        {% endif %}
      </section>
    </div>

    <section class="glass rounded-2xl p-4 mt-5">
      <div class="flex items-center justify-between mb-3">
        <h3 class="font-semibold text-lg">User List</h3>
        <div class="text-xs text-muted">
          {% if role=="reseller" %}Menampilkan user milik: <b>{{who}}</b>{% else %}Menampilkan semua user{% endif %}
        </div>
      </div>

      <div class="overflow-x-auto">
        <table class="min-w-full text-sm">
          <thead class="text-white/70">
            <tr class="border-b border-white/10">
              <th class="text-left py-2 pr-3">Username</th>
              <th class="text-left py-2 pr-3">Password</th>
              <th class="text-left py-2 pr-3">Expires</th>
              <th class="text-left py-2 pr-3">Status</th>
              <th class="text-left py-2 pr-3">Left</th>
              <th class="text-right py-2">Action</th>
            </tr>
          </thead>
          <tbody>
            {% for u in all_users %}
            <tr class="border-b border-white/5 table-row" data-exp="{{u.expires}}">
              <td class="py-2 pr-3 font-semibold">{{u.username}}</td>
              <td class="py-2 pr-3">
                <div class="flex items-center gap-2">
                  <span class="font-mono">{{u.password}}</span>
                  <button onclick="copyText('{{u.password}}', this)" class="px-3 py-1 rounded-lg bg-white/10 border border-white/10 text-xs">Copy</button>
                </div>
              </td>
              <td class="py-2 pr-3 font-mono text-white/80">{{u.expires}}</td>
              <td class="py-2 pr-3"><span data-badge class="px-2 py-1 rounded-lg text-xs bg-white/10 border border-white/10">...</span></td>
              <td class="py-2 pr-3 font-mono text-white/80" data-left>-</td>
              <td class="py-2 text-right">
                {% if role=="admin" %}
                  <div class="inline-flex items-center gap-2 justify-end">
                    <a href="/?edit={{u.username}}" class="px-4 py-2 rounded-xl btn-gradient text-sm">Edit</a>
                    <form method="post" action="/del/{{u.username}}" onsubmit="return confirm('Delete user: {{u.username}} ?')">
                      <button class="px-4 py-2 rounded-xl btn-danger text-sm">Delete</button>
                    </form>
                  </div>
                {% else %}
                  <span class="text-xs text-muted">No action</span>
                {% endif %}
              </td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
    </section>
  </div>
<!-- Date Modal -->
<div id="dateModal" class="fixed inset-0 z-[9999] hidden">
  <div class="absolute inset-0 bg-black/60 backdrop-blur-sm" onclick="closeDateModal()"></div>
  <div class="absolute left-1/2 top-1/2 w-[92%] max-w-[420px] -translate-x-1/2 -translate-y-1/2">
    <div class="glass rounded-2xl border border-white/10 overflow-hidden">
      <div class="px-4 py-3 flex items-center justify-between bg-white/5 border-b border-white/10">
        <div class="font-semibold">Set Expiry</div>
        <button type="button" onclick="closeDateModal()" class="px-3 py-1 rounded-lg bg-white/10 border border-white/10 text-sm">âœ•</button>
      </div>
      <div class="p-3">
        <div id="fpInlineWrap" class="rounded-2xl overflow-hidden"></div>
        <div class="mt-3 grid grid-cols-2 gap-2">
          <button type="button" onclick="closeDateModal()" class="px-4 py-2.5 rounded-xl bg-white/10 border border-white/10 font-semibold">Cancel</button>
          <button type="button" onclick="applyDateModal()" class="px-4 py-2.5 rounded-xl btn-gradient font-semibold">OK / Apply</button>
        </div>
        <div class="mt-2 text-[11px] text-white/60">Pilih tanggal &amp; jam, lalu tekan <b>OK / Apply</b>.</div>
      </div>
    </div>
  </div>
</div>
</body></html>'''

@app.route("/")
@login_required
def index():
    role = session.get("role", "")
    who = session.get("user", "")

    if role == "reseller":
        where = "WHERE owner=?"
        args = (who,)
    else:
        where = ""
        args = ()

    with db() as con:
        total_users = con.execute(f"SELECT COUNT(*) FROM users {where}", args).fetchone()[0]
        if role == "reseller":
            total_active = con.execute("SELECT COUNT(*) FROM users WHERE owner=? AND datetime(expires) >= datetime('now')", args).fetchone()[0]
        else:
            total_active = con.execute("SELECT COUNT(*) FROM users WHERE datetime(expires) >= datetime('now')").fetchone()[0]

        rows = con.execute(
            f"SELECT username,password,expires,COALESCE(owner,'') AS owner FROM users {where} ORDER BY datetime(expires) ASC, username ASC",
            args
        ).fetchall()

    users = [{"username": r["username"], "password": r["password"], "expires": str(r["expires"] or ""), "owner": str(r["owner"] or "")} for r in rows]

    edit_row = None
    if role == "admin":
        edit_u = (request.args.get("edit", "") or "").strip()
        if edit_u:
            with db() as con:
                edit_row = con.execute("SELECT username,password,expires FROM users WHERE username=?", (edit_u,)).fetchone()

    default_exp = (datetime.utcnow() + timedelta(hours=24)).strftime("%Y-%m-%d %H:%M")
    edit_expires = None
    if edit_row and edit_row["expires"]:
        # keep compatibility: JS will normalize
        edit_expires = str(edit_row["expires"]).replace(" ", "T")[:16]

    try:
        vps_ip = subprocess.check_output(["hostname", "-I"]).decode().split()[0]
    except Exception:
        vps_ip = request.host.split(":")[0]

    return render_template_string(
        DASH_TPL,
        panel_name=PANEL_NAME,
        role=role,
        who=who,
        total_users=total_users,
        total_active=total_active,
        all_users=users,
        edit_row=edit_row,
        default_exp_dt=default_exp,
        edit_expires=edit_expires,
        vps_ip=vps_ip,
        server_ts=int(time.time()),
    )

@app.route("/save", methods=["POST"])
@login_required
def save():
    u = (request.form.get("username", "") or "").strip()
    p = (request.form.get("password", "") or "").strip()
    e = _norm_expires(request.form.get("expires", ""))

    if not u or not p or not e:
        flash("Please fill all fields")
        return redirect("/")

    role = session.get("role", "")
    who = session.get("user", "")

    if role == "reseller":
        with db() as con:
            exists = con.execute("SELECT 1 FROM users WHERE username=?", (u,)).fetchone()
        if exists:
            flash("Reseller hanya bisa buat akun baru (tidak bisa edit).")
            return redirect("/")
        with db() as con:
            con.execute("INSERT INTO users(username,password,expires,owner) VALUES(?,?,?,?)", (u, p, e, who))
        sync(restart=True)
        flash("User dibuat & Synced")
        return redirect("/")

    with db() as con:
        con.execute(
            """INSERT INTO users(username,password,expires,owner)
               VALUES(?,?,?,COALESCE((SELECT owner FROM users WHERE username=?),'admin'))
               ON CONFLICT(username) DO UPDATE SET password=?, expires=?""",
            (u, p, e, u, p, e),
        )
    sync(restart=True)
    flash("Saved & Synced")
    return redirect("/")

@app.route("/trial", methods=["POST"])
@login_required
def trial():
    # Trial hanya 1 akun, durasi hanya 10/15/20/30 menit
    minutes = int(request.form.get("minutes") or 15)
    if minutes not in (10, 15, 20, 30):
        minutes = 15

    role = session.get("role", "")
    who = session.get("user", "")
    owner = who if role == "reseller" else "admin"

    exp = (datetime.utcnow() + timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")

    with db() as con:
        uname = "trial" + secrets.token_hex(3)
        pw = secrets.token_hex(4)
        con.execute("INSERT INTO users(username,password,expires,owner) VALUES(?,?,?,?)", (uname, pw, exp, owner))

    sync(restart=True)
    flash(f"Trial dibuat: 1 akun | {minutes} menit | Exp: {exp}")
    return redirect("/")

@app.route("/del/<path:username>", methods=["POST"])
@login_required
@admin_required
def del_user(username):
    u = (username or "").strip()
    if not u:
        flash("Username kosong")
        return redirect("/")
    with db() as con:
        con.execute("DELETE FROM users WHERE username=?", (u,))
    sync(restart=True)
    flash(f"Deleted & Synced: {u}")
    return redirect("/")

if __name__ == "__main__":
    from waitress import serve
    serve(app, host=os.getenv("BIND_HOST", "0.0.0.0"), port=int(os.getenv("BIND_PORT", "8088")))
PY

cat > "${SYNC_PY}" <<'PY'
import json, sqlite3, tempfile, subprocess, os
from subprocess import DEVNULL

DB="/var/lib/zivpn-admin/zivpn.db"
CFG="/etc/zivpn/config.json"
SVC="zivpn.service"

def actives():
    os.makedirs("/var/lib/zivpn-admin", exist_ok=True)
    with sqlite3.connect(DB) as con:
        con.execute("""CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            expires TEXT,
            owner TEXT
        )""")
        pw=[r[0] for r in con.execute("""
            SELECT DISTINCT password
            FROM users
            WHERE datetime(expires) >= datetime('now')
        """)]
    return pw or ["zi"]

cfg={}
try:
    cfg=json.load(open(CFG))
except Exception:
    pass

pw=actives()
cfg.setdefault("auth",{})["mode"]="passwords"
cfg["auth"]["config"]=pw
cfg["config"]=pw

with tempfile.NamedTemporaryFile("w",delete=False) as f:
    json.dump(cfg,f,indent=2); tmp=f.name
os.replace(tmp,CFG)
subprocess.Popen(["systemctl","restart",SVC], stdout=DEVNULL, stderr=DEVNULL)
PY

chmod +x "${APP_PY}" "${SYNC_PY}"

cat >/etc/systemd/system/${PANEL_SVC} <<EOF
[Unit]
Description=ZIVPN Web Panel
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

cat >/etc/systemd/system/${SYNC_SVC} <<EOF
[Unit]
Description=ZIVPN Daily Sync

[Service]
ExecStart=${VENV}/bin/python ${SYNC_PY}
EOF

cat >/etc/systemd/system/${SYNC_TIMER} <<'EOF'
[Unit]
Description=Run ZIVPN daily sync

[Timer]
OnCalendar=*-*-* 00:10:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now "${PANEL_SVC}"
systemctl enable --now "${SYNC_TIMER}"

IP="$(hostname -I | awk '{print $1}')"
echo ""
echo "INSTALL COMPLETE"
echo "Admin   : http://${IP}:8088/login"
echo "Reseller: http://${IP}:8088/reseller"
echo "======================================"
echo "NOTE: Bandwidth label sudah jadi Download/Upload + kalender flatpickr baru."
read -rp "Tekan ENTER untuk selesai..." _ || true
exit
