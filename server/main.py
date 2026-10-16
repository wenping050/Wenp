import os
import sqlite3
import json
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, List
from fastapi import FastAPI, HTTPException, Request, Depends, Header
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

DB_PATH = os.path.join(os.path.dirname(__file__), "data.db")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "wp51000")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        expire_at TEXT NOT NULL,
        max_devices INTEGER DEFAULT 1,
        devices TEXT DEFAULT '[]',
        status INTEGER DEFAULT 1,
        token TEXT DEFAULT '',
        notes TEXT DEFAULT '',
        created_at TEXT NOT NULL,
        last_login_at TEXT DEFAULT ''
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS cards (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        card_key TEXT UNIQUE NOT NULL,
        days INTEGER NOT NULL,
        used INTEGER DEFAULT 0,
        used_by TEXT DEFAULT '',
        used_at TEXT DEFAULT '',
        created_at TEXT NOT NULL
    )
    """)
    # Create default demo user if empty
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        demo_expire = (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
        c.execute("""
        INSERT INTO users (username, password, expire_at, max_devices, devices, status, notes, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, ("admin_test", "123456", demo_expire, 2, "[]", 1, "初始测试账号", datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

init_db()

app = FastAPI(title="Wenp Account & License Server", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------- Models -----------------
class LoginRequest(BaseModel):
    username: str
    password: str
    machine_id: str

class VerifyRequest(BaseModel):
    username: str
    token: str
    machine_id: str

class RedeemRequest(BaseModel):
    username: str
    card_key: str

class AdminLoginRequest(BaseModel):
    password: str

class CreateUserRequest(BaseModel):
    username: str
    password: str
    days: int
    max_devices: int = 1
    notes: str = ""

class UpdateUserRequest(BaseModel):
    username: str
    password: Optional[str] = None
    expire_at: Optional[str] = None
    max_devices: Optional[int] = None
    status: Optional[int] = None
    notes: Optional[str] = None

class RenewUserRequest(BaseModel):
    username: str
    days: int

class UnbindUserRequest(BaseModel):
    username: str

class GenerateCardsRequest(BaseModel):
    days: int
    count: int

# ----------------- Helpers -----------------
def calc_days_left(expire_at_str: str) -> int:
    try:
        exp = datetime.strptime(expire_at_str, "%Y-%m-%d %H:%M:%S")
        delta = exp - datetime.now()
        return max(0, delta.days + (1 if delta.seconds > 0 else 0))
    except:
        return 0

def is_expired(expire_at_str: str) -> bool:
    try:
        exp = datetime.strptime(expire_at_str, "%Y-%m-%d %H:%M:%S")
        return datetime.now() > exp
    except:
        return True

# ----------------- Client Auth APIs -----------------
@app.get("/api/auth/status")
def server_status():
    return {"ok": True, "server_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "name": "Wenp Auth Server"}

@app.post("/api/auth/login")
def client_login(req: LoginRequest):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (req.username.strip(),))
    user = c.fetchone()
    if not user:
        conn.close()
        return JSONResponse(status_code=400, content={"ok": False, "msg": "账号不存在"})
    
    if user["password"] != req.password.strip():
        conn.close()
        return JSONResponse(status_code=400, content={"ok": False, "msg": "密码错误"})
    
    if user["status"] != 1:
        conn.close()
        return JSONResponse(status_code=403, content={"ok": False, "msg": "账号已被管理员封禁或禁用"})
    
    if is_expired(user["expire_at"]):
        conn.close()
        return JSONResponse(status_code=403, content={
            "ok": False,
            "code": "expired",
            "msg": f"账号授权已于 {user['expire_at']} 到期，请联系管理员续费或使用卡密激活",
            "expire_at": user["expire_at"],
            "days_left": 0
        })
    
    devices = json.loads(user["devices"] or "[]")
    m_id = req.machine_id.strip()
    if m_id not in devices:
        if len(devices) >= user["max_devices"]:
            conn.close()
            return JSONResponse(status_code=403, content={
                "ok": False,
                "code": "device_limit",
                "msg": f"当前账号已达最大绑定设备数({user['max_devices']}台)，新电脑无法登录，请在后台解绑或联系管理员"
            })
        devices.append(m_id)
    
    token = secrets.token_hex(20)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("UPDATE users SET token = ?, devices = ?, last_login_at = ? WHERE username = ?",
              (token, json.dumps(devices), now_str, user["username"]))
    conn.commit()
    conn.close()

    days_left = calc_days_left(user["expire_at"])
    return {
        "ok": True,
        "token": token,
        "username": user["username"],
        "expire_at": user["expire_at"],
        "days_left": days_left,
        "max_devices": user["max_devices"],
        "devices_count": len(devices),
        "msg": "登录成功"
    }

@app.post("/api/auth/verify")
def client_verify(req: VerifyRequest):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (req.username.strip(),))
    user = c.fetchone()
    conn.close()
    if not user:
        return JSONResponse(status_code=401, content={"ok": False, "msg": "用户不存在"})
    
    if user["token"] != req.token or not user["token"]:
        return JSONResponse(status_code=401, content={"ok": False, "msg": "登录会话已失效，请重新登录"})
    
    if user["status"] != 1:
        return JSONResponse(status_code=403, content={"ok": False, "msg": "账号已被禁用"})
    
    if is_expired(user["expire_at"]):
        return JSONResponse(status_code=403, content={
            "ok": False,
            "code": "expired",
            "msg": f"账号已到期 ({user['expire_at']})",
            "expire_at": user["expire_at"],
            "days_left": 0
        })
    
    devices = json.loads(user["devices"] or "[]")
    if req.machine_id.strip() not in devices:
        return JSONResponse(status_code=403, content={"ok": False, "msg": "当前设备未绑定或已被解绑，请重新登录"})
    
    days_left = calc_days_left(user["expire_at"])
    return {
        "ok": True,
        "username": user["username"],
        "expire_at": user["expire_at"],
        "days_left": days_left
    }

@app.post("/api/auth/redeem")
def client_redeem(req: RedeemRequest):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (req.username.strip(),))
    user = c.fetchone()
    if not user:
        conn.close()
        return JSONResponse(status_code=400, content={"ok": False, "msg": "用户不存在"})
    
    c.execute("SELECT * FROM cards WHERE card_key = ?", (req.card_key.strip(),))
    card = c.fetchone()
    if not card:
        conn.close()
        return JSONResponse(status_code=400, content={"ok": False, "msg": "卡密无效，请仔细检查"})
    
    if card["used"] == 1:
        conn.close()
        return JSONResponse(status_code=400, content={"ok": False, "msg": f"卡密已被使用 (使用者: {card['used_by']})"})
    
    # Calculate new expiry
    now = datetime.now()
    try:
        cur_exp = datetime.strptime(user["expire_at"], "%Y-%m-%d %H:%M:%S")
        base_time = max(now, cur_exp)
    except:
        base_time = now
    
    new_exp = (base_time + timedelta(days=card["days"])).strftime("%Y-%m-%d %H:%M:%S")
    now_str = now.strftime("%Y-%m-%d %H:%M:%S")

    c.execute("UPDATE cards SET used = 1, used_by = ?, used_at = ? WHERE id = ?",
              (user["username"], now_str, card["id"]))
    c.execute("UPDATE users SET expire_at = ? WHERE username = ?",
              (new_exp, user["username"]))
    conn.commit()
    conn.close()

    days_left = calc_days_left(new_exp)
    return {
        "ok": True,
        "msg": f"卡密充值成功！已成功增加 {card['days']} 天授权",
        "expire_at": new_exp,
        "days_left": days_left
    }

# ----------------- Admin APIs -----------------
def verify_admin(authorization: Optional[str] = Header(None)):
    if not authorization or authorization != f"Bearer {ADMIN_PASSWORD}":
        raise HTTPException(status_code=401, detail="管理员授权未通过")

@app.post("/api/admin/login")
def admin_login(req: AdminLoginRequest):
    if req.password == ADMIN_PASSWORD:
        return {"ok": True, "token": ADMIN_PASSWORD, "msg": "管理员登录成功"}
    return JSONResponse(status_code=401, content={"ok": False, "msg": "密码错误"})

@app.get("/api/admin/users", dependencies=[Depends(verify_admin)])
def admin_get_users():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    users = []
    for r in rows:
        devs = json.loads(r["devices"] or "[]")
        users.append({
            "id": r["id"],
            "username": r["username"],
            "password": r["password"],
            "expire_at": r["expire_at"],
            "days_left": calc_days_left(r["expire_at"]),
            "is_expired": is_expired(r["expire_at"]),
            "max_devices": r["max_devices"],
            "devices": devs,
            "devices_count": len(devs),
            "status": r["status"],
            "notes": r["notes"],
            "created_at": r["created_at"],
            "last_login_at": r["last_login_at"]
        })
    return {"ok": True, "users": users}

@app.post("/api/admin/user/create", dependencies=[Depends(verify_admin)])
def admin_create_user(req: CreateUserRequest):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username = ?", (req.username.strip(),))
    if c.fetchone():
        conn.close()
        return JSONResponse(status_code=400, content={"ok": False, "msg": "用户名已存在"})
    
    exp_time = (datetime.now() + timedelta(days=req.days)).strftime("%Y-%m-%d %H:%M:%S")
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("""
    INSERT INTO users (username, password, expire_at, max_devices, devices, status, notes, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (req.username.strip(), req.password.strip(), exp_time, req.max_devices, "[]", 1, req.notes.strip(), now_str))
    conn.commit()
    conn.close()
    return {"ok": True, "msg": f"用户 {req.username} 创建成功，有效期至 {exp_time}"}

@app.post("/api/admin/user/update", dependencies=[Depends(verify_admin)])
def admin_update_user(req: UpdateUserRequest):
    conn = get_db()
    c = conn.cursor()
    updates = []
    params = []
    if req.password is not None and req.password.strip():
        updates.append("password = ?")
        params.append(req.password.strip())
    if req.expire_at is not None and req.expire_at.strip():
        updates.append("expire_at = ?")
        params.append(req.expire_at.strip())
    if req.max_devices is not None:
        updates.append("max_devices = ?")
        params.append(req.max_devices)
    if req.status is not None:
        updates.append("status = ?")
        params.append(req.status)
    if req.notes is not None:
        updates.append("notes = ?")
        params.append(req.notes.strip())
    
    if updates:
        params.append(req.username.strip())
        sql = f"UPDATE users SET {', '.join(updates)} WHERE username = ?"
        c.execute(sql, params)
        conn.commit()
    conn.close()
    return {"ok": True, "msg": "用户信息已更新"}

@app.post("/api/admin/user/renew", dependencies=[Depends(verify_admin)])
def admin_renew_user(req: RenewUserRequest):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT expire_at FROM users WHERE username = ?", (req.username.strip(),))
    row = c.fetchone()
    if not row:
        conn.close()
        return JSONResponse(status_code=400, content={"ok": False, "msg": "用户不存在"})
    
    now = datetime.now()
    try:
        cur_exp = datetime.strptime(row["expire_at"], "%Y-%m-%d %H:%M:%S")
        base = max(now, cur_exp)
    except:
        base = now
    
    new_exp = (base + timedelta(days=req.days)).strftime("%Y-%m-%d %H:%M:%S")
    c.execute("UPDATE users SET expire_at = ? WHERE username = ?", (new_exp, req.username.strip()))
    conn.commit()
    conn.close()
    return {"ok": True, "msg": f"用户 {req.username} 成功续期 {req.days} 天，最新到期时间为 {new_exp}", "expire_at": new_exp}

@app.post("/api/admin/user/unbind", dependencies=[Depends(verify_admin)])
def admin_unbind_user(req: UnbindUserRequest):
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE users SET devices = '[]' WHERE username = ?", (req.username.strip(),))
    conn.commit()
    conn.close()
    return {"ok": True, "msg": f"用户 {req.username} 绑定的所有设备已清空解绑"}

@app.post("/api/admin/user/delete", dependencies=[Depends(verify_admin)])
def admin_delete_user(req: UnbindUserRequest):
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE username = ?", (req.username.strip(),))
    conn.commit()
    conn.close()
    return {"ok": True, "msg": f"用户 {req.username} 已删除"}

@app.get("/api/admin/cards", dependencies=[Depends(verify_admin)])
def admin_get_cards():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM cards ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    cards = [dict(r) for r in rows]
    return {"ok": True, "cards": cards}

@app.post("/api/admin/cards/generate", dependencies=[Depends(verify_admin)])
def admin_generate_cards(req: GenerateCardsRequest):
    conn = get_db()
    c = conn.cursor()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    created_keys = []
    for _ in range(max(1, min(req.count, 200))):
        key = f"WENP-{req.days}D-" + secrets.token_hex(6).upper()
        c.execute("INSERT INTO cards (card_key, days, created_at) VALUES (?, ?, ?)",
                  (key, req.days, now_str))
        created_keys.append(key)
    conn.commit()
    conn.close()
    return {"ok": True, "keys": created_keys, "count": len(created_keys)}

# ----------------- Modern Single Page Web UI -----------------
HTML_CONTENT = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Wenp 账号授权管理系统</title>
<style>
:root {
  --primary: #2563eb;
  --primary-hover: #1d4ed8;
  --bg: #f8fafc;
  --card-bg: #ffffff;
  --text: #1e293b;
  --text-muted: #64748b;
  --border: #e2e8f0;
  --success: #16a34a;
  --danger: #dc2626;
  --warning: #d97706;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", "Microsoft YaHei", sans-serif; background: var(--bg); color: var(--text); line-height: 1.5; padding: 24px; }
.container { max-width: 1200px; margin: 0 auto; }
.header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; padding-bottom: 16px; border-bottom: 1px solid var(--border); }
.header h1 { font-size: 22px; font-weight: 700; color: #0f172a; }
.header-actions { display: flex; gap: 10px; align-items: center; }
.card { background: var(--card-bg); border-radius: 12px; border: 1px solid var(--border); padding: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); margin-bottom: 24px; }
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
.stat-box { background: white; border: 1px solid var(--border); border-radius: 10px; padding: 16px; text-align: center; }
.stat-box .num { font-size: 26px; font-weight: 700; color: var(--primary); margin-top: 4px; }
.stat-box .label { font-size: 13px; color: var(--text-muted); }
.nav-tabs { display: flex; gap: 8px; margin-bottom: 16px; border-bottom: 1px solid var(--border); }
.tab-btn { background: none; border: none; padding: 10px 18px; font-size: 14px; font-weight: 600; color: var(--text-muted); cursor: pointer; border-bottom: 2px solid transparent; }
.tab-btn.active { color: var(--primary); border-bottom-color: var(--primary); }
table { width: 100%; border-collapse: collapse; font-size: 13px; text-align: left; }
th, td { padding: 12px 14px; border-bottom: 1px solid var(--border); }
th { background: #f1f5f9; color: var(--text-muted); font-weight: 600; }
tr:hover { background: #f8fafc; }
.badge { display: inline-block; padding: 3px 8px; border-radius: 9999px; font-size: 12px; font-weight: 600; }
.badge.ok { background: #dcfce7; color: var(--success); }
.badge.err { background: #fee2e2; color: var(--danger); }
.badge.warn { background: #fef3c7; color: var(--warning); }
.btn { display: inline-flex; align-items: center; gap: 6px; padding: 7px 14px; border-radius: 6px; font-size: 13px; font-weight: 500; cursor: pointer; border: 1px solid transparent; transition: all 0.2s; }
.btn.primary { background: var(--primary); color: white; }
.btn.primary:hover { background: var(--primary-hover); }
.btn.outline { background: white; border-color: var(--border); color: var(--text); }
.btn.outline:hover { background: #f1f5f9; }
.btn.danger { background: #fee2e2; color: var(--danger); border-color: #fca5a5; }
.btn.danger:hover { background: #fecaca; }
.btn.sm { padding: 4px 8px; font-size: 12px; }
.form-group { margin-bottom: 14px; }
.form-group label { display: block; font-size: 13px; font-weight: 600; margin-bottom: 6px; }
.form-control { width: 100%; padding: 8px 12px; border: 1px solid var(--border); border-radius: 6px; font-size: 14px; }
.modal-mask { position: fixed; inset: 0; background: rgba(0,0,0,0.4); display: flex; align-items: center; justify-content: center; z-index: 1000; }
.modal { background: white; border-radius: 12px; width: 90%; max-width: 480px; padding: 24px; box-shadow: 0 10px 25px rgba(0,0,0,0.15); }
.modal h3 { margin-bottom: 16px; font-size: 18px; }
.modal-actions { display: flex; justify-content: flex-end; gap: 10px; margin-top: 20px; }
.hidden { display: none !important; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>🚀 Wenp 账号授权管理系统</h1>
    <div class="header-actions">
      <span id="loginNotice" class="badge ok">已连接 VPS (3.25.95.151)</span>
      <button class="btn outline" id="logoutBtn" onclick="logout()">退出管理</button>
    </div>
  </div>

  <div id="loginCard" class="card" style="max-width: 400px; margin: 60px auto;">
    <h3 style="margin-bottom: 16px;">🔑 管理员登录</h3>
    <div class="form-group">
      <label>管理密码</label>
      <input type="password" id="adminPwd" class="form-control" placeholder="请输入管理员密码" value="wp51000">
    </div>
    <button class="btn primary" style="width: 100%;" onclick="login()">登录后台</button>
  </div>

  <div id="mainPanel" class="hidden">
    <div class="stats">
      <div class="stat-box"><div class="label">总用户数</div><div class="num" id="statUsers">0</div></div>
      <div class="stat-box"><div class="label">有效授权用户</div><div class="num" id="statValid" style="color:var(--success);">0</div></div>
      <div class="stat-box"><div class="label">已过期用户</div><div class="num" id="statExpired" style="color:var(--danger);">0</div></div>
      <div class="stat-box"><div class="label">未激活卡密数</div><div class="num" id="statCards">0</div></div>
    </div>

    <div class="nav-tabs">
      <button class="tab-btn active" onclick="switchTab('usersTab', this)">👥 用户账号管理</button>
      <button class="tab-btn" onclick="switchTab('cardsTab', this)">🎫 卡密激活码管理</button>
    </div>

    <!-- 用户管理 Tab -->
    <div id="usersTab">
      <div style="display:flex; justify-content:space-between; margin-bottom: 14px;">
        <button class="btn primary" onclick="showAddUserModal()">+ 新建用户账号</button>
        <button class="btn outline" onclick="loadUsers()">🔄 刷新列表</button>
      </div>
      <div class="card" style="padding:0; overflow:hidden;">
        <table>
          <thead>
            <tr>
              <th>用户名</th>
              <th>密码</th>
              <th>到期时间</th>
              <th>剩余</th>
              <th>绑定设备数</th>
              <th>状态</th>
              <th>备注</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody id="userTableBody">
            <tr><td colspan="8" style="text-align:center; padding:30px;">加载中...</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- 卡密管理 Tab -->
    <div id="cardsTab" class="hidden">
      <div style="display:flex; justify-content:space-between; margin-bottom: 14px;">
        <button class="btn primary" onclick="showGenCardsModal()">+ 批量生成卡密</button>
        <button class="btn outline" onclick="exportUnusedCards()">📋 复制所有可用卡密</button>
        <button class="btn outline" onclick="loadCards()">🔄 刷新列表</button>
      </div>
      <div class="card" style="padding:0; overflow:hidden;">
        <table>
          <thead>
            <tr>
              <th>卡密 Key</th>
              <th>面额天数</th>
              <th>使用状态</th>
              <th>使用者</th>
              <th>使用时间</th>
              <th>生成时间</th>
            </tr>
          </thead>
          <tbody id="cardTableBody">
            <tr><td colspan="6" style="text-align:center; padding:30px;">加载中...</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</div>

<!-- Modal: 添加用户 -->
<div id="addUserModal" class="modal-mask hidden">
  <div class="modal">
    <h3>新建用户</h3>
    <div class="form-group">
      <label>用户名</label>
      <input type="text" id="newUsername" class="form-control" placeholder="如: user01">
    </div>
    <div class="form-group">
      <label>密码</label>
      <input type="text" id="newPassword" class="form-control" placeholder="设置登录密码">
    </div>
    <div class="form-group">
      <label>初始有效天数</label>
      <select id="newDays" class="form-control">
        <option value="7">7 天 (试用)</option>
        <option value="30" selected>30 天 (月度)</option>
        <option value="90">90 天 (季度)</option>
        <option value="365">365 天 (年度)</option>
        <option value="3650">3650 天 (永久)</option>
      </select>
    </div>
    <div class="form-group">
      <label>最大允许设备数</label>
      <input type="number" id="newMaxDevices" class="form-control" value="1" min="1" max="10">
    </div>
    <div class="form-group">
      <label>备注说明</label>
      <input type="text" id="newNotes" class="form-control" placeholder="客户姓名/联系方式">
    </div>
    <div class="modal-actions">
      <button class="btn outline" onclick="hideModal('addUserModal')">取消</button>
      <button class="btn primary" onclick="submitAddUser()">立即创建</button>
    </div>
  </div>
</div>

<!-- Modal: 批量生成卡密 -->
<div id="genCardsModal" class="modal-mask hidden">
  <div class="modal">
    <h3>批量生成激活卡密</h3>
    <div class="form-group">
      <label>卡密面额</label>
      <select id="genCardDays" class="form-control">
        <option value="7">7 天卡</option>
        <option value="30" selected>30 天月卡</option>
        <option value="90">90 天季卡</option>
        <option value="365">365 天年卡</option>
      </select>
    </div>
    <div class="form-group">
      <label>生成数量</label>
      <input type="number" id="genCardCount" class="form-control" value="10" min="1" max="100">
    </div>
    <div class="modal-actions">
      <button class="btn outline" onclick="hideModal('genCardsModal')">取消</button>
      <button class="btn primary" onclick="submitGenCards()">立即生成</button>
    </div>
  </div>
</div>

<script>
let token = localStorage.getItem('wenp_admin_token') || 'wp51000';
let allCards = [];

function api(path, method='GET', body=null) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = 'Bearer ' + token;
  return fetch(path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : null
  }).then(async r => {
    if (r.status === 401) {
      logout();
      throw new Error('未授权');
    }
    const data = await r.json();
    if (!r.ok || !data.ok) throw new Error(data.msg || '请求失败');
    return data;
  });
}

function login() {
  const pwd = document.getElementById('adminPwd').value.trim();
  if (!pwd) return alert('请输入密码');
  token = pwd;
  api('/api/admin/users').then(() => {
    localStorage.setItem('wenp_admin_token', token);
    showPanel();
    loadUsers();
    loadCards();
  }).catch(e => {
    alert(e.message || '密码错误');
  });
}

function logout() {
  localStorage.removeItem('wenp_admin_token');
  token = '';
  document.getElementById('loginCard').classList.remove('hidden');
  document.getElementById('mainPanel').classList.add('hidden');
  document.getElementById('logoutBtn').classList.add('hidden');
}

function showPanel() {
  document.getElementById('loginCard').classList.add('hidden');
  document.getElementById('mainPanel').classList.remove('hidden');
  document.getElementById('logoutBtn').classList.remove('hidden');
}

function switchTab(tabId, btn) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('usersTab').classList.add('hidden');
  document.getElementById('cardsTab').classList.add('hidden');
  document.getElementById(tabId).classList.remove('hidden');
}

function loadUsers() {
  api('/api/admin/users').then(data => {
    const users = data.users || [];
    let valid = 0, expired = 0;
    users.forEach(u => u.is_expired ? expired++ : valid++);
    document.getElementById('statUsers').innerText = users.length;
    document.getElementById('statValid').innerText = valid;
    document.getElementById('statExpired').innerText = expired;

    const tbody = document.getElementById('userTableBody');
    if (!users.length) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; padding:20px; color:#94a3b8;">暂无用户，请点击上方「新建用户」</td></tr>';
      return;
    }
    tbody.innerHTML = users.map(u => `
      <tr>
        <td><b>${u.username}</b></td>
        <td><code>${u.password}</code></td>
        <td>${u.expire_at}</td>
        <td><span class="badge ${u.is_expired ? 'err' : (u.days_left < 7 ? 'warn' : 'ok')}">${u.is_expired ? '已过期' : u.days_left + ' 天'}</span></td>
        <td>${u.devices_count} / ${u.max_devices} 台</td>
        <td><span class="badge ${u.status === 1 ? 'ok' : 'err'}">${u.status === 1 ? '正常' : '禁用'}</span></td>
        <td style="color:#64748b;">${u.notes || '—'}</td>
        <td>
          <button class="btn outline sm" onclick="renewUser('${u.username}', 30)">+30天</button>
          <button class="btn outline sm" onclick="renewUser('${u.username}', 90)">+90天</button>
          <button class="btn outline sm" onclick="unbindUser('${u.username}')">解绑设备</button>
          <button class="btn danger sm" onclick="deleteUser('${u.username}')">删除</button>
        </td>
      </tr>
    `).join('');
  }).catch(err => {
    console.error(err);
  });
}

function loadCards() {
  api('/api/admin/cards').then(data => {
    allCards = data.cards || [];
    const unused = allCards.filter(c => c.used === 0);
    document.getElementById('statCards').innerText = unused.length;

    const tbody = document.getElementById('cardTableBody');
    if (!allCards.length) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:20px; color:#94a3b8;">暂无卡密，请点击上方「批量生成卡密」</td></tr>';
      return;
    }
    tbody.innerHTML = allCards.map(c => `
      <tr>
        <td><code>${c.card_key}</code></td>
        <td><span class="badge warn">${c.days} 天</span></td>
        <td><span class="badge ${c.used === 1 ? 'err' : 'ok'}">${c.used === 1 ? '已使用' : '未使用'}</span></td>
        <td>${c.used_by || '—'}</td>
        <td style="color:#64748b;">${c.used_at || '—'}</td>
        <td style="color:#64748b;">${c.created_at}</td>
      </tr>
    `).join('');
  });
}

function showAddUserModal() { document.getElementById('addUserModal').classList.remove('hidden'); }
function showGenCardsModal() { document.getElementById('genCardsModal').classList.remove('hidden'); }
function hideModal(id) { document.getElementById(id).classList.add('hidden'); }

function submitAddUser() {
  const username = document.getElementById('newUsername').value.trim();
  const password = document.getElementById('newPassword').value.trim();
  const days = parseInt(document.getElementById('newDays').value);
  const max_devices = parseInt(document.getElementById('newMaxDevices').value);
  const notes = document.getElementById('newNotes').value.trim();

  if (!username || !password) return alert('用户名和密码不能为空');
  api('/api/admin/user/create', 'POST', { username, password, days, max_devices, notes })
    .then(r => {
      alert(r.msg);
      hideModal('addUserModal');
      document.getElementById('newUsername').value = '';
      document.getElementById('newPassword').value = '';
      loadUsers();
    }).catch(e => alert(e.message));
}

function renewUser(username, days) {
  if (!confirm(`确认给用户 ${username} 延长 ${days} 天授权吗？`)) return;
  api('/api/admin/user/renew', 'POST', { username, days })
    .then(r => {
      alert(r.msg);
      loadUsers();
    }).catch(e => alert(e.message));
}

function unbindUser(username) {
  if (!confirm(`确认清空用户 ${username} 绑定的所有设备吗？解绑后用户可在新电脑重新绑定。`)) return;
  api('/api/admin/user/unbind', 'POST', { username })
    .then(r => {
      alert(r.msg);
      loadUsers();
    }).catch(e => alert(e.message));
}

function deleteUser(username) {
  if (!confirm(`危险操作：确定要彻底删除用户 ${username} 吗？`)) return;
  api('/api/admin/user/delete', 'POST', { username })
    .then(r => {
      alert(r.msg);
      loadUsers();
    }).catch(e => alert(e.message));
}

function submitGenCards() {
  const days = parseInt(document.getElementById('genCardDays').value);
  const count = parseInt(document.getElementById('genCardCount').value);
  api('/api/admin/cards/generate', 'POST', { days, count })
    .then(r => {
      alert(`成功生成 ${r.count} 张卡密！`);
      hideModal('genCardsModal');
      loadCards();
    }).catch(e => alert(e.message));
}

function exportUnusedCards() {
  const unused = allCards.filter(c => c.used === 0).map(c => c.card_key).join('\\n');
  if (!unused) return alert('暂无未使用的卡密！');
  navigator.clipboard.writeText(unused).then(() => {
    alert(`已将 ${allCards.filter(c => c.used === 0).length} 张未使用的卡密复制到剪贴板！`);
  }).catch(() => {
    prompt('请手动复制卡密：', unused);
  });
}

// 自动检测登录态
if (token) {
  api('/api/admin/users').then(() => {
    showPanel();
    loadUsers();
    loadCards();
  }).catch(() => {
    logout();
  });
}
</script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def index_page():
    return HTML_CONTENT

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
