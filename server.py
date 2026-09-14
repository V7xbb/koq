from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from pathlib import Path
import random
import string
import json
import hashlib
import secrets
import os
import time
from collections import defaultdict, deque

app = FastAPI(title="XO Game Server", version="4.0")

# ============ CORS ============
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# 👑 إعدادات المالك (عدّل الإيميل ده)
# ============================================================
KING_EMAIL = "king@xo.com"  # ← غيّره لإيميلك

# الأرقام المحجوزة للملك
KING_RESERVED_IDS = {1, 7, 77, 777, 7777, 77777, 0, 100, 1000, 9999, 12345}

# الأرقام "النادرة" (مميزة)
def is_rare_id(num: int) -> bool:
    s = str(num)
    # أقل من 5 خانات = نادر
    if len(s) <= 4:
        return True
    # متكرر (111, 777, 1111, 7777)
    if len(set(s)) == 1:
        return True
    # تسلسلي (123, 1234, 12345, 98765)
    if s in ("123", "1234", "12345", "987", "9876", "98765", "101", "1010"):
        return True
    # أرقام مميزة
    if num in (100, 200, 300, 500, 1000, 2000, 5000, 10000):
        return True
    return False

def id_price(num: int) -> int:
    """سعر شراء رقم معين"""
    s = str(num)
    n = len(s)
    # متكرر: خصم 50%
    repeat_discount = 0.5 if len(set(s)) == 1 else 1.0
    if n == 1: return 999999  # الملك فقط
    if n == 2: return int(50000 * repeat_discount)
    if n == 3: return int(10000 * repeat_discount)
    if n == 4: return int(3000 * repeat_discount)
    if n == 5: return int(500 * repeat_discount)
    return 0  # 6+ مجاني

# ============ الملفات ============
DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)
USERS_FILE = DATA_DIR / "users.json"
AUTH_FILE = DATA_DIR / "auth.json"
SESSIONS_FILE = DATA_DIR / "sessions.json"
MATCHES_FILE = DATA_DIR / "matches.json"
GLOBAL_CHAT_FILE = DATA_DIR / "global_chat.json"
FRIENDS_FILE = DATA_DIR / "friends.json"
DM_FILE = DATA_DIR / "dm.json"
REWARDS_FILE = DATA_DIR / "rewards.json"
ID_STORE_FILE = DATA_DIR / "id_store.json"

def load_json(path: Path, default):
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
        return default
    except:
        return default

def save_json(path: Path, data):
    try:
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as e:
        print(f"خطأ في الحفظ: {e}")

# ============ البيانات ============
users: Dict[str, dict] = load_json(USERS_FILE, {})
auth_users: Dict[str, dict] = load_json(AUTH_FILE, {})
sessions: Dict[str, dict] = load_json(SESSIONS_FILE, {})
matches: List[dict] = load_json(MATCHES_FILE, [])
global_chat: List[dict] = load_json(GLOBAL_CHAT_FILE, [])
friendships: Dict[str, dict] = load_json(FRIENDS_FILE, {})  # user_id -> {friends: [], requests_in: [], requests_out: []}
dm_messages: Dict[str, List[dict]] = load_json(DM_FILE, {})  # "uid1_uid2" -> [msgs]
rewards_log: Dict[str, dict] = load_json(REWARDS_FILE, {})  # user_id -> {last_daily, last_weekly, last_monthly}
id_store: Dict[str, int] = load_json(ID_STORE_FILE, {})  # id -> owner_user_id (للأرقام المملوكة)
rooms: Dict[str, dict] = {}
connections: Dict[str, Dict[str, WebSocket]] = {}
global_connections: Dict[str, WebSocket] = {}
dm_connections: Dict[str, WebSocket] = {}  # user_id -> ws (لرسائل الأصدقاء)

# ============ 🔐 Security / Anti-Cheat ============
# Simple in-memory rate limiter. It protects the running server without changing the UI.
RATE_WINDOW_SECONDS = 10
RATE_LIMITS = {
    "default": 60,
    "auth": 12,
    "chat": 20,
    "game": 40,
}
_rate_buckets = defaultdict(deque)

def client_key(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    return (forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "unknown"))

def enforce_rate_limit(key: str, bucket: str = "default"):
    now = time.monotonic()
    q = _rate_buckets[(key, bucket)]
    limit = RATE_LIMITS.get(bucket, RATE_LIMITS["default"])
    while q and now - q[0] > RATE_WINDOW_SECONDS:
        q.popleft()
    if len(q) >= limit:
        raise HTTPException(429, "طلبات كتير، استنى شوية وجرب تاني")
    q.append(now)

def bearer_token(request: Request) -> str:
    value = request.headers.get("Authorization", "")
    if value.lower().startswith("bearer "):
        return value[7:].strip()
    return ""

def require_auth(request: Request) -> dict:
    token = bearer_token(request)
    user = get_user_from_token(token)
    if not user:
        raise HTTPException(401, "غير مسجل الدخول")
    enforce_rate_limit(f"user:{user['id']}")
    return user

def require_owner(request: Request, user_id: int) -> dict:
    user = require_auth(request)
    if int(user.get("id")) != int(user_id):
        raise HTTPException(403, "غير مصرح")
    return user

def ws_token(ws: WebSocket) -> str:
    # Browsers cannot set Authorization headers on WebSocket, so the token is sent as a query parameter.
    return ws.query_params.get("token", "").strip()

def require_ws_user(ws: WebSocket) -> Optional[dict]:
    token = ws_token(ws)
    return get_user_from_token(token) if token else None

# ============ الأدوات ============
def generate_code(length=6):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

def generate_id(length=12):
    return secrets.token_hex(length // 2)

def now_iso():
    return datetime.utcnow().isoformat()

def today_str():
    return datetime.utcnow().strftime("%Y-%m-%d")

def week_str():
    y, w, _ = datetime.utcnow().isocalendar()
    return f"{y}-W{w}"

def month_str():
    return datetime.utcnow().strftime("%Y-%m")

def hash_password(password: str, salt: str = None) -> tuple:
    if salt is None:
        salt = secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()
    return (salt, pwd_hash)

def verify_password(password: str, salt: str, stored_hash: str) -> bool:
    _, computed = hash_password(password, salt)
    return secrets.compare_digest(computed, stored_hash)

def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    expires = (datetime.utcnow() + timedelta(days=30)).isoformat()
    sessions[token] = {"user_id": user_id, "expires": expires, "created": now_iso()}
    save_json(SESSIONS_FILE, sessions)
    return token

def get_user_from_token(token: str) -> Optional[dict]:
    sess = sessions.get(token)
    if not sess:
        return None
    if datetime.fromisoformat(sess["expires"]) < datetime.utcnow():
        del sessions[token]
        save_json(SESSIONS_FILE, sessions)
        return None
    uid = str(sess["user_id"])
    return users.get(uid)

def save_users():
    save_json(USERS_FILE, users)

def is_king(user: dict) -> bool:
    return user.get("email", "").lower() == KING_EMAIL.lower()

def is_vip(user: dict) -> bool:
    if is_king(user):
        return True
    # VIP مؤقت؟ تحقق من الانتهاء
    vip_until = user.get("vip_until")
    if vip_until:
        try:
            if datetime.fromisoformat(vip_until) > datetime.utcnow():
                return True
        except:
            pass
    return False

def get_role(user: dict) -> str:
    if is_king(user):
        return "king"
    if is_vip(user):
        return "vip"
    return "user"

def public_user(u: dict) -> dict:
    """نسخة نظيفة من المستخدم للإرسال (بدون باسورد)"""
    d = {k: v for k, v in u.items() if not k.startswith("password_")}
    d["role"] = get_role(u)
    d["is_king"] = is_king(u)
    d["is_vip"] = is_vip(u)
    d["is_rare_id"] = is_rare_id(u.get("id", 0))
    return d

def get_or_create_user(user_id: int, name: str = "Player", username: str = ""):
    uid = str(user_id)
    if uid not in users:
        users[uid] = {
            "id": user_id,
            "name": name,
            "username": username,
            "email": "",
            "points": 500,
            "games": 0, "wins": 0, "losses": 0, "draws": 0,
            "streak": 0, "best_streak": 0,
            "owned_skins": ["gold"],
            "current_skin": "gold",
            "owned_items": {},
            "current_items": {},
            "avatar": "👤",
            "title": None,
            "bio": "",
            "created_at": now_iso(),
            "last_seen": now_iso(),
            "is_registered": False,
            "vip_until": None,
            "vip_granted_by": None,
        }
        save_users()
    else:
        users[uid]["last_seen"] = now_iso()
        if name and name != "Player":
            users[uid]["name"] = name
    return users[uid]

# ============================================================
# 🔐 Auth
# ============================================================
class RegisterReq(BaseModel):
    email: str
    username: str
    password: str
    desired_id: Optional[int] = None  # ← اختيار ID يدوي

class LoginReq(BaseModel):
    email: str
    password: str

@app.post("/api/auth/register")
async def register(req: RegisterReq):
    email = req.email.strip().lower()
    username = req.username.strip()
    password = req.password

    if not email or "@" not in email:
        raise HTTPException(400, "البريد الإلكتروني غير صحيح")
    if len(username) < 3:
        raise HTTPException(400, "اسم المستخدم لازم 3 أحرف على الأقل")
    if len(password) < 6:
        raise HTTPException(400, "كلمة السر لازم 6 أحرف على الأقل")

    for uid, u in users.items():
        if u.get("email", "").lower() == email:
            raise HTTPException(400, "البريد الإلكتروني مستخدم بالفعل")

    is_king_registration = (email == KING_EMAIL.lower())

    # ===== اختيار الـ ID =====
    if req.desired_id is not None:
        desired = int(req.desired_id)
        if str(desired) in users:
            raise HTTPException(400, f"الرقم {desired} مستخدم بالفعل")
        # الأرقام المحجوزة للملك
        if desired in KING_RESERVED_IDS and not is_king_registration:
            raise HTTPException(403, "هذا الرقم محجوز")
        # أرقام قصيرة جدًا
        if desired < 100 and not is_king_registration:
            raise HTTPException(403, "الأرقام أقل من 100 للملك فقط")
        # سعر خاص للأرقام النادرة
        price = id_price(desired)
        if price > 500 and not is_king_registration:
            raise HTTPException(400, f"هذا الرقم نادر — سعره {price} نقطة. اشتره من المتجر بعد التسجيل.")
        new_id = desired
    else:
        # توليد ID عشوائي
        new_id = int(datetime.utcnow().timestamp() * 1000) % 1000000000
        while str(new_id) in users or len(str(new_id)) < 5:
            new_id = random.randint(10000, 999999999)

    salt, pwd_hash = hash_password(password)

    users[str(new_id)] = {
        "id": new_id,
        "name": username,
        "username": username,
        "email": email,
        "password_salt": salt,
        "password_hash": pwd_hash,
        "points": 500,
        "games": 0, "wins": 0, "losses": 0, "draws": 0,
        "streak": 0, "best_streak": 0,
        "owned_skins": ["gold"],
        "current_skin": "gold",
        "owned_items": {},
        "current_items": {},
        "avatar": "👤",
        "title": None,
        "bio": "",
        "created_at": now_iso(),
        "last_seen": now_iso(),
        "is_registered": True,
        "vip_until": None,
        "vip_granted_by": None,
    }
    save_users()

    token = create_session(new_id)
    return {"success": True, "token": token, "user": public_user(users[str(new_id)])}

@app.post("/api/auth/login")
async def login(req: LoginReq):
    email = req.email.strip().lower()
    password = req.password

    found_user = None
    for uid, u in users.items():
        if u.get("email", "").lower() == email:
            found_user = u
            break

    if not found_user:
        raise HTTPException(401, "البريد الإلكتروني أو كلمة السر غير صحيحة")

    salt = found_user.get("password_salt", "")
    stored_hash = found_user.get("password_hash", "")
    if not salt or not stored_hash:
        raise HTTPException(401, "هذا الحساب غير مسجل")

    if not verify_password(password, salt, stored_hash):
        raise HTTPException(401, "البريد الإلكتروني أو كلمة السر غير صحيحة")

    token = create_session(found_user["id"])
    return {"success": True, "token": token, "user": public_user(found_user)}

@app.post("/api/auth/logout")
async def logout(request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if token in sessions:
        del sessions[token]
        save_json(SESSIONS_FILE, sessions)
    return {"success": True}

@app.get("/api/auth/me")
async def me(request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = get_user_from_token(token)
    if not user:
        raise HTTPException(401, "غير مسجل الدخول")
    return public_user(user)

# ============================================================
# ⏱️ مؤقت الضيف (server-side)
# ============================================================
GUEST_LIMIT_MINUTES = 10

class GuestReq(BaseModel):
    name: str = ""

@app.post("/api/user/guest")
async def guest_session(req: GuestReq):
    """ينشئ حساب ضيف بمؤقت 10 دقايق"""
    guest_id = random.randint(10000, 999999999)
    while str(guest_id) in users:
        guest_id = random.randint(10000, 999999999)

    expires = (datetime.utcnow() + timedelta(minutes=GUEST_LIMIT_MINUTES)).isoformat()

    users[str(guest_id)] = {
        "id": guest_id,
        "name": req.name or f"ضيف_{str(guest_id)[-4:]}",
        "username": "",
        "email": "",
        "points": 0,
        "games": 0, "wins": 0, "losses": 0, "draws": 0,
        "streak": 0, "best_streak": 0,
        "owned_skins": ["gold"],
        "current_skin": "gold",
        "owned_items": {},
        "current_items": {},
        "avatar": "👤",
        "title": None,
        "bio": "",
        "created_at": now_iso(),
        "last_seen": now_iso(),
        "is_registered": False,
        "is_guest": True,
        "guest_expires": expires,
        "vip_until": None,
    }
    save_users()
    token = create_session(guest_id)

    return {
        "success": True,
        "token": token,
        "user": public_user(users[str(guest_id)]),
        "expires": expires,
        "limit_minutes": GUEST_LIMIT_MINUTES,
    }
    # ============================================================
# ✏️ تعديل البروفايل
# ============================================================
class UpdateProfileReq(BaseModel):
    name: Optional[str] = None
    avatar: Optional[str] = None
    title: Optional[str] = None
    bio: Optional[str] = None

@app.patch("/api/user/{user_id}/profile")
async def update_profile(user_id: int, req: UpdateProfileReq, request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    me_user = get_user_from_token(token)
    if not me_user or me_user["id"] != user_id:
        raise HTTPException(403, "غير مصرح")

    uid = str(user_id)
    if uid not in users:
        raise HTTPException(404, "المستخدم غير موجود")

    u = users[uid]
    if req.name is not None:
        name = req.name.strip()
        if len(name) < 2 or len(name) > 20:
            raise HTTPException(400, "الاسم لازم بين 2 و 20 حرف")
        u["name"] = name
    if req.avatar is not None:
        u["avatar"] = req.avatar[:4]
    if req.title is not None:
        # العنوان المخصص للملك فقط
        if req.title and not is_king(u):
            if req.title not in (u.get("owned_items", {}).get("titles", [])):
                raise HTTPException(403, "هذا اللقب غير مملوك")
        u["title"] = req.title[:30]
    if req.bio is not None:
        u["bio"] = req.bio[:150]

    save_users()
    return {"success": True, "user": public_user(u)}

# ============================================================
# 🆔 البحث بالـ ID + متجر الأرقام
# ============================================================
@app.get("/api/user/search/{query}")
async def search_user(query: str):
    """يبحث بالـ ID أو الاسم"""
    results = []
    q = query.strip().lower()
    for uid, u in users.items():
        if q in str(u.get("id", "")).lower() or q in u.get("name", "").lower():
            results.append(public_user(u))
            if len(results) >= 20:
                break
    return results

@app.get("/api/user/find-by-id/{uid}")
async def find_by_id(uid: int):
    u = users.get(str(uid))
    if not u:
        raise HTTPException(404, "لا يوجد مستخدم بهذا الرقم")
    return public_user(u)

@app.get("/api/ids/check/{num}")
async def check_id(num: int):
    """يتحقق إذا كان الرقم متاح وسعره"""
    taken = str(num) in users
    reserved_for_king = num in KING_RESERVED_IDS or num < 100
    rare = is_rare_id(num)
    price = id_price(num)
    return {
        "available": not taken,
        "reserved_for_king": reserved_for_king,
        "is_rare": rare,
        "price": price,
        "owner": public_user(users[str(num)]) if taken else None,
    }

class BuyIDReq(BaseModel):
    new_id: int

@app.post("/api/user/{user_id}/buy-id")
async def buy_id(user_id: int, req: BuyIDReq, request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    me_user = get_user_from_token(token)
    if not me_user or me_user["id"] != user_id:
        raise HTTPException(403, "غير مصرح")

    uid = str(user_id)
    u = users[uid]
    new_id = int(req.new_id)

    if str(new_id) in users and str(new_id) != uid:
        raise HTTPException(400, "الرقم محجوز")

    # الملك ياخد أي رقم
    if not is_king(u):
        if new_id in KING_RESERVED_IDS or new_id < 100:
            raise HTTPException(403, "هذا الرقم محجوز للملك")
        price = id_price(new_id)
        if price > 0 and u.get("points", 0) < price:
            raise HTTPException(400, f"محتاج {price} نقطة")
        u["points"] -= price

    # نقل البيانات للـ ID الجديد
    old_data = dict(u)
    old_data["id"] = new_id
    users[str(new_id)] = old_data
    if str(new_id) != uid:
        del users[uid]

    save_users()
    return {"success": True, "user": public_user(old_data), "new_id": new_id}

# ============================================================
# 👑💎 نظام الرتب: الملك + VIP
# ============================================================
class GrantVIPReq(BaseModel):
    target_id: int
    days: int = 30

@app.post("/api/king/grant-vip")
async def grant_vip(req: GrantVIPReq, request: Request):
    """الملك بس اللي يقدر يرفع VIP"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    me_user = get_user_from_token(token)
    if not me_user or not is_king(me_user):
        raise HTTPException(403, "الملك بس")

    target = users.get(str(req.target_id))
    if not target:
        raise HTTPException(404, "المستخدم غير موجود")

    vip_until = (datetime.utcnow() + timedelta(days=req.days)).isoformat()
    target["vip_until"] = vip_until
    target["vip_granted_by"] = me_user["id"]
    save_users()

    return {"success": True, "target": public_user(target), "vip_until": vip_until}

class RevokeVIPReq(BaseModel):
    target_id: int

@app.post("/api/king/revoke-vip")
async def revoke_vip(req: RevokeVIPReq, request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    me_user = get_user_from_token(token)
    if not me_user or not is_king(me_user):
        raise HTTPException(403, "الملك بس")

    target = users.get(str(req.target_id))
    if not target:
        raise HTTPException(404, "المستخدم غير موجود")

    target["vip_until"] = None
    target["vip_granted_by"] = None
    save_users()
    return {"success": True, "target": public_user(target)}

@app.get("/api/vip/list")
async def vip_list():
    """قائمة الـ VIP الحاليين"""
    vips = []
    for u in users.values():
        if is_vip(u) and not is_king(u):
            vips.append(public_user(u))
    return vips

# ============================================================
# 🎁 المكافآت (يومي / أسبوعي / شهري)
# ============================================================
@app.post("/api/user/{user_id}/claim-daily")
async def claim_daily(user_id: int, request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    me_user = get_user_from_token(token)
    if not me_user or me_user["id"] != user_id:
        raise HTTPException(403, "غير مصرح")

    uid = str(user_id)
    u = users[uid]
    log = rewards_log.get(uid, {})
    today = today_str()

    if log.get("last_daily") == today:
        raise HTTPException(400, "خدت مكافأة النهاردة خلاص")

    role = get_role(u)
    base = 100
    if role == "vip": base = 200
    if role == "king": base = 500

    u["points"] = u.get("points", 0) + base
    log["last_daily"] = today
    rewards_log[uid] = log
    save_users()
    save_json(REWARDS_FILE, rewards_log)

    return {"success": True, "points": base, "total": u["points"]}

@app.post("/api/user/{user_id}/claim-weekly")
async def claim_weekly(user_id: int, request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    me_user = get_user_from_token(token)
    if not me_user or me_user["id"] != user_id:
        raise HTTPException(403, "غير مصرح")

    uid = str(user_id)
    u = users[uid]
    log = rewards_log.get(uid, {})
    week = week_str()

    if log.get("last_weekly") == week:
        raise HTTPException(400, "خدت مكافأة الأسبوع خلاص")

    role = get_role(u)
    if role == "user":
        raise HTTPException(403, "المكافأة الأسبوعية للـ VIP بس")

    base = 500 if role == "vip" else 2000
    u["points"] = u.get("points", 0) + base
    log["last_weekly"] = week
    rewards_log[uid] = log
    save_users()
    save_json(REWARDS_FILE, rewards_log)

    return {"success": True, "points": base, "total": u["points"]}

@app.post("/api/user/{user_id}/claim-monthly")
async def claim_monthly(user_id: int, request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    me_user = get_user_from_token(token)
    if not me_user or me_user["id"] != user_id:
        raise HTTPException(403, "غير مصرح")

    uid = str(user_id)
    u = users[uid]
    if not is_king(u):
        raise HTTPException(403, "للملك بس")

    log = rewards_log.get(uid, {})
    month = month_str()
    if log.get("last_monthly") == month:
        raise HTTPException(400, "خدت المكافأة الشهرية خلاص")

    u["points"] = u.get("points", 0) + 10000
    log["last_monthly"] = month
    rewards_log[uid] = log
    save_users()
    save_json(REWARDS_FILE, rewards_log)

    return {"success": True, "points": 10000, "total": u["points"]}

@app.get("/api/user/{user_id}/reward-status")
async def reward_status(user_id: int):
    uid = str(user_id)
    u = users.get(uid)
    if not u:
        raise HTTPException(404, "المستخدم غير موجود")
    log = rewards_log.get(uid, {})
    role = get_role(u)
    return {
        "role": role,
        "daily_available": log.get("last_daily") != today_str(),
        "weekly_available": role in ("vip", "king") and log.get("last_weekly") != week_str(),
        "monthly_available": role == "king" and log.get("last_monthly") != month_str(),
        "daily_amount": 100 if role == "user" else 200 if role == "vip" else 500,
        "weekly_amount": 0 if role == "user" else 500 if role == "vip" else 2000,
        "monthly_amount": 0 if role != "king" else 10000,
    }

# ============================================================
# 👥 نظام الأصدقاء
# ============================================================
def get_friendship(uid: str) -> dict:
    if uid not in friendships:
        friendships[uid] = {"friends": [], "requests_in": [], "requests_out": []}
    return friendships[uid]

class FriendReq(BaseModel):
    target_id: int

@app.post("/api/user/{user_id}/friends/add")
async def add_friend(user_id: int, req: FriendReq, request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    me_user = get_user_from_token(token)
    if not me_user or me_user["id"] != user_id:
        raise HTTPException(403, "غير مصرح")

    uid = str(user_id)
    tid = str(req.target_id)

    if uid == tid:
        raise HTTPException(400, "ما ينفعش تضيف نفسك")
    if tid not in users:
        raise HTTPException(404, "المستخدم غير موجود")

    my_fs = get_friendship(uid)
    their_fs = get_friendship(tid)

    if tid in my_fs["friends"]:
        raise HTTPException(400, "هو صاحبك بالفعل")

    if uid in their_fs["requests_out"]:
        # يقبل الطلب تلقائيًا
        their_fs["requests_out"].remove(uid)
        my_fs["requests_in"] = [x for x in my_fs["requests_in"] if x != tid]
        my_fs["friends"].append(tid)
        their_fs["friends"].append(uid)
        save_json(FRIENDS_FILE, friendships)
        return {"success": True, "status": "accepted"}

    if tid not in my_fs["requests_out"]:
        my_fs["requests_out"].append(tid)
        their_fs["requests_in"].append(uid)
        save_json(FRIENDS_FILE, friendships)

    return {"success": True, "status": "requested"}

@app.post("/api/user/{user_id}/friends/accept")
async def accept_friend(user_id: int, req: FriendReq, request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    me_user = get_user_from_token(token)
    if not me_user or me_user["id"] != user_id:
        raise HTTPException(403, "غير مصرح")

    uid = str(user_id)
    tid = str(req.target_id)

    my_fs = get_friendship(uid)
    their_fs = get_friendship(tid)

    if tid not in my_fs["requests_in"]:
        raise HTTPException(400, "مافيش طلب من الشخص ده")

    my_fs["requests_in"].remove(tid)
    their_fs["requests_out"] = [x for x in their_fs["requests_out"] if x != uid]

    if tid not in my_fs["friends"]:
        my_fs["friends"].append(tid)
    if uid not in their_fs["friends"]:
        their_fs["friends"].append(uid)

    save_json(FRIENDS_FILE, friendships)
    return {"success": True, "status": "accepted"}

@app.post("/api/user/{user_id}/friends/reject")
async def reject_friend(user_id: int, req: FriendReq, request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    me_user = get_user_from_token(token)
    if not me_user or me_user["id"] != user_id:
        raise HTTPException(403, "غير مصرح")

    uid = str(user_id)
    tid = str(req.target_id)
    my_fs = get_friendship(uid)
    their_fs = get_friendship(tid)

    my_fs["requests_in"] = [x for x in my_fs["requests_in"] if x != tid]
    their_fs["requests_out"] = [x for x in their_fs["requests_out"] if x != uid]
    save_json(FRIENDS_FILE, friendships)
    return {"success": True}

@app.post("/api/user/{user_id}/friends/remove")
async def remove_friend(user_id: int, req: FriendReq, request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    me_user = get_user_from_token(token)
    if not me_user or me_user["id"] != user_id:
        raise HTTPException(403, "غير مصرح")

    uid = str(user_id)
    tid = str(req.target_id)
    my_fs = get_friendship(uid)
    their_fs = get_friendship(tid)

    my_fs["friends"] = [x for x in my_fs["friends"] if x != tid]
    their_fs["friends"] = [x for x in their_fs["friends"] if x != uid]
    save_json(FRIENDS_FILE, friendships)
    return {"success": True}

@app.get("/api/user/{user_id}/friends")
async def list_friends(user_id: int):
    uid = str(user_id)
    fs = get_friendship(uid)
    friends = [public_user(users[fid]) for fid in fs["friends"] if fid in users]
    requests_in = [public_user(users[fid]) for fid in fs["requests_in"] if fid in users]
    requests_out = [public_user(users[fid]) for fid in fs["requests_out"] if fid in users]
    return {
        "friends": friends,
        "requests_in": requests_in,
        "requests_out": requests_out,
    }

# ============================================================
# 💬 شات الأصدقاء (DM)
# ============================================================
def dm_key(uid1: str, uid2: str) -> str:
    a, b = sorted([uid1, uid2], key=int)
    return f"{a}_{b}"

class SendDMReq(BaseModel):
    to_id: int
    text: str

@app.post("/api/user/{user_id}/dm/send")
async def send_dm(user_id: int, req: SendDMReq, request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    me_user = get_user_from_token(token)
    if not me_user or me_user["id"] != user_id:
        raise HTTPException(403, "غير مصرح")

    uid = str(user_id)
    tid = str(req.to_id)
    if tid not in users:
        raise HTTPException(404, "المستخدم غير موجود")

    # لازم أصدقاء
    fs = get_friendship(uid)
    if tid not in fs["friends"]:
        raise HTTPException(403, "لازم تكونوا أصدقاء")

    text = req.text.strip()[:500]
    if not text:
        raise HTTPException(400, "الرسالة فاضية")

    key = dm_key(uid, tid)
    if key not in dm_messages:
        dm_messages[key] = []

    msg = {
        "id": len(dm_messages[key]) + 1,
        "from_id": user_id,
        "to_id": req.to_id,
        "from_name": me_user.get("name", "Player"),
        "text": text,
        "timestamp": now_iso(),
    }
    dm_messages[key].append(msg)
    if len(dm_messages[key]) > 200:
        dm_messages[key].pop(0)
    save_json(DM_FILE, dm_messages)

    # إرسال realtime لو الطرف التاني متصل
    ws_target = dm_connections.get(tid)
    if ws_target:
        try:
            await ws_target.send_json({"type": "dm", "message": msg})
        except:
            pass

    return {"success": True, "message": msg}

@app.get("/api/user/{user_id}/dm/{other_id}")
async def get_dm(user_id: int, other_id: int):
    key = dm_key(str(user_id), str(other_id))
    return dm_messages.get(key, [])[-100:]

@app.get("/api/user/{user_id}/dm-list")
async def dm_list(user_id: int):
    """قائمة كل المحادثات"""
    uid = str(user_id)
    convs = []
    for key, msgs in dm_messages.items():
        if key.startswith(uid + "_") or key.endswith("_" + uid):
            other_uid = key.replace(uid + "_", "").replace("_" + uid, "")
            if other_uid and other_uid != uid and other_uid in users:
                last_msg = msgs[-1] if msgs else None
                convs.append({
                    "other": public_user(users[other_uid]),
                    "last_message": last_msg,
                    "count": len(msgs),
                })
    convs.sort(key=lambda c: c["last_message"]["timestamp"] if c["last_message"] else "", reverse=True)
    return convs

# ============================================================
# 🏅 الإنجازات
# ============================================================
ACHIEVEMENTS = [
    {"id": "first_win", "name": "أول فوز", "icon": "🥇", "desc": "فزت بأول مباراة", "check": lambda u: u.get("wins", 0) >= 1},
    {"id": "ten_wins", "name": "10 مرات فوز", "icon": "🏆", "desc": "فزت 10 مرات", "check": lambda u: u.get("wins", 0) >= 10},
    {"id": "hundred_wins", "name": "100 فوز", "icon": "👑", "desc": "فزت 100 مرة", "check": lambda u: u.get("wins", 0) >= 100},
    {"id": "streak5", "name": "5 متتالية", "icon": "🔥", "desc": "5 فوزات متتالية", "check": lambda u: u.get("best_streak", 0) >= 5},
    {"id": "streak10", "name": "10 متتالية", "icon": "⚡", "desc": "10 فوزات متتالية", "check": lambda u: u.get("best_streak", 0) >= 10},
    {"id": "games50", "name": "لاعب نشيط", "icon": "🎮", "desc": "لعبت 50 مباراة", "check": lambda u: u.get("games", 0) >= 50},
    {"id": "rich1k", "name": "ألفير", "icon": "💰", "desc": "معاك 1000 نقطة", "check": lambda u: u.get("points", 0) >= 1000},
    {"id": "rich10k", "name": "مليونير", "icon": "💎", "desc": "معاك 10000 نقطة", "check": lambda u: u.get("points", 0) >= 10000},
]

@app.get("/api/user/{user_id}/achievements")
async def get_achievements(user_id: int):
    u = users.get(str(user_id))
    if not u:
        raise HTTPException(404, "المستخدم غير موجود")
    result = []
    for a in ACHIEVEMENTS:
        try:
            unlocked = a["check"](u)
        except:
            unlocked = False
        result.append({
            "id": a["id"],
            "name": a["name"],
            "icon": a["icon"],
            "desc": a["desc"],
            "unlocked": unlocked,
        })
    return result

@app.get("/api/user/{user_id}/streak")
async def get_streak(user_id: int):
    u = users.get(str(user_id))
    if not u:
        raise HTTPException(404, "المستخدم غير موجود")
    return {
        "current": u.get("streak", 0),
        "best": u.get("best_streak", 0),
    }

# ============================================================
# 🏠 الغرف (مع Best of N + VS + Spectators)
# ============================================================
class CreateRoomReq(BaseModel):
    player_id: int
    player_name: str = "Player"
    is_party: bool = False
    best_of: int = 1  # 1 / 3 / 5 / 7

class JoinRoomReq(BaseModel):
    player_id: int
    player_name: str = "Player"
    as_spectator: bool = False

@app.post("/api/rooms/create")
async def create_room(req: CreateRoomReq, request: Request):
    enforce_rate_limit(client_key(request), "game")
    me_user = require_owner(request, req.player_id)
    req.player_name = me_user.get("name", "Player")
    code = generate_code()
    while code in rooms:
        code = generate_code()

    best_of = req.best_of if req.best_of in (1, 3, 5, 7) else 1

    rooms[code] = {
        "code": code,
        "host_id": req.player_id,
        "host_name": req.player_name,
        "guest_id": None,
        "guest_name": None,
        "board": [" "] * 9,
        "turn": "X",
        "status": "waiting",
        "winner": None,
        "moves": [],
        "spectators": [],
        "messages": [],
        "is_party": req.is_party,
        "best_of": best_of,
        "round": 1,
        "score_host": 0,
        "score_guest": 0,
        "wins_needed": (best_of // 2) + 1,
        "round_history": [],  # نتائج الجولات السابقة
        "started_at": None,
        "created_at": now_iso(),
    }
    return {"code": code, "room": rooms[code]}

@app.post("/api/rooms/join/{code}")
async def join_room(code: str, req: JoinRoomReq, request: Request):
    code = code.upper()
    enforce_rate_limit(client_key(request), "game")
    me_user = require_owner(request, req.player_id)
    req.player_name = me_user.get("name", "Player")

    if code not in rooms:
        raise HTTPException(404, "الغرفة غير موجودة")

    room = rooms[code]

    if room["host_id"] == req.player_id:
        return {"code": code, "room": room, "role": "host"}
    if room["guest_id"] == req.player_id:
        return {"code": code, "room": room, "role": "guest"}

    for s in room["spectators"]:
        if s["id"] == req.player_id:
            return {"code": code, "room": room, "role": "spectator"}

    if not req.as_spectator and room["guest_id"] is None and room["status"] != "finished":
        room["guest_id"] = req.player_id
        room["guest_name"] = req.player_name
        room["status"] = "playing"
        room["started_at"] = now_iso()
        return {"code": code, "room": room, "role": "guest"}

    if room["is_party"] or room["guest_id"] is not None:
        room["spectators"].append({"id": req.player_id, "name": req.player_name, "joined_at": now_iso()})
        return {"code": code, "room": room, "role": "spectator"}

    raise HTTPException(400, "الغرفة ممتلئة")

@app.get("/api/rooms/{code}")
async def get_room(code: str):
    code = code.upper()
    if code not in rooms:
        raise HTTPException(404, "الغرفة غير موجودة")
    return rooms[code]

@app.get("/api/rooms")
async def list_rooms():
    return [
        {
            "code": r["code"],
            "host": r["host_name"],
            "status": r["status"],
            "spectators": len(r["spectators"]),
            "is_party": r["is_party"],
            "best_of": r.get("best_of", 1),
        }
        for r in rooms.values()
        if r["status"] in ("waiting", "playing") and not r["is_party"]
    ]

@app.get("/api/parties")
async def list_parties():
    return [
        {
            "code": r["code"],
            "host": r["host_name"],
            "status": r["status"],
            "spectators": len(r["spectators"]),
            "best_of": r.get("best_of", 1),
        }
        for r in rooms.values()
        if r["is_party"] and r["status"] in ("waiting", "playing")
    ]

# ============================================================
# 💬 الشات العام (REST)
# ============================================================
class ChatReq(BaseModel):
    user_id: int
    name: str
    text: str

@app.post("/api/chat/global/send")
async def global_send(req: ChatReq, request: Request):
    enforce_rate_limit(client_key(request), "chat")
    me_user = require_owner(request, req.user_id)
    req.name = me_user.get("name", "Player")
    text = req.text.strip()[:200]
    if not text:
        raise HTTPException(400, "الرسالة فاضية")

    u = users.get(str(req.user_id), {})
    role = get_role(u)
    is_rare = is_rare_id(u.get("id", 0))

    msg = {
        "id": len(global_chat) + 1,
        "user_id": req.user_id,
        "name": req.name,
        "text": text,
        "role": role,
        "is_rare_id": is_rare,
        "avatar": u.get("avatar", "👤"),
        "title": u.get("title"),
        "timestamp": now_iso(),
    }
    global_chat.append(msg)
    if len(global_chat) > 200:
        global_chat.pop(0)
    save_json(GLOBAL_CHAT_FILE, global_chat)

    for uid, ws in list(global_connections.items()):
        try:
            await ws.send_json({"type": "global_chat", "message": msg})
        except:
            pass

    return {"success": True, "message": msg}

@app.get("/api/chat/global/messages")
async def global_messages(limit: int = 50):
    return global_chat[-limit:]

# ============================================================
# 🌐 WebSocket - الغرف
# ============================================================
@app.websocket("/ws/{code}/{player_id}")
async def ws_endpoint(ws: WebSocket, code: str, player_id: int):
    code = code.upper()
    pid = str(player_id)

    user = require_ws_user(ws)
    if not user or int(user.get("id")) != int(player_id):
        await ws.close(code=1008, reason="Unauthorized")
        return
    if code not in rooms:
        await ws.close(code=1008, reason="Room not found")
        return

    await ws.accept()

    if code not in connections:
        connections[code] = {}
    connections[code][pid] = ws

    try:
        if code in rooms:
            room = rooms[code]
            role = "spectator"
            if room["host_id"] == player_id:
                role = "host"
            elif room["guest_id"] == player_id:
                role = "guest"

            await ws.send_json({
                "type": "welcome",
                "room": room,
                "role": role,
            })

            await broadcast(code, {
                "type": "player_joined",
                "player_id": player_id,
            }, exclude=player_id)

        while True:
            data = await ws.receive_json()
            await handle_message(code, player_id, ws, data)

    except WebSocketDisconnect:
        if code in connections:
            connections[code].pop(pid, None)
            if not connections[code]:
                del connections[code]

        if code in rooms:
            room = rooms[code]
            room["spectators"] = [s for s in room["spectators"] if s["id"] != player_id]

        await broadcast(code, {
            "type": "player_left",
            "player_id": player_id,
        })

async def handle_message(code: str, player_id: int, ws: WebSocket, data: dict):
    msg_type = data.get("type")

    if code not in rooms:
        await ws.send_json({"type": "error", "message": "الغرفة غير موجودة"})
        return

    room = rooms[code]
    enforce_rate_limit(f"user:{player_id}", "game")

    if msg_type == "move":
        if player_id not in (room["host_id"], room["guest_id"]):
            await ws.send_json({"type": "error", "message": "أنت مشاهد فقط"})
            return
        if room["status"] != "playing":
            await ws.send_json({"type": "error", "message": "اللعبة لم تبدأ"})
            return

        expected = room["host_id"] if room["turn"] == "X" else room["guest_id"]
        if player_id != expected:
            await ws.send_json({"type": "error", "message": "ليس دورك"})
            return

        index = data.get("index")
        if not isinstance(index, int) or index < 0 or index > 8:
            return
        if room["board"][index] != " ":
            return

        room["board"][index] = room["turn"]
        room["moves"].append(index)

        winner = check_winner(room["board"])
        if winner:
            await finish_round(room, winner, code)
        elif " " not in room["board"]:
            await finish_round(room, "draw", code)
        else:
            room["turn"] = "O" if room["turn"] == "X" else "X"
            await broadcast(code, {"type": "room_update", "room": room})

    elif msg_type == "restart":
        if player_id not in (room["host_id"], room["guest_id"]):
            return
        # في Best of N، ما نسمحش بإعادة إلا لو خلصت السلسلة
        if room["status"] == "finished":
            # سلسلة جديدة
            room["board"] = [" "] * 9
            room["turn"] = "X"
            room["status"] = "playing" if room["guest_id"] else "waiting"
            room["winner"] = None
            room["moves"] = []
            room["round"] = 1
            room["score_host"] = 0
            room["score_guest"] = 0
            room["round_history"] = []
            room["started_at"] = now_iso()
            await broadcast(code, {"type": "room_update", "room": room})

    elif msg_type == "next_round":
        # بداية الجولة التالية في Best of N
        if player_id not in (room["host_id"], room["guest_id"]):
            return
        if room["status"] == "round_finished":
            room["board"] = [" "] * 9
            room["turn"] = "X"
            room["status"] = "playing"
            room["winner"] = None
            room["moves"] = []
            room["round"] += 1
            await broadcast(code, {"type": "room_update", "room": room})

    elif msg_type == "chat":
        text = str(data.get("text", ""))[:200].strip()
        if not text:
            return
        user = users.get(str(player_id), {})
        msg = {
            "id": len(room["messages"]) + 1,
            "player_id": player_id,
            "player_name": user.get("name", "Player"),
            "avatar": user.get("avatar", "👤"),
            "role": get_role(user),
            "text": text,
            "timestamp": now_iso(),
        }
        room["messages"].append(msg)
        if len(room["messages"]) > 100:
            room["messages"].pop(0)
        await broadcast(code, {"type": "chat", "message": msg})

    elif msg_type == "reaction":
        # إيموجي سريع
        emoji = str(data.get("emoji", "👍"))[:2]
        user = users.get(str(player_id), {})
        await broadcast(code, {
            "type": "reaction",
            "player_id": player_id,
            "player_name": user.get("name", "Player"),
            "emoji": emoji,
        })

    elif msg_type == "forfeit":
        if player_id not in (room["host_id"], room["guest_id"]):
            return
        if room["status"] != "playing":
            return
        winner = "O" if player_id == room["host_id"] else "X"
        await finish_round(room, winner, code, forfeit=True)

async def finish_round(room: dict, winner: str, code: str, forfeit: bool = False):
    """يخلص الجولة ولو Best of N يقرر إذا السلسلة خلصت"""
    room["round_history"].append({
        "round": room["round"],
        "winner": winner,
        "moves": room["moves"],
    })

    if winner == "X":
        room["score_host"] += 1
    elif winner == "O":
        room["score_guest"] += 1

    wins_needed = room["wins_needed"]

    # هل السلسلة خلصت؟
    if room["score_host"] >= wins_needed or room["score_guest"] >= wins_needed:
        room["status"] = "finished"
        room["winner"] = "X" if room["score_host"] >= wins_needed else "O"
        record_match(room["host_id"], room["guest_id"], room["winner"], room["moves"], code)
    else:
        room["status"] = "round_finished"

    await broadcast(code, {
        "type": "room_update",
        "room": room,
        "round_finished": True,
        "forfeit": forfeit,
    })

async def broadcast(code: str, msg: dict, exclude: Optional[int] = None):
    if code not in connections:
        return
    for pid_str, ws in list(connections[code].items()):
        if exclude is not None and pid_str == str(exclude):
            continue
        try:
            await ws.send_json(msg)
        except:
            pass

# ============================================================
# 🌐 WebSocket - الشات العام
# ============================================================
@app.websocket("/ws/global/{user_id}")
async def global_ws(ws: WebSocket, user_id: int):
    user = require_ws_user(ws)
    if not user or int(user.get("id")) != int(user_id):
        await ws.close(code=1008, reason="Unauthorized")
        return
    await ws.accept()
    global_connections[str(user_id)] = ws

    # إشعار دخول الملك
    u = users.get(str(user_id), {})
    if is_king(u):
        for uid, cws in list(global_connections.items()):
            try:
                await cws.send_json({
                    "type": "system",
                    "message": f"👑 الملك {u.get('name', '')} دخل اللعبة!",
                    "timestamp": now_iso(),
                })
            except:
                pass

    try:
        await ws.send_json({"type": "history", "messages": global_chat[-50:]})
        while True:
            data = await ws.receive_json()
            if data.get("type") == "chat":
                enforce_rate_limit(f"user:{user_id}", "chat")
                text = str(data.get("text", ""))[:200].strip()
                if not text:
                    continue
                user = users.get(str(user_id), {})
                msg = {
                    "id": len(global_chat) + 1,
                    "user_id": user_id,
                    "name": user.get("name", "Player"),
                    "text": text,
                    "role": get_role(user),
                    "is_rare_id": is_rare_id(user.get("id", 0)),
                    "avatar": user.get("avatar", "👤"),
                    "title": user.get("title"),
                    "timestamp": now_iso(),
                }
                global_chat.append(msg)
                if len(global_chat) > 200:
                    global_chat.pop(0)
                save_json(GLOBAL_CHAT_FILE, global_chat)
                for uid, cws in list(global_connections.items()):
                    try:
                        await cws.send_json({"type": "global_chat", "message": msg})
                    except:
                        pass
    except WebSocketDisconnect:
        global_connections.pop(str(user_id), None)

# ============================================================
# 🌐 WebSocket - رسائل الأصدقاء (DM)
# ============================================================
@app.websocket("/ws/dm/{user_id}")
async def dm_ws(ws: WebSocket, user_id: int):
    user = require_ws_user(ws)
    if not user or int(user.get("id")) != int(user_id):
        await ws.close(code=1008, reason="Unauthorized")
        return
    await ws.accept()
    dm_connections[str(user_id)] = ws
    try:
        while True:
            data = await ws.receive_json()
            if data.get("type") == "dm":
                enforce_rate_limit(f"user:{user_id}", "chat")
                to_id = data.get("to_id")
                text = str(data.get("text", ""))[:500].strip()
                if not text or not to_id:
                    continue

                uid = str(user_id)
                tid = str(to_id)
                fs = get_friendship(uid)
                if tid not in fs["friends"]:
                    await ws.send_json({"type": "error", "message": "لازم تكونوا أصدقاء"})
                    continue

                key = dm_key(uid, tid)
                if key not in dm_messages:
                    dm_messages[key] = []
                msg = {
                    "id": len(dm_messages[key]) + 1,
                    "from_id": user_id,
                    "to_id": to_id,
                    "from_name": users.get(uid, {}).get("name", "Player"),
                    "text": text,
                    "timestamp": now_iso(),
                }
                dm_messages[key].append(msg)
                if len(dm_messages[key]) > 200:
                    dm_messages[key].pop(0)
                save_json(DM_FILE, dm_messages)

                # إرسال للطرف التاني
                ws_target = dm_connections.get(tid)
                if ws_target:
                    try:
                        await ws_target.send_json({"type": "dm", "message": msg})
                    except:
                        pass

                # إرسال ack للراسل
                await ws.send_json({"type": "dm_sent", "message": msg})
    except WebSocketDisconnect:
        dm_connections.pop(str(user_id), None)

# ============================================================
# 🎮 Server-side game validation / AI match recording
# ============================================================
def check_winner(board: list) -> Optional[str]:
    for a, b, c in ((0,1,2),(3,4,5),(6,7,8),(0,3,6),(1,4,7),(2,5,8),(0,4,8),(2,4,6)):
        if board[a] != " " and board[a] == board[b] == board[c]:
            return board[a]
    return None

def record_match(player_x: int, player_o: int, winner: str, moves: list, code: str = ""):
    if not player_x or not player_o or player_x == player_o:
        return False
    ux, uo = users.get(str(player_x)), users.get(str(player_o))
    if not ux or not uo:
        return False
    # Prevent duplicate finalization for the same room result.
    if code and any(m.get("room_code") == code for m in matches[-20:]):
        return False
    if winner == "X":
        ux["wins"] = ux.get("wins", 0) + 1; uo["losses"] = uo.get("losses", 0) + 1
        ux["points"] = ux.get("points", 0) + 60; ux["streak"] = ux.get("streak", 0) + 1
        uo["streak"] = 0
        ux["best_streak"] = max(ux.get("best_streak", 0), ux.get("streak", 0))
    elif winner == "O":
        uo["wins"] = uo.get("wins", 0) + 1; ux["losses"] = ux.get("losses", 0) + 1
        uo["points"] = uo.get("points", 0) + 60; uo["streak"] = uo.get("streak", 0) + 1
        ux["streak"] = 0
        uo["best_streak"] = max(uo.get("best_streak", 0), uo.get("streak", 0))
    elif winner == "draw":
        ux["draws"] = ux.get("draws", 0) + 1; uo["draws"] = uo.get("draws", 0) + 1
        ux["points"] = ux.get("points", 0) + 10; uo["points"] = uo.get("points", 0) + 10
    else:
        return False
    ux["games"] = ux.get("games", 0) + 1; uo["games"] = uo.get("games", 0) + 1
    match = {"player_x": player_x, "player_o": player_o, "winner": winner, "moves": list(moves or []), "mode": "online", "room_code": code, "timestamp": now_iso()}
    matches.append(match)
    if len(matches) > 5000: del matches[:-5000]
    save_users(); save_json(MATCHES_FILE, matches)
    return True

class RecordAIReq(BaseModel):
    user_id: int
    result: str
    moves: List[int]
    difficulty: str = "easy"

@app.post("/api/matches/record-ai")
async def record_ai(req: RecordAIReq, request: Request):
    user = require_owner(request, req.user_id)
    enforce_rate_limit(f"user:{req.user_id}", "game")
    if user.get("is_guest"):
        raise HTTPException(403, "الضيف مش بيكسب نقاط من مباريات البوت")
    if req.result not in ("win", "loss", "draw") or req.difficulty not in ("easy", "medium", "hard"):
        raise HTTPException(400, "بيانات المباراة غير صحيحة")
    if not isinstance(req.moves, list) or len(req.moves) < 5 or len(req.moves) > 9:
        raise HTTPException(400, "حركات المباراة غير صحيحة")
    if any(not isinstance(x, int) or x < 0 or x > 8 for x in req.moves) or len(set(req.moves)) != len(req.moves):
        raise HTTPException(400, "حركات المباراة غير قانونية")

    # Rebuild the board and verify the claimed result. This does not trust the client result.
    board = [" "] * 9
    terminal = None
    for i, move in enumerate(req.moves):
        if board[move] != " ": raise HTTPException(400, "حركة مكررة")
        board[move] = "X" if i % 2 == 0 else "O"
        terminal = check_winner(board)
        if terminal or i == len(req.moves) - 1 and " " not in board:
            break
    if terminal:
        actual = "win" if terminal == "X" else "loss"
    elif " " not in board:
        actual = "draw"
    else:
        raise HTTPException(400, "المباراة غير مكتملة")
    if actual != req.result:
        raise HTTPException(400, "نتيجة المباراة غير متطابقة")

    # Prevent the same exact finished game from being submitted repeatedly.
    signature = hashlib.sha256(f"ai|{req.user_id}|{req.difficulty}|{','.join(map(str, req.moves))}|{req.result}".encode()).hexdigest()
    if any(m.get("signature") == signature for m in matches[-200:]):
        raise HTTPException(409, "المباراة اتسجلت قبل كده")

    reward = {"easy": 20, "medium": 35, "hard": 60}[req.difficulty]
    if actual == "win":
        user["wins"] = user.get("wins", 0) + 1; user["points"] = user.get("points", 0) + reward; user["streak"] = user.get("streak", 0) + 1
        user["best_streak"] = max(user.get("best_streak", 0), user["streak"])
    elif actual == "loss":
        user["losses"] = user.get("losses", 0) + 1; user["streak"] = 0
    else:
        user["draws"] = user.get("draws", 0) + 1; user["points"] = user.get("points", 0) + 5
    user["games"] = user.get("games", 0) + 1
    matches.append({"player_x": req.user_id, "player_o": 0, "winner": "X" if actual == "win" else "O" if actual == "loss" else "draw", "moves": list(req.moves), "mode": f"ai_{req.difficulty}", "signature": signature, "timestamp": now_iso()})
    if len(matches) > 5000: del matches[:-5000]
    save_users(); save_json(MATCHES_FILE, matches)
    return {"success": True, "points": user.get("points", 0), "stats": {k: user.get(k, 0) for k in ("games","wins","losses","draws","streak","best_streak")}}

# ============================================================
# 📊 الإحصائيات والـ Leaderboard
# ============================================================
@app.get("/api/user/{user_id}/stats")
async def user_stats(user_id: int):
    uid = str(user_id)
    if uid not in users:
        raise HTTPException(404, "المستخدم غير موجود")
    u = users[uid]
    total = u.get("games", 0)
    wins = u.get("wins", 0)
    win_rate = round((wins / total * 100) if total > 0 else 0, 1)
    return {
        "user_id": user_id,
        "name": u.get("name"),
        "points": u.get("points", 0),
        "games": total,
        "wins": wins,
        "losses": u.get("losses", 0),
        "draws": u.get("draws", 0),
        "win_rate": win_rate,
        "streak": u.get("streak", 0),
        "best_streak": u.get("best_streak", 0),
        "role": get_role(u),
        "is_rare_id": is_rare_id(user_id),
    }

@app.get("/api/leaderboard")
async def leaderboard(limit: int = 20):
    sorted_users = sorted(
        users.values(),
        key=lambda u: (u.get("points", 0), u.get("wins", 0)),
        reverse=True
    )[:limit]
    return [
        {
            "rank": i + 1,
            "id": u["id"],
            "name": u.get("name", "Player"),
            "username": u.get("username", ""),
            "points": u.get("points", 0),
            "wins": u.get("wins", 0),
            "games": u.get("games", 0),
            "role": get_role(u),
            "is_rare_id": is_rare_id(u["id"]),
            "avatar": u.get("avatar", "👤"),
        }
        for i, u in enumerate(sorted_users)
    ]

@app.get("/api/leaderboard/vip")
async def leaderboard_vip(limit: int = 20):
    """Leaderboard للـ VIP فقط"""
    vips = [u for u in users.values() if is_vip(u)]
    vips.sort(key=lambda u: u.get("points", 0), reverse=True)
    return [
        {
            "rank": i + 1,
            "id": u["id"],
            "name": u.get("name", ""),
            "points": u.get("points", 0),
            "wins": u.get("wins", 0),
            "role": get_role(u),
        }
        for i, u in enumerate(vips[:limit])
    ]

@app.get("/api/leaderboard/rare-ids")
async def leaderboard_rare_ids(limit: int = 20):
    """أصحاب الأرقام النادرة"""
    rares = [u for u in users.values() if is_rare_id(u["id"])]
    rares.sort(key=lambda u: u.get("points", 0), reverse=True)
    return [
        {
            "rank": i + 1,
            "id": u["id"],
            "name": u.get("name", ""),
            "points": u.get("points", 0),
            "wins": u.get("wins", 0),
        }
        for i, u in enumerate(rares[:limit])
    ]

@app.get("/api/matches/recent")
async def recent_matches(limit: int = 20):
    return matches[-limit:][::-1]

@app.get("/api/user/{user_id}/matches")
async def user_matches(user_id: int, limit: int = 30):
    result = []
    for m in reversed(matches):
        if m["player_x"] == user_id or m["player_o"] == user_id:
            result.append(m)
            if len(result) >= limit:
                break
    return result

# ============================================================
# 🏠 الصفحة الرئيسية + Health
# ============================================================
@app.get("/", response_class=HTMLResponse)
async def root():
    for path in ["index.html", "static/index.html"]:
        f = Path(path)
        if f.exists():
            return f.read_text(encoding="utf-8")
    return "<h1>XO Server v4.0</h1><p>index.html not found</p>"

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "version": "4.0",
        "users": len(users),
        "registered": sum(1 for u in users.values() if u.get("is_registered")),
        "vips": sum(1 for u in users.values() if is_vip(u) and not is_king(u)),
        "rooms": len(rooms),
        "matches": len(matches),
        "timestamp": now_iso(),
    }

# ============================================================
# 🧹 تنظيف الضيوف المنتهيين (يشتغل تلقائي)
# ============================================================
@app.on_event("startup")
async def cleanup_guests():
    """يشيل الضيوف اللي انتهى وقتهم"""
    now = datetime.utcnow()
    to_remove = []
    for uid, u in users.items():
        if u.get("is_guest") and u.get("guest_expires"):
            try:
                if datetime.fromisoformat(u["guest_expires"]) < now:
                    to_remove.append(uid)
            except:
                pass
    for uid in to_remove:
        del users[uid]
    if to_remove:
        save_users()
    print(f"✅ Server v4.0 ready — King: {KING_EMAIL}")

@app.on_event("shutdown")
async def on_shutdown():
    save_users()
    save_json(SESSIONS_FILE, sessions)
    save_json(FRIENDS_FILE, friendships)
    save_json(DM_FILE, dm_messages)
    save_json(REWARDS_FILE, rewards_log)
    print("💾 Data saved.")
