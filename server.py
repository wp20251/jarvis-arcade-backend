"""Jarvis Arcade Backend.
Run:  pip install fastapi "uvicorn[standard]"   then   python server.py
Env:  ALLOWED_ORIGINS=https://f0d829-3.myshopify.com,https://www.your-store.com
                                  (every address your store is opened on, comma-separated; default * for testing)
      ARENA_DB=arena.db           (SQLite file, keep it on a persistent disk)
      SHOPIFY_SECRET=  (same value as in the theme snippet; turns on "Sign in with your store account")
      BLOCKED_NAMES=word1,word2   (optional: usernames containing any of these are refused)
"""
import asyncio, hashlib, hmac, json, os, re, secrets, sqlite3, uuid
from typing import Optional
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Load a local .env for development without replacing variables supplied by the
# deployment host (Render environment variables take precedence).
load_dotenv(override=False)

ORIGINS = [o.strip().rstrip("/") for o in os.getenv("ALLOWED_ORIGINS", "*").split(",") if o.strip()] or ["*"]
SHOP_SECRET = os.getenv("SHOPIFY_SECRET", "").strip()
BLOCKED = [w.strip().lower() for w in os.getenv("BLOCKED_NAMES", "").split(",") if w.strip()]
NEED = {"1v1": 2, "2v2": 4, "4v4": 8}
GAMES = {"asteroid_miner", "neon_racer", "grid_defender", "cyber_hacker", "word_vault"}
MAX_PER_LEVEL = 9000          # scores above level * this are clamped (basic anti-cheat)
NAME_RE = re.compile(r"[A-Za-z0-9_]{3,16}")
# Clearly-labeled house bots: score targets so the board is never empty.
HOUSE = [{"name": "CyberAce", "score": 4500, "wins": 52, "bot": True},
         {"name": "NeonViper", "score": 12400, "wins": 110, "bot": True},
         {"name": "JarvisMaster", "score": 25000, "wins": 215, "bot": True}]
RESERVED = {h["name"].lower() for h in HOUSE}

app = FastAPI(title="Jarvis Arcade Backend")
app.add_middleware(CORSMiddleware, allow_origins=ORIGINS, allow_methods=["*"], allow_headers=["*"])

@app.get("/healthz")
def healthz():
    """Health probe used by Render; do not expose configuration or secrets."""
    return {"ok": True}

db = sqlite3.connect(os.getenv("ARENA_DB", "arena.db"), check_same_thread=False)
db.executescript("""
CREATE TABLE IF NOT EXISTS users(name TEXT PRIMARY KEY COLLATE NOCASE, salt BLOB, pw BLOB,
  score INTEGER DEFAULT 0, wins INTEGER DEFAULT 0, games INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS tokens(token TEXT PRIMARY KEY, name TEXT);""")
try:    # sid = the Shopify customer id a player is linked to (older databases get the column added here)
    db.execute("ALTER TABLE users ADD COLUMN sid TEXT")
except sqlite3.OperationalError:
    pass
db.execute("CREATE UNIQUE INDEX IF NOT EXISTS users_sid ON users(sid)")
db.commit()

def hash_pw(pw: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000)

def issue(name: str) -> dict:
    token = secrets.token_urlsafe(24)
    db.execute("INSERT INTO tokens VALUES(?,?)", (token, name))
    # keep only each player's 5 newest sessions so the table can't grow forever
    db.execute("DELETE FROM tokens WHERE name=? AND rowid NOT IN "
               "(SELECT rowid FROM tokens WHERE name=? ORDER BY rowid DESC LIMIT 5)", (name, name))
    db.commit()
    return {"token": token, "username": name}

def name_problem(name: str):
    """Error message if this leaderboard name can't be used, else None."""
    if not NAME_RE.fullmatch(name):
        return "Username must be 3-16 letters, numbers or underscores"
    low = name.lower()
    if low in RESERVED or any(w in low for w in BLOCKED):
        return "That username isn't available"
    return None

class Cred(BaseModel):
    username: str
    password: str

class Shop(BaseModel):
    id: str
    sig: str
    username: Optional[str] = None

@app.post("/api/register")
def register(c: Cred):
    bad = name_problem(c.username)
    if bad:
        raise HTTPException(400, bad)
    if len(c.password) < 6:
        raise HTTPException(400, "Password must be at least 6 characters")
    salt = secrets.token_bytes(16)
    try:
        db.execute("INSERT INTO users(name,salt,pw) VALUES(?,?,?)", (c.username, salt, hash_pw(c.password, salt)))
    except sqlite3.IntegrityError:
        db.rollback()
        raise HTTPException(409, "That username is taken")
    db.commit()
    return issue(c.username)

@app.post("/api/login")
def login(c: Cred):
    row = db.execute("SELECT name,salt,pw FROM users WHERE name=?", (c.username,)).fetchone()
    # accounts made through the store login have no password (salt/pw are NULL) and can't be used here
    if not row or row[1] is None or row[2] is None or not hmac.compare_digest(row[2], hash_pw(c.password, row[1])):
        raise HTTPException(401, "Wrong username or password")
    return issue(row[0])

def shop_sig(customer_id: str) -> str:
    # Identical to Liquid's  {{ customer.id | hmac_sha256: 'SECRET' }}  (lowercase hex)
    return hmac.new(SHOP_SECRET.encode(), customer_id.encode(), hashlib.sha256).hexdigest()

@app.post("/api/shopify")
def shopify_login(s: Shop):
    """Sign in with a store (Shopify) account.
    The theme snippet sends the logged-in customer's id plus a signature only the store can produce,
    so nobody can pose as someone else by editing the page in their browser."""
    if not SHOP_SECRET:
        raise HTTPException(503, "Store login isn't switched on for this server yet")
    if not re.fullmatch(r"[0-9]{1,20}", s.id) or not hmac.compare_digest(shop_sig(s.id).encode(), s.sig.strip().lower().encode()):
        raise HTTPException(401, "We couldn't verify your store login. Please sign in again.")
    row = db.execute("SELECT name FROM users WHERE sid=?", (s.id,)).fetchone()
    if row:                                   # already picked a leaderboard name: just sign them in
        return issue(row[0])
    if not s.username:                        # first visit: the page asks them to choose a name
        return {"need_username": True}
    bad = name_problem(s.username)
    if bad:
        raise HTTPException(400, bad)
    try:
        db.execute("INSERT INTO users(name,sid) VALUES(?,?)", (s.username, s.id))
        db.commit()
    except sqlite3.IntegrityError:
        db.rollback()
        row = db.execute("SELECT name FROM users WHERE sid=?", (s.id,)).fetchone()   # double-click: already created a moment ago
        if row:
            return issue(row[0])
        raise HTTPException(409, "That username is taken")
    return issue(s.username)

def board(limit: int = 25):
    rows = [{"name": n, "score": s, "wins": w, "bot": False} for n, s, w in
            db.execute("SELECT name,score,wins FROM users WHERE games>0 ORDER BY score DESC LIMIT ?", (limit,))]
    return sorted(rows + HOUSE, key=lambda r: -r["score"])[:limit]

@app.get("/api/leaderboard")
def leaderboard():
    return {"rows": board()}

# ---------------- live play ----------------
conns: dict = {}      # WebSocket -> player dict
queues: dict = {}     # (game, level, mode) -> [WebSocket]
matches: dict = {}    # match_id -> match dict

async def send(ws, obj):
    try: await ws.send_json(obj)
    except Exception: pass

async def push_all(obj):
    await asyncio.gather(*[send(w, obj) for w in list(conns)])

def leave_queue(ws):
    me = conns.get(ws)
    if me and me["queue"]:
        q = queues.get(me["queue"], [])
        if ws in q: q.remove(ws)
        me["queue"] = None

async def settle(mid):
    m = matches.pop(mid, None)
    if not m: return
    best = max(m["scores"].values(), default=0)
    for p in m["players"]:
        sc = m["scores"].get(p["id"], 0)
        if p["reg"] and sc > 0:
            won = len(m["players"]) > 1 and sc == best
            db.execute("UPDATE users SET score=score+?,wins=wins+?,games=games+1 WHERE name=?", (sc, int(won), p["name"]))
    db.commit()
    await push_all({"type": "leaderboard", "rows": board()})

async def maybe_settle(mid):
    m = matches.get(mid)
    if m and all(p["done"] or p["gone"] for p in m["players"]): await settle(mid)

async def settle_later(mid):
    await asyncio.sleep(75)
    await settle(mid)

def clamp(v, level):
    try: return max(0, min(int(v), MAX_PER_LEVEL * level))
    except Exception: return 0

async def handle(ws, me, d):
    t = d.get("type")
    if t == "join_queue":
        leave_queue(ws)
        game, mode = d.get("game"), d.get("mode")
        try: level = int(d.get("level"))
        except Exception: return
        if game not in GAMES or mode not in NEED or not 1 <= level <= 10: return
        key = (game, level, mode)
        queues.setdefault(key, []).append(ws); me["queue"] = key
        q = queues[key]
        if len(q) >= NEED[mode]:
            group = [q.pop(0) for _ in range(NEED[mode])]
            mid = uuid.uuid4().hex[:12]
            players = [conns[w] for w in group if w in conns]
            matches[mid] = {"players": players, "scores": {}, "level": level}
            for p in players: p["queue"], p["match"], p["done"], p["gone"] = None, mid, False, False
            msg = {"type": "matched", "match_id": mid, "players": [{"id": p["id"], "name": p["name"]} for p in players]}
            await asyncio.gather(*[send(w, msg) for w in group])
            asyncio.create_task(settle_later(mid))
    elif t == "leave_queue":
        leave_queue(ws)
    elif t in ("score", "finish"):
        m = matches.get(me.get("match"))
        if not m or d.get("match_id") != me["match"]: return
        m["scores"][me["id"]] = clamp(d.get("score"), m["level"])
        if t == "finish":
            me["done"] = True
            await maybe_settle(me["match"])
        else:
            msg = {"type": "scores", "match_id": me["match"], "scores": m["scores"]}
            await asyncio.gather(*[send(w, msg) for w, p in conns.items() if p.get("match") == me["match"]])
    elif t == "solo_finish" and me["reg"]:      # ranked run vs bots: counts for score, not wins
        db.execute("UPDATE users SET score=score+?,games=games+1 WHERE name=?",
                   (clamp(d.get("score"), min(max(int(d.get("level", 1) or 1), 1), 10)), me["name"]))
        db.commit()
        await push_all({"type": "leaderboard", "rows": board()})

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket, token: str = ""):
    await ws.accept()
    row = db.execute("SELECT name FROM tokens WHERE token=?", (token,)).fetchone() if token else None
    guest = "Guest-" + secrets.token_hex(2)
    me = {"id": row[0] if row else "guest_" + secrets.token_hex(4), "name": row[0] if row else guest,
          "reg": bool(row), "queue": None, "match": None, "done": False, "gone": False}
    conns[ws] = me
    await send(ws, {"type": "hello", "id": me["id"], "name": me["name"], "reg": me["reg"]})
    await send(ws, {"type": "leaderboard", "rows": board()})
    await push_all({"type": "online", "count": len(conns)})
    try:
        while True:
            try: d = json.loads(await ws.receive_text())
            except json.JSONDecodeError: continue
            if isinstance(d, dict): await handle(ws, me, d)
    except WebSocketDisconnect:
        pass
    finally:
        leave_queue(ws); me["gone"] = True; conns.pop(ws, None)
        if me.get("match"): await maybe_settle(me["match"])
        await push_all({"type": "online", "count": len(conns)})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
