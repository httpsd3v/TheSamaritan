import os
import re
import io
import uuid
import json
import time
import jwt
from functools import wraps
from datetime import datetime, timezone, timedelta

from flask import Flask, render_template, request, session, jsonify, send_from_directory

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

from supabase import create_client, Client

try:
    from pywebpush import webpush, WebPushException
except ImportError:
    webpush = None
    WebPushException = Exception

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")
app.config["MAX_CONTENT_LENGTH"] = 12 * 1024 * 1024
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)
if os.environ.get("RENDER") == "true":
    app.config["SESSION_COOKIE_SECURE"] = True

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY") or os.environ.get("SUPABASE_KEY")
SUPABASE_SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY") or os.environ.get("SUPABASE_KEY")

DOMAIN = "@samaritan.app"
USERNAME_RE = re.compile(r"^[a-z0-9_.]{3,30}$")
STORAGE_BUCKET = os.environ.get("SUPABASE_STORAGE_BUCKET", "media")
MAX_MEDIA_BYTES = 8 * 1024 * 1024
ALLOWED_MIME = {
    "image/png": "png",
    "image/jpeg": "jpg",
    "image/webp": "webp",
    "image/gif": "gif",
}

VAPID_PUBLIC_KEY = os.environ.get("VAPID_PUBLIC_KEY", "")
VAPID_PRIVATE_KEY = os.environ.get("VAPID_PRIVATE_KEY", "")
VAPID_CLAIMS_EMAIL = os.environ.get("VAPID_CLAIMS_EMAIL", "mailto:admin@samaritan.app")

# Voice (LiveKit) - tokens generated with pure PyJWT for zero SDK errors
LIVEKIT_URL = os.environ.get("LIVEKIT_URL", "")
LIVEKIT_API_KEY = os.environ.get("LIVEKIT_API_KEY", "")
LIVEKIT_API_SECRET = os.environ.get("LIVEKIT_API_SECRET", "")

VOICE_ROOMS = [
    {"id": "lounge", "name": "The Lounge"},
    {"id": "debate", "name": "The Debate"},
    {"id": "study", "name": "The Study"},
    {"id": "music", "name": "The Music Room"},
    {"id": "latenight", "name": "Late Night"},
]


def normalize_username(raw):
    return (raw or "").strip().lower()


def _admin_variants(name):
    n = normalize_username(name)
    return {n, n.rstrip(".")}


ADMIN_USERNAMES = set()
for _x in os.environ.get("ADMIN_USERNAMES", "").split(","):
    if _x.strip():
        ADMIN_USERNAMES.update(_admin_variants(_x))


def is_admin_username(username):
    return bool(_admin_variants(username or "") & ADMIN_USERNAMES)


if not SUPABASE_URL or not SUPABASE_ANON_KEY or not SUPABASE_SERVICE_ROLE_KEY:
    raise RuntimeError("Missing Supabase environment variables.")

auth_client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
db = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)


# --------------------------------------------------------------------------
# Core helpers
# --------------------------------------------------------------------------
def ok(**kwargs):
    kwargs["ok"] = True
    return jsonify(kwargs)


def err(message, status=400):
    return jsonify({"ok": False, "error": message}), status


def get_ban_remaining(profile):
    bu = (profile or {}).get("banned_until")
    if not bu:
        return None
    try:
        until = datetime.fromisoformat(str(bu).replace("Z", "+00:00"))
    except Exception:
        return None
    now = datetime.now(timezone.utc)
    if until <= now:
        return None
    return until - now


def ban_message(rem):
    total_minutes = int(rem.total_seconds() // 60)
    h, m = divmod(total_minutes, 60)
    if h > 0:
        return f"You are banned. Try again in {h}h {m}m."
    return f"You are banned. Try again in {m}m."


def login_required_api(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        uid = session.get("user_id")
        if not uid:
            return err("Not signed in.", 401)
        prof = get_profile(uid)
        if prof:
            rem = get_ban_remaining(prof)
            if rem is not None:
                session.clear()
                return err(ban_message(rem), 403)
        return f(*args, **kwargs)
    return decorated


def require_admin():
    if not is_admin_username(session.get("username", "")):
        return err("Forbidden.", 403)
    return None


def authenticate(username, password):
    email = f"{username}{DOMAIN}"
    res = auth_client.auth.sign_in_with_password({"email": email, "password": password})
    user = getattr(res, "user", None) or getattr(getattr(res, "session", None), "user", None)
    if not user:
        raise Exception("Supabase did not return a user object.")
    session["user_id"] = user.id
    session["username"] = username
    ensure_profile(user.id, username)
    return user


def ensure_profile(uid, uname):
    if not uid or not uname:
        return
    try:
        db.table("profiles").upsert({"id": uid, "username": uname}, on_conflict="id").execute()
    except Exception as e:
        app.logger.error(f"ensure_profile failed: {e}")


def get_profile(uid):
    try:
        r = db.table("profiles").select("*").eq("id", uid).limit(1).execute()
        if not r.data:
            return None
        p = r.data[0]
        p.setdefault("id", uid)
        p.setdefault("username", "unknown")
        p.setdefault("bio", "")
        p.setdefault("verified", False)
        p.setdefault("avatar_url", "")
        p.setdefault("banned_until", None)
        return p
    except Exception as e:
        app.logger.error(f"get_profile failed: {e}")
        return None


def username_exists(uname):
    try:
        return bool(db.table("profiles").select("id").eq("username", uname).limit(1).execute().data)
    except Exception:
        return False


def count_rows(table, col, val):
    try:
        return db.table(table).select("id", count="exact").eq(col, val).execute().count or 0
    except Exception:
        return 0


def get_blocked_ids(user_id):
    try:
        res = db.table("blocks").select("blocked_id").eq("blocker_id", user_id).execute()
        return [r["blocked_id"] for r in res.data or []]
    except Exception:
        return []


def upload_file(f, folder):
    if not f:
        return None
    mime = f.mimetype or ""
    ext = ALLOWED_MIME.get(mime)
    if not ext and "." in (f.filename or ""):
        fe = f.filename.rsplit(".", 1)[-1].lower()
        ext = {"jpg": "jpg", "jpeg": "jpg", "png": "png", "webp": "webp", "gif": "gif"}.get(fe)
        mime = f"image/{ext}" if ext else mime
    if not ext:
        raise ValueError("Only PNG, JPG, WEBP, or GIF allowed.")
    data = f.read()
    if len(data) > MAX_MEDIA_BYTES:
        raise ValueError("File too large. Max 8 MB.")
    path = f"{folder}/{uuid.uuid4()}.{ext}"
    try:
        try:
            db.storage.from_(STORAGE_BUCKET).upload(path, data, {"content-type": mime})
        except TypeError:
            db.storage.from_(STORAGE_BUCKET).upload(path, io.BytesIO(data), {"content-type": mime})
        return db.storage.from_(STORAGE_BUCKET).get_public_url(path)
    except ValueError:
        raise
    except Exception as e:
        app.logger.error(f"Storage upload failed: {e}")
        raise ValueError(f"Media upload failed: {e}")


def delete_media(url):
    if not url or STORAGE_BUCKET not in url:
        return
    try:
        p = url.split(f"/{STORAGE_BUCKET}/", 1)[1].split("?", 1)[0]
        if p:
            db.storage.from_(STORAGE_BUCKET).remove([p])
    except Exception as e:
        app.logger.error(f"Media delete failed: {e}")


def delete_user_data(uid):
    posts = db.table("posts").select("id").eq("user_id", uid).execute().data or []
    pids = [r["id"] for r in posts if r.get("id")]
    if pids:
        db.table("comments").delete().in_("post_id", pids).execute()
        db.table("likes").delete().in_("post_id", pids).execute()
    db.table("comments").delete().eq("user_id", uid).execute()
    db.table("likes").delete().eq("user_id", uid).execute()
    db.table("follows").delete().eq("follower_id", uid).execute()
    db.table("follows").delete().eq("following_id", uid).execute()
    db.table("posts").delete().eq("user_id", uid).execute()
    db.table("profiles").delete().eq("id", uid).execute()


# --------------------------------------------------------------------------
# Serializers
# --------------------------------------------------------------------------
def serialize_profile(r):
    r = r or {}
    return {
        "id": r.get("id"),
        "username": r.get("username", "unknown"),
        "bio": r.get("bio", ""),
        "verified": bool(r.get("verified", False)),
        "avatar_url": r.get("avatar_url", ""),
        "banned_until": r.get("banned_until"),
    }


def serialize_post(r, liked_ids=None, like_counts=None, comment_counts=None):
    liked_ids = liked_ids or set()
    like_counts = like_counts or {}
    comment_counts = comment_counts or {}
    pid = r.get("id")
    prof = r.get("profiles")
    if isinstance(prof, list):
        prof = prof[0] if prof else None
    author = serialize_profile(prof) if prof else {"id": None, "username": "deleted", "verified": False, "avatar_url": ""}
    return {
        "id": pid,
        "content": r.get("content", ""),
        "media_url": r.get("image_url") or r.get("media_url") or "",
        "created_at": r.get("created_at"),
        "author": author,
        "likes": like_counts.get(pid, 0),
        "liked": pid in liked_ids,
        "comments": comment_counts.get(pid, 0),
    }


def serialize_comment(r):
    prof = r.get("profiles")
    if isinstance(prof, list):
        prof = prof[0] if prof else None
    author = serialize_profile(prof) if prof else {"id": None, "username": "deleted", "verified": False, "avatar_url": ""}
    return {
        "id": r.get("id"),
        "post_id": r.get("post_id"),
        "parent_comment_id": r.get("parent_comment_id"),
        "content": r.get("content", ""),
        "created_at": r.get("created_at"),
        "author": author,
    }


def hydrate_posts(posts):
    pids = [p.get("id") for p in posts if p.get("id")]
    lc = {pid: 0 for pid in pids}
    cc = {pid: 0 for pid in pids}
    liked = set()
    if pids:
        try:
            for r in db.table("likes").select("post_id").in_("post_id", pids).execute().data or []:
                if r.get("post_id") in lc:
                    lc[r["post_id"]] += 1
        except Exception:
            pass
        try:
            for r in db.table("comments").select("post_id").in_("post_id", pids).execute().data or []:
                if r.get("post_id") in cc:
                    cc[r["post_id"]] += 1
        except Exception:
            pass
        try:
            liked = {
                r.get("post_id")
                for r in db.table("likes").select("post_id").eq("user_id", session.get("user_id")).in_("post_id", pids).execute().data or []
                if r.get("post_id")
            }
        except Exception:
            pass
    return [serialize_post(p, liked, lc, cc) for p in posts]


# --------------------------------------------------------------------------
# Notifications
# --------------------------------------------------------------------------
def create_notification(user_id, actor_id, type_, post_id=None, comment_id=None):
    if not user_id or user_id == actor_id:
        return
    try:
        db.table("notifications").insert({
            "user_id": user_id,
            "actor_id": actor_id,
            "type": type_,
            "post_id": post_id,
            "comment_id": comment_id,
            "read": False,
        }).execute()
    except Exception as e:
        app.logger.error(f"create_notification failed: {e}")


def notify_user(user_id, title, body, url="/"):
    if not VAPID_PRIVATE_KEY or not webpush:
        return
    try:
        subs = db.table("push_subscriptions").select("*").eq("user_id", user_id).execute().data or []
        payload = json.dumps({"title": title, "body": body, "url": url})
        dead = []
        for s in subs:
            try:
                webpush(
                    {"endpoint": s["endpoint"], "keys": {"p256dh": s["p256dh"], "auth": s["auth"]}},
                    data=payload,
                    vapid_private_key=VAPID_PRIVATE_KEY,
                    vapid_claims={"sub": VAPID_CLAIMS_EMAIL},
                )
            except WebPushException as e:
                status = getattr(getattr(e, "response", None), "status_code", None)
                app.logger.error(f"webpush failed for sub {s.get('id')}: status={status}")
                if status in (400, 401, 403, 404, 410):
                    dead.append(s.get("id"))
        for sid in dead:
            db.table("push_subscriptions").delete().eq("id", sid).execute()
    except Exception as e:
        app.logger.error(f"notify_user failed: {e}")


# --------------------------------------------------------------------------
# Auth routes
# --------------------------------------------------------------------------
@app.route("/api/me")
def api_me():
    if not session.get("user_id"):
        return ok(authenticated=False)
    p = get_profile(session["user_id"])
    if p:
        if get_ban_remaining(p) is not None:
            session.clear()
            return ok(authenticated=False)
    else:
        p = {
            "id": session["user_id"],
            "username": session.get("username", "unknown"),
            "bio": "",
            "verified": False,
            "avatar_url": "",
            "banned_until": None,
        }
        ensure_profile(p["id"], p["username"])
    return ok(
        authenticated=True,
        user={"id": session["user_id"], "username": p["username"]},
        profile=serialize_profile(p),
        is_admin=is_admin_username(p["username"]),
    )


@app.route("/api/signin", methods=["POST"])
def api_signin():
    d = request.get_json(silent=True) or {}
    u, pw = normalize_username(d.get("username", "")), d.get("password", "")
    if not u or not pw:
        return err("Username and password are required.")
    try:
        r = db.table("profiles").select("*").eq("username", u).limit(1).execute()
        prof = r.data[0] if r.data else None
    except Exception:
        prof = None
    if prof:
        rem = get_ban_remaining(prof)
        if rem is not None:
            return err(ban_message(rem), 403)
    try:
        authenticate(u, pw)
    except Exception as e:
        app.logger.error(f"Signin error: {e}")
        return err("Invalid credentials.", 401)
    return ok(
        user={"id": session["user_id"], "username": u},
        profile=serialize_profile(get_profile(session["user_id"])),
        is_admin=is_admin_username(u),
    )


@app.route("/api/signup", methods=["POST"])
def api_signup():
    d = request.get_json(silent=True) or {}
    u, pw = normalize_username(d.get("username", "")), d.get("password", "")
    if not u or not pw:
        return err("Username and password are required.")
    if not USERNAME_RE.match(u):
        return err("Invalid username format.")
    if len(pw) < 6:
        return err("Password must be 6+ chars.")
    if username_exists(u):
        return err("Username taken.")
    try:
        c = db.auth.admin.create_user({
            "email": f"{u}{DOMAIN}",
            "password": pw,
            "email_confirm": True,
            "user_metadata": {"username": u},
        })
        uid = getattr(getattr(c, "user", c), "id", None)
        ensure_profile(uid, u)
        authenticate(u, pw)
        return ok(
            user={"id": uid, "username": u},
            profile=serialize_profile(get_profile(uid)),
            is_admin=is_admin_username(u),
        )
    except Exception as e:
        m = str(e).lower()
        app.logger.error(f"Signup error: {e}")
        if "already" in m or "duplicate" in m:
            return err("Username taken.")
        if "password" in m:
            return err("Password too short.")
        return err("Signup failed.")


@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.pop("user_id", None)
    session.pop("username", None)
    return ok()


# --------------------------------------------------------------------------
# Feed / posts
# --------------------------------------------------------------------------
@app.route("/api/feed")
@login_required_api
def api_feed():
    try:
        limit = max(1, min(int(request.args.get("limit", 30)), 50))
    except Exception:
        limit = 30
    cursor = request.args.get("cursor")
    blocked_ids = get_blocked_ids(session["user_id"])
    try:
        q = db.table("posts").select("*, profiles(*)").order("created_at", desc=True).limit(limit)
        if cursor:
            q = q.lt("created_at", cursor)
        if blocked_ids:
            q = q.not_.in_("user_id", blocked_ids)
        posts = q.execute().data or []
        return ok(posts=hydrate_posts(posts), has_more=len(posts) == limit)
    except Exception as e:
        app.logger.error(f"Feed failed: {e}")
        return err("Could not load feed.", 500)


@app.route("/api/posts", methods=["POST"])
@login_required_api
def api_create_post():
    content = (request.form.get("content") or "").strip()[:1000]
    media_url = None
    if request.files.get("media"):
        try:
            media_url = upload_file(request.files["media"], "posts")
        except ValueError as e:
            return err(str(e))
    if not content and not media_url:
        return err("Post cannot be empty.")
    try:
        r = db.table("posts").insert({
            "user_id": session["user_id"],
            "content": content,
            "image_url": media_url,
        }).execute()
        post = r.data[0] if r.data else db.table("posts").select("*").eq("user_id", session["user_id"]).order("created_at", desc=True).limit(1).execute().data[0]
        post["profiles"] = get_profile(session["user_id"])
        return ok(post=serialize_post(post, set(), {post.get("id"): 0}, {post.get("id"): 0}))
    except Exception as e:
        app.logger.error(f"Create post failed: {e}")
        return err("Could not create post.", 500)


@app.route("/api/posts/<pid>/like", methods=["POST"])
@login_required_api
def api_toggle_like(pid):
    try:
        ex = db.table("likes").select("id").eq("user_id", session["user_id"]).eq("post_id", pid).limit(1).execute().data
        if ex:
            db.table("likes").delete().eq("id", ex[0]["id"]).execute()
            liked = False
        else:
            db.table("likes").insert({"user_id": session["user_id"], "post_id": pid}).execute()
            liked = True
        return ok(liked=liked, likes=count_rows("likes", "post_id", pid))
    except Exception as e:
        app.logger.error(f"Like failed: {e}")
        return err("Could not update like.", 500)


@app.route("/api/posts/<pid>/delete", methods=["POST"])
@login_required_api
def api_delete_post(pid):
    try:
        post = db.table("posts").select("*").eq("id", pid).limit(1).execute().data[0]
    except Exception:
        return err("Post not found.", 404)
    if post.get("user_id") != session["user_id"] and not is_admin_username(session.get("username", "")):
        return err("Forbidden.", 403)
    try:
        db.table("comments").delete().eq("post_id", pid).execute()
        db.table("likes").delete().eq("post_id", pid).execute()
        db.table("posts").delete().eq("id", pid).execute()
        delete_media(post.get("image_url") or post.get("media_url"))
        return ok()
    except Exception as e:
        app.logger.error(f"Delete post failed: {e}")
        return err("Could not delete.", 500)


@app.route("/api/posts/<pid>/comments", methods=["GET", "POST"])
@login_required_api
def api_comments(pid):
    if request.method == "GET":
        try:
            owner = db.table("posts").select("user_id").eq("id", pid).limit(1).execute().data
            owner_id = owner[0].get("user_id") if owner else None
            comments = db.table("comments").select("*, profiles(*)").eq("post_id", pid).order("created_at", desc=False).limit(200).execute().data or []
            out = []
            for c in comments:
                item = serialize_comment(c)
                item["post_author_id"] = owner_id
                out.append(item)
            return ok(comments=out)
        except Exception as e:
            app.logger.error(f"Comments fetch failed: {e}")
            return err("Could not load comments.", 500)

    d = request.get_json(silent=True) or {}
    content = (d.get("content") or "").strip()[:500]
    parent = d.get("parent_id")
    if not content:
        return err("Comment cannot be empty.")
    try:
        owner = db.table("posts").select("user_id").eq("id", pid).limit(1).execute().data
        owner_id = owner[0].get("user_id") if owner else None
        r = db.table("comments").insert({
            "user_id": session["user_id"],
            "post_id": pid,
            "content": content,
            "parent_comment_id": parent,
        }).execute()
        c = r.data[0] if r.data else None
        if not c:
            return err("Could not add comment.", 500)
        c["profiles"] = get_profile(session["user_id"])
        out = serialize_comment(c)
        out["post_author_id"] = owner_id

        if owner_id and owner_id != session["user_id"]:
            actor = get_profile(session["user_id"]) or {}
            create_notification(owner_id, session["user_id"], "reply", pid, c.get("id"))
            notify_user(owner_id, f"@{actor.get('username', 'Someone')} replied", content[:100])

        return ok(comment=out)
    except Exception as e:
        app.logger.error(f"Comment create failed: {e}")
        return err("Could not add comment.", 500)


@app.route("/api/comments/<cid>/delete", methods=["POST"])
@login_required_api
def api_delete_comment(cid):
    try:
        c = db.table("comments").select("*").eq("id", cid).limit(1).execute().data[0]
    except Exception:
        return err("Comment not found.", 404)
    try:
        p = db.table("posts").select("user_id").eq("id", c.get("post_id")).limit(1).execute().data
        p_owner = p[0].get("user_id") if p else None
    except Exception:
        p_owner = None
    if c.get("user_id") != session["user_id"] and p_owner != session["user_id"] and not is_admin_username(session.get("username", "")):
        return err("Forbidden.", 403)
    try:
        db.table("comments").delete().eq("id", cid).execute()
        return ok()
    except Exception as e:
        app.logger.error(f"Delete comment failed: {e}")
        return err("Could not delete.", 500)


@app.route("/api/posts/<pid>/report", methods=["POST"])
@login_required_api
def api_report_post(pid):
    d = request.get_json(silent=True) or {}
    reason = (d.get("reason") or "").strip()[:500]
    if not reason:
        return err("Reason required.")
    try:
        if not db.table("posts").select("id").eq("id", pid).limit(1).execute().data:
            return err("Post not found.", 404)
        db.table("reports").insert({
            "reporter_id": session["user_id"],
            "post_id": pid,
            "comment_id": None,
            "reason": reason,
            "status": "open",
        }).execute()
        return ok()
    except Exception as e:
        app.logger.error(f"Report post failed: {e}")
        return err("Could not report.", 500)


@app.route("/api/comments/<cid>/report", methods=["POST"])
@login_required_api
def api_report_comment(cid):
    d = request.get_json(silent=True) or {}
    reason = (d.get("reason") or "").strip()[:500]
    if not reason:
        return err("Reason required.")
    try:
        if not db.table("comments").select("id").eq("id", cid).limit(1).execute().data:
            return err("Comment not found.", 404)
        db.table("reports").insert({
            "reporter_id": session["user_id"],
            "post_id": None,
            "comment_id": cid,
            "reason": reason,
            "status": "open",
        }).execute()
        return ok()
    except Exception as e:
        app.logger.error(f"Report comment failed: {e}")
        return err("Could not report.", 500)


# --------------------------------------------------------------------------
# Account
# --------------------------------------------------------------------------
@app.route("/api/account/password", methods=["POST"])
@login_required_api
def api_change_password():
    d = request.get_json(silent=True) or {}
    cur, new = d.get("current_password", ""), d.get("new_password", "")
    if not cur or not new:
        return err("Both passwords required.")
    if len(new) < 6:
        return err("New password too short.")
    try:
        auth_client.auth.sign_in_with_password({"email": f"{session['username']}{DOMAIN}", "password": cur})
    except Exception:
        return err("Current password incorrect.", 403)
    try:
        db.auth.admin.update_user_by_id(session["user_id"], {"password": new})
        return ok()
    except Exception as e:
        app.logger.error(f"Password change failed: {e}")
        return err("Could not change password.", 500)


@app.route("/api/account/delete", methods=["POST"])
@login_required_api
def api_delete_account():
    d = request.get_json(silent=True) or {}
    pw = d.get("password", "")
    if not pw:
        return err("Password required.")
    try:
        auth_client.auth.sign_in_with_password({"email": f"{session['username']}{DOMAIN}", "password": pw})
    except Exception:
        return err("Incorrect password.", 403)
    try:
        db.auth.admin.delete_user(session["user_id"])
    except Exception as e:
        app.logger.error(f"Auth delete failed: {e}")
        return err("Could not delete.", 500)
    try:
        delete_user_data(session["user_id"])
    except Exception as e:
        app.logger.error(f"Data cleanup failed: {e}")
    session.clear()
    return ok()


# --------------------------------------------------------------------------
# Profiles / follow / block
# --------------------------------------------------------------------------
@app.route("/api/profile/<uname>")
@login_required_api
def api_profile(uname):
    uname = normalize_username(uname)
    try:
        p = db.table("profiles").select("*").eq("username", uname).limit(1).execute().data[0]
    except Exception:
        return err("User not found.", 404)
    p.setdefault("bio", "")
    p.setdefault("verified", False)
    p.setdefault("avatar_url", "")
    p.setdefault("banned_until", None)
    try:
        posts = db.table("posts").select("*, profiles(*)").eq("user_id", p["id"]).order("created_at", desc=True).limit(50).execute().data or []
    except Exception:
        posts = []
    followers = count_rows("follows", "following_id", p["id"])
    following = count_rows("follows", "follower_id", p["id"])
    is_me = p["id"] == session.get("user_id")
    is_following = False
    is_blocked = False
    if not is_me:
        try:
            is_following = bool(db.table("follows").select("id").eq("follower_id", session["user_id"]).eq("following_id", p["id"]).limit(1).execute().data)
            is_blocked = bool(db.table("blocks").select("id").eq("blocker_id", session["user_id"]).eq("blocked_id", p["id"]).limit(1).execute().data)
        except Exception:
            pass
    return ok(
        profile=serialize_profile(p),
        posts=hydrate_posts(posts),
        followers=followers,
        following=following,
        is_me=is_me,
        is_following=is_following,
        is_blocked=is_blocked,
    )


@app.route("/api/profile/update", methods=["POST"])
@login_required_api
def api_update_profile():
    uid = session["user_id"]
    p = get_profile(uid) or {}
    cur_u = p.get("username") or session.get("username", "")
    new_u = normalize_username(request.form.get("username", ""))
    bio = (request.form.get("bio") or "").strip()[:160]
    if not new_u:
        return err("Username required.")
    if not USERNAME_RE.match(new_u):
        return err("Invalid username.")
    if new_u != cur_u and username_exists(new_u):
        return err("Username taken.")
    auth_updated = False
    old_email = f"{cur_u}{DOMAIN}"
    try:
        if new_u != cur_u:
            try:
                db.auth.admin.update_user_by_id(uid, {"email": f"{new_u}{DOMAIN}", "email_confirm": True, "user_metadata": {"username": new_u}})
            except Exception:
                db.auth.admin.update_user_by_id(uid, {"email": f"{new_u}{DOMAIN}", "user_metadata": {"username": new_u}})
            auth_updated = True
        payload = {"username": new_u, "bio": bio}
        if request.files.get("avatar"):
            payload["avatar_url"] = upload_file(request.files["avatar"], "avatars")
        db.table("profiles").update(payload).eq("id", uid).execute()
        session["username"] = new_u
        return ok(user={"id": uid, "username": new_u}, profile=serialize_profile(get_profile(uid)))
    except ValueError as e:
        return err(str(e))
    except Exception as e:
        app.logger.error(f"Profile update failed: {e}")
        if auth_updated:
            try:
                db.auth.admin.update_user_by_id(uid, {"email": old_email, "email_confirm": True, "user_metadata": {"username": cur_u}})
            except Exception:
                pass
        return err("Could not update profile.", 500)


@app.route("/api/follow/<uid>", methods=["POST"])
@login_required_api
def api_toggle_follow(uid):
    if uid == session.get("user_id"):
        return err("Cannot follow yourself.")
    try:
        ex = db.table("follows").select("id").eq("follower_id", session["user_id"]).eq("following_id", uid).limit(1).execute().data
        if ex:
            db.table("follows").delete().eq("id", ex[0]["id"]).execute()
            following = False
        else:
            db.table("follows").insert({"follower_id": session["user_id"], "following_id": uid}).execute()
            following = True
        return ok(following=following)
    except Exception as e:
        app.logger.error(f"Follow failed: {e}")
        return err("Could not update follow.", 500)


@app.route("/api/block/<uid>", methods=["POST"])
@login_required_api
def api_toggle_block(uid):
    if uid == session.get("user_id"):
        return err("Cannot block yourself.")
    try:
        ex = db.table("blocks").select("id").eq("blocker_id", session["user_id"]).eq("blocked_id", uid).limit(1).execute().data
        if ex:
            db.table("blocks").delete().eq("id", ex[0]["id"]).execute()
            return ok(blocked=False)
        else:
            db.table("blocks").insert({"blocker_id": session["user_id"], "blocked_id": uid}).execute()
            return ok(blocked=True)
    except Exception as e:
        app.logger.error(f"Block failed: {e}")
        return err("Could not update block.", 500)


@app.route("/api/block/status/<uid>")
@login_required_api
def api_block_status(uid):
    try:
        ex = db.table("blocks").select("id").eq("blocker_id", session["user_id"]).eq("blocked_id", uid).limit(1).execute().data
        return ok(blocked=bool(ex))
    except Exception:
        return ok(blocked=False)


# --------------------------------------------------------------------------
# Search / admin
# --------------------------------------------------------------------------
@app.route("/api/search")
@login_required_api
def api_search():
    q = request.args.get("q", "").strip()
    if not q:
        return ok(users=[])
    try:
        return ok(users=[serialize_profile(u) for u in db.table("profiles").select("*").ilike("username", f"%{q}%").limit(20).execute().data or []])
    except Exception as e:
        app.logger.error(f"Search failed: {e}")
        return err("Search failed.", 500)


@app.route("/api/admin/users")
@login_required_api
def api_admin_users():
    admin_error = require_admin()
    if admin_error:
        return admin_error
    q = request.args.get("q", "").strip()
    try:
        qry = db.table("profiles").select("*").limit(50)
        if q:
            qry = qry.ilike("username", f"%{q}%")
        return ok(users=[serialize_profile(u) for u in qry.order("username").execute().data or []])
    except Exception as e:
        app.logger.error(f"Admin users failed: {e}")
        return err("Could not load users.", 500)


@app.route("/api/admin/verify/<uid>", methods=["POST"])
@login_required_api
def api_admin_verify(uid):
    admin_error = require_admin()
    if admin_error:
        return admin_error
    t = get_profile(uid)
    if not t:
        return err("User not found.", 404)
    nv = not bool(t.get("verified", False))
    try:
        db.table("profiles").update({"verified": nv}).eq("id", uid).execute()
        return ok(verified=nv)
    except Exception as e:
        app.logger.error(f"Verify failed: {e}")
        return err("Could not update.", 500)


@app.route("/api/admin/ban/<uid>", methods=["POST"])
@login_required_api
def api_admin_ban(uid):
    admin_error = require_admin()
    if admin_error:
        return admin_error
    d = request.get_json(silent=True) or {}
    try:
        hours = float(d.get("hours", 0))
    except Exception:
        hours = 0
    if hours <= 0:
        banned_until = None
    else:
        banned_until = (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()
    try:
        db.table("profiles").update({"banned_until": banned_until}).eq("id", uid).execute()
        return ok(banned_until=banned_until)
    except Exception as e:
        app.logger.error(f"Ban failed: {e}")
        return err("Could not update ban.", 500)


# --------------------------------------------------------------------------
# Push + notifications
# --------------------------------------------------------------------------
@app.route("/api/vapid-public-key")
def api_vapid_key():
    return ok(public_key=VAPID_PUBLIC_KEY)


@app.route("/api/push/subscribe", methods=["POST"])
@login_required_api
def api_push_subscribe():
    d = request.get_json(silent=True) or {}
    ep, keys = d.get("endpoint"), d.get("keys") or {}
    if not ep or not keys.get("p256dh") or not keys.get("auth"):
        return err("Invalid subscription.")
    payload = {
        "user_id": session["user_id"],
        "endpoint": ep,
        "p256dh": keys["p256dh"],
        "auth": keys["auth"],
    }
    try:
        existing = db.table("push_subscriptions").select("id").eq("endpoint", ep).limit(1).execute().data
        if existing:
            db.table("push_subscriptions").update(payload).eq("id", existing[0]["id"]).execute()
        else:
            try:
                db.table("push_subscriptions").insert(payload).execute()
            except Exception:
                db.table("push_subscriptions").update(payload).eq("endpoint", ep).execute()
        return ok()
    except Exception as e:
        app.logger.error(f"Push subscribe failed: {e}")
        return err("Could not save.", 500)


@app.route("/api/notifications")
@login_required_api
def api_notifications():
    try:
        notifs = db.table("notifications").select("*").eq("user_id", session["user_id"]).order("created_at", desc=True).limit(50).execute().data or []
        aids = list({n.get("actor_id") for n in notifs if n.get("actor_id")})
        actors = {}
        if aids:
            actors = {r["id"]: serialize_profile(r) for r in db.table("profiles").select("*").in_("id", aids).execute().data or []}
        out = []
        for n in notifs:
            out.append({
                "id": n.get("id"),
                "type": n.get("type"),
                "post_id": n.get("post_id"),
                "comment_id": n.get("comment_id"),
                "read": n.get("read"),
                "created_at": n.get("created_at"),
                "actor": actors.get(n.get("actor_id")) or {"username": "someone", "verified": False, "avatar_url": ""},
            })
        return ok(notifications=out)
    except Exception as e:
        app.logger.error(f"Notifs fetch failed: {e}")
        return err("Could not load.", 500)


@app.route("/api/notifications/unread-count")
@login_required_api
def api_unread_count():
    try:
        return ok(count=db.table("notifications").select("id", count="exact").eq("user_id", session["user_id"]).eq("read", False).execute().count or 0)
    except Exception:
        return ok(count=0)


@app.route("/api/notifications/read", methods=["POST"])
@login_required_api
def api_mark_read():
    try:
        db.table("notifications").update({"read": True}).eq("user_id", session["user_id"]).eq("read", False).execute()
        return ok()
    except Exception as e:
        app.logger.error(f"Mark read failed: {e}")
        return err("Could not mark.", 500)


# --------------------------------------------------------------------------
# Voice (LiveKit via pure PyJWT - lowest delay, zero SDK errors)
# --------------------------------------------------------------------------
@app.route("/api/voice/rooms")
@login_required_api
def api_voice_rooms():
    return ok(rooms=VOICE_ROOMS)


@app.route("/api/voice/token")
@login_required_api
def api_voice_token():
    room_id = (request.args.get("room") or "").strip()

    valid_rooms = {r["id"] for r in VOICE_ROOMS}
    if room_id not in valid_rooms:
        return jsonify({"ok": False, "error": "Unknown voice room."}), 400

    if not LIVEKIT_URL or not LIVEKIT_API_KEY or not LIVEKIT_API_SECRET:
        return jsonify({"ok": False, "error": "Voice env vars missing in Render."}), 500

    try:
        now = int(time.time())
        claims = {
            "iss": LIVEKIT_API_KEY,
            "sub": session["user_id"],
            "name": session.get("username", "user"),
            "nbf": now,
            "exp": now + 600,
            "video": {
                "roomJoin": True,
                "room": room_id,
                "canPublish": True,
                "canSubscribe": True,
            },
        }
        token = jwt.encode(claims, LIVEKIT_API_SECRET, algorithm="HS256")
        if isinstance(token, bytes):
            token = token.decode("utf-8")
        return jsonify({"ok": True, "token": token, "url": LIVEKIT_URL, "room": room_id})
    except Exception as e:
        app.logger.error(f"Voice token failed: {e}")
        return jsonify({"ok": False, "error": f"Token Error: {e}"}), 500


# --------------------------------------------------------------------------
# Static + SPA
# --------------------------------------------------------------------------
@app.route("/sw.js")
def sw_js():
    r = send_from_directory("static", "sw.js")
    r.headers["Content-Type"] = "application/javascript"
    r.headers["Service-Worker-Allowed"] = "/"
    return r


@app.route("/favicon.ico")
def favicon():
    return "", 204


@app.route("/health")
def health():
    return "ok", 200


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def catch_all(path):
    if path.startswith("api/"):
        return err("Not found.", 404)
    if path.startswith("static/"):
        return send_from_directory("static", path.split("static/", 1)[1])
    return render_template("index.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
