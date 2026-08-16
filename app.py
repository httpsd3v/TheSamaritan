import os
import re
import uuid
from functools import wraps

from flask import Flask, render_template, request, session, jsonify

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

from supabase import create_client, Client

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


def normalize_username(raw: str) -> str:
    return (raw or "").strip().lower()


ADMIN_USERNAMES = set(
    normalize_username(x)
    for x in os.environ.get("ADMIN_USERNAMES", "").split(",")
    if x.strip()
)


if not SUPABASE_URL or not SUPABASE_ANON_KEY or not SUPABASE_SERVICE_ROLE_KEY:
    raise RuntimeError(
        "Missing Supabase environment variables. "
        "Set SUPABASE_URL and either SUPABASE_KEY, "
        "or SUPABASE_ANON_KEY + SUPABASE_SERVICE_ROLE_KEY."
    )


auth_client: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
db: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)


# --------------------------------------------------------------------------
# JSON helpers
# --------------------------------------------------------------------------

def ok(**kwargs):
    kwargs["ok"] = True
    return jsonify(kwargs)


def err(message: str, status: int = 400):
    return jsonify({
        "ok": False,
        "error": message,
    }), status


def login_required_api(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id"):
            return err("Not signed in.", 401)
        return f(*args, **kwargs)

    return decorated


def require_admin():
    username = normalize_username(session.get("username", ""))
    if username not in ADMIN_USERNAMES:
        return err("Forbidden.", 403)
    return None


def is_admin_username(username: str) -> bool:
    return normalize_username(username) in ADMIN_USERNAMES


# --------------------------------------------------------------------------
# Core helpers
# --------------------------------------------------------------------------

def authenticate(username: str, password: str):
    email = f"{username}{DOMAIN}"

    response = auth_client.auth.sign_in_with_password({
        "email": email,
        "password": password,
    })

    user = getattr(response, "user", None)

    if not user and getattr(response, "session", None):
        user = response.session.user

    if not user:
        raise Exception("Supabase did not return a user object.")

    session["user_id"] = user.id
    session["username"] = username

    ensure_profile(user.id, username)

    return user


def ensure_profile(user_id: str, username: str):
    if not user_id or not username:
        return

    try:
        db.table("profiles").upsert(
            {
                "id": user_id,
                "username": username,
            },
            on_conflict="id",
        ).execute()
    except Exception as exc:
        app.logger.error(f"ensure_profile failed: {exc}")


def get_profile(user_id: str):
    try:
        response = (
            db.table("profiles")
            .select("*")
            .eq("id", user_id)
            .limit(1)
            .execute()
        )

        if not response.data:
            return None

        profile = response.data[0]

        profile.setdefault("id", user_id)
        profile.setdefault("username", "unknown")
        profile.setdefault("bio", "")
        profile.setdefault("verified", False)
        profile.setdefault("avatar_url", "")

        return profile
    except Exception as exc:
        app.logger.error(f"get_profile failed: {exc}")
        return None


def username_exists(username: str) -> bool:
    try:
        response = (
            db.table("profiles")
            .select("id")
            .eq("username", username)
            .limit(1)
            .execute()
        )
        return bool(response.data)
    except Exception as exc:
        app.logger.error(f"username_exists failed: {exc}")
        return False


def count_rows(table: str, column: str, value: str) -> int:
    try:
        response = (
            db.table(table)
            .select("id", count="exact")
            .eq(column, value)
            .execute()
        )
        return response.count or 0
    except Exception as exc:
        app.logger.error(f"count_rows failed on {table}: {exc}")
        return 0


def upload_file(file_storage, folder: str) -> str:
    if not file_storage:
        return None

    filename = file_storage.filename or ""
    mime = file_storage.mimetype or ""
    ext = ALLOWED_MIME.get(mime)

    if not ext and "." in filename:
        file_ext = filename.rsplit(".", 1)[-1].lower()

        if file_ext in ("jpg", "jpeg"):
            ext = "jpg"
            mime = "image/jpeg"
        elif file_ext == "png":
            ext = "png"
            mime = "image/png"
        elif file_ext == "webp":
            ext = "webp"
            mime = "image/webp"
        elif file_ext == "gif":
            ext = "gif"
            mime = "image/gif"

    if not ext:
        raise ValueError("Only PNG, JPG, WEBP, or GIF files are allowed.")

    data = file_storage.read()

    if len(data) > MAX_MEDIA_BYTES:
        raise ValueError("File too large. Max 8 MB.")

    path = f"{folder}/{uuid.uuid4()}.{ext}"

    try:
        db.storage.from_(STORAGE_BUCKET).upload(
            path,
            data,
            {
                "content-type": mime or f"image/{ext}",
            },
        )

        return db.storage.from_(STORAGE_BUCKET).get_public_url(path)
    except Exception as exc:
        app.logger.error(f"Storage upload failed: {exc}")
        raise ValueError("Media upload failed. Check Supabase Storage bucket.")


def delete_user_data(user_id: str):
    posts_response = (
        db.table("posts")
        .select("id")
        .eq("user_id", user_id)
        .execute()
    )

    post_ids = [
        row["id"]
        for row in posts_response.data or []
        if row.get("id")
    ]

    if post_ids:
        db.table("comments").delete().in_("post_id", post_ids).execute()
        db.table("likes").delete().in_("post_id", post_ids).execute()

    db.table("comments").delete().eq("user_id", user_id).execute()
    db.table("likes").delete().eq("user_id", user_id).execute()

    db.table("follows").delete().eq("follower_id", user_id).execute()
    db.table("follows").delete().eq("following_id", user_id).execute()

    db.table("posts").delete().eq("user_id", user_id).execute()
    db.table("profiles").delete().eq("id", user_id).execute()


# --------------------------------------------------------------------------
# Serializers
# --------------------------------------------------------------------------

def serialize_profile(row):
    row = row or {}

    return {
        "id": row.get("id"),
        "username": row.get("username", "unknown"),
        "bio": row.get("bio", ""),
        "verified": bool(row.get("verified", False)),
        "avatar_url": row.get("avatar_url", ""),
    }


def serialize_post(row, liked_ids=None, like_counts=None, comment_counts=None):
    liked_ids = liked_ids or set()
    like_counts = like_counts or {}
    comment_counts = comment_counts or {}

    post_id = row.get("id")

    profile = row.get("profiles")

    if isinstance(profile, list):
        profile = profile[0] if profile else None

    if profile:
        author = serialize_profile(profile)
    else:
        author = {
            "id": None,
            "username": "deleted",
            "verified": False,
            "avatar_url": "",
        }

    return {
        "id": post_id,
        "content": row.get("content", ""),
        "media_url": row.get("image_url") or row.get("media_url") or "",
        "created_at": row.get("created_at"),
        "author": author,
        "likes": like_counts.get(post_id, 0),
        "liked": post_id in liked_ids,
        "comments": comment_counts.get(post_id, 0),
    }


def serialize_comment(row):
    profile = row.get("profiles")

    if isinstance(profile, list):
        profile = profile[0] if profile else None

    if profile:
        author = serialize_profile(profile)
    else:
        author = {
            "id": None,
            "username": "deleted",
            "verified": False,
            "avatar_url": "",
        }

    return {
        "id": row.get("id"),
        "post_id": row.get("post_id"),
        "parent_comment_id": row.get("parent_comment_id"),
        "content": row.get("content", ""),
        "created_at": row.get("created_at"),
        "author": author,
    }


def hydrate_posts(posts):
    post_ids = [
        post.get("id")
        for post in posts
        if post.get("id")
    ]

    like_counts = {post_id: 0 for post_id in post_ids}
    comment_counts = {post_id: 0 for post_id in post_ids}
    liked_ids = set()

    if post_ids:
        try:
            likes_response = (
                db.table("likes")
                .select("post_id")
                .in_("post_id", post_ids)
                .execute()
            )

            for row in likes_response.data or []:
                post_id = row.get("post_id")
                if post_id in like_counts:
                    like_counts[post_id] += 1
        except Exception as exc:
            app.logger.error(f"Like counts failed: {exc}")

        try:
            comments_response = (
                db.table("comments")
                .select("post_id")
                .in_("post_id", post_ids)
                .execute()
            )

            for row in comments_response.data or []:
                post_id = row.get("post_id")
                if post_id in comment_counts:
                    comment_counts[post_id] += 1
        except Exception as exc:
            app.logger.error(f"Comment counts failed: {exc}")

        try:
            my_likes_response = (
                db.table("likes")
                .select("post_id")
                .eq("user_id", session.get("user_id"))
                .in_("post_id", post_ids)
                .execute()
            )

            liked_ids = {
                row.get("post_id")
                for row in my_likes_response.data or []
                if row.get("post_id")
            }
        except Exception as exc:
            app.logger.error(f"Current user likes failed: {exc}")

    return [
        serialize_post(post, liked_ids, like_counts, comment_counts)
        for post in posts
    ]


# --------------------------------------------------------------------------
# Auth routes
# --------------------------------------------------------------------------

@app.route("/api/me")
def api_me():
    if not session.get("user_id"):
        return ok(authenticated=False)

    profile = get_profile(session["user_id"])

    if not profile:
        profile = {
            "id": session["user_id"],
            "username": session.get("username", "unknown"),
            "bio": "",
            "verified": False,
            "avatar_url": "",
        }

        ensure_profile(profile["id"], profile["username"])

    return ok(
        authenticated=True,
        user={
            "id": session["user_id"],
            "username": profile.get("username"),
        },
        profile=serialize_profile(profile),
        is_admin=is_admin_username(profile.get("username", "")),
    )


@app.route("/api/signin", methods=["POST"])
def api_signin():
    data = request.get_json(silent=True) or {}

    username = normalize_username(data.get("username", ""))
    password = data.get("password", "")

    if not username or not password:
        return err("Username and password are required.")

    try:
        authenticate(username, password)
    except Exception as exc:
        app.logger.error(f"Signin error: {exc}")
        return err("Invalid username or password.", 401)

    profile = get_profile(session["user_id"])

    return ok(
        user={
            "id": session["user_id"],
            "username": username,
        },
        profile=serialize_profile(profile),
        is_admin=is_admin_username(username),
    )


@app.route("/api/signup", methods=["POST"])
def api_signup():
    data = request.get_json(silent=True) or {}

    username = normalize_username(data.get("username", ""))
    password = data.get("password", "")

    if not username or not password:
        return err("Username and password are required.")

    if not USERNAME_RE.match(username):
        return err("Username can only contain letters, numbers, dots, and underscores.")

    if len(password) < 6:
        return err("Password must be at least 6 characters.")

    if username_exists(username):
        return err("Username is already taken.")

    email = f"{username}{DOMAIN}"

    try:
        created = db.auth.admin.create_user({
            "email": email,
            "password": password,
            "email_confirm": True,
            "user_metadata": {
                "username": username,
            },
        })

        user = getattr(created, "user", created)
        user_id = getattr(user, "id", None)

        ensure_profile(user_id, username)

        authenticate(username, password)

        profile = get_profile(user_id)

        return ok(
            user={
                "id": user_id,
                "username": username,
            },
            profile=serialize_profile(profile),
            is_admin=is_admin_username(username),
        )

    except Exception as exc:
        message = str(exc).lower()
        app.logger.error(f"Signup error: {exc}")

        if (
            "already registered" in message
            or "already been registered" in message
            or "already exists" in message
            or "duplicate" in message
        ):
            return err("Username is already taken.")

        if "password" in message:
            return err("Password must be at least 6 characters.")

        if "api key" in message or "invalid" in message:
            return err("Signup failed. Set SUPABASE_SERVICE_ROLE_KEY correctly.")

        return err("Signup failed. Check server logs.")


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
        limit = int(request.args.get("limit", 30))
        limit = max(1, min(limit, 50))
    except Exception:
        limit = 30

    try:
        response = (
            db.table("posts")
            .select("*, profiles(*)")
            .order("created_at", desc=True)
            .limit(limit)
            .execute()
        )

        posts = response.data or []
        return ok(posts=hydrate_posts(posts))
    except Exception as exc:
        app.logger.error(f"Feed query failed: {exc}")
        return err("Could not load feed.", 500)


@app.route("/api/posts", methods=["POST"])
@login_required_api
def api_create_post():
    content = (request.form.get("content") or "").strip()[:1000]
    media_file = request.files.get("media")

    media_url = None

    if media_file and media_file.filename:
        try:
            media_url = upload_file(media_file, "posts")
        except ValueError as exc:
            return err(str(exc))

    if not content and not media_url:
        return err("Post cannot be empty.")

    payload = {
        "user_id": session["user_id"],
        "content": content,
        "image_url": media_url,
    }

    try:
        inserted = db.table("posts").insert(payload).execute()
        post = inserted.data[0] if inserted.data else None

        if not post:
            latest = (
                db.table("posts")
                .select("*")
                .eq("user_id", session["user_id"])
                .order("created_at", desc=True)
                .limit(1)
                .execute()
                .data
            )

            post = latest[0] if latest else None

        if not post:
            return err("Could not create post.", 500)

        post["profiles"] = get_profile(session["user_id"])

        serialized = serialize_post(
            post,
            liked_ids=set(),
            like_counts={post.get("id"): 0},
            comment_counts={post.get("id"): 0},
        )

        return ok(post=serialized)
    except Exception as exc:
        app.logger.error(f"create_post failed: {exc}")
        return err("Could not create post.", 500)


@app.route("/api/posts/<post_id>/like", methods=["POST"])
@login_required_api
def api_toggle_like(post_id):
    try:
        existing = (
            db.table("likes")
            .select("id")
            .eq("user_id", session["user_id"])
            .eq("post_id", post_id)
            .limit(1)
            .execute()
        )

        if existing.data:
            like_id = existing.data[0]["id"]
            db.table("likes").delete().eq("id", like_id).execute()
            liked = False
        else:
            db.table("likes").insert({
                "user_id": session["user_id"],
                "post_id": post_id,
            }).execute()
            liked = True

        likes = count_rows("likes", "post_id", post_id)

        return ok(
            liked=liked,
            likes=likes,
        )
    except Exception as exc:
        app.logger.error(f"toggle_like failed: {exc}")
        return err("Could not update like.", 500)


@app.route("/api/posts/<post_id>/comments", methods=["GET", "POST"])
@login_required_api
def api_comments(post_id):
    if request.method == "GET":
        try:
            response = (
                db.table("comments")
                .select("*, profiles(*)")
                .eq("post_id", post_id)
                .order("created_at", desc=False)
                .limit(200)
                .execute()
            )

            comments = response.data or []

            return ok(comments=[
                serialize_comment(comment)
                for comment in comments
            ])
        except Exception as exc:
            app.logger.error(f"Comments fetch failed: {exc}")
            return err("Could not load comments.", 500)

    data = request.get_json(silent=True) or {}

    content = (data.get("content") or "").strip()[:500]
    parent_id = data.get("parent_id") or None

    if not content:
        return err("Comment cannot be empty.")

    payload = {
        "user_id": session["user_id"],
        "post_id": post_id,
        "content": content,
        "parent_comment_id": parent_id,
    }

    try:
        inserted = db.table("comments").insert(payload).execute()
        comment = inserted.data[0] if inserted.data else None

        if not comment:
            return err("Could not add comment.", 500)

        comment["profiles"] = get_profile(session["user_id"])

        return ok(comment=serialize_comment(comment))
    except Exception as exc:
        app.logger.error(f"Comment create failed: {exc}")
        return err("Could not add comment.", 500)


# --------------------------------------------------------------------------
# Profiles
# --------------------------------------------------------------------------

@app.route("/api/profile/<username>")
@login_required_api
def api_profile(username):
    username = normalize_username(username)

    try:
        response = (
            db.table("profiles")
            .select("*")
            .eq("username", username)
            .limit(1)
            .execute()
        )

        profile = response.data[0] if response.data else None
    except Exception as exc:
        app.logger.error(f"profile fetch failed: {exc}")
        return err("Could not load profile.", 500)

    if not profile:
        return err("User not found.", 404)

    profile.setdefault("bio", "")
    profile.setdefault("verified", False)
    profile.setdefault("avatar_url", "")

    posts = []

    try:
        posts_response = (
            db.table("posts")
            .select("*, profiles(*)")
            .eq("user_id", profile["id"])
            .order("created_at", desc=True)
            .limit(50)
            .execute()
        )

        posts = posts_response.data or []
    except Exception as exc:
        app.logger.error(f"profile posts fetch failed: {exc}")

    followers = count_rows("follows", "following_id", profile["id"])
    following = count_rows("follows", "follower_id", profile["id"])

    is_me = profile["id"] == session.get("user_id")

    is_following = False

    if not is_me:
        try:
            follow_response = (
                db.table("follows")
                .select("id")
                .eq("follower_id", session["user_id"])
                .eq("following_id", profile["id"])
                .limit(1)
                .execute()
            )

            is_following = bool(follow_response.data)
        except Exception as exc:
            app.logger.error(f"follow check failed: {exc}")

    return ok(
        profile=serialize_profile(profile),
        posts=hydrate_posts(posts),
        followers=followers,
        following=following,
        is_me=is_me,
        is_following=is_following,
    )


@app.route("/api/profile/update", methods=["POST"])
@login_required_api
def api_update_profile():
    user_id = session["user_id"]
    profile = get_profile(user_id) or {}

    current_username = profile.get("username") or session.get("username", "")

    new_username = normalize_username(request.form.get("username", ""))
    bio = (request.form.get("bio") or "").strip()[:160]

    avatar_file = request.files.get("avatar")

    if not new_username:
        return err("Username is required.")

    if not USERNAME_RE.match(new_username):
        return err("Username can only contain letters, numbers, dots, and underscores.")

    if new_username != current_username and username_exists(new_username):
        return err("Username is already taken.")

    auth_updated = False
    old_email = f"{current_username}{DOMAIN}"

    try:
        if new_username != current_username:
            new_email = f"{new_username}{DOMAIN}"

            try:
                db.auth.admin.update_user_by_id(
                    user_id,
                    {
                        "email": new_email,
                        "email_confirm": True,
                        "user_metadata": {
                            "username": new_username,
                        },
                    },
                )
            except Exception:
                db.auth.admin.update_user_by_id(
                    user_id,
                    {
                        "email": new_email,
                        "user_metadata": {
                            "username": new_username,
                        },
                    },
                )

            auth_updated = True

        payload = {
            "username": new_username,
            "bio": bio,
        }

        if avatar_file and avatar_file.filename:
            payload["avatar_url"] = upload_file(avatar_file, "avatars")

        db.table("profiles").update(payload).eq("id", user_id).execute()

        session["username"] = new_username

        updated_profile = get_profile(user_id)

        return ok(
            user={
                "id": user_id,
                "username": new_username,
            },
            profile=serialize_profile(updated_profile),
        )

    except ValueError as exc:
        return err(str(exc))

    except Exception as exc:
        app.logger.error(f"Profile update failed: {exc}")

        if auth_updated:
            try:
                db.auth.admin.update_user_by_id(
                    user_id,
                    {
                        "email": old_email,
                        "email_confirm": True,
                        "user_metadata": {
                            "username": current_username,
                        },
                    },
                )
            except Exception:
                try:
                    db.auth.admin.update_user_by_id(
                        user_id,
                        {
                            "email": old_email,
                            "user_metadata": {
                                "username": current_username,
                            },
                        },
                    )
                except Exception as rollback_exc:
                    app.logger.error(f"Email rollback failed: {rollback_exc}")

        return err("Could not update profile.", 500)


@app.route("/api/follow/<user_id>", methods=["POST"])
@login_required_api
def api_toggle_follow(user_id):
    if user_id == session.get("user_id"):
        return err("You cannot follow yourself.")

    try:
        existing = (
            db.table("follows")
            .select("id")
            .eq("follower_id", session["user_id"])
            .eq("following_id", user_id)
            .limit(1)
            .execute()
        )

        if existing.data:
            follow_id = existing.data[0]["id"]
            db.table("follows").delete().eq("id", follow_id).execute()
            following = False
        else:
            db.table("follows").insert({
                "follower_id": session["user_id"],
                "following_id": user_id,
            }).execute()
            following = True

        return ok(following=following)
    except Exception as exc:
        app.logger.error(f"toggle_follow failed: {exc}")
        return err("Could not update follow.", 500)


@app.route("/api/search")
@login_required_api
def api_search():
    q = request.args.get("q", "").strip()

    if not q:
        return ok(users=[])

    try:
        response = (
            db.table("profiles")
            .select("*")
            .ilike("username", f"%{q}%")
            .limit(20)
            .execute()
        )

        users = response.data or []

        return ok(users=[
            serialize_profile(user)
            for user in users
        ])
    except Exception as exc:
        app.logger.error(f"Search failed: {exc}")
        return err("Search failed.", 500)


# --------------------------------------------------------------------------
# Admin
# --------------------------------------------------------------------------

@app.route("/api/admin/users")
@login_required_api
def api_admin_users():
    admin_error = require_admin()
    if admin_error:
        return admin_error

    q = request.args.get("q", "").strip()

    try:
        query = db.table("profiles").select("*").limit(50)

        if q:
            query = query.ilike("username", f"%{q}%")

        response = query.order("username").execute()
        users = response.data or []

        return ok(users=[
            serialize_profile(user)
            for user in users
        ])
    except Exception as exc:
        app.logger.error(f"Admin users failed: {exc}")
        return err("Could not load users.", 500)


@app.route("/api/admin/verify/<user_id>", methods=["POST"])
@login_required_api
def api_admin_verify(user_id):
    admin_error = require_admin()
    if admin_error:
        return admin_error

    target = get_profile(user_id)

    if not target:
        return err("User not found.", 404)

    new_verified = not bool(target.get("verified", False))

    try:
        db.table("profiles").update({
            "verified": new_verified,
        }).eq("id", user_id).execute()

        return ok(verified=new_verified)
    except Exception as exc:
        app.logger.error(f"Admin verify failed: {exc}")
        return err("Could not update verification.", 500)


# --------------------------------------------------------------------------
# Account deletion
# --------------------------------------------------------------------------

@app.route("/api/account/delete", methods=["POST"])
@login_required_api
def api_delete_account():
    user_id = session["user_id"]
    profile = get_profile(user_id) or {}
    username = profile.get("username") or session.get("username", "")

    data = request.get_json(silent=True) or {}
    password = data.get("password", "")

    if not password:
        return err("Password is required.")

    try:
        auth_client.auth.sign_in_with_password({
            "email": f"{username}{DOMAIN}",
            "password": password,
        })
    except Exception as exc:
        app.logger.error(f"Delete account password check failed: {exc}")
        return err("Incorrect password.", 403)

    try:
        db.auth.admin.delete_user(user_id)
    except Exception as exc:
        app.logger.error(f"Auth user deletion failed: {exc}")
        return err("Could not delete account.", 500)

    try:
        delete_user_data(user_id)
    except Exception as exc:
        app.logger.error(f"User data cleanup failed: {exc}")

    session.pop("user_id", None)
    session.pop("username", None)

    return ok()


# --------------------------------------------------------------------------
# SPA serving
# --------------------------------------------------------------------------

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
        return app.send_static_file(path.split("static/", 1)[1])

    return render_template("index.html")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
