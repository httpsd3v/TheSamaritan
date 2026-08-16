import os
import re
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash

# Optional: loads .env locally if you have one.
# If you don't have python-dotenv installed, this just gets ignored.
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

from supabase import create_client, Client

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

# --------------------------------------------------------------------------
# Supabase config
#
# Recommended Render env vars:
#
# SUPABASE_URL=https://your-project.supabase.co
# SUPABASE_ANON_KEY=your-anon-key
# SUPABASE_SERVICE_ROLE_KEY=your-service-role-key
# SECRET_KEY=random-long-secret
#
# If you only want to set one key, set SUPABASE_KEY to the service_role key.
# --------------------------------------------------------------------------
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY") or os.environ.get("SUPABASE_KEY")
SUPABASE_SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY") or os.environ.get("SUPABASE_KEY")

DOMAIN = "@samaritan.app"
USERNAME_RE = re.compile(r"^[a-z0-9_.]{3,30}$")

if not SUPABASE_URL or not SUPABASE_ANON_KEY or not SUPABASE_SERVICE_ROLE_KEY:
    raise RuntimeError(
        "Missing Supabase environment variables. "
        "Set SUPABASE_URL and either SUPABASE_KEY, "
        "or SUPABASE_ANON_KEY + SUPABASE_SERVICE_ROLE_KEY."
    )

# auth_client is used for sign up / sign in.
# db is used for database reads/writes.
#
# For reliable server-side writes, SUPABASE_SERVICE_ROLE_KEY should be your
# Supabase service_role key. Do NOT expose that key to the frontend.
auth_client: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
db: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def normalize_username(raw: str) -> str:
    return (raw or "").strip().lower()


def parse_timestamp(value):
    if isinstance(value, datetime):
        dt = value
    else:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt


def time_ago(value) -> str:
    try:
        dt = parse_timestamp(value)
        now = datetime.now(timezone.utc)
        diff = int((now - dt).total_seconds())

        if diff < 0:
            return "just now"
        if diff < 60:
            return "just now"
        if diff < 3600:
            return f"{diff // 60}m ago"
        if diff < 86400:
            return f"{diff // 3600}h ago"
        if diff < 604800:
            return f"{diff // 86400}d ago"

        return dt.strftime("%b %d")
    except Exception:
        return ""


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("signin"))
        return f(*args, **kwargs)

    return decorated


def authenticate(username: str, password: str):
    """
    Signs a user in with fake email:
    username@samaritan.app
    """
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

    # Make sure their profile row exists.
    ensure_profile(user.id, username)

    return user


def ensure_profile(user_id: str, username: str):
    """
    Creates the profile row if it does not exist.
    Uses upsert so it will not duplicate.
    """
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
        profile.setdefault("username", "unknown")
        profile.setdefault("bio", "")
        profile.setdefault("verified", False)

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
        app.logger.error(f"count_rows failed for {table}: {exc}")
        return 0


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------

@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("feed"))
    return redirect(url_for("signin"))


@app.route("/health")
def health():
    return "ok", 200


@app.route("/signin", methods=["GET", "POST"])
def signin():
    if request.method == "POST":
        username = normalize_username(request.form.get("username", ""))
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password are required.")
            return render_template("auth.html", mode="signin")

        try:
            authenticate(username, password)
            return redirect(url_for("feed"))
        except Exception as exc:
            app.logger.error(f"Signin error: {exc}")
            flash("Invalid username or password.")

    return render_template("auth.html", mode="signin")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = normalize_username(request.form.get("username", ""))
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password are required.")
            return render_template("auth.html", mode="signup")

        if not USERNAME_RE.match(username):
            flash("Username can only contain letters, numbers, dots, and underscores.")
            return render_template("auth.html", mode="signup")

        if len(password) < 6:
            flash("Password must be at least 6 characters.")
            return render_template("auth.html", mode="signup")

        if username_exists(username):
            flash("Username is already taken.")
            return render_template("auth.html", mode="signup")

        email = f"{username}{DOMAIN}"

        try:
            response = auth_client.auth.sign_up({
                "email": email,
                "password": password,
                "options": {
                    "data": {
                        "username": username,
                    }
                },
            })

            user = getattr(response, "user", None)

            if not user and getattr(response, "session", None):
                user = response.session.user

            user_id = getattr(user, "id", None)

            # Create/repair profile row immediately.
            ensure_profile(user_id, username)

            # If Supabase gave us a session already, log them in.
            if user_id and getattr(response, "session", None):
                session["user_id"] = user_id
                session["username"] = username
                return redirect(url_for("feed"))

            # Otherwise try signing them in manually.
            try:
                authenticate(username, password)
                return redirect(url_for("feed"))
            except Exception as sign_in_exc:
                app.logger.error(f"Signup succeeded but sign-in failed: {sign_in_exc}")
                flash(
                    "Account created, but automatic sign-in failed. "
                    "Disable Supabase email confirmation, then sign in."
                )
                return redirect(url_for("signin"))

        except Exception as exc:
            message = str(exc).lower()
            app.logger.error(f"Signup error: {exc}")

            if (
                "already registered" in message
                or "already been registered" in message
                or "already exists" in message
                or "duplicate" in message
            ):
                flash("Username is already taken.")
            elif "password" in message:
                flash("Password must be at least 6 characters.")
            elif "email" in message:
                flash("Signup failed because of an auth/email setting. Check Supabase logs.")
            else:
                flash("Signup failed. Check server logs for the exact Supabase error.")

    return render_template("auth.html", mode="signup")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("signin"))


@app.route("/feed")
@login_required
def feed():
    posts = []

    try:
        response = (
            db.table("posts")
            .select("*, profiles(username, verified)")
            .order("created_at", desc=True)
            .limit(50)
            .execute()
        )
        posts = response.data or []
    except Exception as exc:
        app.logger.error(f"Feed query failed: {exc}")
        flash("Could not load feed.")

    post_ids = [post["id"] for post in posts if post.get("id")]

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
                .eq("user_id", session["user_id"])
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

    # Normalize embedded profile data so templates do not crash.
    for post in posts:
        profile = post.get("profiles")

        # Sometimes embedded relationships can come back as a list.
        if isinstance(profile, list):
            profile = profile[0] if profile else None

        if not profile:
            profile = {
                "username": "deleted",
                "verified": False,
            }

        profile.setdefault("username", "deleted")
        profile.setdefault("verified", False)

        post["profiles"] = profile
        post["like_count"] = like_counts.get(post.get("id"), 0)
        post["comment_count"] = comment_counts.get(post.get("id"), 0)

    return render_template(
        "feed.html",
        posts=posts,
        liked_ids=liked_ids,
        like_counts=like_counts,
        time_ago=time_ago,
    )


@app.route("/post", methods=["POST"])
@login_required
def create_post():
    text = request.form.get("text", "").strip()
    image_url = request.form.get("image_url", "").strip() or None

    if not text:
        flash("Post cannot be empty.")
        return redirect(url_for("feed"))

    try:
        db.table("posts").insert({
            "user_id": session["user_id"],
            "content": text,
            "image_url": image_url,
        }).execute()
    except Exception as exc:
        app.logger.error(f"create_post failed: {exc}")
        flash("Could not create post.")

    return redirect(url_for("feed"))


@app.route("/like/<post_id>", methods=["POST"])
@login_required
def toggle_like(post_id):
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
        else:
            db.table("likes").insert({
                "user_id": session["user_id"],
                "post_id": post_id,
            }).execute()
    except Exception as exc:
        app.logger.error(f"toggle_like failed: {exc}")
        flash("Could not update like.")

    return redirect(request.referrer or url_for("feed"))


@app.route("/comment/<post_id>", methods=["POST"])
@login_required
def add_comment(post_id):
    text = request.form.get("text", "").strip()

    if not text:
        return redirect(request.referrer or url_for("feed"))

    try:
        db.table("comments").insert({
            "user_id": session["user_id"],
            "post_id": post_id,
            "content": text,
        }).execute()
    except Exception as exc:
        app.logger.error(f"add_comment failed: {exc}")
        flash("Could not add comment.")

    return redirect(request.referrer or url_for("feed"))


@app.route("/profile")
@login_required
def profile():
    user = get_profile(session["user_id"])

    if not user:
        user = {
            "id": session["user_id"],
            "username": session.get("username", "unknown"),
            "bio": "",
            "verified": False,
        }
        ensure_profile(user["id"], user["username"])

    posts = []

    try:
        response = (
            db.table("posts")
            .select("*")
            .eq("user_id", session["user_id"])
            .order("created_at", desc=True)
            .limit(50)
            .execute()
        )
        posts = response.data or []
    except Exception as exc:
        app.logger.error(f"Profile posts query failed: {exc}")

    followers = count_rows("follows", "following_id", user["id"])
    following = count_rows("follows", "follower_id", user["id"])

    return render_template(
        "profile.html",
        user=user,
        posts=posts,
        followers=followers,
        following=following,
        time_ago=time_ago,
        is_me=True,
    )


@app.route("/user/<username>")
@login_required
def user_profile(username):
    username = normalize_username(username)

    try:
        response = (
            db.table("profiles")
            .select("*")
            .eq("username", username)
            .limit(1)
            .execute()
        )
        user = response.data[0] if response.data else None
    except Exception as exc:
        app.logger.error(f"user_profile query failed: {exc}")
        user = None

    if not user:
        return "User not found", 404

    user.setdefault("username", username)
    user.setdefault("bio", "")
    user.setdefault("verified", False)

    posts = []

    try:
        response = (
            db.table("posts")
            .select("*")
            .eq("user_id", user["id"])
            .order("created_at", desc=True)
            .limit(50)
            .execute()
        )
        posts = response.data or []
    except Exception as exc:
        app.logger.error(f"User posts query failed: {exc}")

    followers = count_rows("follows", "following_id", user["id"])
    following = count_rows("follows", "follower_id", user["id"])

    is_me = user.get("id") == session.get("user_id")

    return render_template(
        "profile.html",
        user=user,
        posts=posts,
        followers=followers,
        following=following,
        time_ago=time_ago,
        is_me=is_me,
    )


@app.route("/follow/<user_id>", methods=["POST"])
@login_required
def toggle_follow(user_id):
    if user_id == session.get("user_id"):
        return redirect(request.referrer or url_for("feed"))

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
        else:
            db.table("follows").insert({
                "follower_id": session["user_id"],
                "following_id": user_id,
            }).execute()
    except Exception as exc:
        app.logger.error(f"toggle_follow failed: {exc}")
        flash("Could not update follow.")

    return redirect(request.referrer or url_for("feed"))


@app.route("/search")
@login_required
def search():
    q = request.args.get("q", "").strip()
    results = []

    if q:
        try:
            response = (
                db.table("profiles")
                .select("*")
                .ilike("username", f"%{q}%")
                .limit(20)
                .execute()
            )
            results = response.data or []
        except Exception as exc:
            app.logger.error(f"Search failed: {exc}")

    return render_template(
        "search.html",
        results=results,
        q=q,
    )


# --------------------------------------------------------------------------
# Run
# --------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
