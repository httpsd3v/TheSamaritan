import os
import time
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from supabase import create_client, Client
from functools import wraps
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-in-prod")

# Supabase config (from env vars on Render)
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# --- Helpers ---------------------------------------------------------------

DOMAIN = "@samaritan.app"  # fake email domain since Supabase needs an email

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("signin"))
        return f(*args, **kwargs)
    return decorated

def time_ago(ts: str) -> str:
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    diff = int(time.time() - dt.timestamp())
    if diff < 60: return "just now"
    if diff < 3600: return f"{diff//60}m ago"
    if diff < 86400: return f"{diff//3600}h ago"
    return f"{diff//86400}d ago"

def get_profile(user_id):
    r = supabase.table("profiles").select("*").eq("id", user_id).single().execute()
    return r.data if r.data else None

# --- Auth routes -----------------------------------------------------------

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("feed"))
    return redirect(url_for("signin"))

@app.route("/signin", methods=["GET", "POST"])
def signin():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Username and password required", "error")
            return render_template("auth.html", mode="signin")
        try:
            res = supabase.auth.sign_in_with_password({
                "email": username + DOMAIN,
                "password": password,
            })
            session["user_id"] = res.user.id
            session["username"] = username
            return redirect(url_for("feed"))
        except Exception as e:
            flash("Invalid credentials", "error")
    return render_template("auth.html", mode="signin")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Username and password required", "error")
            return render_template("auth.html", mode="signup")
        if len(username) < 3 or len(password) < 6:
            flash("Username 3+ chars, password 6+ chars", "error")
            return render_template("auth.html", mode="signup")
        try:
            res = supabase.auth.sign_up({
                "email": username + DOMAIN,
                "password": password,
                "options": {"data": {"username": username}}
            })
            # Create profile row
            supabase.table("profiles").insert({
                "id": res.user.id,
                "username": username,
                "bio": "",
                "verified": False,
            }).execute()
            session["user_id"] = res.user.id
            session["username"] = username
            return redirect(url_for("feed"))
        except Exception as e:
            flash("Username taken or error", "error")
    return render_template("auth.html", mode="signup")

@app.route("/logout")
def logout():
    supabase.auth.sign_out()
    session.clear()
    return redirect(url_for("signin"))

# --- Feed & posts ----------------------------------------------------------

@app.route("/feed")
@login_required
def feed():
    posts = supabase.table("posts").select("*, profiles(username, verified)").order("created_at", desc=True).limit(50).execute().data or []
    # Get current user's likes
    likes = supabase.table("likes").select("post_id").eq("user_id", session["user_id"]).execute().data or []
    liked_ids = {l["post_id"] for l in likes}
    # Counts
    like_counts = {}
    counts_res = supabase.rpc("count_likes").execute() if False else None  # placeholder
    for p in posts:
        c = supabase.table("likes").select("id", count="exact").eq("post_id", p["id"]).execute()
        like_counts[p["id"]] = c.count or 0
        cc = supabase.table("comments").select("id", count="exact").eq("post_id", p["id"]).execute()
        p["comment_count"] = cc.count or 0
    return render_template("feed.html", posts=posts, liked_ids=liked_ids, like_counts=like_counts, time_ago=time_ago)

@app.route("/post", methods=["POST"])
@login_required
def create_post():
    text = request.form.get("text", "").strip()
    if text:
        supabase.table("posts").insert({
            "user_id": session["user_id"],
            "content": text,
            "image_url": None,
        }).execute()
    return redirect(url_for("feed"))

@app.route("/like/<post_id>", methods=["POST"])
@login_required
def toggle_like(post_id):
    existing = supabase.table("likes").select("id").eq("user_id", session["user_id"]).eq("post_id", post_id).execute().data
    if existing:
        supabase.table("likes").delete().eq("id", existing[0]["id"]).execute()
    else:
        supabase.table("likes").insert({"user_id": session["user_id"], "post_id": post_id}).execute()
    return redirect(url_for("feed"))

@app.route("/comment/<post_id>", methods=["POST"])
@login_required
def add_comment(post_id):
    text = request.form.get("text", "").strip()
    if text:
        supabase.table("comments").insert({
            "user_id": session["user_id"],
            "post_id": post_id,
            "content": text,
        }).execute()
    return redirect(url_for("feed"))

# --- Profile ---------------------------------------------------------------

@app.route("/profile")
@login_required
def profile():
    me = get_profile(session["user_id"])
    posts = supabase.table("posts").select("*").eq("user_id", session["user_id"]).order("created_at", desc=True).execute().data or []
    followers = supabase.table("follows").select("id", count="exact").eq("following_id", session["user_id"]).execute().count or 0
    following = supabase.table("follows").select("id", count="exact").eq("follower_id", session["user_id"]).execute().count or 0
    return render_template("profile.html", user=me, posts=posts, followers=followers, following=following, time_ago=time_ago, is_me=True)

@app.route("/user/<username>")
@login_required
def user_profile(username):
    r = supabase.table("profiles").select("*").eq("username", username).single().execute()
    if not r.data:
        return "User not found", 404
    u = r.data
    posts = supabase.table("posts").select("*").eq("user_id", u["id"]).order("created_at", desc=True).execute().data or []
    followers = supabase.table("follows").select("id", count="exact").eq("following_id", u["id"]).execute().count or 0
    following = supabase.table("follows").select("id", count="exact").eq("follower_id", u["id"]).execute().count or 0
    is_me = (u["id"] == session.get("user_id"))
    return render_template("profile.html", user=u, posts=posts, followers=followers, following=following, time_ago=time_ago, is_me=is_me)

@app.route("/follow/<user_id>", methods=["POST"])
@login_required
def toggle_follow(user_id):
    if user_id == session["user_id"]:
        return redirect(request.referrer or url_for("feed"))
    existing = supabase.table("follows").select("id").eq("follower_id", session["user_id"]).eq("following_id", user_id).execute().data
    if existing:
        supabase.table("follows").delete().eq("id", existing[0]["id"]).execute()
    else:
        supabase.table("follows").insert({"follower_id": session["user_id"], "following_id": user_id}).execute()
    return redirect(request.referrer or url_for("feed"))

@app.route("/search")
@login_required
def search():
    q = request.args.get("q", "").strip()
    results = []
    if q:
        results = supabase.table("profiles").select("*").ilike("username", f"%{q}%").limit(20).execute().data or []
    return render_template("search.html", results=results, q=q)

# --- Run -------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
