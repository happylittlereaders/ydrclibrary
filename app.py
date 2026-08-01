from flask import Flask, render_template, request, redirect, url_for, session, flash
import pandas as pd
from datetime import datetime
from google.cloud import firestore
from google.oauth2 import service_account
import hashlib
import re
import requests
import json
import os
from rapidfuzz import process, fuzz

app = Flask(__name__)
# Uses the environment variable set on Render
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "fallback-secret-key")

# ==========================================
# 1. Database Connection
# ==========================================
def get_db_client():
    try:
        firestore_keys = os.environ.get("FIRESTORE_KEYS")
        if firestore_keys:
            key_dict = json.loads(firestore_keys)
            creds = service_account.Credentials.from_service_account_info(key_dict)
            return firestore.Client(
                credentials=creds,
                project=key_dict.get("project_id", "").strip(),
                database="default"
            )
    except Exception as e:
        print(f"❌ Database Connection Error: {e}")
    return None

db = get_db_client()

# ==========================================
# 2. Security & Helper Functions
# ==========================================
def make_hash(password):
    return hashlib.sha256(str.encode(password)).hexdigest()

def check_hashes(password, hashed_text):
    return make_hash(password) == hashed_text

def validate_email(email):
    return re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email)

def get_user_role(email):
    if not db:
        return "guest"
    if email == os.environ.get("OWNER_EMAIL", ""):
        return "owner"
    try:
        doc = db.collection("users").document(email).get()
        if doc.exists:
            return doc.to_dict().get("role", "user")
    except Exception:
        pass
    return "guest"

# ==========================================
# 3. Data Processing & Lazy Loading
# ==========================================
CSV_URL = "https://docs.google.com/spreadsheets/d/1wqamTRHb2vUHU_JXFq38NlYy6uQUguEHbuv0XQfdW5M/export?format=csv&gid=897583843"
_cached_df = None

def fetch_openlibrary_cover(title, author):
    try:
        query = f"{title} {author}".replace(" ", "+")
        api_url = f"https://openlibrary.org/search.json?q={query}"
        res = requests.get(api_url, timeout=3).json()
        if res.get("docs"):
            for doc in res["docs"]:
                if "cover_i" in doc:
                    return f"https://covers.openlibrary.org/b/id/{doc['cover_i']}-M.jpg"
    except Exception:
        pass
    return ""

def load_data():
    global _cached_df
    if _cached_df is not None:
        return _cached_df

    try:
        df = pd.read_csv(CSV_URL)
        c = {
            "il": 1, "rec": 2, "title": 3, "author": 5,
            "quiz": 6, "ar": 7, "word": 8, "fnf": 9,
            "topic": 10, "series": 11, "en": 12, "cn": 13
        }

        # Format numeric columns
        df.iloc[:, c['ar']] = pd.to_numeric(
            df.iloc[:, c['ar']].astype(str).str.extract(r'(\d+\.?\d*)')[0],
            errors='coerce'
        ).fillna(0.0)

        word_cleaned = df.iloc[:, c['word']].astype(str).str.replace(r'[^\d.]', '', regex=True)
        df.iloc[:, c['word']] = pd.to_numeric(word_cleaned, errors='coerce').fillna(0).astype(int)
        df = df.fillna(" ")

        # Context block for RapidFuzz lookup
        def build_search_context(row):
            return (
                f"{row.iloc[c['title']]} {row.iloc[c['author']]} {row.iloc[c['topic']]} "
                f"{row.iloc[c['fnf']]} {row.iloc[c['series']]} {row.iloc[c['en']]} {row.iloc[c['cn']]}"
            )

        df['_search_context'] = df.apply(build_search_context, axis=1)

        # Batch load artwork covers
        cover_urls = []
        for _, row in df.iterrows():
            cover_urls.append(fetch_openlibrary_cover(row.iloc[c['title']], row.iloc[c['author']]))
        df['_cover_url'] = cover_urls

        _cached_df = (df, c)
        return _cached_df
    except Exception as e:
        print(f"Data loading failed: {e}")
        return pd.DataFrame(), {}

# ==========================================
# 4. Web Routes
# ==========================================
@app.route("/", methods=["GET"])
def index():
    df, c = load_data()
    if df.empty:
        return "Database unavailable.", 500

    # Retrieve request parameters for search/filtering
    f_fuzzy = request.args.get("fuzzy", "").strip()
    f_title = request.args.get("title", "").strip()
    f_author = request.args.get("author", "").strip()
    f_fnf = request.args.get("fnf", "All")
    f_il = request.args.get("il", "All")
    f_quiz = request.args.get("quiz", "").strip()
    f_series = request.args.get("series", "").strip()
    f_topic = request.args.get("topic", "").strip()
    f_ar_min = float(request.args.get("ar_min", 0.0))
    f_ar_max = float(request.args.get("ar_max", 12.0))
    f_word = int(request.args.get("word", 0))

    f_df = df.copy()

    # Apply RapidFuzz Fuzzy Match
    if f_fuzzy:
        corpus = f_df['_search_context'].tolist()
        results = process.extract(f_fuzzy, corpus, scorer=fuzz.token_set_ratio, limit=len(corpus))
        matched_indices = [idx for text, score, idx in results if score > 35]
        f_df = f_df.iloc[matched_indices]

    if f_title:
        f_df = f_df[f_df.iloc[:, c['title']].astype(str).str.contains(f_title, case=False)]
    if f_author:
        f_df = f_df[f_df.iloc[:, c['author']].astype(str).str.contains(f_author, case=False)]
    if f_fnf != "All":
        f_df = f_df[f_df.iloc[:, c['fnf']] == f_fnf]
    if f_il != "All":
        f_df = f_df[f_df.iloc[:, c['il']] == f_il]
    if f_quiz:
        f_df = f_df[f_df.iloc[:, c['quiz']].astype(str).str.contains(f_quiz)]
    if f_series:
        f_df = f_df[f_df.iloc[:, c['series']].astype(str).str.contains(f_series, case=False)]
    if f_topic:
        f_df = f_df[f_df.iloc[:, c['topic']].astype(str).str.contains(f_topic, case=False)]

    f_df = f_df[
        (f_df.iloc[:, c['ar']] >= f_ar_min) & 
        (f_df.iloc[:, c['ar']] <= f_ar_max) & 
        (f_df.iloc[:, c['word']] >= f_word)
    ]

    # Pagination setup
    page = int(request.args.get("page", 1))
    per_page = 12
    total_books = len(f_df)
    total_pages = max(1, (total_books - 1) // per_page + 1)
    page = min(max(1, page), total_pages)

    start_idx = (page - 1) * per_page
    end_idx = min(start_idx + per_page, total_books)
    page_chunk = f_df.iloc[start_idx:end_idx]

    il_options = sorted([x for x in df.iloc[:, c['il']].unique().tolist() if str(x) != "nan"])

    return render_template(
        "index.html",
        books=page_chunk,
        idx=c,
        page=page,
        total_pages=total_pages,
        total_books=total_books,
        il_options=il_options,
        filters=request.args,
        user=session.get("user")
    )

@app.route("/book/<int:book_idx>")
def book_detail(book_idx):
    df, c = load_data()
    if book_idx < 0 or book_idx >= len(df):
        return "Book not found", 404

    row = df.iloc[book_idx]
    title = str(row.iloc[c['title']])

    # Load book comments from Firestore
    comments = []
    if db:
        try:
            col_ref = db.collection("comments").where("book", "==", title)
            docs = col_ref.stream()
            comments = [{"id": d.id, **d.to_dict()} for d in docs]
            comments = sorted(comments, key=lambda x: str(x.get('time', '')), reverse=True)
        except Exception as e:
            print(f"Error reading comments: {e}")

    return render_template(
        "detail.html",
        row=row,
        idx=c,
        book_idx=book_idx,
        comments=comments,
        user=session.get("user")
    )

@app.route("/login", methods=["POST"])
def login():
    email = request.form.get("email")
    password = request.form.get("password")

    if not db:
        flash("Database unavailable.", "danger")
        return redirect(url_for("index"))

    doc = db.collection("users").document(email).get()
    if doc.exists:
        user_data = doc.to_dict()
        if check_hashes(password, user_data.get("password", "")):
            session["user"] = {
                "email": email,
                "nickname": user_data.get("nickname", "User"),
                "role": get_user_role(email)
            }
            flash("Welcome back!", "success")
        else:
            flash("Incorrect password.", "danger")
    else:
        flash("User profile not found.", "danger")

    return redirect(url_for("index"))

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("index"))

@app.route("/register", methods=["POST"])
def register():
    email = request.form.get("email")
    password = request.form.get("password")
    nickname = request.form.get("nickname")

    if not validate_email(email) or len(password) < 6:
        flash("Registration invalid.", "danger")
        return redirect(url_for("index"))

    if db:
        doc_ref = db.collection("users").document(email)
        if doc_ref.get().exists:
            flash("Account already exists.", "warning")
        else:
            role = "owner" if email == os.environ.get("OWNER_EMAIL", "") else "user"
            doc_ref.set({
                "email": email,
                "password": make_hash(password),
                "nickname": nickname,
                "role": role,
                "created_at": firestore.SERVER_TIMESTAMP
            })
            flash("Account registered successfully!", "success")
            
    return redirect(url_for("index"))

@app.route("/comment/add", methods=["POST"])
def add_comment():
    user = session.get("user")
    if not user:
        return "Unauthorized", 401

    book_title = request.form.get("book_title")
    text = request.form.get("text")
    book_idx = request.form.get("book_idx")

    if db and text.strip():
        db.collection("comments").add({
            "book": book_title,
            "text": text,
            "author_email": user["email"],
            "author_nick": user["nickname"],
            "time": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "timestamp": firestore.SERVER_TIMESTAMP
        })
    return redirect(url_for("book_detail", book_idx=book_idx))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
