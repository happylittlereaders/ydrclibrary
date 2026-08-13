from flask import Flask, render_template, request, redirect, url_for, session, flash
import pandas as pd
from datetime import datetime
from google.cloud import firestore
from google.oauth2 import service_account
import hashlib
import re
import json
import os
import io
import random
import traceback
import requests
from rapidfuzz import process, fuzz

app = Flask(__name__)
# Uses the secret key set in Render environment variables
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "fallback-secret-key")

# ==========================================
# Safe Conversion Helpers (Prevents 500 Errors)
# ==========================================
def safe_float(val, default=0.0):
    try:
        if val is None or str(val).strip() == "":
            return default
        return float(val)
    except (ValueError, TypeError):
        return default

def safe_int(val, default=0):
    try:
        if val is None or str(val).strip() == "":
            return default
        return int(val)
    except (ValueError, TypeError):
        return default

# ==========================================
# 1. Database Connection & Helpers
# ==========================================
def get_db_client():
    """Establish connection to Google Cloud Firestore using credentials JSON."""
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

def make_hash(password):
    """Hash password using SHA-256."""
    return hashlib.sha256(str.encode(password)).hexdigest()

def check_hashes(password, hashed_text):
    """Verify input password against stored hash."""
    return make_hash(password) == hashed_text

def validate_email(email):
    """Check standard email format."""
    return re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email) if email else False

def get_user_role(email):
    """Determine user role: owner, admin, user, or guest."""
    if not db or not email:
        return "guest"
    if email == os.environ.get("OWNER_EMAIL", ""):
        return "owner"
    try:
        doc = db.collection("users").document(email).get()
        if doc.exists:
            return doc.to_dict().get("role", "user")
    except Exception as e:
        print(f"Error fetching role: {e}")
    return "guest"

# ==========================================
# 2. Data Loading Service (Optimized)
# ==========================================
CSV_URL = "https://docs.google.com/spreadsheets/d/1wqamTRHb2vUHU_JXFq38NlYy6uQUguEHbuv0XQfdW5M/export?format=csv&gid=897583843"
_cached_df = None

def load_data():
    """Load Google Sheet dataset and clean numerical values instantly without blocking HTTP calls."""
    global _cached_df
    if _cached_df is not None:
        return _cached_df

    try:
        # Fetch manually with a browser-like User-Agent — Google Sheets export links
        # sometimes reject/redirect bare urllib requests (which is what pd.read_csv
        # uses internally) when they come from a datacenter IP like Render's.
        resp = requests.get(CSV_URL, headers={"User-Agent": "Mozilla/5.0"}, timeout=15)
        resp.raise_for_status()

        # If Google didn't give us CSV (e.g. an HTML sign-in/interstitial page
        # because of a sharing-permission issue), fail loudly instead of silently.
        content_type = resp.headers.get("Content-Type", "")
        if "csv" not in content_type and resp.text.lstrip().startswith("<"):
            raise ValueError(
                f"Expected CSV but got content-type={content_type!r}; "
                f"first 200 chars: {resp.text[:200]!r}"
            )

        df = pd.read_csv(io.StringIO(resp.text))

        c = {
            "il": 1, "rec": 2, "title": 3, "author": 5,
            "quiz": 6, "ar": 7, "word": 8, "fnf": 9,
            "topic": 10, "series": 11, "en": 12, "cn": 13
        }

        # Resolve positional indices to actual column names once, up front.
        # (Everywhere else in the app still reads via `c` + iloc, which is fine —
        # this only affects the in-place *writes* below.)
        ar_col = df.columns[c['ar']]
        word_col = df.columns[c['word']]

        # Format ATOS Book Level column to float — assign by column name, not
        # df.iloc[:, idx] = ..., because recent pandas versions raise instead of
        # silently upcasting a column's dtype through positional iloc-assignment.
        # .round(1) matters here: binary floats can't represent decimals like
        # 5.7 exactly, so two rows that both "mean" 5.7 can land as slightly
        # different floats (5.7 vs 5.699999999999999) and get treated as
        # separate buckets by value_counts() later — showing up as a stray
        # near-invisible sliver bar next to the real one on the chart.
        df[ar_col] = pd.to_numeric(
            df[ar_col].astype(str).str.extract(r'(\d+\.?\d*)')[0],
            errors='coerce'
        ).fillna(0.0).round(1)

        # Format Word Count column to integer — same fix
        word_cleaned = df[word_col].astype(str).str.replace(r'[^\d.]', '', regex=True)
        df[word_col] = pd.to_numeric(word_cleaned, errors='coerce').fillna(0).astype(int)

        df = df.fillna(" ")

        _cached_df = (df, c)
        return _cached_df
    except Exception as e:
        # Print full traceback (not just str(e)) so Render logs show the real cause
        print(f"❌ Data loading failed: {e}")
        traceback.print_exc()
        return pd.DataFrame(), {}

# ==========================================
# 3. Fuzzy Search Ranking
# ==========================================
def fuzzy_rank(f_df, c, query, cutoff=65):
    """Rank & filter rows by how well `query` matches their metadata fields
    (title, author, series, topic), typo-tolerant.

    Two-pass per field:
      1. Exact substring match -> instant top score (100). This guarantees
         a query like "sound" always surfaces "The Sound of Waves" and
         puts it first, rather than leaving it to fuzzy-score luck.
      2. token_sort_ratio as a typo-tolerant fallback, run against the
         WHOLE field value (not a giant concatenated blob of every field).
         token_sort_ratio compares full strings after sorting their words,
         so it's forgiving of typos and word reordering, but — unlike
         WRatio's partial_ratio component — it won't hand out high scores
         just because a short common word like "the"/"of" happens to
         appear somewhere in a long row. That's what made the old search
         return "every book with a word similar to 'the'".

    Each row's score is the max across fields. Results are actually sorted
    by score (descending) instead of left in arbitrary original-row order,
    so the best matches land on page 1 instead of possibly page 3.
    """
    query_stripped = query.strip()
    if not query_stripped:
        return f_df

    query_lower = query_stripped.lower()
    fields = [c['title'], c['author'], c['series'], c['topic']]

    n = len(f_df)
    scores = [0.0] * n

    for col_idx in fields:
        values = f_df.iloc[:, col_idx].astype(str).tolist()

        # Pass 1: exact substring match, instant max score.
        for i, val in enumerate(values):
            if query_lower in val.lower():
                scores[i] = 100.0

        # Pass 2: typo-tolerant fallback for everything else.
        results = process.extract(
            query_stripped, values, scorer=fuzz.token_sort_ratio, limit=n
        )
        for _, score, idx in results:
            if score > scores[idx]:
                scores[idx] = score

    ranked = sorted(
        ((score, pos) for pos, score in enumerate(scores) if score >= cutoff),
        key=lambda item: item[0],
        reverse=True,
    )

    if not ranked:
        return f_df.iloc[0:0]

    order = [pos for _, pos in ranked]
    return f_df.iloc[order]

# ==========================================
# 4. Shared Filtering Logic
# ==========================================
def apply_filters(df, c, args):
    """Apply all sidebar filters/search to a dataframe. Shared by index() and blind_box()
    so the mystery box always respects whatever filters are currently active."""
    f_fuzzy = args.get("fuzzy", "").strip()
    f_title = args.get("title", "").strip()
    f_author = args.get("author", "").strip()
    f_fnf = args.get("fnf", "All")
    f_il = args.get("il", "All")
    f_quiz = args.get("quiz", "").strip()
    f_series = args.get("series", "").strip()
    f_topic = args.get("topic", "").strip()
    f_ar_min = safe_float(args.get("ar_min"), 0.0)
    f_ar_max = safe_float(args.get("ar_max"), 12.0)
    f_word = safe_int(args.get("word"), 0)

    f_df = df.copy()

    # Rank & filter by fuzzy match — see fuzzy_rank() above.
    if f_fuzzy:
        f_df = fuzzy_rank(f_df, c, f_fuzzy)

    # Specific field filtering
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

    # Numerical range filters
    f_df = f_df[
        (f_df.iloc[:, c['ar']] >= f_ar_min) &
        (f_df.iloc[:, c['ar']] <= f_ar_max) &
        (f_df.iloc[:, c['word']] >= f_word)
    ]

    return f_df

# ==========================================
# 5. Main Dashboard & Search Routes
# ==========================================
@app.route("/", methods=["GET"])
def index():
    df, c = load_data()
    if df.empty:
        return "Database or dataset currently unavailable.", 500

    # Clean URL query parameters
    args = request.args.to_dict()

    f_df = apply_filters(df, c, args)

    # Calculate level distribution for Chart.js.
    # Excludes 0 — that's the placeholder for books with no ATOS level in the
    # sheet (filled in during cleaning), not a real reading level, so it
    # shouldn't get its own bar.
    ar_series = f_df.iloc[:, c['ar']]
    level_counts = ar_series[ar_series > 0].value_counts().sort_index().to_dict()

    # Pagination calculation
    page = safe_int(args.get("page"), 1)
    per_page = 12
    total_books = len(f_df)
    total_pages = max(1, (total_books - 1) // per_page + 1)
    page = min(max(1, page), total_pages)

    start_idx = (page - 1) * per_page
    end_idx = min(start_idx + per_page, total_books)
    page_chunk = f_df.iloc[start_idx:end_idx]

    # Extract distinct interest levels for dropdown
    il_options = sorted([x for x in df.iloc[:, c['il']].unique().tolist() if str(x) != "nan" and str(x).strip() != ""])

    if "favorites" not in session:
        session["favorites"] = []

    # Clean filters passed to pagination links
    filters_clean = {k: v for k, v in args.items() if k != 'page' and v != ''}

    return render_template(
        "index.html",
        books=page_chunk,
        idx=c,
        page=page,
        total_pages=total_pages,
        total_books=total_books,
        il_options=il_options,
        filters=filters_clean,
        user=session.get("user"),
        favorites=session.get("favorites", []),
        level_counts=level_counts
    )

# ==========================================
# 6. Blind Box Route
# ==========================================
@app.route("/blind-box")
def blind_box():
    """Pick a random book from the CURRENTLY FILTERED dataset and redirect to its detail page."""
    df, c = load_data()
    if df.empty:
        flash("Library data is currently unavailable.", "warning")
        return redirect(url_for("index"))

    args = request.args.to_dict()
    f_df = apply_filters(df, c, args)

    filters_clean = {k: v for k, v in args.items() if v != ''}

    if f_df.empty:
        flash("No books match your current filters for the mystery box. Try loosening your filters.", "warning")
        return redirect(url_for("index", **filters_clean))

    # f_df retains original row indices from the full dataframe, so this stays
    # consistent with the book_idx used by book_detail()
    random_idx = random.choice(f_df.index.tolist())
    return redirect(url_for("book_detail", book_idx=random_idx))

# ==========================================
# 7. User Favorites Route
# ==========================================
@app.route("/favorite/toggle", methods=["POST"])
def toggle_favorite():
    title = request.form.get("title")
    favs = session.get("favorites", [])
    if title in favs:
        favs.remove(title)
    else:
        favs.append(title)
    session["favorites"] = favs
    session.modified = True
    return redirect(request.referrer or url_for("index"))

# ==========================================
# 8. User Auth Routes (Login, Register, Reset)
# ==========================================
@app.route("/login", methods=["POST"])
def login():
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")

    if not db:
        flash("Database service unavailable.", "danger")
        return redirect(url_for("index"))

    try:
        doc = db.collection("users").document(email).get()
        if doc.exists:
            user_data = doc.to_dict()
            if check_hashes(password, user_data.get("password", "")):
                session["user"] = {
                    "email": email,
                    "nickname": user_data.get("nickname", "User"),
                    "role": get_user_role(email)
                }
                flash("Logged in successfully!", "success")
            else:
                flash("Incorrect password.", "danger")
        else:
            flash("User account not found.", "danger")
    except Exception as e:
        flash(f"Login error: {e}", "danger")

    return redirect(url_for("index"))

@app.route("/register", methods=["POST"])
def register():
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")
    nickname = request.form.get("nickname", "").strip()

    if not validate_email(email):
        flash("Please enter a valid email address.", "danger")
        return redirect(url_for("index"))

    if len(password) < 6:
        flash("Password must be at least 6 characters.", "warning")
        return redirect(url_for("index"))

    if db:
        try:
            doc_ref = db.collection("users").document(email)
            if doc_ref.get().exists:
                flash("An account with this email already exists.", "warning")
            else:
                role = "owner" if email == os.environ.get("OWNER_EMAIL", "") else "user"
                doc_ref.set({
                    "email": email,
                    "password": make_hash(password),
                    "nickname": nickname,
                    "role": role,
                    "created_at": firestore.SERVER_TIMESTAMP
                })
                flash("Account registered successfully! You can now log in.", "success")
        except Exception as e:
            flash(f"Registration error: {e}", "danger")

    return redirect(url_for("index"))

@app.route("/reset-password", methods=["POST"])
def reset_password():
    email = request.form.get("email", "").strip()
    project_id = request.form.get("project_id", "").strip()
    new_password = request.form.get("new_password", "")

    env_proj_id = os.environ.get("PROJECT_ID", "").strip()

    if not env_proj_id or project_id != env_proj_id:
        flash("Invalid Project ID verification.", "danger")
        return redirect(url_for("index"))

    if len(new_password) < 6:
        flash("New password must be at least 6 characters.", "warning")
        return redirect(url_for("index"))

    if db:
        try:
            doc_ref = db.collection("users").document(email)
            if doc_ref.get().exists:
                doc_ref.update({"password": make_hash(new_password)})
                flash("Password reset successfully! Please log in with your new password.", "success")
            else:
                flash("Account email not found.", "danger")
        except Exception as e:
            flash(f"Reset error: {e}", "danger")

    return redirect(url_for("index"))

@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("Logged out successfully.", "info")
    return redirect(url_for("index"))

# ==========================================
# 9. Book Detail & Comment Routes
# ==========================================
@app.route("/book/<int:book_idx>")
def book_detail(book_idx):
    df, c = load_data()
    if book_idx < 0 or book_idx >= len(df):
        return "Book not found", 404

    row = df.iloc[book_idx]
    title = str(row.iloc[c['title']])
    author = str(row.iloc[c['author']])

    # ------------------------------------------------------------------
    # Find every row in the full dataset that represents the SAME book
    # (matched on title + author) so that duplicate entries — e.g. the
    # same book recommended by multiple people — surface as multiple
    # numbered EN/CN recommendation tabs instead of only showing
    # whichever single row happened to be clicked.
    # ------------------------------------------------------------------
    title_col = df.iloc[:, c['title']].astype(str).str.strip()
    author_col = df.iloc[:, c['author']].astype(str).str.strip()
    dup_mask = (title_col == title.strip()) & (author_col == author.strip())
    dup_rows = df[dup_mask]

    recommendations = []
    for i, (_, drow) in enumerate(dup_rows.iterrows(), start=1):
        recommendations.append({
            "num": i,
            "en": drow.iloc[c['en']],
            "cn": drow.iloc[c['cn']],
            "recommender": drow.iloc[c['rec']],
        })

    # Fallback: should never trigger since `row` itself always matches
    # its own title/author, but guards against an empty list either way.
    if not recommendations:
        recommendations = [{
            "num": 1,
            "en": row.iloc[c['en']],
            "cn": row.iloc[c['cn']],
            "recommender": row.iloc[c['rec']],
        }]

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
        recommendations=recommendations,
        user=session.get("user")
    )

@app.route("/comment/add", methods=["POST"])
def add_comment():
    user = session.get("user")
    if not user:
        flash("You must be logged in to post comments.", "warning")
        return redirect(url_for("index"))

    book_title = request.form.get("book_title")
    text = request.form.get("text", "").strip()
    book_idx = request.form.get("book_idx")

    if db and text:
        try:
            db.collection("comments").add({
                "book": book_title,
                "text": text,
                "author_email": user["email"],
                "author_nick": user["nickname"],
                "time": datetime.now().strftime("%Y-%m-%d %H:%M"),
                "timestamp": firestore.SERVER_TIMESTAMP
            })
            flash("Comment posted successfully!", "success")
        except Exception as e:
            flash(f"Error posting comment: {e}", "danger")

    return redirect(url_for("book_detail", book_idx=book_idx))

# ==========================================
# 10. Application Entrypoint
# ==========================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
