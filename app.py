import os
import json
import re
import hashlib
from datetime import datetime
from flask import Flask, request, jsonify, session
import pandas as pd
import requests
from google.cloud import firestore
from google.oauth2 import service_account
from rapidfuzz import process, fuzz

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "ydrc-library-super-secret-key")

# ==========================================
# 1. Database Connection (Firestore)
# ==========================================
def get_db_client():
    """Initialize Google Cloud Firestore Client using environment variables with PEM fix."""
    try:
        keys_json = os.environ.get("FIRESTORE_KEYS")
        if keys_json:
            key_dict = json.loads(keys_json)
            
            # Fix double-escaped newlines in private_key if present (resolves PEM invalid symbol error)
            if "private_key" in key_dict and isinstance(key_dict["private_key"], str):
                key_dict["private_key"] = key_dict["private_key"].replace("\\n", "\n")
                
            creds = service_account.Credentials.from_service_account_info(key_dict)
            return firestore.Client(
                credentials=creds,
                project=key_dict["project_id"].strip(),
                database="default"
            )
    except Exception as e:
        print(f"❌ Firestore connection error: {e}")
    return None

db = get_db_client()

# ==========================================
# 2. Helper & Security Functions
# ==========================================
def make_hash(password: str) -> str:
    return hashlib.sha256(str.encode(password)).hexdigest()

def validate_email(email: str) -> bool:
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return bool(re.match(pattern, email))

def fetch_openlibrary_cover(title: str, author: str) -> str:
    """Fetch book cover image URL from Open Library API."""
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

def get_user_role(email: str) -> str:
    """Retrieve role for a given user email."""
    if not db:
        return "guest"
    owner_email = os.environ.get("OWNER_EMAIL", "")
    if email == owner_email:
        return "owner"
    try:
        doc = db.collection("users").document(email).get()
        if doc.exists:
            return doc.to_dict().get("role", "user")
    except Exception:
        pass
    return "guest"

# ==========================================
# 3. Data Loading & Context Setup
# ==========================================
CSV_URL = "https://docs.google.com/spreadsheets/d/1wqamTRHb2vUHU_JXFq38NlYy6uQUguEHbuv0XQfdW5M/export?format=csv&gid=897583843"

def load_data():
    """Load and process Google Sheets catalog data into Pandas DataFrame."""
    try:
        df = pd.read_csv(CSV_URL)
        
        c = {
            "il": 1, "rec": 2, "title": 3, "author": 5, "quiz": 6,
            "ar": 7, "word": 8, "fnf": 9, "topic": 10, "series": 11,
            "en": 12, "cn": 13
        }

        # Clean ATOS Book Level
        df.iloc[:, c['ar']] = pd.to_numeric(
            df.iloc[:, c['ar']].astype(str).str.extract(r'(\d+\.?\d*)')[0],
            errors='coerce'
        ).fillna(0.0)

        # Clean Word Count
        word_col_cleaned = df.iloc[:, c['word']].astype(str).str.replace(r'[^\d.]', '', regex=True)
        df.iloc[:, c['word']] = pd.to_numeric(word_col_cleaned, errors='coerce').fillna(0).astype(int)

        df = df.fillna("")

        # Precompute string context for RapidFuzz matching
        def build_search_context(row):
            return (
                f"{row.iloc[c['title']]} {row.iloc[c['author']]} "
                f"{row.iloc[c['topic']]} {row.iloc[c['fnf']]} "
                f"{row.iloc[c['series']]} {row.iloc[c['en']]} {row.iloc[c['cn']]}"
            )
        df['_ai_context'] = df.apply(build_search_context, axis=1)

        # Pre-fetch cover image URLs
        cover_urls = []
        for _, row in df.iterrows():
            cover_urls.append(fetch_openlibrary_cover(row.iloc[c['title']], row.iloc[c['author']]))
        df['_cover_url'] = cover_urls

        return df, c
    except Exception as e:
        print(f"❌ Data loading failed: {e}")
        return pd.DataFrame(), {}

df, idx = load_data()

# ==========================================
# 4. Authentication Endpoints
# ==========================================

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.json or {}
    email = data.get('email', '').strip()
    password = data.get('password', '').strip()
    nickname = data.get('nickname', '').strip()

    if not email or not password or not nickname:
        return jsonify({"error": "All fields required."}), 400
    if not validate_email(email):
        return jsonify({"error": "Invalid email format."}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters long."}), 400
    if not db:
        return jsonify({"error": "Database not connected."}), 500

    try:
        doc_ref = db.collection("users").document(email)
        if doc_ref.get().exists:
            return jsonify({"error": "Email is already registered."}), 409

        role = "owner" if email == os.environ.get("OWNER_EMAIL", "") else "user"
        doc_ref.set({
            "email": email,
            "password": make_hash(password),
            "nickname": nickname,
            "role": role,
            "created_at": firestore.SERVER_TIMESTAMP
        })
        return jsonify({"message": "Registration successful!"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json or {}
    email = data.get('email', '').strip()
    password = data.get('password', '').strip()

    if not email or not password:
        return jsonify({"error": "Email and password required."}), 400
    if not db:
        return jsonify({"error": "Database not connected."}), 500

    try:
        doc = db.collection("users").document(email).get()
        if doc.exists:
            user_data = doc.to_dict()
            if make_hash(password) == user_data.get('password'):
                session['user_email'] = email
                session['nickname'] = user_data.get('nickname', 'User')
                session['role'] = get_user_role(email)
                return jsonify({
                    "message": "Login successful",
                    "user": {
                        "email": session['user_email'],
                        "nickname": session['nickname'],
                        "role": session['role']
                    }
                }), 200
            return jsonify({"error": "Incorrect password."}), 401
        return jsonify({"error": "User does not exist."}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"message": "Logged out successfully."}), 200

@app.route('/api/auth/me', methods=['GET'])
def get_current_user():
    if 'user_email' in session:
        return jsonify({
            "logged_in": True,
            "email": session['user_email'],
            "nickname": session['nickname'],
            "role": session['role']
        })
    return jsonify({"logged_in": False, "role": "guest"}), 200

# ==========================================
# 5. Book Search & Catalog Endpoints
# ==========================================

@app.route('/api/books', methods=['GET'])
def get_books():
    """Query, filter, and paginate catalog items using RapidFuzz."""
    if df.empty:
        return jsonify({"books": [], "total": 0, "page": 1, "pages": 0})

    f_df = df.copy()

    # 1. Lightweight RapidFuzz Fuzzy Search
    query = request.args.get('fuzzy', '').strip()
    if query:
        choices = f_df['_ai_context'].tolist()
        results = process.extract(query, choices, scorer=fuzz.WRatio, limit=100)
        # Keep items with match score greater than 45
        matched_indices = [f_df.index[res[2]] for res in results if res[1] > 45]
        f_df = f_df.loc[matched_indices]

    # 2. Categorical & Range Filters
    title = request.args.get('title', '').strip()
    author = request.args.get('author', '').strip()
    fnf = request.args.get('fnf', 'All').strip()
    il = request.args.get('il', 'All').strip()
    quiz = request.args.get('quiz', '').strip()
    series = request.args.get('series', '').strip()
    topic = request.args.get('topic', '').strip()
    min_words = int(request.args.get('min_words', 0))
    min_ar = float(request.args.get('min_ar', 0.0))
    max_ar = float(request.args.get('max_ar', 12.0))

    if title: f_df = f_df[f_df.iloc[:, idx['title']].astype(str).str.contains(title, case=False)]
    if author: f_df = f_df[f_df.iloc[:, idx['author']].astype(str).str.contains(author, case=False)]
    if fnf != "All": f_df = f_df[f_df.iloc[:, idx['fnf']] == fnf]
    if il != "All": f_df = f_df[f_df.iloc[:, idx['il']] == il]
    if quiz: f_df = f_df[f_df.iloc[:, idx['quiz']].astype(str).str.contains(quiz)]
    if series: f_df = f_df[f_df.iloc[:, idx['series']].astype(str).str.contains(series, case=False)]
    if topic: f_df = f_df[f_df.iloc[:, idx['topic']].astype(str).str.contains(topic, case=False)]

    f_df = f_df[
        (f_df.iloc[:, idx['ar']] >= min_ar) & 
        (f_df.iloc[:, idx['ar']] <= max_ar) & 
        (f_df.iloc[:, idx['word']] >= min_words)
    ]

    # 3. Pagination
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 12))
    total_books = len(f_df)
    total_pages = max((total_books - 1) // per_page + 1, 1)

    start = (page - 1) * per_page
    end = min(start + per_page, total_books)
    page_chunk = f_df.iloc[start:end]

    books = []
    for orig_idx, row in page_chunk.iterrows():
        books.append({
            "id": int(orig_idx),
            "title": str(row.iloc[idx['title']]),
            "author": str(row.iloc[idx['author']]),
            "ar": float(row.iloc[idx['ar']]),
            "word": int(row.iloc[idx['word']]),
            "fnf": str(row.iloc[idx['fnf']]),
            "quiz": str(row.iloc[idx['quiz']]),
            "il": str(row.iloc[idx['il']]),
            "cover_url": str(row['_cover_url'])
        })

    return jsonify({
        "books": books,
        "total": total_books,
        "page": page,
        "pages": total_pages
    })

@app.route('/api/books/<int:book_id>', methods=['GET'])
def get_book_details(book_id):
    if book_id < 0 or book_id >= len(df):
        return jsonify({"error": "Book not found."}), 404

    row = df.iloc[book_id]
    return jsonify({
        "id": book_id,
        "title": str(row.iloc[idx['title']]),
        "author": str(row.iloc[idx['author']]),
        "genre": str(row.iloc[idx['fnf']]),
        "interest_level": str(row.iloc[idx['il']]),
        "atos_level": float(row.iloc[idx['ar']]),
        "quiz_number": str(row.iloc[idx['quiz']]),
        "word_count": int(row.iloc[idx['word']]),
        "series": str(row.iloc[idx['series']]),
        "topic": str(row.iloc[idx['topic']]),
        "recommender": str(row.iloc[idx['rec']]),
        "blurb_en": str(row.iloc[idx['en']]),
        "blurb_cn": str(row.iloc[idx['cn']]),
        "cover_url": str(row['_cover_url'])
    })

@app.route('/api/books/random', methods=['GET'])
def get_random_book():
    if df.empty:
        return jsonify({"error": "No books available."}), 404
    sampled = df.sample(1)
    return jsonify({
        "id": int(sampled.index[0]),
        "title": str(sampled.iloc[0].iloc[idx['title']]),
        "author": str(sampled.iloc[0].iloc[idx['author']])
    })

# ==========================================
# 6. Comments CRUD Endpoints
# ==========================================

@app.route('/api/comments', methods=['GET'])
def get_comments():
    book_title = request.args.get('book')
    if not book_title or not db:
        return jsonify([])
    try:
        col_ref = db.collection("comments").where("book", "==", book_title)
        docs = col_ref.stream()
        comments = [{"id": d.id, **d.to_dict()} for d in docs]
        comments.sort(key=lambda x: x.get('timestamp', str(datetime.now())), reverse=True)
        return jsonify(comments)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/comments', methods=['POST'])
def save_comment():
    if 'user_email' not in session:
        return jsonify({"error": "Unauthorized."}), 401
    if not db:
        return jsonify({"error": "Database disconnected."}), 500

    data = request.json or {}
    book_title = data.get('book')
    text = data.get('text', '').strip()

    if not text or not book_title:
        return jsonify({"error": "Book title and comment text required."}), 400

    try:
        new_data = {
            "book": book_title,
            "text": text,
            "author_email": session['user_email'],
            "author_nick": session['nickname'],
            "time": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "timestamp": firestore.SERVER_TIMESTAMP
        }
        db.collection("comments").add(new_data)
        return jsonify({"message": "Comment posted successfully."}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/comments/<comment_id>', methods=['DELETE'])
def delete_comment(comment_id):
    if 'user_email' not in session:
        return jsonify({"error": "Unauthorized."}), 401
    if not db:
        return jsonify({"error": "Database disconnected."}), 500

    try:
        doc_ref = db.collection("comments").document(comment_id)
        doc = doc_ref.get()
        if doc.exists:
            comment = doc.to_dict()
            if comment.get('author_email') == session['user_email'] or session.get('role') in ['admin', 'owner']:
                doc_ref.delete()
                return jsonify({"message": "Comment deleted."}), 200
            return jsonify({"error": "Permission denied."}), 403
        return jsonify({"error": "Comment not found."}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==========================================
# 7. Analytics & System Stats
# ==========================================

@app.route('/api/stats', methods=['GET'])
def get_stats():
    if df.empty:
        return jsonify({})
    counts = df.iloc[:, idx['ar']].value_counts().sort_index().to_dict()
    return jsonify({str(k): int(v) for k, v in counts.items()})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
