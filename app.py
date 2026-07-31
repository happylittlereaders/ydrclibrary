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
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

app = Flask(__name__)
# Set a secret key for session management
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "ydrc-library-super-secret-key")

# ==========================================
# 1. Database Connection (Firestore)
# ==========================================
def get_db_client():
    """Initialize Google Cloud Firestore Client using environment variables."""
    try:
        keys_json = os.environ.get("FIRESTORE_KEYS")
        if keys_json:
            key_dict = json.loads(keys_json)
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
# 3. Data Loading & NLP Setup
# ==========================================
CSV_URL = "https://docs.google.com/spreadsheets/d/1wqamTRHb2vUHU_JXFq38NlYy6uQUguEHbuv0XQfdW5M/export?format=csv&gid=897583843"

def load_data():
    """Load and process Google Sheets catalog data into Pandas DataFrame."""
    try:
        df = pd.read_csv(CSV_URL)
        
        # Column mappings based on standard positions
        c = {
            "il": 1, "rec": 2, "title": 3, "author": 5, "quiz": 6,
            "ar": 7, "word": 8, "fnf": 9, "topic": 10, "series": 11,
            "en": 12, "cn": 13
        }

        # Clean ATOS Book Level (Col H)
        df.iloc[:, c['ar']] = pd.to_numeric(
            df.iloc[:, c['ar']].astype(str).str.extract(r'(\d+\.?\d*)')[0],
            errors='coerce'
        ).fillna(0.0)

        # Clean Word Count (Col I)
        word_col_cleaned = df.iloc[:, c['word']].astype(str).str.replace(r'[^\d.]', '', regex=True)
        df.iloc[:, c['word']] = pd.to_numeric(word_col_cleaned, errors='coerce').fillna(0).astype(int)

        df = df.fillna("")

        # Precompute string context for AI Semantic Search
        def build_ai_context(row):
            return (
                f"Title: {row.iloc[c['title']]} | Author: {row.iloc[c['author']]} | "
                f"Topic: {row.iloc[c['topic']]} | Genre: {row.iloc[c['fnf']]} | "
                f"Series: {row.iloc[c['series']]} | Interest Level: {row.iloc[c['il']]} | "
                f"AR Level: {row.iloc[c['ar']]} | Quiz: {row.iloc[c['quiz']]} | "
                f"Words: {row.iloc[c['word']]} | Blurbs: {row.iloc[c['en']]} {row.iloc[c['cn']]}"
            )
        df['_ai_context'] = df.apply(build_ai_context, axis=1)

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

# Initialize SentenceTransformer Model for Semantic Search
nlp_model = None
corpus_embeddings = None
if not df.empty:
    try:
        nlp_model = SentenceTransformer('all-MiniLM-L6-v2')
        corpus_embeddings = nlp_model.encode(df['_ai_context'].tolist(), show_progress_bar=False)
    except Exception as e:
        print(f"❌ NLP Model setup failed: {e}")

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
        return jsonify({"error": "All fields (email, password, nickname) are required."}), 400
    if not validate_email(email):
        return jsonify({"error": "Invalid email format."}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters long."}), 400
    if not db:
        return jsonify({"error": "Database not connected."}), 500

    try:
        doc_ref = db.collection("users").document(email)
        if doc_ref.get().exists:
            return jsonify({"error": "This email is already registered."}), 409

        role = "owner" if email == os.environ.get("OWNER_EMAIL", "") else "user"
        doc_ref.set({
            "email": email,
            "password": make_hash(password),
            "nickname": nickname,
            "role": role,
            "created_at": firestore.SERVER_TIMESTAMP
        })
        return jsonify({"message": "Registration successful! Please log in."}), 201
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

@app.route('/api/auth/reset-password', methods=['POST'])
def reset_password():
    data = request.json or {}
    email = data.get('email', '').strip()
    project_id_key = data.get('project_id_key', '').strip()
    new_password = data.get('new_password', '').strip()

    if not db:
        return jsonify({"error": "Database disconnected."}), 500

    try:
        keys_json = os.environ.get("FIRESTORE_KEYS", "{}")
        expected_project_id = json.loads(keys_json).get("project_id", "")
        
        if project_id_key == expected_project_id:
            db.collection("users").document(email).update({"password": make_hash(new_password)})
            return jsonify({"message": "Password reset successful!"}), 200
        return jsonify({"error": "Incorrect verification key."}), 403
    except Exception as e:
        return jsonify({"error": f"Reset failed: {e}"}), 400

@app.route('/api/users/role', methods=['PUT'])
def update_user_role():
    """Owner-only endpoint to promote/demote user permissions."""
    if session.get('role') != 'owner':
        return jsonify({"error": "Forbidden: Owner access required."}), 403

    data = request.json or {}
    target_email = data.get('email')
    new_role = data.get('role')

    if new_role not in ['user', 'admin']:
        return jsonify({"error": "Invalid role value."}), 400

    try:
        db.collection("users").document(target_email).update({"role": new_role})
        return jsonify({"message": f"Updated {target_email} to {new_role}."}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==========================================
# 5. Book Search & Catalog Endpoints
# ==========================================

@app.route('/api/books', methods=['GET'])
def get_books():
    """Query, filter, and paginate catalog items."""
    if df.empty:
        return jsonify({"books": [], "total": 0, "page": 1, "pages": 0})

    f_df = df.copy()

    # 1. AI Fuzzy/Semantic Search
    query = request.args.get('fuzzy', '').strip()
    if query and nlp_model is not None and corpus_embeddings is not None:
        try:
            q_embed = nlp_model.encode([query])
            scores = cosine_similarity(q_embed, corpus_embeddings).flatten()
            f_df['search_score'] = scores
            f_df = f_df[f_df['search_score'] > 0.12].sort_values(by='search_score', ascending=False)
        except Exception:
            f_df = f_df[f_df.apply(lambda r: query.lower() in str(r.values).lower(), axis=1)]

    # 2. Categorical / Range Filters
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

    # 3. Pagination Setup
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
    """Retrieve complete metadata and blurbs for a single book."""
    if book_id < 0 or book_id >= len(df):
        return jsonify({"error": "Book not found."}), 404

    row = df.iloc[book_id]
    data = {
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
    }
    return jsonify(data)

@app.route('/api/books/random', methods=['GET'])
def get_random_book():
    """Retrieve a random mystery blind box book recommendation."""
    if df.empty:
        return jsonify({"error": "No books available."}), 404
    sampled = df.sample(1)
    book_id = int(sampled.index[0])
    row = sampled.iloc[0]
    return jsonify({
        "id": book_id,
        "title": str(row.iloc[idx['title']]),
        "author": str(row.iloc[idx['author']])
    })

# ==========================================
# 6. Comments CRUD Endpoints
# ==========================================

@app.route('/api/comments', methods=['GET'])
def get_comments():
    """Fetch comments associated with a specific book title."""
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
    """Add new comment or update existing comment."""
    if 'user_email' not in session:
        return jsonify({"error": "Unauthorized: Log in required."}), 401
    if not db:
        return jsonify({"error": "Database disconnected."}), 500

    data = request.json or {}
    book_title = data.get('book')
    text = data.get('text', '').strip()
    comment_id = data.get('comment_id')

    if not text or not book_title:
        return jsonify({"error": "Book title and content required."}), 400

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M")

    try:
        if comment_id:
            # Verify owner or admin before edit
            doc_ref = db.collection("comments").document(comment_id)
            doc = doc_ref.get()
            if doc.exists and (doc.to_dict().get('author_email') == session['user_email'] or session['role'] in ['admin', 'owner']):
                doc_ref.update({"text": text, "time": now_str})
                return jsonify({"message": "Comment updated successfully."}), 200
            return jsonify({"error": "Permission denied."}), 403
        else:
            new_data = {
                "book": book_title,
                "text": text,
                "author_email": session['user_email'],
                "author_nick": session['nickname'],
                "time": now_str,
                "timestamp": firestore.SERVER_TIMESTAMP
            }
            db.collection("comments").add(new_data)
            return jsonify({"message": "Comment posted successfully."}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/comments/<comment_id>', methods=['DELETE'])
def delete_comment(comment_id):
    """Delete a comment by ID."""
    if 'user_email' not in session:
        return jsonify({"error": "Unauthorized."}), 401
    if not db:
        return jsonify({"error": "Database disconnected."}), 500

    try:
        doc_ref = db.collection("comments").document(comment_id)
        doc = doc_ref.get()
        if doc.exists:
            comment = doc.to_dict()
            is_mine = comment.get('author_email') == session['user_email']
            is_admin = session['role'] in ['admin', 'owner']
            if is_mine or is_admin:
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
    """Compute ATOS level distribution for visualizations."""
    if df.empty:
        return jsonify({})
    counts = df.iloc[:, idx['ar']].value_counts().sort_index().to_dict()
    # Convert numpy keys to native strings
    return jsonify({str(k): int(v) for k, v in counts.items()})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
