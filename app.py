import streamlit as st
import pandas as pd
from datetime import datetime
from google.cloud import firestore
from google.oauth2 import service_account
import hashlib
import re
import requests
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

# ==========================================
# 1. Styles and Configuration
# ==========================================
st.set_page_config(page_title="Smart Library · Flagship Edition", layout="wide", page_icon="📚")

st.markdown("""
    <style>
    .stApp { background-color: #fdf6e3; }
    [data-testid="stSidebar"] { background-color: #f0f2f6; border-right: 1px solid #e6e9ef; }
    .sidebar-title { color: #1e3d59; font-size: 1.5em; font-weight: bold; border-bottom: 2px solid #1e3d59; margin-bottom: 15px; }
    
    /* MODIFIED: Increased tile height to 400px to perfectly fit book covers alongside text tags */
    .book-tile {
        background: white; padding: 20px; border-radius: 12px; border: 1px solid #e2d1b0;
        box-shadow: 0 4px 6px rgba(0,0,0,0.05); height: 400px; box-sizing: border-box;
        display: flex; flex-direction: column; justify-content: space-between;
    }
    
    /* FIX: Support auto-wrapping up to 3 lines, then gracefully truncate with ellipses if text overflows */
    .tile-title { 
        color: #1e3d59; font-size: 1.1em; font-weight: bold; margin-bottom: 4px; 
        line-height: 1.3; display: -webkit-box; -webkit-line-clamp: 3; -webkit-box-orient: vertical;
        overflow: hidden; overflow-wrap: break-word; word-wrap: break-word;
    }
    
    /* Added CSS class layout for book cover containment */
    .cover-container {
        display: flex; justify-content: center; align-items: center; margin-bottom: 10px; height: 140px;
    }
    .cover-img {
        max-height: 140px; max-width: 100%; border-radius: 6px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); object-fit: contain;
    }
    
    .tag-container { margin-top: auto; display: flex; flex-wrap: wrap; gap: 5px; margin-bottom: 15px; }
    .tag { padding: 3px 8px; border-radius: 4px; font-size: 0.75em; font-weight: bold; color: white; }
    .tag-ar { background: #ff6e40; }
    .tag-word { background: #1e3d59; }
    .tag-fnf { background: #2a9d8f; }
    .tag-quiz { background: #6d597a; }
    .tag-il { background: #8888cc; }

    .comment-box { background: white; padding: 15px; border-radius: 10px; margin-bottom: 12px; border: 1px solid #eee; border-left: 5px solid #1e3d59; }
    .comment-meta { color: #888; font-size: 0.8em; margin-bottom: 5px; display: flex; justify-content: space-between;}
    .blind-box-container {
        background: white; border: 4px solid #ff6e40; border-radius: 20px; padding: 30px;
        text-align: center; box-shadow: 0 10px 25px rgba(255,110,64,0.15); margin: 15px 0;
    }
    .info-card { background: white; padding: 15px; border-radius: 12px; border-left: 6px solid #ff6e40; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
     
    .user-badge { padding: 5px 10px; border-radius: 15px; font-size: 0.8rem; font-weight: bold; margin-bottom: 10px; display: inline-block; }
    .badge-owner { background-color: #ffd700; color: #000; }
    .badge-admin { background-color: #ff6e40; color: #fff; }
    .badge-user { background-color: #2a9d8f; color: #fff; }
    .badge-guest { background-color: #ccc; color: #555; }
    footer {visibility: hidden;}
    .stAppDeployButton {display: none;}
    [data-testid="stStatusWidget"] {visibility: hidden;}
    a[href*="streamlit.io"] {display: none !important;}
    div[class*="viewerBadge"] {display: none !important;}
    </style>
""", unsafe_allow_html=True)


# ==========================================
# 2. Database and Security Tools
# ==========================================

@st.cache_resource
def get_db_client():
    """Connect to Firestore Database"""
    try:
        # Pull the dictionary from Streamlit Secrets
        key_dict = st.secrets["firestore"]
         
        # Create credentials from the dictionary
        creds = service_account.Credentials.from_service_account_info(key_dict)
         
        # Initialize the client with explicit project and database ID
        return firestore.Client(
            credentials=creds,
            project=key_dict["project_id"].strip(),
            database="default"
        )
    except Exception as e:
        st.error(f"❌ Database Connection Error: {e}")
        return None

# Global database instance
db = get_db_client()

# NLP Semantic Search Precomputation setup
@st.cache_resource
def load_nlp_search_engine(text_corpus):
    """Loads a pre-trained Transformer model and encodes the book catalog"""
    model = SentenceTransformer('all-MiniLM-L6-v2')
    corpus_embeddings = model.encode(text_corpus, show_progress_bar=False)
    return model, corpus_embeddings

def make_hash(password):
    """Simple password hashing"""
    return hashlib.sha256(str.encode(password)).hexdigest()

def check_hashes(password, hashed_text):
    return make_hash(password) == hashed_text

def validate_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email)


# ==========================================
# 3. User Permission Management Logic
# ==========================================

def get_user_role(email):
    """Retrieve user role"""
    if db is None:
        return "guest"
     
    # Check if this is the owner email defined in secrets
    if email == st.secrets.get("owner_email", ""):
        return "owner"
     
    try:
        doc = db.collection("users").document(email).get()
        if doc.exists:
            return doc.to_dict().get("role", "user")
    except Exception:
        pass
    return "guest"

def register_user(email, password, nickname):
    if db is None:
        st.error("Database not connected.")
        return False
         
    # Basic validation to prevent empty documents (like in your screenshot)
    if not email or not password or not nickname:
        st.error("All fields are required for registration.")
        return False

    try:
        doc_ref = db.collection("users").document(email)
        if doc_ref.get().exists:
            st.warning("This email is already registered.")
            return False
         
        # Determine role based on owner email
        role = "owner" if email == st.secrets.get("owner_email", "") else "user"
         
        doc_ref.set({
            "email": email,
            "password": make_hash(password),
            "nickname": nickname,
            "role": role,
            "created_at": firestore.SERVER_TIMESTAMP
        })
        st.success("Registration successful! Please log in.")
        return True
    except Exception as e:
        st.error(f"Registration failed: {e}")
        return False

def login_user(email, password):
    if db is None:
        st.error("Database connection is down.")
        return None
         
    if not email or not password:
        st.error("Please enter both email and password.")
        return None

    try:
        doc = db.collection("users").document(email).get()
        if doc.exists:
            user_data = doc.to_dict()
            if check_hashes(password, user_data.get('password', '')):
                return user_data
            else:
                st.error("Incorrect password.")
        else:
            st.error("User does not exist.")
    except Exception as e:
        # This will catch the 404 if the project/database ID is still wrong
        st.error(f"Login error: {e}")
    return None


# ==========================================
# 4. Data Loading
# ==========================================
CSV_URL = "https://docs.google.com/spreadsheets/d/1wqamTRHb2vUHU_JXFq38NlYy6uQUguEHbuv0XQfdW5M/export?format=csv&gid=897583843"

def fetch_openlibrary_cover(title, author):
    """Utility function to query Open Library API for book artwork dynamically"""
    try:
        query = f"{title} {author}".replace(" ", "+")
        api_url = f"https://openlibrary.org/search.json?q={query}"
        res = requests.get(api_url, timeout=4).json()
        if res.get("docs"):
            for doc in res["docs"]:
                if "cover_i" in doc:
                    return f"https://covers.openlibrary.org/b/id/{doc['cover_i']}-M.jpg"
    except:
        pass
    return ""  # Return empty string instead of a broken placeholder URL link

@st.cache_data(ttl=600)
def load_data():
    try:
        df = pd.read_csv(CSV_URL)
         
        # Mapping accounts for Column A (Timestamp) as Index 0
        c = {
            "il": 1,        # Col B: Interest Level
            "rec": 2,       # Col C: Recommended By
            "title": 3,     # Col D: Book Title
            "author": 5,    # Col F: Author
            "quiz": 6,      # Col G: AR Quiz Number
            "ar": 7,        # Col H: ATOS Book Level
            "word": 8,      # Col I: Word Count
            "fnf": 9,       # Col J: Fiction/Nonfiction
            "topic": 10,    # Col K: Topic-Subtopic
            "series": 11,   # Col L: Series
            "en": 12,       # Col M: ENGLISH Recommendation
            "cn": 13        # Col N: CHINESE Recommendation
        }
         
        # Convert AR level (Col H) - robust handling for strings or numbers
        df.iloc[:, c['ar']] = pd.to_numeric(
            df.iloc[:, c['ar']].astype(str).str.extract(r'(\d+\.?\d*)')[0],
            errors='coerce'
        ).fillna(0.0)
         
        # Convert Word Count (Col I) - Cleaned to handle the dtype error correctly
        word_col_cleaned = df.iloc[:, c['word']].astype(str).str.replace(r'[^\d.]', '', regex=True)
        df.iloc[:, c['word']] = pd.to_numeric(
            word_col_cleaned,
            errors='coerce'
        ).fillna(0).astype(int)
         
        df = df.fillna(" ")
         
        # Precompute string records - NOW INCLUDES EVERYTHING (including levels, quiz numbers, and word counts)
        def build_ai_context(row):
            return (
                f"Title: {row.iloc[c['title']]} | "
                f"Author: {row.iloc[c['author']]} | "
                f"Topic: {row.iloc[c['topic']]} | "
                f"Genre: {row.iloc[c['fnf']]} | "
                f"Series: {row.iloc[c['series']]} | "
                f"Interest Level: {row.iloc[c['il']]} | "
                f"AR Level: {row.iloc[c['ar']]} | "
                f"Quiz: {row.iloc[c['quiz']]} | "
                f"Words: {row.iloc[c['word']]} | "
                f"Blurbs: {row.iloc[c['en']]} {row.iloc[c['cn']]}"
            )
         
        df['_ai_context'] = df.apply(build_ai_context, axis=1)
        
        # Pull Cover Image URLs in batch loop (Cached inside function)
        cover_urls = []
        for _, row in df.iterrows():
            t_val = row.iloc[c['title']]
            a_val = row.iloc[c['author']]
            cover_urls.append(fetch_openlibrary_cover(t_val, a_val))
        df['_cover_url'] = cover_urls
        
        return df, c
    except Exception as e:
        st.error(f"Data loading failed: {e}")
        return pd.DataFrame(), {}

df, idx = load_data()

# Automatically build vector parameters if dataset loaded successfully
if not df.empty:
    nlp_model, corpus_embeddings = load_nlp_search_engine(df['_ai_context'].tolist())


# ==========================================
# 5. Initialize Session State
# ==========================================
state_keys = {
    'bk_focus': None, 'lang_mode': 'EN', 'voted': set(),
    'edit_id': None, 'edit_doc_id': None, 'blind_idx': None,
    'temp_comment': "", 'form_version': 0,
    'logged_in': False, 'user_email': None, 'user_nickname': "Guest", 'user_role': 'guest'
}

for key, val in state_keys.items():
    if key not in st.session_state:
        st.session_state[key] = val


# ==========================================
# 6. Sidebar: User Auth & Management
# ==========================================
with st.sidebar:
    try: st.image("YDRC-logo.png", use_container_width=True)
    except: pass
    
    st.markdown("### 👤 User Center")
    
    if not st.session_state.logged_in:
        auth_mode = st.tabs(["Login", "Register"])
        
        with auth_mode[0]:
            l_email = st.text_input("Email", key="l_email")
            l_pass = st.text_input("Password", type="password", key="l_pass")
            if st.button("🚀 Login"):
                user_info = login_user(l_email, l_pass)
                if user_info:
                    st.session_state.logged_in = True
                    st.session_state.user_email = user_info.get('email', l_email)
                    st.session_state.user_nickname = user_info.get('nickname', 'User')
                    st.session_state.user_role = get_user_role(st.session_state.user_email)
                    st.rerun()

        with auth_mode[1]:
            r_email = st.text_input("Email (Account ID)", key="r_email")
            r_nick = st.text_input("Nickname (Display Name)", key="r_nick")
            r_pass = st.text_input("Password", type="password", key="r_pass")
            if st.button("📝 Register"):
                if validate_email(r_email):
                    if len(r_pass) >= 6:
                        register_user(r_email, r_pass, r_nick)
                    else: st.warning("Password must be at least 6 characters.")
                else: st.warning("Please enter a valid email.")
            
            st.write("---")
            with st.expander("🔑 Forgot/Reset Password"):
                st.caption("Verify Project ID to reset account")
                target_m = st.text_input("Account Email", key="t_m")
                pid_key = st.text_input("Project ID Verification", type="password")
                new_p = st.text_input("New Password", type="password", key="n_p")
                if st.button("Confirm Reset"):
                    try:
                        if pid_key == st.secrets["firestore"]["project_id"]:
                            db.collection("users").document(target_m).update({"password": make_hash(new_p)})
                            st.success("✅ Reset successful! Please log in.")
                        else: st.error("❌ Incorrect verification key.")
                    except: st.error("Reset failed. Email might not be registered.")

    else:
        role_badges = {"owner": "👑 Owner", "admin": "🛡️ Admin", "user": "👤 User"}
        role_cls = f"badge-{st.session_state.user_role}"
        st.markdown(f"""
        <div class='user-badge {role_cls}'>{role_badges.get(st.session_state.user_role, 'Guest')}</div>
        <div style='font-size:1.2em'>Hello, <b>{st.session_state.user_nickname}</b></div>
        """, unsafe_allow_html=True)
        
        if st.button("👋 Log Out"):
            st.session_state.logged_in = False
            st.session_state.user_email = None
            st.session_state.user_nickname = "Guest"
            st.session_state.user_role = "guest"
            st.rerun()

        if st.session_state.user_role == 'owner':
            with st.expander("⚙️ Permissions (Owner Only)"):
                manage_email = st.text_input("User Email")
                new_role = st.selectbox("Set Role", ["user", "admin"])
                if st.button("Update Permissions"):
                    if db:
                        try:
                            db.collection("users").document(manage_email).update({"role": new_role})
                            st.success(f"Set {manage_email} as {new_role}")
                        except Exception as e:
                            st.error(f"Update failed: {e}")

    st.write("---")
    st.markdown('<div class="sidebar-title">🔍 Search Center</div>', unsafe_allow_html=True)


# ==========================================
# 7. Comment Logic
# ==========================================

def load_db_comments(book_title):
    if db is None: return []
    try:
        col_ref = db.collection("comments").where("book", "==", book_title)
        docs = col_ref.stream()
        comments = [{"id": d.id, **d.to_dict()} for d in docs]
        return sorted(comments, key=lambda x: x.get('timestamp', str(datetime.now())), reverse=True)
    except: return []

def save_db_comment(book_title, text, comment_id=None):
    if db is None: return
    data = {
        "book": book_title, "text": text,
        "author_email": st.session_state.user_email,
        "author_nick": st.session_state.user_nickname,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "timestamp": firestore.SERVER_TIMESTAMP
    }
    try:
        if comment_id:
            db.collection("comments").document(comment_id).update({"text": text, "time": data["time"]})
        else:
            db.collection("comments").add(data)
        st.toast("✅ Comment posted", icon='☁️')
    except Exception as e:
        st.error(f"Save failed: {e}")

def delete_comment(comment_id):
    if db:
        try:
            db.collection("comments").document(comment_id).delete()
            st.toast("🗑️ Comment deleted")
        except Exception as e:
            st.error(f"Delete failed: {e}")


# ==========================================
# 8. Book Detail Page
# ==========================================
if st.session_state.bk_focus is not None:
    row = df.iloc[st.session_state.bk_focus]
    title_key = str(row.iloc[idx['title']])
    
    if st.button("⬅️ Back to Library"):
        st.session_state.bk_focus = None
        st.rerun()
    
    st.markdown(f"# 📖 {title_key}")
    
    # Split layout into Book Cover artwork side vs info matrix cards side
    side_c1, side_c2 = st.columns([1, 3])
    
    with side_c1:
        if row['_cover_url']:
            st.image(row['_cover_url'], use_container_width=True)
        else:
            st.markdown("""<div style="width:100%; height:320px; background-color:#f0f2f6; border:2px dashed #cccccc; border-radius:12px; display:flex; flex-direction:column; align-items:center; justify-content:center; color:#777777; font-size:1em; font-weight:bold; text-align:center; padding:20px; box-sizing:border-box;"><div>📚</div><div style="margin-top:10px;">No Book Cover Available</div></div>""", unsafe_allow_html=True)
        
    with side_c2:
        c1, c2, c3 = st.columns(3)
        infos = [
            ("👤 Author", row.iloc[idx['author']]),
            ("📚 Genre", row.iloc[idx['fnf']]),
            ("🎯 Interest Level", row.iloc[idx['il']]),
            ("📊 ATOS Book Level", row.iloc[idx['ar']]),
            ("🔢 Quiz No.", row.iloc[idx['quiz']]),
            ("📝 Word Count", f"{row.iloc[idx['word']]:,}"),
            ("🔗 Series", row.iloc[idx['series']]),
            ("🏷️ Topic", row.iloc[idx['topic']]),
            ("🙋 Recommender", row.iloc[idx['rec']])
        ]
        for i, (l, v) in enumerate(infos):
            with [c1, c2, c3][i % 3]:
                st.markdown(f'<div class="info-card"><small>{l}</small><br><b>{v}</b></div>', unsafe_allow_html=True)

    st.write("#### 🌟 Recommendation Details")
    lb1, lb2, _ = st.columns([1,1,2])
    
    # Swapped Buttons layout configuration preserved safely
    if lb1.button("CN 中文理由", use_container_width=True): st.session_state.lang_mode = "CN"; st.rerun()
    if lb2.button("US English", use_container_width=True): st.session_state.lang_mode = "EN"; st.rerun()
    
    content = row.iloc[idx["cn"]] if st.session_state.lang_mode=="CN" else row.iloc[idx["en"]]
    st.markdown(f'<div style="background:#fffcf5; padding:25px; border-radius:15px; border:2px dashed #ff6e40;">{content}</div>', unsafe_allow_html=True)

    st.markdown("---")
    st.subheader("💬 Comment Area")
    cloud_comments = load_db_comments(title_key)
    
    for i, m in enumerate(cloud_comments):
        is_mine = m.get('author_email') == st.session_state.user_email
        is_admin = st.session_state.user_role in ['admin', 'owner']
        
        st.markdown(f"""
        <div class="comment-box">
            <div class="comment-meta">
                <span>👤 {m.get('author_nick', 'Anonymous')}</span>
                <span>📅 {m.get('time')}</span>
            </div>
            {m.get('text')}
        </div>
        """, unsafe_allow_html=True)
        
        col_ops = st.columns([1, 1, 8])
        if st.session_state.logged_in and is_mine and st.session_state.edit_id is None:
            if col_ops[0].button("✏️", key=f"edit_{i}"):
                st.session_state.edit_id = i; st.session_state.edit_doc_id = m["id"]
                st.session_state.temp_comment = m["text"]; st.session_state.form_version += 1; st.rerun()
        
        if st.session_state.logged_in and (is_mine or is_admin) and st.session_state.edit_id is None:
             if col_ops[1].button("🗑️", key=f"del_{i}"):
                 delete_comment(m["id"]); st.rerun()

    if st.session_state.logged_in:
        is_editing = st.session_state.edit_id is not None
        with st.form("comment_form", clear_on_submit=False):
            st.write("✍️ " + ("Edit Comment" if is_editing else f"Post Comment"))
            user_input = st.text_area("Content", value=st.session_state.temp_comment, key=f"input_area_v{st.session_state.form_version}")
            cb1, cb2, _ = st.columns([1, 1, 4])
            if cb1.form_submit_button("Post" if not is_editing else "Save"):
                if user_input.strip():
                    save_db_comment(title_key, user_input, st.session_state.get('edit_doc_id'))
                    st.session_state.edit_id = None; st.session_state.temp_comment = ""; st.session_state.form_version += 1; st.rerun()
            if is_editing and cb2.form_submit_button("❌ Cancel"):
                st.session_state.edit_id = None; st.session_state.temp_comment = ""; st.session_state.form_version += 1; st.rerun()
    else: st.info("🔒 Guest mode is view-only. Log in to comment.")


# ==========================================
# 9. Main Gallery View
# ==========================================
elif not df.empty:
    with st.sidebar:
        # Upgraded to intelligent non-LLM vector search bar
        f_fuzzy = st.text_input("💡 **Smart AI Search**", placeholder="Enter concepts or keywords...")
        st.write("---")
        f_title = st.text_input("📖 Title")
        f_author = st.text_input("👤 Author")
        f_fnf = st.selectbox("📚 Genre", ["All", "Fiction", "Nonfiction"])
        il_opts = ["All"] + sorted([x for x in df.iloc[:, idx['il']].unique().tolist() if str(x)!="nan"])
        f_il = st.selectbox("🎯 Interest Level", il_opts)
        f_word = st.number_input("📝 Minimum Word Count", min_value=0, step=100)
        f_quiz = st.text_input("🔢 AR Quiz Number")
        f_series = st.text_input("🔗 Series")
        f_topic = st.text_input("🏷️ Topic")
        st.write("---")
        f_ar = st.slider("📊 ATOS Book Level Range", 0.0, 12.0, (0.0, 12.0))

    f_df = df.copy()
    
    # Process NLP Semantic Search matching
    if f_fuzzy.strip():
        with st.spinner("🧠 NLP model understanding your query..."):
            try:
                # Encode the user's natural language search query into an embedding vector
                query_embedding = nlp_model.encode([f_fuzzy])
                
                # Calculate semantic similarity between user query and all books
                scores = cosine_similarity(query_embedding, corpus_embeddings).flatten()
                
                # Apply computed semantic scores
                f_df['search_score'] = scores
                # Filter out completely unrelated books (optimized threshold of 0.12)
                f_df = f_df[f_df['search_score'] > 0.12].sort_values(by='search_score', ascending=False)
            except Exception as ai_err:
                st.sidebar.error(f"NLP search error: {ai_err}")
                f_df = f_df[f_df.apply(lambda r: f_fuzzy.lower() in str(r.values).lower(), axis=1)]

    # Preserve remaining sequential logic processing configurations
    if f_title: f_df = f_df[f_df.iloc[:, idx['title']].astype(str).str.contains(f_title, case=False)]
    if f_author: f_df = f_df[f_df.iloc[:, idx['author']].astype(str).str.contains(f_author, case=False)]
    if f_fnf != "All": f_df = f_df[f_df.iloc[:, idx['fnf']] == f_fnf]
    if f_il != "All": f_df = f_df[f_df.iloc[:, idx['il']] == f_il]
    if f_quiz: f_df = f_df[f_df.iloc[:, idx['quiz']].astype(str).str.contains(f_quiz)]
    if f_series: f_df = f_df[f_df.iloc[:, idx['series']].astype(str).str.contains(f_series, case=False)]
    if f_topic: f_df = f_df[f_df.iloc[:, idx['topic']].astype(str).str.contains(f_topic, case=False)]
    f_df = f_df[(f_df.iloc[:, idx['ar']] >= f_ar[0]) & (f_df.iloc[:, idx['ar']] <= f_ar[1]) & (f_df.iloc[:, idx['word']] >= f_word)]

    tab1, tab2, tab3 = st.tabs(["📚 Book Gallery", "📊 Level Distribution", "🏆 Top Rated"])
   
    with tab1:
        if st.button("🎁 Open Mystery Book Blind Box", use_container_width=True):
            st.balloons()
            st.session_state.blind_idx = f_df.sample(1).index[0] if not f_df.empty else df.sample(1).index[0]
       
        if st.session_state.blind_idx is not None:
            b_row = df.iloc[st.session_state.blind_idx]
            _, b_col, _ = st.columns([1, 2, 1])
            with b_col:
                st.markdown(f'<div class="blind-box-container"><h3>《{b_row.iloc[idx["title"]]}》</h3><p>Author: {b_row.iloc[idx["author"]]}</p></div>', unsafe_allow_html=True)
                if st.button(f"🚀 Click for Details", key="blind_go", use_container_width=True):
                    st.session_state.bk_focus = st.session_state.blind_idx; st.rerun()

        if f_df.empty:
            st.info("No matching books discovered. Try adjusting your query keywords or range limits.")
        else:
            # 📄 PAGINATION CONFIGURATION
            BOOKS_PER_PAGE = 12  
            
            if 'current_page' not in st.session_state:
                st.session_state.current_page = 0
                
            total_books = len(f_df)
            total_pages = (total_books - 1) // BOOKS_PER_PAGE + 1
            
            # Guardrail layout checking
            if st.session_state.current_page >= total_pages:
                st.session_state.current_page = 0

            # Slice dataset chunk
            start_idx = st.session_state.current_page * BOOKS_PER_PAGE
            end_idx = min(start_idx + BOOKS_PER_PAGE, total_books)
            page_chunk = f_df.iloc[start_idx:end_idx]

            # Display the grid of books for the current page chunk
            cols = st.columns(3)
            for i, (orig_idx, row) in enumerate(page_chunk.iterrows()):
                with cols[i % 3]:
                    t = row.iloc[idx['title']]
                    voted = t in st.session_state.voted
                    cover_img_link = row['_cover_url']
                    
                    # FIX: Keep fallback block flat on one line to ensure text isn't treated as plain markdown code text
                    if cover_img_link:
                        cover_html = f'<img class="cover-img" src="{cover_img_link}">'
                    else:
                        cover_html = '<div style="width:100%; height:140px; background-color:#f0f2f6; border:1px dashed #cccccc; border-radius:6px; display:flex; align-items:center; justify-content:center; color:#777777; font-size:0.85em; font-weight:500; text-align:center; padding:10px; box-sizing:border-box;">No Book Cover Available</div>'
                    
                    st.markdown(f"""
                    <div class="book-tile">
                        <div>
                            <div class="cover-container">
                                {cover_html}
                            </div>
                            <div class="tile-title">《{t}》</div>
                            <div style="color:#666; font-size:0.85em; margin-bottom:10px;">{row.iloc[idx["author"]]}</div>
                        </div>
                        <div class="tag-container">
                            <span class="tag tag-ar">ATOS {row.iloc[idx["ar"]]}</span>
                            <span class="tag tag-word">{row.iloc[idx["word"]]:,} Words</span>
                            <span class="tag tag-fnf">{row.iloc[idx["fnf"]]}</span>
                            <span class="tag tag-quiz">Q: {row.iloc[idx["quiz"]]}</span>
                            <span class="tag tag-il">{row.iloc[idx["il"]]}</span>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    cl, cr = st.columns(2)
                    if cl.button("❤️" if voted else "🤍", key=f"h_{orig_idx}", use_container_width=True):
                        if voted: st.session_state.voted.remove(t)
                        else: st.session_state.voted.add(t)
                        st.rerun()
                    
                    if cr.button("View Details", key=f"d_{orig_idx}", use_container_width=True):
                        st.session_state.bk_focus = orig_idx; st.rerun()

            # --- NAVIGATION AND TEXT BOX ROW AT THE BOTTOM (FIXED WIDTH) ---
            st.write("---")
            
            # Isolated callback state functions to guarantee action routing
            def go_first(): st.session_state.current_page = 0
            def go_prev(): st.session_state.current_page -= 1
            def go_next(): st.session_state.current_page += 1
            def go_last(): st.session_state.current_page = total_pages - 1
            
            # Optimized column spacing ratios to perfectly fit everything on one line
            nav_cols = st.columns([1, 1.2, 1, 1, 3.8, 1, 1])
            
            nav_cols[0].button("First", key="b_first", use_container_width=True, disabled=(st.session_state.current_page == 0), on_click=go_first)
            nav_cols[1].button("Previous", key="b_prev", use_container_width=True, disabled=(st.session_state.current_page == 0), on_click=go_prev)
            
            # Text input without + and -
            with nav_cols[2]:
                typed_val = st.text_input(
                    label="Go to page input",
                    value=str(st.session_state.current_page + 1),
                    label_visibility="collapsed",
                    key="direct_page_box"
                )
            
            # Safely triggers changes with direct layout padding protection
            if nav_cols[3].button("Go", key="b_go", use_container_width=True):
                if typed_val.isdigit():
                    parsed_val = int(typed_val)
                    if 1 <= parsed_val <= total_pages:
                        st.session_state.current_page = parsed_val - 1
                        st.rerun()
            
            with nav_cols[4]:
                st.markdown(f"<p style='text-align: left; font-size: 1.05em; padding-top: 5px; margin: 0; padding-left: 10px;'>Page <b>{st.session_state.current_page + 1}</b> of {total_pages} &nbsp;&nbsp;•&nbsp;&nbsp; ({total_books} total books)</p>", unsafe_allow_html=True)
                
            nav_cols[5].button("Next", key="b_next", use_container_width=True, disabled=(st.session_state.current_page >= total_pages - 1), on_click=go_next)
            nav_cols[6].button("Last", key="b_last", use_container_width=True, disabled=(st.session_state.current_page >= total_pages - 1), on_click=go_last)

    with tab2:
        st.subheader("📊 ATOS Book Level Distribution")
        if not f_df.empty:
            st.bar_chart(f_df.iloc[:, idx['ar']].value_counts().sort_index())

    with tab3:
        st.subheader("🏆 Your Favorites")
        if st.session_state.voted:
            title_to_idx = {str(row.iloc[idx['title']]): i for i, row in df.iterrows()}
            for b_name in st.session_state.voted:
                col_n, col_b = st.columns([3, 1])
                with col_n: st.markdown(f"⭐ **{b_name}**")
                with col_b:
                    if b_name in title_to_idx:
                        if st.button("View Details", key=f"fav_{b_name}"):
                            st.session_state.bk_focus = title_to_idx[b_name]; st.rerun()
        else: st.info("No favorites yet, go click ❤️!")
