from flask import Flask, render_template_string, request, redirect, url_for, flash, jsonify
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64, hashlib, secrets, string, sqlite3, pathlib

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

DB_PATH = "opsec_ish.db"


# --- Database helpers ---
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS checklist (
                    id INTEGER PRIMARY KEY,
                    item TEXT UNIQUE,
                    done INTEGER DEFAULT 0
                 )''')
    c.execute('''CREATE TABLE IF NOT EXISTS notes (
                    id INTEGER PRIMARY KEY,
                    title TEXT,
                    encrypted_blob TEXT
                 )''')
    c.execute('''CREATE TABLE IF NOT EXISTS threatmodel (
                    id INTEGER PRIMARY KEY,
                    content TEXT
                 )''')
    # sample checklist items
    defaults = [
        ("Use unique passwords or a password manager", 0),
        ("Enable 2FA where available", 0),
        ("Back up important data encrypted", 0),
        ("Keep OS and apps updated", 0),
        ("Use strong passphrases (not reused)", 0),
        ("Minimize sharing PII publicly", 0)
    ]
    for item, done in defaults:
        try:
            c.execute("INSERT OR IGNORE INTO checklist (item, done) VALUES (?,?)", (item, done))
        except:
            pass
    # sample threat model if empty
    c.execute("SELECT COUNT(*) FROM threatmodel")
    if c.fetchone()[0] == 0:
        sample = ("Actors: unknown adversaries, social engineers\n"
                  "Assets: email, bank access, SSH keys, company docs\n"
                  "Entry points: reused passwords, phishing, lost device\n"
                  "Mitigations: 2FA, device encryption, password manager\n")
        c.execute("INSERT INTO threatmodel (content) VALUES (?)", (sample,))
    conn.commit()
    conn.close()

def query_db(q, args=(), one=False):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.execute(q, args)
    rv = cur.fetchall()
    conn.close()
    return (rv[0] if rv else None) if one else rv

def execute_db(q, args=()):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(q, args)
    conn.commit()
    conn.close()


# --- Encryption helpers (PyCryptodome) ---
def derive_key(password: str):
    """Derive 32-byte AES key from password"""
    return hashlib.sha256(password.encode()).digest()

def encrypt_note(password: str, plaintext: str):
    key = derive_key(password)
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return base64.b64encode(nonce + tag + ciphertext).decode()

def decrypt_note(password: str, token: str):
    raw = base64.b64decode(token)
    key = derive_key(password)
    nonce, tag, ciphertext = raw[:16], raw[16:32], raw[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()


# --- Passphrase & password generator ---
def generate_passphrase(num_words=6, separator='-'):
    WORDS = [
        "alpha","bravo","charlie","delta","echo","foxtrot","golf",
        "hotel","india","juliet","kilo","lima","mike","november",
        "oscar","papa","quebec","romeo","sierra","tango","uniform",
        "victor","whiskey","xray","yankee","zulu","cobalt","ember",
        "vector","matrix","quantum","nebula","zenith","aurora","prism"
    ]
    chosen = [secrets.choice(WORDS) for _ in range(num_words)]
    return separator.join(chosen)

def generate_random_password(length=20, use_symbols=True):
    alphabet = string.ascii_letters + string.digits
    if use_symbols:
        alphabet += "!@#$%^&*()-_=+[]{};:,.<>/?"
    return ''.join(secrets.choice(alphabet) for _ in range(length))


# --- HTML Template ---
BASE_HTML = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>OPSEC Assistant iSH</title>
<style>
body{font-family:Inter,Segoe UI,Arial;background:#0f1113;color:#e6edf3;padding:20px}
.card{background:#111217;padding:18px;border-radius:10px;margin-bottom:12px;box-shadow:0 4px 18px rgba(0,0,0,0.6)}
h1{margin:0 0 12px 0}
button,input,textarea,select{padding:8px;border-radius:6px;border:1px solid #2a2f36;background:#0f1113;color:#e6edf3}
.row{display:flex;gap:12px;flex-wrap:wrap}
.col{flex:1;min-width:250px}
label{display:block;margin-bottom:6px;color:#9fb0c8}
.small{font-size:0.9em;color:#aab7c6}
.done{opacity:0.6;text-decoration:line-through}
.pass{font-family:monospace;background:#0b0c0d;padding:6px;border-radius:6px;display:inline-block}
a {color:#6ad1ff}
</style>
</head>
<body>
<div class="card">
<h1>OPSEC Assistant iSH</h1>
<p class="small">Lightweight privacy tool for iSH. Defensive OPSEC only.</p>
</div>

<div class="row">
<div class="col card">
<h3>Checklist</h3>
<form method="POST" action="/toggle_item">
{% for item in checklist %}
<div>
<input type="checkbox" name="item_id" value="{{item['id']}}" {% if item['done'] %}checked{%endif%} onchange="this.form.submit()">
<span class="{% if item['done'] %}done{%endif%}">{{item['item']}}</span>
</div>
{% endfor %}
</form>
<form method="POST" action="/add_check">
<input name="new_item" placeholder="Add checklist item..." style="width:70%">
<button>Add</button>
</form>
</div>

<div class="col card">
<h3>Passphrase Generator</h3>
<form method="POST" action="/generate">
<label>Words</label>
<input type="number" name="num_words" value="6" min="3" max="12">
<label>Separator</label>
<input name="sep" value="-">
<button>Generate</button>
</form>
{% if passphrase %}
<p class="small">Generated:</p>
<div class="pass">{{passphrase}}</div>
{% endif %}
<hr>
<form method="POST" action="/generate_random">
<label>Password length</label>
<input type="number" name="length" value="20" min="8" max="128">
<label><input type="checkbox" name="symbols" checked> Include symbols</label><br>
<button>Generate Random</button>
</form>
{% if randpass %}
<p class="small">Random password:</p>
<div class="pass">{{randpass}}</div>
{% endif %}
</div>
</div>

<div class="card">
<h3>Secure Notes</h3>
<form method="POST" action="/save_note">
<label>Title</label>
<input name="title" required>
<label>Master password</label>
<input name="master" type="password" required>
<label>Note</label>
<textarea name="note" rows="4" style="width:100%"></textarea>
<button>Save</button>
</form>

<h4>Saved Notes</h4>
<form method="POST" action="/decrypt_note">
<label>Select note</label>
<select name="note_id">
{% for n in notes %}
<option value="{{n['id']}}">{{n['title']}}</option>
{% endfor %}
</select>
<label>Master password</label>
<input name="master2" type="password" required>
<button>Decrypt</button>
</form>
{% if decrypted %}
<h4>Decrypted:</h4>
<div style="white-space:pre-wrap;background:#081018;padding:12px;border-radius:8px">{{decrypted}}</div>
{% endif %}
</div>

<div class="card">
<h3>Threat Model</h3>
<form method="POST" action="/save_threat">
<textarea name="content" rows="8" style="width:100%">{{threat}}</textarea>
<button>Save</button>
</form>
</div>

<div class="card small">
<strong>Notes:</strong>
<ul>
<li>Database: <code>{{db}}</code></li>
<li>Keep master passwords secret.</li>
</ul>
</div>

</body>
</html>
"""

# --- Flask Routes ---
@app.route('/')
def index():
    checklist = query_db("SELECT * FROM checklist")
    notes = query_db("SELECT id,title FROM notes")
    tm = query_db("SELECT content FROM threatmodel LIMIT 1", one=True)
    return render_template_string(BASE_HTML,
                                  checklist=checklist,
                                  notes=notes,
                                  threat=tm['content'] if tm else "",
                                  passphrase=None,
                                  randpass=None,
                                  decrypted=None,
                                  db=pathlib.Path(DB_PATH).absolute())

@app.route('/toggle_item', methods=['POST'])
def toggle_item():
    item_id = request.form.get('item_id')
    if item_id:
        cur = query_db("SELECT done FROM checklist WHERE id = ?", (item_id,), one=True)
        if cur:
            execute_db("UPDATE checklist SET done = ? WHERE id = ?", (0 if cur['done'] else 1, item_id))
    return redirect(url_for('index'))

@app.route('/add_check', methods=['POST'])
def add_check():
    text = request.form.get('new_item','').strip()
    if text:
        execute_db("INSERT OR IGNORE INTO checklist (item, done) VALUES (?,0)", (text,))
    return redirect(url_for('index'))

@app.route('/generate', methods=['POST'])
def generate():
    num = int(request.form.get('num_words',6))
    sep = request.form.get('sep','-')[:3]
    ph = generate_passphrase(num_words=num, separator=sep)
    checklist = query_db("SELECT * FROM checklist")
    notes = query_db("SELECT id,title FROM notes")
    tm = query_db("SELECT content FROM threatmodel LIMIT 1", one=True)
    return render_template_string(BASE_HTML,
                                  checklist=checklist,
                                  notes=notes,
                                  passphrase=ph,
                                  randpass=None,
                                  decrypted=None,
                                  threat=tm['content'] if tm else "",
                                  db=pathlib.Path(DB_PATH).absolute())

@app.route('/generate_random', methods=['POST'])
def gen_random():
    length = int(request.form.get('length',20))
    symbols = 'symbols' in request.form
    p = generate_random_password(length=length, use_symbols=symbols)
    checklist = query_db("SELECT * FROM checklist")
    notes = query_db("SELECT id,title FROM notes")
    tm = query_db("SELECT content FROM threatmodel LIMIT 1", one=True)
    return render_template_string(BASE_HTML,
                                  checklist=checklist,
                                  notes=notes,
                                  passphrase=None,
                                  randpass=p,
                                  decrypted=None,
                                  threat=tm['content'] if tm else "",
                                  db=pathlib.Path(DB_PATH).absolute())

@app.route('/save_note', methods=['POST'])
def save_note():
    title = request.form.get('title','Untitled')[:200]
    master = request.form.get('master','')
    note = request.form.get('note','')
    if not master:
        flash("Master password required", "error")
        return redirect(url_for('index'))
    blob = encrypt_note(master, note)
    execute_db("INSERT INTO notes (title, encrypted_blob) VALUES (?,?)", (title, blob))
    flash("Encrypted note saved", "info")
    return redirect(url_for('index'))

@app.route('/decrypt_note', methods=['POST'])
def decrypt_note_route():
    nid = request.form.get('note_id')
    master = request.form.get('master2','')
    row = query_db("SELECT encrypted_blob FROM notes WHERE id = ?", (nid,), one=True)
    notes = query_db("SELECT id,title FROM notes")
    checklist = query_db("SELECT * FROM checklist")
    tm = query_db("SELECT content FROM threatmodel LIMIT 1", one=True)
    decrypted = None
    if row:
        try:
            decrypted = decrypt_note(master, row['encrypted_blob'])
        except:
            flash("Decryption failed. Check master password.", "error")
    return render_template_string(BASE_HTML,
                                  checklist=checklist,
                                  notes=notes,
                                  passphrase=None,
                                  randpass=None,
                                  decrypted=decrypted,
                                  threat=tm['content'] if tm else "",
                                  db=pathlib.Path(DB_PATH).absolute())

@app.route('/save_threat', methods=['POST'])
def save_threat():
    content = request.form.get('content','')
    execute_db("UPDATE threatmodel SET content = ? WHERE id = 1", (content,))
    flash("Threat model saved", "info")
    return redirect(url_for('index'))

@app.route('/api/export/checklist')
def api_export():
    items = query_db("SELECT item, done FROM checklist")
    out = [{"item": r['item'], "done": bool(r['done'])} for r in items]
    return jsonify(out)


if __name__ == '__main__':
    init_db()
    # iSH-friendly host binding
    app.run(host="127.0.0.1", port=5000, debug=True)