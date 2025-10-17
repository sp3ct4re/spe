from flask import Flask, render_template_string, request, redirect, url_for, flash, jsonify
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from base64 import urlsafe_b64encode
import os, sqlite3, secrets, string, json, pathlib, hashlib

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

DB_PATH = "opsec_assistant.db"
SALT = b'opsec_fixed_salt_please_change'  # change to random on first run if you like


# --- Simple DB helpers ---
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
                    encrypted_blob BLOB
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


# --- Crypto helpers ---
def derive_key(password: str, salt: bytes = SALT):
    # PBKDF2 to produce a 32-byte key, base64-urlsafe for Fernet
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
    )
    key = urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_note(password: str, plaintext: str) -> bytes:
    key = derive_key(password)
    f = Fernet(key)
    return f.encrypt(plaintext.encode())

def decrypt_note(password: str, token: bytes) -> str:
    key = derive_key(password)
    f = Fernet(key)
    return f.decrypt(token).decode()


# --- Passphrase generator ---
def generate_passphrase(num_words=6, separator='-'):
    # built-in small wordlist to avoid external downloads (you can replace)
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


# --- Routes / Views ---
BASE_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>OPSEC Assistant</title>
  <style>
    body{font-family:Inter,Segoe UI,Arial;background:#0f1113;color:#e6edf3;padding:20px}
    .card{background:#111217;padding:18px;border-radius:10px;margin-bottom:12px;box-shadow:0 4px 18px rgba(0,0,0,0.6)}
    h1{margin:0 0 12px 0}
    button, input, textarea, select{padding:8px;border-radius:6px;border:1px solid #2a2f36;background:#0f1113;color:#e6edf3}
    .row{display:flex;gap:12px}
    .col{flex:1}
    label{display:block;margin-bottom:6px;color:#9fb0c8}
    .small{font-size:0.9em;color:#aab7c6}
    .done{opacity:0.6;text-decoration:line-through}
    .pass{font-family:monospace;background:#0b0c0d;padding:6px;border-radius:6px;display:inline-block}
    a {color:#6ad1ff}
  </style>
</head>
<body>
  <div class="card">
    <h1>OPSEC Assistant</h1>
    <p class="small">Defensive OPSEC toolkit — privacy hygiene, passphrases, encrypted notes, and threat model. Run locally. For lawful use only.</p>
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
        <label>Words (diceware-style)</label>
        <input type="number" name="num_words" value="6" min="3" max="12">
        <label>Separator</label>
        <input name="sep" value="-">
        <button>Generate Passphrase</button>
      </form>
      {% if passphrase %}
        <p class="small">Generated passphrase:</p>
        <div class="pass">{{passphrase}}</div>
      {% endif %}
      <hr>
      <form method="POST" action="/generate_random">
        <label>Random password length</label>
        <input type="number" name="length" value="20" min="8" max="128">
        <label><input type="checkbox" name="symbols" checked> Include symbols</label><br>
        <button>Generate Random Password</button>
      </form>
      {% if randpass %}
        <p class="small">Random password:</p>
        <div class="pass">{{randpass}}</div>
      {% endif %}
    </div>
  </div>

  <div class="card">
    <h3>Secure Notes (encrypted)</h3>
    <form method="POST" action="/save_note">
      <label>Title</label>
      <input name="title" required>
      <label>Master password (used to encrypt/decrypt notes) — keep this safe</label>
      <input name="master" type="password" required>
      <label>Note</label>
      <textarea name="note" rows="4" style="width:100%"></textarea>
      <button>Save Encrypted Note</button>
    </form>
    <h4>Saved Notes</h4>
    <div class="small">To decrypt a note, enter the same master password used to encrypt it.</div>
    <form method="POST" action="/decrypt_note" style="margin-top:8px">
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
    <h3>Threat Model (editable)</h3>
    <form method="POST" action="/save_threat">
      <textarea name="content" rows="8" style="width:100%">{{threat}}</textarea>
      <button>Save Threat Model</button>
    </form>
  </div>

  <div class="card small">
    <strong>Notes & safety:</strong>
    <ul>
      <li>This tool stores data in a local sqlite file: <code>{{db}}</code></li>
      <li>Change the SALT constant if you want a fresh salt; do not share your master password.</li>
      <li>For stronger production use, add rate-limiting, HTTPS, and use hardware-backed key storage.</li>
    </ul>
  </div>
</body>
</html>
"""

@app.route('/')
def index():
    checklist = query_db("SELECT * FROM checklist")
    notes = query_db("SELECT id,title FROM notes")
    tm = query_db("SELECT content FROM threatmodel LIMIT 1", one=True)
    return render_template_string(BASE_HTML,
                                  checklist=checklist,
                                  notes=notes,
                                  threat=tm['content'] if tm else "",
                                  db=pathlib.Path(DB_PATH).absolute(),
                                  passphrase=None,
                                  randpass=None,
                                  decrypted=None)

@app.route('/toggle_item', methods=['POST'])
def toggle_item():
    # expects checkbox submission (single value)
    item_id = request.form.get('item_id')
    if item_id:
        cur = query_db("SELECT done FROM checklist WHERE id = ?", (item_id,), one=True)
        if cur:
            new = 0 if cur['done'] else 1
            execute_db("UPDATE checklist SET done = ? WHERE id = ?", (new, item_id))
    return redirect(url_for('index'))

@app.route('/add_check', methods=['POST'])
def add_check():
    text = request.form.get('new_item','').strip()
    if text:
        execute_db("INSERT OR IGNORE INTO checklist (item, done) VALUES (?,0)", (text,))
    return redirect(url_for('index'))

@app.route('/generate', methods=['POST'])
def generate():
    num = int(request.form.get('num_words', 6))
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
    symbols = ('symbols' in request.form)
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
        flash("Master password required to encrypt note", "error")
        return redirect(url_for('index'))
    blob = encrypt_note(master, note)
    execute_db("INSERT INTO notes (title, encrypted_blob) VALUES (?,?)", (title, blob))
    flash("Encrypted note saved", "info")
    return redirect(url_for('index'))

@app.route('/decrypt_note', methods=['POST'])
def decrypt_note():
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
        except Exception as e:
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

# simple API endpoint to export checklist as JSON
@app.route('/api/export/checklist')
def api_export():
    items = query_db("SELECT item, done FROM checklist")
    out = [{"item": r['item'], "done": bool(r['done'])} for r in items]
    return jsonify(out)


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
