import os
import uuid
from datetime import datetime
from flask import Flask, render_template, render_template_string, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import OperationalError
from werkzeug.utils import secure_filename
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO, join_room, leave_room, send

app = Flask(__name__)
app.secret_key = "your_secret_key"  # Change to a secure key
bcrypt = Bcrypt(app)
socketio = SocketIO(app, cors_allowed_origins="http://localhost:5000")
# --- File upload config ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {
    "png", "jpg", "jpeg", "gif", "webp",
    "pdf", "doc", "docx", "txt"
}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB limit

# --- Database config ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///notes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- Models ---
class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

class Note(db.Model):
    __tablename__ = "note"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    attachment = db.Column(db.String(255))  # stores uploaded file name

class Group(db.Model):
    __tablename__ = "groups"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    uuid_link = db.Column(db.String(36), unique=True, nullable=False)
    created_at = db.Column(db.String(30), nullable=False)

class GroupMember(db.Model):
    __tablename__ = "group_members"
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('groups.id'), primary_key=True)

class Message(db.Model):
    __tablename__ = "messages"
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('groups.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.String(30), nullable=False)

# --- Helpers ---
def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def unique_filename(original_name: str) -> str:
    name = secure_filename(original_name)
    base, ext = os.path.splitext(name)
    return f"{uuid.uuid4().hex}{ext.lower()}"

def delete_file_if_exists(filename: str):
    if not filename:
        return
    path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass

def ensure_attachment_column():
    try:
        result = db.session.execute(db.text("PRAGMA table_info(note);"))
        cols = [row[1] for row in result]
        if "attachment" not in cols:
            db.session.execute(db.text("ALTER TABLE note ADD COLUMN attachment VARCHAR(255);"))
            db.session.commit()
    except Exception:
        db.session.rollback()

def init_db():
    try:
        db.create_all()
        ensure_attachment_column()
    except Exception as e:
        print("Error creating/upgrading database:", e)

# Initialize database at startup
with app.app_context():
    init_db()

# --- Routes ---

# Root route redirects to /code
@app.route('/')
def index():
    return redirect(url_for('code_page'))

# Signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        if not username or not password:
            flash("Username and password cannot be empty!", "error")
            return redirect(url_for('signup'))
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        try:
            user = User(username=username, password=hashed_password)
            db.session.add(user)
            db.session.commit()
            flash('Account created! Please log in.', 'success')
            return redirect(url_for('login'))
        except db.exc.IntegrityError:
            db.session.rollback()
            flash('Username already taken.', 'error')
            return redirect(url_for('signup'))
    
    return render_template('signup.html')

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['username'] = username
            flash('Logged in successfully!', 'success')
            return redirect(url_for('code_page'))  # Redirect to code.html after login
        flash('Invalid username or password.', 'error')
        return redirect(url_for('login'))
    
    return render_template('login.html')

# Dashboard
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        flash('Please log in.', 'error')
        return redirect(url_for('login'))
    user = User.query.filter_by(username=session['username']).first()
    if not user:
        session.pop('username', None)
        flash('User not found.', 'error')
        return redirect(url_for('login'))
    
    # Count user's created groups
    group_count = Group.query.filter_by(owner_id=user.id).count()
    
    # List joined groups
    groups = db.session.query(Group).join(GroupMember).filter(GroupMember.user_id == user.id).all()
    
    return render_template('dashboard.html', username=session['username'], group_count=group_count, groups=groups)

# Create group
@app.route('/create_group', methods=['POST'])
def create_group():
    if 'username' not in session:
        flash('Please log in.', 'error')
        return redirect(url_for('login'))
    user = User.query.filter_by(username=session['username']).first()
    if not user:
        session.pop('username', None)
        flash('User not found.', 'error')
        return redirect(url_for('login'))
    
    if Group.query.filter_by(owner_id=user.id).count() >= 4:
        flash('Max groups reached.', 'error')
        return redirect(url_for('dashboard'))
    
    group_name = request.form.get('group_name', '').strip()
    if not group_name:
        flash('Group name cannot be empty.', 'error')
        return redirect(url_for('dashboard'))
    
    uuid_link = str(uuid.uuid4())
    group = Group(name=group_name, owner_id=user.id, uuid_link=uuid_link, created_at=datetime.now().isoformat())
    db.session.add(group)
    db.session.flush()  # Get group.id before commit
    db.session.add(GroupMember(user_id=user.id, group_id=group.id))
    db.session.commit()
    flash('Group created!', 'success')
    return redirect(url_for('dashboard'))

# Join group via link
@app.route('/join/<uuid_link>')
def join(uuid_link):
    if 'username' not in session:
        flash('Please log in.', 'error')
        return redirect(url_for('login'))
    user = User.query.filter_by(username=session['username']).first()
    if not user:
        session.pop('username', None)
        flash('User not found.', 'error')
        return redirect(url_for('login'))
    
    group = Group.query.filter_by(uuid_link=uuid_link).first()
    if not group:
        flash('Invalid link.', 'error')
        return redirect(url_for('dashboard'))
    
    existing_member = GroupMember.query.filter_by(user_id=user.id, group_id=group.id).first()
    if not existing_member:
        db.session.add(GroupMember(user_id=user.id, group_id=group.id))
        db.session.commit()
        flash('Joined group!', 'success')
    return redirect(url_for('chat', group_id=group.id))

# Chat room
@app.route('/chat/<int:group_id>')
def chat(group_id):
    if 'username' not in session:
        flash('Please log in.', 'error')
        return redirect(url_for('login'))
    user = User.query.filter_by(username=session['username']).first()
    if not user:
        session.pop('username', None)
        flash('User not found.', 'error')
        return redirect(url_for('login'))
    
    member = GroupMember.query.filter_by(user_id=user.id, group_id=group_id).first()
    if not member:
        flash('Not a member.', 'error')
        return redirect(url_for('dashboard'))
    
    group = Group.query.get_or_404(group_id)
    messages = db.session.query(Message, User.username).join(User, Message.user_id == User.id).filter(Message.group_id == group_id).order_by(Message.timestamp).all()
    print(f"Rendering chat.html with group_id: {group_id}")  # Debug print
    return render_template('chat.html', group_name=group.name, group_id=group_id, messages=messages)

# SocketIO: Join room
@socketio.on('join')
def on_join(data):
    group_id = data['group_id']
    join_room(str(group_id))

# SocketIO: Send message
@socketio.on('send_message')
def on_message(data):
    if 'username' not in session:
        return
    user = User.query.filter_by(username=session['username']).first()
    if not user:
        return
    group_id = data['group_id']
    message_content = data['message']
    timestamp = datetime.now().isoformat()
    
    message = Message(group_id=group_id, user_id=user.id, content=message_content, timestamp=timestamp)
    db.session.add(message)
    db.session.commit()
    
    send({'username': session['username'], 'message': message_content}, to=str(group_id))

# Logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Logged out.', 'success')
    return redirect(url_for('login'))

# Main Notes page (renamed to avoid endpoint conflict)
@app.route('/notes')
def notes_index():
    if 'username' not in session:
        flash('Please log in.', 'error')
        return redirect(url_for('login'))
    try:
        notes = Note.query.order_by(Note.id.desc()).all()
    except OperationalError:
        init_db()
        notes = []
    return render_template('index.html', notes=notes)

# AI Study Partner (code.html) page
@app.route('/code')
def code_page():
    if 'username' not in session:
        return render_template('code.html')  # Allow access without login for landing page
    return render_template('code.html')

# Add Note (updated url_for to match new route name)
@app.route('/add', methods=['POST'])
def add_note():
    if 'username' not in session:
        flash('Please log in.', 'error')
        return redirect(url_for('login'))
    title = request.form.get('title', '').strip()
    content = request.form.get('content', '').strip()
    if not title or not content:
        flash("Title and content cannot be empty!", "error")
        return redirect(url_for('notes_index'))  # Updated to notes_index

    file = request.files.get('attachment')
    filename = None
    if file and file.filename:
        if not allowed_file(file.filename):
            flash("Unsupported file type.", "error")
            return redirect(url_for('notes_index'))  # Updated to notes_index
        filename = unique_filename(file.filename)
        save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(save_path)

    db.session.add(Note(title=title, content=content, attachment=filename))
    db.session.commit()
    flash("Note added!", "success")
    return redirect(url_for('notes_index'))  # Updated to notes_index

# Edit Note (updated url_for to match new route name)
@app.route('/edit/<int:id>', methods=['POST'])
def edit_note(id):
    if 'username' not in session:
        flash('Please log in.', 'error')
        return redirect(url_for('login'))
    note = Note.query.get_or_404(id)
    new_title = request.form.get('title', '').strip()
    new_content = request.form.get('content', '').strip()

    if not new_title or not new_content:
        flash("Title and content cannot be empty!", "error")
        return redirect(url_for('notes_index'))  # Updated to notes_index

    file = request.files.get('attachment')
    if file and file.filename:
        if not allowed_file(file.filename):
            flash("Unsupported file type.", "error")
            return redirect(url_for('notes_index'))  # Updated to notes_index
        if note.attachment:
            delete_file_if_exists(note.attachment)
        filename = unique_filename(file.filename)
        save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(save_path)
        note.attachment = filename

    note.title = new_title
    note.content = new_content
    db.session.commit()
    flash("Note updated!", "success")
    return redirect(url_for('notes_index'))  # Updated to notes_index

# Delete Note (updated url_for to match new route name)
@app.route('/delete/<int:id>')
def delete_note(id):
    if 'username' not in session:
        flash('Please log in.', 'error')
        return redirect(url_for('login'))
    note = Note.query.get_or_404(id)
    if note.attachment:
        delete_file_if_exists(note.attachment)
    db.session.delete(note)
    db.session.commit()
    flash("Note deleted!", "success")
    return redirect(url_for('notes_index'))  # Updated to notes_index

# --- Run ---
if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)