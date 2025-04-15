# app.py - Main Application File
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import tempfile
import secrets
from datetime import datetime
import sys
from pathlib import Path
import io

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///stego_service.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize database
db = SQLAlchemy(app)

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Add relationship to posts
    posts = db.relationship('StegoPost', backref='author', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class StegoPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    original_filename = db.Column(db.String(200), nullable=False)
    carrier_path = db.Column(db.String(200), nullable=False)
    file_type = db.Column(db.String(50))  # Store file MIME type
    is_image = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    start_bit = db.Column(db.Integer)
    periodicity = db.Column(db.Integer)
    mode = db.Column(db.String(50))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Steganography functions from the provided code
def bits_from_bytes(data):
    """Convert bytes to a generator of individual bits."""
    for byte in data:
        for i in range(7, -1, -1):  # MSB to LSB
            yield (byte >> i) & 1

def bytes_from_bits(bits):
    """Convert an iterable of bits back to bytes."""
    result = bytearray()
    byte = 0
    for i, bit in enumerate(bits):
        byte = (byte << 1) | bit
        if (i + 1) % 8 == 0:
            result.append(byte)
            byte = 0
    # Handle any remaining bits
    if len(result) * 8 < len(bits):
        remaining_bits = len(bits) % 8
        if remaining_bits > 0:
            byte = byte << (8 - remaining_bits)
            result.append(byte)
    return bytes(result)

def get_periodicity_sequence(mode, base_l):
    """Generate a sequence of periodicity values based on mode."""
    if mode == 'constant':
        while True:
            yield base_l
    elif mode == 'alternating':
        # Alternates between L and 2*L
        while True:
            yield base_l
            yield base_l * 2
    elif mode == 'increasing':
        # Increases L by 4 each time, resets after L+20
        l = base_l
        max_l = base_l + 20
        while True:
            yield l
            l += 4
            if l > max_l:
                l = base_l
    elif mode == 'fibonacci':
        # Uses Fibonacci sequence starting with L, L
        a, b = base_l, base_l
        while True:
            yield a
            a, b = b, a + b
            # Prevent L from getting too large
            if b > base_l * 10:
                a, b = base_l, base_l
    else:
        # Default to constant mode
        while True:
            yield base_l

def hide_message(carrier_data, message_data, start_bit, base_periodicity, mode):
    """Hide a message in a carrier file using bit-level steganography."""
    # Prepare message size (32 bits) to prepend to message
    message_size = len(message_data) * 8
    size_bits = [(message_size >> i) & 1 for i in range(31, -1, -1)]
    
    # Combine size and message bits
    message_bits = list(bits_from_bytes(message_data))
    all_message_bits = size_bits + message_bits
    
    # Convert carrier to bit array for manipulation
    carrier_bits = list(bits_from_bytes(carrier_data))
    
    # Make sure carrier is large enough
    if len(carrier_bits) < start_bit:
        raise ValueError(f"Carrier file too small for specified start_bit {start_bit}")
    
    # Calculate required carrier size
    required_bits = start_bit
    l_generator = get_periodicity_sequence(mode, base_periodicity)
    msg_index = 0
    bit_index = start_bit
    
    # First pass to check if the carrier is large enough
    while msg_index < len(all_message_bits):
        periodicity = next(l_generator)
        bit_index += periodicity
        required_bits = max(required_bits, bit_index)
        msg_index += 1
    
    if len(carrier_bits) < required_bits:
        raise ValueError(f"Carrier file too small. Need at least {required_bits} bits, but carrier has only {len(carrier_bits)} bits.")
    
    # Reset for actual embedding
    l_generator = get_periodicity_sequence(mode, base_periodicity)
    
    # Embed the message
    for i in range(len(all_message_bits)):
        periodicity = next(l_generator)
        bit_positions = [start_bit]
        for j in range(i):
            bit_positions.append(next(l_generator))
        bit_pos = start_bit + sum(bit_positions[1:])
        if bit_pos < len(carrier_bits):
            carrier_bits[bit_pos] = all_message_bits[i]
        else:
            break
    
    # Convert back to bytes
    return bytes_from_bits(carrier_bits)

def extract_message(carrier_data, start_bit, base_periodicity, mode):
    """Extract a hidden message from a carrier file."""
    carrier_bits = list(bits_from_bytes(carrier_data))
    
    if len(carrier_bits) <= start_bit:
        raise ValueError(f"Carrier file too small for specified start_bit {start_bit}")
    
    # Extract message size first (first 32 bits of the hidden message)
    l_generator = get_periodicity_sequence(mode, base_periodicity)
    extracted_size_bits = []
    
    # Extract 32 bits for the size
    for i in range(32):
        bit_positions = [start_bit]
        for j in range(i):
            bit_positions.append(next(l_generator))
        bit_pos = start_bit + sum(bit_positions[1:])
        if bit_pos < len(carrier_bits):
            extracted_size_bits.append(carrier_bits[bit_pos])
        else:
            raise ValueError("Carrier file too small to contain a valid message")
    
    # Calculate message size
    message_size_bits = 0
    for bit in extracted_size_bits:
        message_size_bits = (message_size_bits << 1) | bit
    
    # Extract the message itself
    l_generator = get_periodicity_sequence(mode, base_periodicity)
    extracted_message_bits = []
    
    # Skip the size bits in the generator
    for _ in range(32):
        next(l_generator)
    
    # Extract message bits
    for i in range(message_size_bits):
        bit_positions = [start_bit]
        for j in range(i + 32):  # +32 for the size bits
            bit_positions.append(next(l_generator))
        bit_pos = start_bit + sum(bit_positions[1:])
        if bit_pos < len(carrier_bits):
            extracted_message_bits.append(carrier_bits[bit_pos])
        else:
            break
    
    # Convert bits back to bytes
    return bytes_from_bits(extracted_message_bits)

# Routes
@app.route('/')
def index():
    # Get the latest stego posts
    posts = StegoPost.query.order_by(StegoPost.created_at.desc()).all()
    return render_template('index.html', posts=posts)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))
        
        # Check if username exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        
        # Check if email exists
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash('Email already exists', 'danger')
            return redirect(url_for('register'))
        
        # Create new user
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get user's posts
    user_posts = StegoPost.query.filter_by(user_id=current_user.id).order_by(StegoPost.created_at.desc()).all()
    return render_template('dashboard.html', user=current_user, posts=user_posts)

@app.route('/create_stego', methods=['GET', 'POST'])
@login_required
def create_stego():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        start_bit = int(request.form.get('start_bit', 0))
        periodicity = int(request.form.get('periodicity', 8))
        mode = request.form.get('mode', 'constant')
        
        # Check if files were uploaded
        if 'carrier_file' not in request.files or 'message_file' not in request.files:
            flash('Both carrier and message files are required', 'danger')
            return redirect(request.url)
            
        carrier_file = request.files['carrier_file']
        message_file = request.files['message_file']
        
        # Check if files were selected
        if carrier_file.filename == '' or message_file.filename == '':
            flash('Both carrier and message files are required', 'danger')
            return redirect(request.url)
        
        # Read file data
        carrier_data = carrier_file.read()
        message_data = message_file.read()
        
        try:
            # Hide the message in the carrier
            modified_carrier = hide_message(carrier_data, message_data, start_bit, periodicity, mode)
            
            # Save the modified carrier
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            original_filename = secure_filename(carrier_file.filename)
            filename_parts = os.path.splitext(original_filename)
            new_filename = f"{filename_parts[0]}_{timestamp}{filename_parts[1]}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
            
            with open(file_path, 'wb') as f:
                f.write(modified_carrier)
            
            # Determine if the file is an image
            is_image = False
            file_type = ''
            if carrier_file.content_type.startswith('image/'):
                is_image = True
                file_type = carrier_file.content_type
            
            # Create new stego post
            new_post = StegoPost(
                title=title,
                description=description,
                original_filename=original_filename,
                carrier_path=file_path,
                file_type=file_type,
                is_image=is_image,
                start_bit=start_bit,
                periodicity=periodicity,
                mode=mode,
                user_id=current_user.id
            )
            
            db.session.add(new_post)
            db.session.commit()
            
            flash('Steganography post created successfully!', 'success')
            return redirect(url_for('view_post', post_id=new_post.id))
            
        except Exception as e:
            flash(f'Error processing files: {str(e)}', 'danger')
            return redirect(request.url)
    
    return render_template('create_stego.html')

@app.route('/view_post/<int:post_id>')
def view_post(post_id):
    post = StegoPost.query.get_or_404(post_id)
    return render_template('view_post.html', post=post)

@app.route('/download_file/<int:post_id>')
def download_file(post_id):
    post = StegoPost.query.get_or_404(post_id)
    
    try:
        return send_file(post.carrier_path, as_attachment=True, download_name=post.original_filename)
    except Exception as e:
        flash(f'Download failed: {str(e)}', 'danger')
        return redirect(url_for('view_post', post_id=post.id))

@app.route('/extract_message', methods=['GET', 'POST'])
def extract_message_route():
    if request.method == 'POST':
        # Check if file was uploaded
        if 'carrier_file' not in request.files:
            flash('No carrier file selected', 'danger')
            return redirect(request.url)
            
        carrier_file = request.files['carrier_file']
        
        # Check if file was selected
        if carrier_file.filename == '':
            flash('No carrier file selected', 'danger')
            return redirect(request.url)
        
        start_bit = int(request.form.get('start_bit', 0))
        periodicity = int(request.form.get('periodicity', 8))
        mode = request.form.get('mode', 'constant')
        
        try:
            # Read carrier data
            carrier_data = carrier_file.read()
            
            # Extract the message
            extracted_message = extract_message(carrier_data, start_bit, periodicity, mode)
            
            # Save the extracted message to a temporary file
            temp_file = tempfile.NamedTemporaryFile(delete=False)
            temp_file.write(extracted_message)
            temp_file.close()
            
            # Determine filename for the extracted message
            extracted_filename = f"extracted_{secure_filename(carrier_file.filename)}"
            
            # Send the file to the user
            return send_file(temp_file.name, as_attachment=True, download_name=extracted_filename)
            
        except Exception as e:
            flash(f'Error extracting message: {str(e)}', 'danger')
            return redirect(request.url)
    
    return render_template('extract_message.html')

@app.route('/delete_post/<int:post_id>')
@login_required
def delete_post(post_id):
    post = StegoPost.query.get_or_404(post_id)
    
    # Ensure the post belongs to the current user
    if post.user_id != current_user.id:
        flash('You do not have permission to delete this post', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        # Delete the file from the filesystem
        if os.path.exists(post.carrier_path):
            os.remove(post.carrier_path)
    except:
        pass
    
    # Delete the post from the database
    db.session.delete(post)
    db.session.commit()
    
    flash('Post deleted successfully', 'success')
    return redirect(url_for('dashboard'))

# Create database tables
with app.app_context():
    db.create_all()
    
    # Check if admin user exists
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        # Create admin user
        admin = User(username='admin', email='admin@example.com')
        admin.set_password('admin') 
        
        db.session.add(admin)
        db.session.commit()

# Run the application
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)