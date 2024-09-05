import os
import random
import string
from flask import Flask, request, render_template, send_file, redirect, url_for, flash, session
from cryptography.fernet import Fernet, InvalidToken
# pylint: disable=no-name-in-module
from cv2 import imread, imwrite
from base64 import urlsafe_b64encode
from hashlib import md5
from flask_sqlalchemy import SQLAlchemy
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.secret_key = os.urandom(24)  # Needed for flash messages
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize Flask-Migrate

db = SQLAlchemy(app)


def create_app():
    from flask_session import Session
    app.config["SESSION_PERMANENT"] = False
    app.config["SESSION_TYPE"] = "filesystem"
    app.secret_key = os.urandom(24)
    Session(app)
    return app
# User Model


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    passwords = db.relationship('PasswordEntry', back_populates='user')

    def to_json(self):
        return {
            'name': self.name,
            'email': self.email,
            'username': self.username,
            'password': self.password,
        }


# Password Model
class PasswordEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    site = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(200), nullable=False)

    user = db.relationship('User', back_populates='passwords')

    def to_json(self):
        return {
            "website": self.site,
            "username": self.username,
            "password": self.password,
        }


migrate = Migrate(app, db)

# Generate a symmetric key (Fernet)
symmetric_key = Fernet.generate_key()
cipher_symmetric = Fernet(symmetric_key)

# Generate an asymmetric key pair (RSA)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# Utility functions


def encrypt_decrypt(string, password, mode='enc'):
    _hash = md5(password.encode()).hexdigest()
    cipher_key = urlsafe_b64encode(_hash.encode())
    cipher = Fernet(cipher_key)
    if mode == 'enc':
        return cipher.encrypt(string.encode()).decode()
    else:
        return cipher.decrypt(string.encode()).decode()


def str2bin(string):
    return ''.join((bin(ord(i))[2:]).zfill(8) for i in string)


def encode(input_filepath, text, output_filepath, password=None):
    if password:
        data = encrypt_decrypt(text, password, 'enc')
    else:
        data = text
    data_length = bin(len(data))[2:].zfill(32)
    bin_data = iter(data_length + str2bin(data))
    img = imread(input_filepath, 1)

    if img is None:
        raise FileError(f"The image file '{input_filepath}' is inaccessible")

    height, width = img.shape[0], img.shape[1]
    encoding_capacity = height * width * 3
    total_bits = 32 + len(data) * 8

    if total_bits > encoding_capacity:
        raise DataError("The data size is too big to fit in this image!")

    completed = False
    modified_bits = 0

    for i in range(height):
        for j in range(width):
            pixel = img[i, j]
            for k in range(3):
                try:
                    x = next(bin_data)
                except StopIteration:
                    completed = True
                    break
                if x == '0' and pixel[k] % 2 == 1:
                    pixel[k] -= 1
                    modified_bits += 1
                elif x == '1' and pixel[k] % 2 == 0:
                    pixel[k] += 1
                    modified_bits += 1
            if completed:
                break
        if completed:
            break

    written = imwrite(output_filepath, img)
    if not written:
        raise FileError(f"Failed to write image '{output_filepath}'")

    loss_percentage = (modified_bits / encoding_capacity) * 100
    return loss_percentage


class FileError(Exception):
    pass


class DataError(Exception):
    pass


class PasswordError(Exception):
    pass


def bin2str(string):
    return ''.join(chr(int(string[i:i+8], 2)) for i in range(len(string))[::8])


def decode(input_filepath, password=None):
    result, extracted_bits, completed, number_of_bits = '', 0, False, None
    img = imread(input_filepath)

    if img is None:
        raise FileError(f"The image file '{input_filepath}' is inaccessible")

    height, width = img.shape[0], img.shape[1]

    for i in range(height):
        for j in range(width):
            for k in img[i, j]:
                result += str(k % 2)
                extracted_bits += 1

                if extracted_bits == 32 and number_of_bits is None:
                    number_of_bits = int(result, 2) * 8
                    result = ''
                    extracted_bits = 0
                elif extracted_bits == number_of_bits:
                    completed = True
                    break
            if completed:
                break
        if completed:
            break

    if password:
        try:
            return encrypt_decrypt(bin2str(result), password, 'dec')
        except:
            raise PasswordError("Invalid password!")
    else:
        return bin2str(result)


@app.route('/')
def index():
    return render_template('index.html')
# Routes for encryption and decryption


@app.route('/register')
def register():
    return render_template('register.html', error_message='')


@app.route('/register.py', methods=['POST'])
def register_user():
    # Get form data
    name = request.form['register--name']
    email = request.form['register--email']
    username = request.form['register--username']
    password = request.form['register--password']
    confirm_password = request.form['register--confirm-password']

    # Check if the passwords match
    if password != confirm_password:
        return render_template('register.html', error_message="Passwords do not match")

    # Check if the username already exists
    user = User.query.filter_by(username=username).first()
    if user:
        return render_template("register.html", error_message="Username already exists")

    # Check if the email already exists
    email_check = User.query.filter_by(email=email).first()
    if email_check:
        return render_template("register.html", error_message="Email already exists")

    # If all checks pass, hash the password and save the new user
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    new_user = User(name=name, email=email, username=username,
                    password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return redirect('/login')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the user exists
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['username'] = user.username
            session['name'] = user.name
            flash('Login Successful!', 'success')
            # Redirect to dashboard or tools page
            return redirect('/')
        else:
            flash('Invalid Username or Password', 'danger')
            return redirect('/login')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out!', 'info')
    return redirect('/login')


@app.route('/symmetric')
def symmetric():
    if 'username' not in session:
        flash('Please login to access this tool', 'warning')
        return redirect('/login')
    return render_template('symmetric.html')


@app.route('/upload-symmetric', methods=['POST'])
def upload_symmetric():
    try:
        if 'file' not in request.files or request.files['file'].filename == '':
            flash('No file selected')
            return redirect(url_for('symmetric'))

        file = request.files['file']
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        if request.form['action'] == 'encrypt':
            return encrypt_symmetric(filepath)
        elif request.form['action'] == 'decrypt':
            return decrypt_symmetric(filepath)
    except Exception as e:
        flash(f'An unexpected error occurred: {str(e)}')
        return redirect(url_for('symmetric'))


@app.route('/asymmetric')
def asymmetric():
    if 'username' not in session:
        flash('Please login to access this tool', 'warning')
        return redirect('/login')
    return render_template('asymmetric.html')


@app.route('/upload-asymmetric', methods=['POST'])
def upload_asymmetric():
    try:
        if 'file' not in request.files or request.files['file'].filename == '':
            flash('No file selected')
            return redirect(url_for('asymmetric'))

        file = request.files['file']
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        if request.form['action'] == 'encrypt':
            return encrypt_asymmetric(filepath)
        elif request.form['action'] == 'decrypt':
            return decrypt_asymmetric(filepath)
    except Exception as e:
        flash(f'An unexpected error occurred: {str(e)}')
        return redirect(url_for('asymmetric'))

# routes for password-manager


@app.route('/password')
def view_passwords():
    if 'username' not in session:
        flash('Please login to access this tool', 'warning')
        return redirect('/login')

    user = User.query.filter_by(username=session['username']).first()
    passwords = PasswordEntry.query.filter_by(user_id=user.id).all()
    return render_template('password.html', passwords=passwords)


@app.route('/add_password', methods=['GET', 'POST'])
def add_password():
    if 'username' not in session:
        flash('Please login to access this tool', 'warning')
        return redirect('/login')

    if request.method == 'POST':
        site = request.form['site']
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=session['username']).first()
        hashed_password = generate_password_hash(
            password, method='pbkdf2:sha256')
        new_password = PasswordEntry(
            user_id=user.id, site=site, username=username, password=hashed_password)

        db.session.add(new_password)
        db.session.commit()

        flash('Password added successfully!', 'success')
        return redirect('/password')

    return render_template('add_password.html')


@app.route('/edit_password/<int:id>', methods=['GET', 'POST'])
def edit_password(id):
    if 'username' not in session:
        flash('Please login to access this tool', 'warning')
        return redirect('/login')

    password_entry = PasswordEntry.query.get_or_404(id)

    if request.method == 'POST':
        site = request.form['site']
        username = request.form['username']
        password = request.form['password']

        password_entry.site = site
        password_entry.username = username
        password_entry.password = generate_password_hash(
            password, method='pbkdf2:sha256')

        db.session.commit()

        flash('Password updated successfully!', 'success')
        return redirect('/password')

    return render_template('edit_password.html', password=password_entry)


@app.route('/delete_password/<int:id>', methods=['POST'])
def delete_password(id):
    if 'username' not in session:
        flash('Please login to access this tool', 'warning')
        return redirect('/login')

    password_entry = PasswordEntry.query.get_or_404(id)
    db.session.delete(password_entry)
    db.session.commit()

    flash('Password deleted successfully!', 'success')
    return redirect('/password')


@app.route('/generate-password', methods=['POST'])
def generate_password():
    # Default length to 12 if not provided
    length = int(request.form.get('length', 12))
    if length < 8:
        flash('Password length should be at least 8 characters', 'warning')
        return redirect(url_for('password'))

    # Generate a random password
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(length))

    return render_template('password', generated_password=password)

# Routes for Image Steganography


@app.route('/steganography')
def steganography():
    if 'username' not in session:
        flash('Please login to access this tool', 'warning')
        return redirect('/login')
    return render_template('steganography.html')


@app.route('/encode_image', methods=['POST'])
def encode_image():
    if 'cover_image' not in request.files or not request.files['cover_image'].filename:
        flash('No cover image provided!', 'warning')
        return redirect(url_for('steganography'))

    cover_image = request.files['cover_image']
    secret_message = request.form['secret_message']
    password = request.form['password']

    if not secret_message:
        flash('No secret message provided!', 'warning')
        return redirect(url_for('steganography'))

    output_filepath = os.path.join(
        app.config['UPLOAD_FOLDER'], 'stego_image.png')
    cover_image_path = os.path.join(
        app.config['UPLOAD_FOLDER'], cover_image.filename)
    cover_image.save(cover_image_path)

    try:
        loss = encode(cover_image_path, secret_message,
                      output_filepath, password)
        flash(f"Image encoded successfully. Data loss: {loss:.2f}%", 'success')
        return send_file(output_filepath, as_attachment=True)
    except FileError as fe:
        flash(f"Error: {fe}", 'danger')
    except DataError as de:
        flash(f"Error: {de}", 'danger')

    return redirect(url_for('steganography'))


@app.route('/decode_image', methods=['POST'])
def decode_image():
    if 'stego_image' not in request.files or not request.files['stego_image'].filename:
        flash('No stego image provided!', 'warning')
        return redirect(url_for('steganography'))

    stego_image = request.files['stego_image']
    # Default to empty string if not provided
    password = request.form.get('password', '')
    stego_image_path = os.path.join(
        app.config['UPLOAD_FOLDER'], secure_filename(stego_image.filename))
    stego_image.save(stego_image_path)

    try:
        secret_message = decode(
            stego_image_path, password if password else None)
        return render_template('result_decode.html', decoded_message=secret_message)
    except FileError as fe:
        flash(f"Error: {fe}", 'error')
    except PasswordError as pe:
        flash(f"Error: {pe}", 'error')

    return redirect(url_for('steganography'))


def encrypt_symmetric(filepath):
    try:
        with open(filepath, 'rb') as f:
            file_data = f.read()

        encrypted_data = cipher_symmetric.encrypt(file_data)
        encrypted_filepath = filepath + '.encrypted'
        with open(encrypted_filepath, 'wb') as f:
            f.write(encrypted_data)

        return send_file(encrypted_filepath, as_attachment=True)
    except Exception as e:
        flash(f'Encryption failed: {str(e)}')
        return redirect(url_for('symmetric'))


def decrypt_symmetric(filepath):
    try:
        with open(filepath, 'rb') as f:
            encrypted_data = f.read()

        decrypted_data = cipher_symmetric.decrypt(encrypted_data)
        decrypted_filepath = filepath.replace('.encrypted', '')
        with open(decrypted_filepath, 'wb') as f:
            f.write(decrypted_data)

        return send_file(decrypted_filepath, as_attachment=True)
    except InvalidToken:
        flash('Invalid token! Decryption failed.')
        return redirect(url_for('symmetric'))
    except Exception as e:
        flash(f'Decryption failed: {str(e)}')
        return redirect(url_for('symmetric'))


def encrypt_asymmetric(filepath):
    try:
        with open(filepath, 'rb') as f:
            file_data = f.read()

        encrypted_data = public_key.encrypt(
            file_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_filepath = filepath + '.encrypted'
        with open(encrypted_filepath, 'wb') as f:
            f.write(encrypted_data)

        return send_file(encrypted_filepath, as_attachment=True)
    except Exception as e:
        flash(f'Encryption failed: {str(e)}')
        return redirect(url_for('asymmetric'))


def decrypt_asymmetric(filepath):
    try:
        with open(filepath, 'rb') as f:
            encrypted_data = f.read()

        decrypted_data = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        decrypted_filepath = filepath.replace('.encrypted', '')
        with open(decrypted_filepath, 'wb') as f:
            f.write(decrypted_data)

        return send_file(decrypted_filepath, as_attachment=True)
    except Exception as e:
        flash(f'Decryption failed: {str(e)}')
        return redirect(url_for('asymmetric'))


if __name__ == '__main__':
    app.run(debug=True)
