from flask import Flask, request, flash, render_template, redirect, url_for, session, send_from_directory
from werkzeug.utils import secure_filename
import os
import mysql.connector
import requests
from cryptography.fernet import Fernet
from config import FTP_CONFIG
from ftplib import FTP

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# MySQL Database Configuration
db = mysql.connector.connect(
    host='*******',
    user='****',
    password='******',
    database='******'
)

UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limit file size to 16MB

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Fernet encryption key setup
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Functions for Encryption and Decryption
def encrypt_file(file_path):
    with open(file_path, 'rb') as file:
        plaintext = file.read()
        encrypted_data = cipher_suite.encrypt(plaintext)
        with open(file_path, 'wb') as encrypted_file:
            encrypted_file.writ0e(encrypted_data)

def decrypt_file(file_path):
    with open(file_path, 'rb') as file:
        encrypted_data = file.read()
        try:
            decrypted_data = cipher_suite.decrypt(encrypted_data)
            with open(file_path, 'wb') as decrypted_file:
                decrypted_file.write(decrypted_data)
        except Exception as e:
            print(f"Decryption failed: {str(e)}")

# FTP Configuration
FTP_HOST = FTP_CONFIG['host']
FTP_USER = FTP_CONFIG['username']
FTP_PASS = FTP_CONFIG['password']
FTP_DIR = '/uploads'

def upload_to_ftp(file_path):
    try:
        ftp = FTP(FTP_HOST)
        ftp.login(user=FTP_USER, passwd=FTP_PASS)

        ftp.cwd(FTP_DIR)

        with open(file_path, 'rb') as file:
            ftp.storbinary(f'STOR {os.path.basename(file_path)}', file)

        ftp.quit()
        return True
    except Exception as e:
        print(f"FTP Upload failed: {str(e)}")
        return False

def get_folder_size(folder):
    total_size = 0
    for dirpath, dirnames, filenames in os.walk(folder):
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            total_size += os.path.getsize(filepath)
    return total_size

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('index'))

    user_id = session.get('user_id')
    user_name = session.get('user_name')

    # Generate a unique folder name for the user
    user_upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], f'user_{user_id}')
    if not os.path.exists(user_upload_folder):
        os.makedirs(user_upload_folder)

    cursor = db.cursor()
    select_query = "SELECT filename FROM files WHERE user_id = %s"
    cursor.execute(select_query, (user_id,))
    files = [os.path.join(user_upload_folder, row[0]) for row in cursor.fetchall()]

    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'error')
            return redirect(request.url)
        
        file = request.files['file']

        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(user_upload_folder, filename)
            
            # Check folder size before saving the file
            folder_size = get_folder_size(user_upload_folder)
            if folder_size + file.content_length > 4 * 1024 * 1024:
                flash('Folder size limit exceeded', 'error')
                return redirect(request.url)
            
            file.save(file_path)
            flash('File successfully uploaded', 'success')

            cursor = db.cursor()
            insert_query = "INSERT INTO files (user_id, filename, file_path) VALUES (%s, %s, %s)"
            cursor.execute(insert_query, (user_id, filename, file_path))
            db.commit()

            return redirect(url_for('uploaded_files'))

        else:
            flash('Invalid file type. Allowed types: txt, pdf, png, jpg, jpeg, gif', 'error')
            return redirect(request.url)

    return render_template('dashboard.html', user_name=user_name, files=files)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        cursor = db.cursor()
        query = "SELECT * FROM users WHERE email = %s AND password = %s"
        cursor.execute(query, (email, password))
        user = cursor.fetchone()

        if user:
            session['logged_in'] = True
            session['user_id'] = user[0]  # Store user ID in session
            session['user_name'] = user[1]
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            error_message = 'Invalid credentials. Please try again.'
            flash(error_message, 'error')
            return render_template('login.html', error=error_message)

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')

        # Check if any field is empty
        if not name or not email or not password:
            flash('Please fill in all fields.', 'error')
            return redirect(url_for('signup'))

        cursor = db.cursor()
        check_query = "SELECT * FROM users WHERE email = %s"
        cursor.execute(check_query, (email,))
        user = cursor.fetchone()

        if user:
            # User already exists
            error_message = 'Email ID already exists! Please try with a different email id.'
            flash(error_message, 'error')
            return render_template('signup.html', error=error_message)
        else:
            # Insert new user into the database
            insert_query = "INSERT INTO users (name, email, password) VALUES (%s, %s, %s)"
            cursor.execute(insert_query, (name, email, password))
            db.commit()
            flash('Account created successfully! Please log in.', 'success')
            # Redirect to dashboard
            return redirect(url_for('dashboard'))

    return render_template('signup.html')

@app.route('/files')
def uploaded_files():
    user_id = session.get('user_id')

    cursor = db.cursor()
    select_query = "SELECT filename FROM files WHERE user_id = %s"
    cursor.execute(select_query, (user_id,))
    files = [row[0] for row in cursor.fetchall()]

    return render_template('files.html', files=files)

@app.route('/downloads/<filename>')
def download_file(filename):
    user_id = session.get('user_id')
    user_upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], f'user_{user_id}')
    file_path = os.path.join(user_upload_folder, filename)
    decrypt_file(file_path)
    return send_from_directory(user_upload_folder, filename, as_attachment=True)

@app.route('/view/<filename>')
def view_file(filename):
    user_id = session.get('user_id')
    user_upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], f'user_{user_id}')
    return send_from_directory(user_upload_folder, filename)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return 'No file part in the request!', 400  

    file = request.files['file']

    if file.filename == '':
        return 'No selected file!', 400  

    user_id = session.get('user_id')
    user_upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], f'user_{user_id}')

    if not os.path.exists(user_upload_folder):
        os.makedirs(user_upload_folder)

    file_path = os.path.join(user_upload_folder, secure_filename(file.filename))

    if os.path.exists(file_path):
        return 'File already exists!', 400

    if file and allowed_file(file.filename):
        file.save(file_path)
        flash('File successfully uploaded', 'success')

        # Encrypt the file before storing
        encrypt_file(file_path)

        if upload_to_ftp(file_path):
            try:
                os.remove(file_path)  
                cursor = db.cursor()
                insert_query = "INSERT INTO files (user_id, filename, file_path) VALUES (%s, %s, %s)"
                cursor.execute(insert_query, (user_id, secure_filename(file.filename), file_path))
                db.commit()

                return 'File uploaded successfully to FTP server and stored in the database!', 200  # OK
            except Exception as e:
                print(f"Failed to delete the file: {str(e)}")
                flash('Failed to delete the local file!', 'error')
                return redirect(url_for('dashboard'))
        else:
            flash('FTP upload failed!', 'error')
            return redirect(url_for('dashboard'))

    else:
        flash('Invalid file type. Allowed types: txt, pdf, png, jpg, jpeg, gif', 'error')
        return redirect(request.url)

# Command prompt client code integrated for file upload
@app.route('/upload_file_from_client', methods=['POST'])
def upload_file_from_client():
    server_url = 'http://0.0.0.0:5000/upload'  

    if 'file' not in request.files:
        return 'No file part in the request!', 400  # Bad request

    file = request.files['file']

    if file.filename == '':
        return 'No selected file!', 400  # Bad request

    files = {'file': (file.filename, file.stream, file.mimetype)}
    response = requests.post(server_url, files=files)

    if response.status_code == 200:
        flash('File uploaded successfully from client!', 'success')
    else:
        flash('File upload from client failed!', 'error')

    return redirect(url_for('dashboard'))  # Redirect back to the dashboard after upload

# Route for the homepage
@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
