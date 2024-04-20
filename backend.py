import http.server
import json
import sqlite3
from http import cookies
import os
import base64
from io import BytesIO
from urllib.parse import urlparse, parse_qs
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from http import HTTPStatus
import cgi
import ssl
import socket
# SQLite database setup
conn = sqlite3.connect('users.db')
cursor = conn.cursor()
cursor.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT)')
cursor.execute('CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, username TEXT)')
cursor.execute('CREATE TABLE IF NOT EXISTS sent_files (id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, sender TEXT, recipient TEXT)')
cursor.execute('CREATE TABLE IF NOT EXISTS received_files (id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, sender TEXT, recipient TEXT)')
cursor.execute('CREATE TABLE IF NOT EXISTS encrypted_sent_files (id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, sender TEXT, recipient TEXT,aes_key BLOB, aes_iv BLOB, is_encrypted INTEGER DEFAULT 0)')
cursor.execute('CREATE TABLE IF NOT EXISTS encrypted_received_files (id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, sender TEXT, recipient TEXT,aes_key BLOB, aes_iv BLOB, is_encrypted INTEGER DEFAULT 0)')
cursor.execute('CREATE TABLE IF NOT EXISTS encrypted_files (id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, username TEXT, aes_key BLOB, aes_iv BLOB, is_encrypted INTEGER DEFAULT 0)')
conn.commit()


def hexStringToArrayBuffer(hexString):
        bytes = []
        for i in range(0, len(hexString), 2):
            bytes.append(int(hexString[i:i+2], 16))
        return bytesToArrayBuffer(bytes)

def bytesToArrayBuffer(bytes):
    array_buffer = bytearray(bytes)
    return array_buffer

 # Define the server's IP address and port
VPN_SERVER_HOST = '127.0.0.1'
VPN_SERVER_PORT = 12345

def bytesToArrayBuffer(bytes):
    array_buffer = bytearray(bytes)
    return array_buffer

def decrypt_file(encrypted_data, aes_key, aes_iv):
        # Convert hexadecimal AES key and IV to bytes
        aes_key_bytes = bytes.fromhex(aes_key)
        aes_iv_bytes = bytes.fromhex(aes_iv)

        # Create AESGCM cipher object
        cipher = AESGCM(aes_key_bytes)

        try:
            # Decrypt the encrypted data
            decrypted_data = cipher.decrypt(aes_iv_bytes, encrypted_data, None)
            return decrypted_data
        except Exception as e:
            # Handle decryption errors
            print("Decryption failed:", e)
            return None
      
class RequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.vpn_client_socket = None  # Initialize the VPN client socket
        super().__init__(*args, **kwargs)
    
    def do_POST(self):
        if self.path == '/register':
            self.register_user()
        elif self.path == '/login':
            self.login_user()
        elif self.path == '/upload':
            self.upload_file()
        elif self.path == '/send_file':
            self.send_file()
        elif self.path == '/upload_encrypted':
            self.upload_encrypted_file()
        elif self.path== '/decrypt_and_download':
            self.decrypt_and_download()
        elif self.path== '/decrypt_sent_file':
            self.decrypt_sent_file()
        elif self.path == '/send_encrypted':
            self.send_encrypted_file()
        elif self.path == '/connect_vpn':
            self.handle_connect_vpn_request()
        elif self.path == '/disconnect_vpn':
            self.handle_disconnect_vpn_request()
        elif self.path == '/logout':
            self.logout_user()

    def do_GET(self):
        parsed_url = urlparse(self.path)
        if self.path == '/dashboard':
            self.serve_dashboard()
        elif self.path == '/uploaded_files':
            self.get_uploaded_files()
        elif self.path == '/sent_files':
            self.get_sent_files()
        elif self.path == '/received_files':
            self.get_received_files()
        elif self.path == '/fetch_public_key':
            self.fetch_public_key()
        elif parsed_url.path == '/download':
            filename = parse_qs(parsed_url.query).get('filename', [None])[0]
            if filename:
                self.download_file(filename, 'received_files')
            else:
                self.send_error(400, 'Bad request: Filename not specified.')
        elif parsed_url.path == '/download_uploaded':
            filename = parse_qs(parsed_url.query).get('filename', [None])[0]
            if filename:
                self.download_file(filename, 'files')
            else:
                self.send_error(400, 'Bad request: Filename not specified.')
        else:
            super().do_GET()
   
    def register_user(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        data = json.loads(post_data.decode('utf-8'))

        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            self.send_response(400)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'message': 'Please provide both username and password.'}).encode('utf-8'))
            return

        # Check if the username already exists
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            self.send_response(400)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'message': 'Username already exists. Please choose another username.'}).encode('utf-8'))
            return

        # Insert user data into the database
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
        conn.commit()

        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'message': 'Registration successful!'}).encode('utf-8'))

    def login_user(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        data = json.loads(post_data.decode('utf-8'))

        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            self.send_response(400)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'message': 'Please provide both username and password.'}).encode('utf-8'))
            return

        # Check if the username and password match
        cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
        matched_user = cursor.fetchone()

        if matched_user:
            self.send_response(200)
            self.send_header('Content-type', 'application/json')

            # Set a cookie for session management (insecure, for demonstration purposes)
            cookie = cookies.SimpleCookie()
            cookie['user'] = matched_user[1]
            self.send_header('Set-Cookie', cookie.output(header='', sep=''))

            self.end_headers()
            self.wfile.write(json.dumps({'message': 'Login successful!', 'success': True}).encode('utf-8'))
        else:
            self.send_response(401)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'message': 'Invalid username or password.', 'success': False}).encode('utf-8'))
            
    def serve_dashboard(self):
        user_cookie = self.get_cookie('user')
        if not user_cookie:
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'Unauthorized: User not logged in.')
            return

        # Check if the user exists in the database (insecure, for demonstration purposes)
        cursor.execute('SELECT * FROM users WHERE username = ?', (user_cookie,))
        matched_user = cursor.fetchone()

        if not matched_user:
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'Unauthorized: User not found in the database.')
            return

        # Serve the dashboard.html file
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

        # Load and send the dashboard.html file content
        with open(os.path.join(os.getcwd(), 'templates', 'dashboard.html'), 'rb') as f:
            self.wfile.write(f.read())
    
    def upload_file(self):
        user_cookie = self.get_cookie('user')
        if not user_cookie:
            self.send_response(HTTPStatus.UNAUTHORIZED)
            self.end_headers()
            self.wfile.write(b'Unauthorized: User not logged in.')
            return

        content_type = self.headers.get('Content-Type')
        if content_type.startswith('multipart/form-data'):
            # Extracting the file data from the request
            _, params = cgi.parse_header(content_type)
            boundary = params.get('boundary').encode()
            content_length = int(self.headers['Content-Length'])
            body = self.rfile.read(content_length)
            form_data = cgi.parse_multipart(BytesIO(body), {'boundary': boundary})
            file_data = form_data.get('file')

            # Checking if file data exists
            if not file_data:
                self.send_response(HTTPStatus.BAD_REQUEST)
                self.end_headers()
                self.wfile.write(b'No file provided.')
                return

            # Getting file name
            file_name = self.headers['X-File-Name']

            # Store the uploaded file specific to the user
            user_directory = os.path.join('files', user_cookie)
            os.makedirs(user_directory, exist_ok=True)
            with open(os.path.join(user_directory, file_name), 'wb') as f:
                f.write(file_data[0])

            # Store the file record in the database
            cursor.execute('INSERT INTO files (filename, username) VALUES (?, ?)', (file_name, user_cookie))
            conn.commit()

            self.send_response(HTTPStatus.OK)
            self.end_headers()
            self.wfile.write(b'File uploaded successfully.')
        else:
            self.send_response(HTTPStatus.BAD_REQUEST)
            self.end_headers()
            self.wfile.write(b'Invalid request format.')   

    def upload_encrypted_file(self):
        user_cookie = self.get_cookie('user')
        if not user_cookie:
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'Unauthorized: User not logged in.')
            return

        content_type = self.headers.get('Content-Type')
        if content_type.startswith('multipart/form-data'):
            _, params = cgi.parse_header(content_type)
            boundary = params.get('boundary').encode()
            content_length = int(self.headers['Content-Length'])
            body = self.rfile.read(content_length)
            form_data = cgi.parse_multipart(BytesIO(body), {'boundary': boundary})
            file_data = form_data.get('file')

            if not file_data:
                self.send_response(HTTPStatus.BAD_REQUEST)
                self.end_headers()
                self.wfile.write(b'No file provided.')
                return

        file_name = self.headers['X-File-Name']
        user_directory = os.path.join('files', user_cookie)
        os.makedirs(user_directory, exist_ok=True)
        
        aes_key = self.headers['X-Aes-Key']
        aes_iv = self.headers['X-Aes-Iv']
        

        # Perform decryption
        decrypted_file = decrypt_file(file_data[0], aes_key, aes_iv)
        

       # Ensure the user directory exists or create it if it doesn't
        user_directory = os.path.join('files', user_cookie)
        if not os.path.exists(user_directory):
            os.makedirs(user_directory)

        # Write the decrypted data to a new file
        with open(os.path.join(user_directory, file_name), 'wb') as f:
            f.write(decrypted_file)

        # Store the file record with AES key and IV in the database
        cursor.execute('INSERT INTO encrypted_files (filename, username, aes_key, aes_iv, is_encrypted) VALUES (?, ?, ?, ?, ?)',(file_name, user_cookie, aes_key, aes_iv, True))
        conn.commit()

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Encrypted file uploaded successfully.')
    
    def get_uploaded_files(self):
        user_cookie = self.get_cookie('user')
        if not user_cookie:
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'Unauthorized: User not logged in.')
            return

        # Retrieve the list of sent files for the user from the database
        cursor.execute('SELECT filename, username FROM files WHERE username = ?', (user_cookie,))
        files = cursor.fetchall()
        files_list = [{'filename': file[0], 'username': file[1]} for file in files]
         # Retrieve files from the 'encrypted_files' table
        cursor.execute('SELECT filename, username FROM encrypted_files WHERE username = ?', (user_cookie,))
        encrypted_files = cursor.fetchall()
        encrypted_files_list = [{'filename': file[0], 'username': file[1], 'encrypted': True} for file in encrypted_files]

        # Combine the results from both tables
        all_files = files_list + encrypted_files_list

        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(all_files).encode('utf-8'))
        
    def send_encrypted_file(self):
        user_cookie = self.get_cookie('user')
        if not user_cookie:
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'Unauthorized: User not logged in.')
            return
        
        content_type = self.headers.get('Content-Type')
        if content_type.startswith('multipart/form-data'):
            _, params = cgi.parse_header(content_type)
            boundary = params.get('boundary').encode()
            content_length = int(self.headers['Content-Length'])
            body = self.rfile.read(content_length)
            form_data = cgi.parse_multipart(BytesIO(body), {'boundary': boundary})
            file_data = form_data.get('file')

            if not file_data:
                self.send_response(HTTPStatus.BAD_REQUEST)
                self.end_headers()
                self.wfile.write(b'No file provided.')
                return

        file_name = self.headers['X-File-Name']  # Retrieve original filename from request
        recipient_name = self.headers['X-Recipient-Username']  # Retrieve recipient username from request
        
        if not recipient_name:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(json.dumps({'message': 'Recipient username not specified.'}).encode('utf-8'))
            return
        
        # Check if recipient username exists in the database
        recipient_exists = self.check_recipient_exists(recipient_name)
        if not recipient_exists:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(json.dumps({'message': 'Recipient user does not exist.'}).encode('utf-8'))
            return

        # Store the encrypted file in the sender's directory
        sender_directory = os.path.join('sent_files', user_cookie)
        os.makedirs(sender_directory, exist_ok=True)
        file_path = os.path.join(sender_directory, file_name)
        
        with open(file_path, 'wb') as f:
            f.write(file_data[0])

        
        aes_key = self.headers['X-Aes-Key']
        aes_iv = self.headers['X-Aes-Iv']

        # Insert into the database
        self.store_file_details(file_name, user_cookie, recipient_name,aes_key,aes_iv)

        # Store the file in the recipient's directory
        recipient_directory = os.path.join('received_files', recipient_name)
        os.makedirs(recipient_directory, exist_ok=True)
        
        with open(os.path.join(recipient_directory, file_name), 'wb') as f:
            f.write(file_data[0])

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Encrypted file sent successfully.')

    def check_recipient_exists(self, recipient_name):
        cursor.execute('SELECT * FROM users WHERE username = ?', (recipient_name,))
        return cursor.fetchone()

    def store_file_details(self, file_name, sender_name, recipient_name,aes_key,aes_iv):
        cursor.execute('INSERT INTO encrypted_sent_files (filename, sender, recipient, aes_key, aes_iv, is_encrypted) VALUES (?, ?, ?, ?, ?, ?)',
                       (file_name, sender_name, recipient_name, aes_key, aes_iv, True))
        conn.commit()

        cursor.execute('INSERT INTO encrypted_received_files (filename, sender, recipient, aes_key, aes_iv, is_encrypted) VALUES (?, ?, ?, ?, ?, ?)',
                       (file_name, sender_name, recipient_name, aes_key, aes_iv, True))
        conn.commit()

    def decrypt_sent_file(self):
        # Verify if the user is authorized
        user_cookie = self.get_cookie('user')
        if not user_cookie:
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'Unauthorized: User not logged in.')
            return

        # Retrieve filename from request header
        file_name = self.headers.get('X-File-Name')

        # Check if the file is encrypted
        cursor.execute('SELECT is_encrypted FROM encrypted_received_files WHERE filename = ? AND recipient = ?', (file_name, user_cookie))
        result = cursor.fetchone()
        if not result:
            self.send_response(HTTPStatus.BAD_REQUEST)
            self.end_headers()
            self.wfile.write(b'File not found in the encrypted recieved files table.')
            return

        is_encrypted = bool(result[0])

        if is_encrypted:
            # Retrieve file data and AES key/IV from request headers
            content_type = self.headers.get('Content-Type')
            if content_type.startswith('multipart/form-data'):
                _, params = cgi.parse_header(content_type)
                boundary = params.get('boundary').encode()
                content_length = int(self.headers['Content-Length'])
                body = self.rfile.read(content_length)
                form_data = cgi.parse_multipart(BytesIO(body), {'boundary': boundary})
                file_data = form_data.get('file')
    
                if not file_data:
                    self.send_response(HTTPStatus.BAD_REQUEST)
                    self.end_headers()
                    self.wfile.write(b'No file provided.')
                    return

            # Retrieve AES key and IV from request headers
            aes_key_hex = self.headers['Aes-Key']
            aes_iv_hex = self.headers['Aes-Iv']

            aes_key = bytes.fromhex(aes_key_hex)
            aes_iv = bytes.fromhex(aes_iv_hex)
            

            # Decrypt the file
            decrypted_data = self.decrypt_file(file_data, aes_key, aes_iv)

            # Ensure the user directory exists or create it if it doesn't
            user_directory = os.path.join('files', user_cookie)
            if not os.path.exists(user_directory):
                os.makedirs(user_directory)

            # Write the decrypted data to a new file
            decrypted_file_path = os.path.join(user_directory, 'decrypted_' + file_name)
            with open(decrypted_file_path, 'wb') as f:
                f.write(decrypted_data)

            # Send the decrypted file to the client for download
            with open(decrypted_file_path, 'rb') as f:
                self.send_response(HTTPStatus.OK)
                self.send_header('Content-Disposition', f'attachment; filename="{file_name}"')
                self.send_header('Content-Type', 'application/octet-stream')
                self.end_headers()
                self.wfile.write(decrypted_data)

            # Clean up - remove the decrypted file
            os.remove(decrypted_file_path)

        else:
            self.send_response(HTTPStatus.BAD_REQUEST)
            self.end_headers()
            self.wfile.write(b'File is not encrypted. If you want to download the unencrypted file, please download it from the recieved files.')

    def decrypt_file(self, file_data, aes_key, aes_iv):
        print(aes_key,aes_iv)
        # Create an AES cipher object with the provided key and IV
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=aes_iv)

        # Decrypt the file data
        try:
            decrypted_data = cipher.decrypt(file_data[0])
            return decrypted_data
        except ValueError as e:
            # Handle decryption error
            print(f"Decryption error: {e}")
            return None

    def send_file(self):
        user_cookie = self.get_cookie('user')
        if not user_cookie:
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'Unauthorized: User not logged in.')
            return

        content_type = self.headers.get('Content-Type')
        if content_type.startswith('multipart/form-data'):
            # Extracting the file data from the request
            _, params = cgi.parse_header(content_type)
            boundary = params.get('boundary').encode()
            content_length = int(self.headers['Content-Length'])
            body = self.rfile.read(content_length)
            form_data = cgi.parse_multipart(BytesIO(body), {'boundary': boundary})
            file_data = form_data.get('fileToSend')

            # Checking if file data exists
            if not file_data:
                self.send_response(HTTPStatus.BAD_REQUEST)
                self.end_headers()
                self.wfile.write(b'No file provided.')
                return

            file_name = self.headers['X-File-Name']
            recipient_username = self.headers['X-Recipient-Username']
            
            if not recipient_username:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(json.dumps({'message': 'Recipient username not specified.'}).encode('utf-8'))
                return
            
            # Check if recipient username exists in the database
            cursor.execute('SELECT * FROM users WHERE username = ?', (recipient_username,))
            recipient_exists = cursor.fetchone()
            if not recipient_exists:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(json.dumps({'message': 'Recipient user does not exist.'}).encode('utf-8'))
                return
            
            # Store the sent file record in the database
            cursor.execute('INSERT INTO sent_files (filename, sender, recipient) VALUES (?, ?, ?)', (file_name, user_cookie, recipient_username))
            conn.commit()

            # Store the sent file record in the database for recipient
            cursor.execute('INSERT INTO received_files (filename, sender, recipient) VALUES (?, ?, ?)', (file_name, user_cookie, recipient_username))
            conn.commit()
        
            # Save the file in the sender's directory on the server
            sender_directory = os.path.join('sent_files', user_cookie)
            os.makedirs(sender_directory, exist_ok=True)
            with open(os.path.join(sender_directory, file_name), 'wb') as f:
                f.write(file_data[0])

            # Save the file in the recipient's directory on the server
            recipient_directory = os.path.join('received_files', recipient_username)
            os.makedirs(recipient_directory, exist_ok=True)
            with open(os.path.join(recipient_directory, file_name), 'wb') as f:
                f.write(file_data[0])

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'File sent successfully.')
        else:
            self.send_response(HTTPStatus.BAD_REQUEST)
            self.end_headers()
            self.wfile.write(b'Invalid request format.')   

    def get_sent_files(self):
        user_cookie = self.get_cookie('user')
        if not user_cookie:
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'Unauthorized: User not logged in.')
            return

        # Retrieve the list of sent files for the user from the database
        cursor.execute('SELECT filename FROM sent_files WHERE sender = ?', (user_cookie,))
        sent_files = cursor.fetchall()
        sent_files = [file[0] for file in sent_files]

        # Retrieve the list of encrypted sent files for the user from the database
        cursor.execute('SELECT filename FROM encrypted_sent_files WHERE sender = ?', (user_cookie,))
        encrypted_sent_files = cursor.fetchall()
        encrypted_sent_files = [file[0] for file in encrypted_sent_files]

        all_sent_files = sent_files + encrypted_sent_files

        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(all_sent_files).encode('utf-8'))

    def get_received_files(self):
        user_cookie = self.get_cookie('user')
        if not user_cookie:
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'Unauthorized: User not logged in.')
            return

        # Retrieve the list of received files for the user from the database
        cursor.execute('SELECT filename, sender FROM received_files WHERE recipient = ?', (user_cookie,))
        received_files = cursor.fetchall()
        received_files_list = [{'filename': file[0], 'sender': file[1]} for file in received_files]

        # Retrieve the list of encrypted received files for the user from the database
        cursor.execute('SELECT filename, sender FROM encrypted_received_files WHERE recipient = ?', (user_cookie,))
        encrypted_received_files = cursor.fetchall()
        encrypted_received_files_list = [{'filename': file[0], 'sender': file[1]} for file in encrypted_received_files]

        all_received_files = received_files_list + encrypted_received_files_list

        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(all_received_files).encode('utf-8'))
  
    def download_file(self, filename, file_directory):
        user_cookie = self.get_cookie('user')
        if not user_cookie:
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'Unauthorized: User not logged in.')
            return

        try:
            with open(os.path.join(file_directory, user_cookie, filename), 'rb') as f:
                file_content = f.read()
                self.send_response(200)
                self.send_header('Content-type', 'application/octet-stream')
                self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
                self.end_headers()
                self.wfile.write(file_content)
        except FileNotFoundError:
            self.send_error(404, 'File not found.')

    def handle_connect_vpn_request(self):
        if not self.vpn_client_socket:
            self.vpn_client_socket = self.connect_to_vpn_server()
            if self.vpn_client_socket:
                print("Socket status: Active")
            else:
                print("Socket status: Inactive")
            if self.vpn_client_socket:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Connected to VPN server")
            else:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Failed to connect to VPN server")
        else:
            self.send_response(200)  # Already connected, send success response
            self.end_headers()
            self.wfile.write(b"Already connected to VPN server")
   
    def handle_disconnect_vpn_request(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"A VPN connection is necessary. Please connect again.")

    def connect_to_vpn_server(self):
        try:
            vpn_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            vpn_client_socket.connect(('127.0.0.1', 12345))  # Adjust as per your VPN server details
            print("Connected to VPN server")
            return vpn_client_socket
        except Exception as e:
            print(f"Error connecting to VPN server: {str(e)}")
            return None
    
    def logout_user(self):
        user_cookie = self.get_cookie('user')
        if user_cookie:
            # Expire the user's cookie
            self.send_response(200)
            self.send_header('Set-Cookie', 'user=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;')
            self.end_headers()
            self.wfile.write(b'Logout successful.')
        else:
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'Unauthorized: User not logged in.')

    def get_cookie(self, key):
        cookies_header = self.headers.get('Cookie')
        if cookies_header:
            cookie = cookies.SimpleCookie(cookies_header)
            cookie_value = cookie.get(key).value  # Extract the value of the cookie
            return cookie_value


if __name__ == '__main__':
    server_address = ('localhost', 8443)  # Change to your desired host and port

    httpd = http.server.HTTPServer(server_address, RequestHandler)
    httpd.socket = ssl.wrap_socket(httpd.socket, keyfile='key.pem', certfile='cert.pem', server_side=True)  # path to SSL certificate

    print('Server started and Running...')
    print("Server is running at https://localhost:8443")
    httpd.serve_forever()
