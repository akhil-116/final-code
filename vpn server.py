'''import socket
import threading

# Define the server's IP address and port
VPN_SERVER_HOST = '127.0.0.1'
VPN_SERVER_PORT = 12345

# Define the buffer size
BUFFER_SIZE = 4096

# Function to handle client connections
def handle_client(client_socket):
    while True:
        # Receive data from the client
        data = client_socket.recv(BUFFER_SIZE)
        if not data:
            break
        
        # Check if it's a disconnect request
        if data.strip().decode() == 'disconnect':
            print(f"[*] Client {client_socket.getpeername()} requested disconnect")
            client_socket.close()
            break
        
        # Process the data (you can modify this part to implement VPN functionalities)
        # Here, we'll just echo back the received data
        client_socket.sendall(data)

# Function to accept incoming connections
def accept_connections():
    while True:
        # Accept a new connection
        client_socket, client_address = vpn_server_socket.accept()
        print(f"[*] Accepted connection from {client_address[0]}:{client_address[1]}")
        
        # Create a new thread to handle the client connection
        client_thread = threading.Thread(target=handle_client, args=(client_socket,))
        client_thread.start()

# Function to handle VPN disconnect request
def disconnect_vpn(client_socket):
    print(f"[*] Client {client_socket.getpeername()} requested disconnect")
    client_socket.close()

# Create a socket object
vpn_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the address and port
vpn_server_socket.bind((VPN_SERVER_HOST, VPN_SERVER_PORT))

# Start listening for incoming connections
vpn_server_socket.listen(5)
print(f"[*] VPN Server listening on {VPN_SERVER_HOST}:{VPN_SERVER_PORT}")

# Start accepting incoming connections in a separate thread
accept_thread = threading.Thread(target=accept_connections)
accept_thread.start()
'''

import threading
import requests
import socket

# Define the server's IP address and port
VPN_SERVER_HOST = '127.0.0.1'
VPN_SERVER_PORT = 12345

# Define the backend server's IP address and port
BACKEND_SERVER_HOST = '127.0.0.1'
BACKEND_SERVER_PORT = 8443

# Define the buffer size
BUFFER_SIZE = 4096

# Function to handle client connections
def handle_client(client_socket):
    while True:
        data = client_socket.recv(BUFFER_SIZE)
        if not data:
            break
        # Forward the data through the tunnel to the destination (backend.py)
        response = requests.post(f'https://{BACKEND_SERVER_HOST}:{BACKEND_SERVER_PORT}', data=data)
        client_socket.sendall(response.content)
    
    # Close the client socket
    client_socket.close()

# Function to run the VPN server
def run_vpn_server():
    # Create a socket object
    vpn_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the address and port
    vpn_server_socket.bind((VPN_SERVER_HOST, VPN_SERVER_PORT))

    # Start listening for incoming connections
    vpn_server_socket.listen(5)
    print(f"[*] VPN Server listening on {VPN_SERVER_HOST}:{VPN_SERVER_PORT}")

    while True:
        client_socket, client_address = vpn_server_socket.accept()
        print(f"[*] Accepted connection from {client_address[0]}:{client_address[1]}")
        
        # Create a thread to handle client communication
        client_thread = threading.Thread(target=handle_client, args=(client_socket,))
        client_thread.start()

# Run the VPN server in one thread
vpn_server_thread = threading.Thread(target=run_vpn_server)
vpn_server_thread.start()
