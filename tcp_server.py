import hashlib
import socket
from threading import Thread

# Global variables
Server_IP = '127.0.0.1' # Localhost ; replace to IP address if needed
Server_PORT = 12000 # Port number ; replace with desired port number
BUFFER_SIZE = 1024 # The number of bytes to be received/sent at once

# List of tuples containing (peer_id, peer_password) of valid Peers
# peer_list = [("czalpha", "password")]  # Commented out: No longer needed as users are stored in users.txt
ADMIN_USERNAME = "admin" # Username for admin login
ADMIN_PASSWORD = "memento_mori" # Password for admin login MUST MATCH

# Communication conventions
SEPARATOR = "<SEP>"

# File to store user credentials
USER_FILE = "users.txt"

# List of online users
online_users = []

# Load existing users from the file
def load_users():
    users = {}
    try:
        with open(USER_FILE, "r") as file:
            for line in file:
                username, password = line.strip().split(SEPARATOR)
                users[username] = password
    except FileNotFoundError:
        pass
    return users

# Save new user to the file
def save_user(username, password):
    with open(USER_FILE, "a") as file:
        file.write(f"{username}{SEPARATOR}{password}\n")


def handle_client(client_socket, client_address):
    '''
    Purpose:
        Function to handle client connection to the P2P network
    Args.:
        client_socket: The client's socket
        client_address: The client's IP address
    Returns:
        Nothing, this is a void function
    '''
    
    try:
        print(f"[+] Connection from {client_address}")
        users = load_users()  # Load users from file
        while True:
            try:
                message = client_socket.recv(BUFFER_SIZE).decode()  # Receive the first 1024 bytes of data from the client
                if not message:  # If there's no data, break
                    break
                
                print(f"[+] Received Message: {message}")  # Print received data to console
                
                if SEPARATOR not in message:  # Check that the minimal formatting is there
                    print(f"[-] Peer sent incorrectly formatted message. Did not contain separator phrase. Message was: {message}")
                    break
                
                parts = message.split(SEPARATOR)
                action = parts[0]
                peer_id = parts[1]
                peer_password = parts[2] if len(parts) > 2 else None
                

                if action == "login":
                    if peer_id in users and users[peer_id] == hashlib.sha256(peer_password.encode()).hexdigest():
                        online_users.append(peer_id)
                        client_socket.send("[+] LOGIN SUCCESSFUL!".encode())
                    else:
                        client_socket.send("[-] LOGIN FAILED! Incorrect credentials.".encode())
                
                elif action == "register":
                    if peer_id in users:
                        client_socket.send("[-] REGISTRATION FAILED! Username already exists.".encode())
                    else:
                        hashed_password = hashlib.sha256(peer_password.encode()).hexdigest()
                        save_user(peer_id, hashed_password)
                        users[peer_id] = hashed_password
                        client_socket.send("[+] REGISTRATION SUCCESSFUL!".encode())
                
                elif action == "get_online_users":
                    client_socket.send(str(online_users).encode())
                
                elif action == "admin_login":
                    if peer_id == ADMIN_USERNAME and peer_password == ADMIN_PASSWORD:
                        client_socket.send("[+] ADMIN LOGIN SUCCESSFUL!".encode())
                    else:
                        client_socket.send("[-] ADMIN LOGIN FAILED! Incorrect credentials.".encode())

            except Exception as e:
                print(f"[-] Error handling client {client_address}: {e}")
                break

    except Exception as e:
        print(f"[-] Unexpected error with client {client_address}: {e}")
    finally:
        if peer_id in online_users:
            online_users.remove(peer_id)
        client_socket.close()
        print(f"[-] Connection closed with {client_address}")


def start_server():
    '''
    Function to start server
    Once it starts, it will actively listen for incoming connections
    '''
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Create a server TCP socket
    server_socket.bind((Server_IP, Server_PORT)) # Bind the sockett to the port and IP
    server_socket.listen(5) # Listen for up to 5 connections
    print(f"[+] Server listening on {Server_IP}:{Server_PORT}") # Announce server startup to console

    try:
        while True: # Infinite loop
            client_socket, client_address = server_socket.accept() # Accept a new connection and store the client's socket and IP address 
            client_thread = Thread(target=handle_client, args=(client_socket, client_address)) # Use threading to handle multiple clients in parallel
            client_thread.start() # Start that thread up
    except KeyboardInterrupt:
        print("[+] Server shutting down...") # If keyboard shortcut, shut down server
    finally:
        server_socket.close() # After everything, shut down the server's socket (shut the server down)
        print("[+] Server closed.")


if __name__ == "__main__":
    start_server() # Upon running this file, start the server up