import hashlib
import socket
from threading import Thread


# Global variables
Server_IP = '127.0.0.1'  # Localhost; replace with IP address if needed
Server_PORT = 12000  # Port number; replace with desired port number
BUFFER_SIZE = 1024  # The number of bytes to be received/sent at once

# Communication conventions
SEPARATOR = "<SEP>"

# File to store user credentials
USER_FILE = "users.txt"

# List of online users
online_users = [] # Just contains the peer_id's of all online users

# List of shared resources
shared_resources = [] # Contains resources in the format: (file_name, file_extension, file_size, peer_id)


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
    print(f"[+] Connection from {client_address}")
    users = load_users()  # Load users from file
    
    try:
        while True:
            message = client_socket.recv(BUFFER_SIZE).decode()
            if not message:
                break  # Client disconnected

            print(f"[+] Received Message: {message}")

            if SEPARATOR not in message:
                print("[-] Incorrectly formatted message. Missing separator.")
                break

            parts = message.split(SEPARATOR)
            action = parts[0]
            peer_id = parts[1]
            peer_password = parts[2] if len(parts) > 2 else None

            if action == "login":
                if peer_id in users and users[peer_id] == hashlib.sha256(peer_password.encode()).hexdigest():
                    if peer_id not in online_users:
                        online_users.append(peer_id)
                    print(f"[+] Online Users List: {online_users}")
                    client_socket.send("[+] LOGIN SUCCESSFUL!".encode())
                    
                    # Keep client in loop for further requests
                    while True:
                        try:
                            client_message = client_socket.recv(BUFFER_SIZE).decode()
                            
                            if client_message != "": # Print the client's message if they sent one
                                print(f"[+] {peer_id} sent: {client_message}")
                            
                            if client_message == "logout":
                                print(f"[+] {peer_id} logged out.")
                                online_users.remove(peer_id)
                                client_socket.send("[+] LOGOUT SUCCESSFUL!".encode())
                                break # Break out of the loop
                            elif client_message == "get_online_users":
                                print(f"[+] Online users request from {peer_id}")
                                client_socket.send(str(online_users).encode())
                            elif client_message == "get_shared_resources":
                                print(f"[+] Get shared resources request from {peer_id}")
                                client_socket.send(str(shared_resources).encode())
                            elif client_message == "": # If they haven't said anything yet, chill and wait
                                pass
                            else:
                                client_socket.send("[-] Unknown command.".encode())
                        
                        except Exception as e:
                            print(f"[-] Error with {peer_id}: {e}")
                            break
                
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
            
            else:
                client_socket.send("[-] Unknown command.".encode())
    
    except Exception as e:
        print(f"[-] Error handling client {client_address}: {e}")
    
    finally:
        if peer_id in online_users:
            online_users.remove(peer_id)
        client_socket.close()
        print(f"[-] Connection closed with {client_address}")


def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Ensures that the insanely stupid 'port already in use' error doesn't occur
    server_socket.bind((Server_IP, Server_PORT))
    server_socket.listen(5)
    print(f"[+] Server listening on {Server_IP}:{Server_PORT}")
    
    try:
        while True:
            client_socket, client_address = server_socket.accept()
            client_thread = Thread(target=handle_client, args=(client_socket, client_address))
            client_thread.start()
    except KeyboardInterrupt:
        print("[+] Server shutting down...")
    finally:
        server_socket.close()
        print("[+] Server closed.")


if __name__ == "__main__":
    start_server()
