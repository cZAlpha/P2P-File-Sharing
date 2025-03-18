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
# Contains resources in the format: (resource_peer_id, resource_file_name, resource_file_extension, resource_file_size)
# No repeat resources are allowed!
shared_resources = [] 


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


def register_resource(resource_peer_id, resource_file_name, resource_file_extension, resource_file_size):
    """
    Purpose: This function appends a resource to the shared_resources list
    Args:
        resource_peer_id: The peer ID of the Peer who has the resource
        resource_file_name: The name of the file to be deregistered
        resource_file_extension: The file extension
        resource_file_size: The size of the file in bytes
    Returns:
        True if resource was added to the list with no issues, otherwise false
    """
    
    # If all args were given
    if (resource_peer_id and resource_file_name and resource_file_extension and resource_file_size):
        resource = (resource_peer_id, resource_file_name, resource_file_extension, resource_file_size)
        # If the resource ain't a repeat, add it and return true
        if resource not in shared_resources:
            shared_resources.append(resource)
            return True
    # Otherwise return false
    return False

  
def deregister_resource(resource_peer_id, resource_file_name):
    """
    Purpose: This function removes a resource from the shared_resources list.
    Args:
        resource_peer_id: The peer ID of the Peer who owns the resource
        resource_file_name: The name of the file to be deregistered
    Returns:
        True if the resource was removed successfully, otherwise False.
    """
    global shared_resources
    for resource in shared_resources:
        if resource[0] == resource_peer_id and resource[1] == resource_file_name:
            shared_resources.remove(resource)
            return True
    return False


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

                            if client_message:
                                if SEPARATOR not in client_message:
                                    print("[-] Incorrectly formatted message. Missing separator.")
                                    break

                                parts = client_message.split(SEPARATOR)
                                action = parts[0]
                                resource_peer_id = parts[1] if len(parts) > 1 else None
                                resource_file_name = parts[2] if len(parts) > 2 else None
                                resource_file_extension = parts[3] if len(parts) > 3 else None
                                resource_file_size = parts[4] if len(parts) > 4 else None

                                if action == "logout":
                                    print(f"[+] {peer_id} logged out.")
                                    online_users.remove(peer_id)
                                    client_socket.send("[+] LOGOUT SUCCESSFUL!".encode())
                                    break

                                elif action == "get_online_users":
                                    print(f"[+] Online users request from {peer_id}")
                                    client_socket.send(str(online_users).encode())

                                elif action == "get_shared_resources":
                                    print(f"[+] Get shared resources request from {peer_id}")
                                    client_socket.send(str(shared_resources).encode())

                                elif action == "r":
                                    print(f"[+] Register resource request from {peer_id}")
                                    if peer_id in online_users and register_resource(peer_id, resource_file_name, resource_file_extension, resource_file_size):
                                        print(f"[+] Resource {resource_file_name}.{resource_file_extension} added.")
                                        client_socket.send(f"[+] Resource {resource_file_name}.{resource_file_extension} was added.".encode())
                                    else:
                                        print("[-] Resource was not added. Possible duplicate or not an active peer.")
                                        client_socket.send("[-] Resource was not added. Possible duplicate or not an active peer.".encode())

                                elif action == "deregister_resource":
                                    if peer_id in online_users and peer_id == resource_peer_id:
                                        deregister()
                                        client_socket.send("[+] FILE WAS DEREGISTERED.".encode())
                                    else:
                                        client_socket.send("[-] YOU ARE NOT A USER IN THE NETWORK.".encode())

                                else:
                                    print(f"[-] Unknown command from {peer_id}: {action}")
                                    client_socket.send("[-] Unknown command.".encode())

                        except Exception as e:
                            print(f"[-] Error with {peer_id}: {e}")
                            break

                else:
                    print(f"[-] LOGIN FAILED! Incorrect credentials from {peer_id}.")
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
