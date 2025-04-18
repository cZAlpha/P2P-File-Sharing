from threading import Thread
import datetime
import hashlib
import socket
import os  # Added for checksum calculation

# Global variables
Server_IP = '127.0.0.1'  # Localhost; replace with IP address if needed
Server_PORT = 12000  # Port number; replace with desired port number
BUFFER_SIZE = 1024  # The number of bytes to be received/sent at once

# Communication conventions
SEPARATOR = "<SEP>"

# File to store user credentials
USER_FILE = "users.txt"

# List of online users
# Format: [(peer_id, (peer_server_ip, peer_server_port)), ...]
online_users = [] # Just contains the peer_id's of all online users

# List of shared resources
# Contains resources in the format: (resource_peer_id, resource_file_name, resource_file_extension, resource_file_size, last_modified, version, checksum)  # Modified line
shared_resources = [] 

# Added function for checksum calculation
# def calculate_checksum(file_path):
#     """Calculate MD5 checksum of a file"""
#     hash_md5 = hashlib.md5()
#     with open(file_path, "rb") as f:
#         for chunk in iter(lambda: f.read(4096), b""):
#             hash_md5.update(chunk)
#     return hash_md5.hexdigest()

# Added function for version tracking
# def get_latest_version(peer_id, file_name, extension):
#     """Get the latest version number for a file"""
#     versions = [res[5] for res in shared_resources if res[:3] == (peer_id, file_name, extension)]
#     return max(versions) if versions else 0


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


# Register a new resource
def register_resource(resource_peer_id, resource_file_name, resource_file_extension, resource_file_size, resource_date_modified, file_checksum=None):  # Modified signature
    """
    Purpose: This function appends a resource to the shared_resources list.
    Now includes version tracking and checksum validation.
    """
    # Generate resource identifier
    resource_id = (resource_peer_id, resource_file_name, resource_file_extension)
    
    # Find existing versions
    existing_versions = [res for res in shared_resources if res[:3] == resource_id]
    
    # Determine new version number
    new_version = max([res[5] for res in existing_versions], default=0) + 1 if existing_versions else 1
    
    # Remove old versions from same peer
    for res in existing_versions[:]:
        if res[0] == resource_peer_id:
            shared_resources.remove(res)
    
    # Add new resource with version info
    new_resource = (*resource_id, resource_file_size, resource_date_modified, new_version, file_checksum)
    shared_resources.append(new_resource)
    
    return True


# Deregister an existing resource
def deregister_resource(resource_peer_id, resource_file_name, resource_file_extension):
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
        if resource[0] == resource_peer_id and resource[1] == resource_file_name and resource[2] == resource_file_extension:
            shared_resources.remove(resource)
            return True
    return False


# Function used to grab the ip and port address from the server information from a given peer
def extract_ip_and_port(server_info):
    # Remove the parentheses and split the string by the comma
    ip, port = server_info.strip("()").split(", ")
    
    # Convert the IP and port into their correct types
    ip = ip.strip("'")  # Remove the quotes around the IP
    port = int(port)    # Convert the port into an integer
    
    return ip, port


# Request a file transfer from one peer to another
def request_file_transfer(requesting_peer, resource_owner, resource_file_name, resource_file_extension):
    """
    Purpose: Facilitates a peer-to-peer file transfer by providing the requesting peer 
    with the resource owner's IP.
    Args:
        requesting_peer: The peer ID of the requesting client.
        resource_owner: The peer ID of the client that owns the resource.
        resource_file_name: The name of the requested file.
        resource_file_extension: The file extension of the requested file.
    Returns:
        The (IP address, port) of the resource owner or an error message.
    """
    if requesting_peer == resource_owner: # Check if the peer is requesting a file from themselves
        return f"[!] You are requesting a file you own, you cannot download a file from yourself!"
    resource_to_check = (resource_owner, resource_file_name, resource_file_extension)
    for user in online_users: # Check if the resource owner is online still
        owner_server_info = user[1] # Format: (server_ip, server_port)
        if user[0] == resource_owner: 
            for resource in shared_resources: # Iterate over the shared_resources and check if the resource_to_check is in it
                if resource[:3] == resource_to_check:  # If the resource is in the shared_resources list
                    owner_server_ip, owner_server_port = extract_ip_and_port(owner_server_info) # Extract the ip and port information
                    resource_version_num = resource[5] # Grab the version number to track if the file should be updated during syncing
                    # Send the requesting peer the owner's contact information and version number of the file
                    return f"a{SEPARATOR}{resource_owner}{SEPARATOR}{owner_server_ip}{SEPARATOR}{owner_server_port}{SEPARATOR}{resource_version_num}"
    return "[-] FILE NOT AVAILABLE OR PEER OFFLINE."


# Handle client(s)
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
            
            logged_in = False
            
            if action == "login":
                # Grab user's server's ip and port
                peer_server_info = parts[3]
                
                if peer_id in users and users[peer_id] == hashlib.sha256(peer_password.encode()).hexdigest():
                    if peer_id not in online_users:
                        online_users.append((peer_id, peer_server_info))
                        print(online_users)
                    print(f"[+] Online Users List: {online_users}")
                    client_socket.send("[+] LOGIN SUCCESSFUL!".encode())
                    logged_in = True
                    
                    # Keep client in loop for further requests
                    while logged_in:
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
                                resource_date_modified = parts[5] if len(parts) > 5 else None
                                file_checksum = parts[6] if len(parts) > 6 else None  # Added for checksum
                                
                                if action == "logout":
                                    for user in online_users[:]:  # Iterate over a copy to avoid modifying while iterating
                                        if user[0] == peer_id:
                                            online_users.remove(user)
                                            print(f"[+] {peer_id} logged out.")
                                            print(f"[+] Online users list is now: {online_users}")
                                            client_socket.send("[+] LOGOUT SUCCESSFUL!".encode())
                                            logged_in = False        
                                
                                elif action == "get_online_users":
                                    print(f"[+] Online users request from {peer_id}")
                                    list_of_online_peer_ids = []
                                    for user in online_users:
                                        list_of_online_peer_ids.append(user[0]) # Only append the peer id not the server info
                                    client_socket.send(str(list_of_online_peer_ids).encode())
                                
                                elif action == "l":
                                    print(f"[+] Get shared resources request from {peer_id}")
                                    # Convert timestamp to human-readable format
                                    formatted_resources = []
                                    for resource in shared_resources:
                                        peer_id, file_name, file_extension, file_size, timestamp, version, checksum = resource  # Modified unpacking
                                        readable_timestamp = datetime.datetime.fromtimestamp(float(timestamp)).strftime('%Y-%m-%d %H:%M:%S')
                                        formatted_resources.append((peer_id, file_name, file_extension, file_size, readable_timestamp, version))  # Added version
                                    
                                    client_socket.send(str(formatted_resources).encode())
                                
                                elif action == "r":
                                    print(f"[+] Register resource request from {resource_peer_id}")
                                    peer_is_online = False
                                    for user in online_users: # Check if the peer is online
                                        if user[0] == peer_id:
                                            peer_is_online = True
                                    if peer_is_online and register_resource(resource_peer_id, resource_file_name, resource_file_extension, resource_file_size, resource_date_modified, file_checksum):  # Modified call
                                        print(f"[+] Resource {resource_file_name}.{resource_file_extension} added.")
                                        client_socket.send(f"[+] Resource {resource_file_name}.{resource_file_extension} was added.".encode())
                                    else:
                                        if not peer_is_online: # If the peer wasn't online and that threw an error
                                            print("[-] Resource was not added because the peer registering the resource is not online. This is an error with out code!")
                                            client_socket.send("[-] Resource was not added because the peer registering the resource is not online. This is an error with out code!".encode())
                                        else: # If the peer WAS online but there was a dup or some other issue
                                            print("[-] Resource was not added. Likely a perfect duplicate file.")
                                            client_socket.send("[-] Resource was not added. Likely a perfect duplicate file.".encode())
                                
                                elif action == "d":
                                    # TODO: Only allow the user whose file it is to de-register the resource (this requires a slight restructure of the 'd' message format!)
                                    for user in online_users:
                                        if user[0] == peer_id:
                                            if len(shared_resources) > 0: # Check there's even a resource to de-register
                                                if (deregister_resource(peer_id, resource_file_name, resource_file_extension)):
                                                    client_socket.send("[+] FILE WAS DEREGISTERED.".encode())
                                                else:
                                                    client_socket.send("[-] FILE DEREGISTRATION FAILED.".encode())
                                            else: # If no resources
                                                client_socket.send("[-] No shared resources to deregister.".encode())
                                        else:
                                            client_socket.send("[-] YOU ARE NOT A USER IN THE NETWORK.".encode())
                                
                                elif action == "p": # Resource Request
                                    # Format: p, self_peer_id, resource_owner_peer_id, file_name, file_extension (commas are <SEP>)
                                    print(f"Parts of resource request message: {parts}")
                                    requesting_peer = parts[1]
                                    resource_owner = parts[2]
                                    resource_file_name = parts[3]
                                    resource_file_extension = parts[4]
                                    # This response will be:
                                    #   - Success: "a{SEPARATOR}{resource_owner}{SEPARATOR}{owner_server_ip}{SEPARATOR}{owner_server_port}{SEPARATOR}{resource_version_num}"
                                    #   - Failure (Not available): "[-] FILE NOT AVAILABLE OR PEER OFFLINE."
                                    #   - Failure (From yourself): "[!] You are requesting a file you own, you cannot download a file from yourself!"
                                    response = request_file_transfer(requesting_peer, resource_owner, resource_file_name, resource_file_extension)
                                    client_socket.send(response.encode())
                                
                                else:
                                    print(f"[-] Unknown command from {peer_id}: {action}")
                                    client_socket.send("[-] Unknown command.".encode())
                        
                        except Exception as e:
                            print(f"[-] Error with {peer_id}: {e}")
                            logged_in = False
                            break
                
                else:
                    print(f"[-] LOGIN FAILED! Incorrect credentials from {peer_id}.")
                    client_socket.send("[-] LOGIN FAILED! Incorrect credentials.".encode())
            
            elif action == "register":
                if peer_id in users:
                    client_socket.send("[-] REGISTRATION FAILED! Username already exists.".encode())
                elif peer_id in online_users:
                    client_socket.send("[-] REGISTRATION FAILED! You're already logged in??".encode())
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
        for user in online_users[:]:  # Iterate over a copy to avoid modifying while iterating
            if user[0] == peer_id:
                online_users.remove(user)
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
            client_thread.daemon = True  # Ensures the thread stops if the main server exits
            client_thread.start()
    except KeyboardInterrupt:
        print("[+] Server shutting down...")
    finally:
        server_socket.close()
        print("[+] Server closed.")


if __name__ == "__main__":
    start_server()