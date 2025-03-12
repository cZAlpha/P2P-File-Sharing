import hashlib  # For hashing passwords when logging in
from socket import *

# Global variables
BUFFER_SIZE = 1024 # The number of bytes to be received/sent at once

# Personal information for this client
# PEER_ID = "czalpha"  # Commented out: No longer needed as users should input their credentials
# PEER_PASSWORD = "password"  # Commented out: No longer needed as users should input their credentials
USER_FILE_PATH = 'users.txt'  # Path to the file storing user ids and hashed passwords

# Server information for easier connection (don't need to enter it every time)
SERVER_IP_ADDRESS = "127.0.0.1"
SERVER_PORT = 12000

# Communication conventions
SEPARATOR = "<SEP>"


def create_persistent_connection(ip, port):
    '''
    Purpose: 
        Establishes a persistent connection to the server.
    Args.:
        ip: The server's IP address
        port: The server's IP port
    Returns: 
        The client socket
    '''
    client_socket = socket(AF_INET, SOCK_STREAM)
    client_socket.connect((ip, port))
    return client_socket


def send_tcp_message(client_socket, message):
    '''
    Purpose: 
        Function that sends a TCP message to a given Server (IP)
    Args.:
        server: The server's IP address
        message: The message to send to the server
    Returns: 
        The string (decoded from byte string) response from the server
    '''
    client_socket.send(message.encode())
    response = client_socket.recv(BUFFER_SIZE).decode()
    return response


def login(client_socket):
    '''
    Purpose: 
        Function that logs the user into the server following our login protocol diagram
    Args: 
        client_socket: The socket that the peer uses to talk to the server
    Returns:
        True if success on login, otherwise false
    Notes:
        Login Message Format: "peer_id<SEP>peer_password" this is a byte string message that contains the id and password of the peer
        Passwords: Passwords are hashed before sending them to the server to avoid sending plain-text passwords over the network
    '''
    
    # Initial console logging
    print("\n", "[+] Client instance is now active.", sep="")
    
    peer_id = input('[+] Enter your Peer ID: ').strip()
    peer_password = input('[+] Enter your password: ').strip()
    
    # Login Message Construction
    hashed_password = hashlib.sha256(peer_password.encode()).hexdigest() # Hex digest of password (using byte digest requires more lines of code)
    login_message = f"login{SEPARATOR}{peer_id}{SEPARATOR}{hashed_password}" # The login message being made
    print(f"[+] Sending the following login message to the server: {login_message}")
    
    response = send_tcp_message(client_socket, login_message)
    print(response) # Print the response returned by the function 'send_tcp_message'
    
    if response[1] == "+": # Login Successful
        return True
    else:
        return False


def logout(client_socket):
    '''
    Purpose: 
        Function that logs the user into the server following our login protocol diagram
    Args: 
        client_socket: The socket that the peer uses to talk to the server
    Returns:
        Nothing, this is a void function
    '''
    response = send_tcp_message(client_socket, "logout")
    print(response) # Print the response returned by the function 'send_tcp_message'


def check_user_exists(peer_id):
    """
    Check if the given peer_id already exists in the user file.
    """
    try:
        with open(USER_FILE_PATH, 'r') as file:
            for line in file:
                user_id, _ = line.strip().split(SEPARATOR)
                if user_id == peer_id:
                    return True
    except FileNotFoundError:
        return False  # If file doesn't exist, return False (no existing users)
    return False


def register(client_socket):
    '''
    Purpose:
        Function to register a new user with the server
    Args:
        client_socket: The socket that the peer uses to talk to the server
    Returns:
        True if registered successfully, false otherwise
    '''
    print("\n[+] Registration")
    
    # Loop var for peer_id getting
    loop_peer_id = True
    while loop_peer_id:
        peer_id = input('[+] Enter your Peer ID: ')
        
        # Check if the peer_id already exists in the file
        if check_user_exists(peer_id):
            print(f"[!] The Peer ID '{peer_id}' already exists. Please choose a different ID.")
        elif peer_id == "": # If blank user id
            print("[!] You cannot enter an empty string as a peer id!")
        else:
            loop_peer_id = False  # Valid peer_id, exit the loop
    
    peer_password = input('[+] Enter your password: ')
    hashed_password = hashlib.sha256(peer_password.encode()).hexdigest()
    register_message = f"register{SEPARATOR}{peer_id}{SEPARATOR}{hashed_password}"
    print(f"[+] Sending registration message: {register_message}")
    response = send_tcp_message(client_socket, register_message)
    
    if response[1] == "+": # Success
        return True
    else:
        return False


def get_online_users(client_socket):
    '''
    Purpose:
        Function to fetch the list of online users from the server
    Args:
        client_socket: The socket that the peer uses to talk to the server
    Returns:
        The response from the server
    '''
    message = f"get_online_users"
    print(f"[+] Fetching online users...")
    response = send_tcp_message(client_socket, message)
    print(f"[+] Online users fetched: {response}")
    return response


def get_shared_resources(client_socket):
    '''
    Purpose:
        Function to fetch the list of shared resources currently active in the P2P network
    Args:
        client_socket: The socket that the peer uses to talk to the server
    Returns:
        The response from the server
    '''
    message = f"get_shared_resources"
    print(f"[+] Fetching shared resources...")
    response = send_tcp_message(client_socket, message)
    print(f"[+] Shared resources fetched: {response}")
    return response


def register_resource(client_socket, resource_peer_id, resource_file_name, resource_file_extension, resource_file_size):
    """
    Purpose: This function returns a byte-encoded message to be sent to
                the indexing server by a Peer in order to register a file
                from the sharable files on the indexing server
    Args:
        client_socket: The socket that the peer uses to talk to the server
        resource_peer_id: The peer ID of the Peer who has the resource
        resource_file_name: The name of the file to be deregistered
        resource_file_extension: The file extension
        resource_file_size: The size of the file in bytes
    Returns: Byte encoded message that will tell the server what to de-register
    """
    # NOTE: The file extension should never include the '.', only the actual extension; i.e. "txt", "png", etc.
    SEPARATOR = "<SEP>" # Establish separator phrase
    message = ("r" + SEPARATOR + resource_peer_id + SEPARATOR + resource_file_name + SEPARATOR + resource_file_extension + SEPARATOR + resource_file_size).encode() # Create the message
    response = send_tcp_message(client_socket, message)
    print(f"[+] Resource Registered: {response}")
    return response


def main():
    '''
    Purpose:
        Main function to provide a menu for the user
    '''
    
    # Connect to the server and ensure connection persistence
    client_socket = create_persistent_connection(SERVER_IP_ADDRESS, SERVER_PORT) 
    
    logged_in = False # Keeps track of if the user is logged in or not
    
    while not logged_in:
        print("\n1. Login\n2. Register\n3. Exit")
        choice = input("Choose an option: ")
        
        if choice == "1": # Log in
            logged_in = login(client_socket) # Update the login status variable by trying to log the user in
        elif choice == "2": # Register
            register(client_socket)
            print("") # Add a new line and then force them to login
            logged_in = login(client_socket) # Update the login status variable by trying to log the user in
        elif choice == "3": # Exit
            break
        else: # Invalid input catch
            print("Invalid choice. Try again.")
    
    for _ in range(20): # Create some white space
            print("")
    
    while logged_in:
        print("\n1. View Online Users\n2. View Shared Resources\n3. Logout")
        choice = input("Choose an option: ")
        
        if choice == "1": # Get Online Users
            online_users = get_online_users(client_socket)
        elif choice == "2": # Get Shared Resources
            shared_resources = get_shared_resources(client_socket)
        elif choice == "3": # Log out
            logout(client_socket) # Logs the user out by sending the server a logout message
            logged_in = False 


if __name__ == '__main__':
    main() # Upon running this file, call the main function