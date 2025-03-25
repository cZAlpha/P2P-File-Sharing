import hashlib  # For hashing passwords when logging in
import time  # timer and countdown
import webbrowser  # For opening the browser
from socket import *  # For socket programming

from stegano import lsb  # For steganography

# Global variables
BUFFER_SIZE = 1024 # The number of bytes to be received/sent at once

# Personal information for this client
# PEER_ID = "czalpha"  # Commented out: No longer needed as users should input their credentials
# PEER_PASSWORD = "password"  # Commented out: No longer needed as users should input their credentials
USER_FILE_PATH = 'users.txt'  # Path to the file storing user ids and hashed passwords

# Server information for easier connection (don't need to enter it every time)
SERVER_IP_ADDRESS = "127.0.0.1"
SERVER_PORT = 12000


ADMIN_USERNAME =   "admin"  # hardcoded Admin username for logging in
# Communication conventions
SEPARATOR = "<SEP>"


def send_tcp_message(server, message):
    '''
    Purpose: 
        Function that sends a TCP message to a given Server (IP)
    Args.:
        server: The server's IP address
        message: The message to send to the server
    Returns: 
        The string (decoded from byte string) response from the server
    '''
    client_socket = socket(AF_INET,SOCK_STREAM) # Instantiate a client socket with which to connect to the server
    client_socket.connect(server) # Connect to the server
    client_socket.send(message.encode()) # Send the encoded message from the server
    response = client_socket.recv(BUFFER_SIZE) # Wait for a response, and then accept the first BUFFER_SIZE # of bytes from the response
    client_socket.close()
    return response.decode()


def login():
    '''
    Purpose: 
        Function that logs the user into the server following our login protocol diagram
    Args: 
        server_ip_address: This is the server's IPv4 address
        server_port: The port with which the server is using
        peer_id: Similar to a user id for a normal program, this is a unique identifier for Peers
        peer_password: This is the password the Peer uses to log into the server (can also use Steno. password but that isn't implemented yet)
    Returns:
        Nothing, this is a void function.
    Notes:
        Login Message Format: "peer_id<SEP>peer_password" this is a byte string message that contains the id and password of the peer
        Passwords: Passwords are hashed before sending them to the server to avoid sending plain-text passwords over the network
    '''
    
    # Initial console logging
    print("\n", "[+] Client instance is now active.", sep="")
    print("    For default args., hit enter on prompts without typing anything", end="\n\n")
    
    # User input
    ip = input('[+] Enter IP address: ')
    if ip == "": # Default case handling
        print("Default args.")
        ip = SERVER_IP_ADDRESS
    port = input('[+] Enter port: ')
    if port == "": # Default case handling
        print("Default args.")
        port = SERVER_PORT
    else: # If something was entered, typecast to integer
        port = int(port)
    
    peer_id = input('[+] Enter your Peer ID: ')
    # if peer_id == "": # Default case handling
    #     print("Default args.")
    #     peer_id = PEER_ID  # Commented out: No longer needed as users should input their credentials
    peer_password = input('[+] Enter your password: ')
    # if peer_password == "":
    #     print("Default args.")
    #     peer_password = PEER_PASSWORD  # Commented out: No longer needed as users should input their credentials
    
    # Login Message Construction
    hashed_password = hashlib.sha256(peer_password.encode()).hexdigest() # Hex digest of password (using byte digest requires more lines of code)
    login_message = f"login{SEPARATOR}{peer_id}{SEPARATOR}{hashed_password}" # The login message being made
    print(f"[+] Sending the following login message to the server: {login_message}")
    print(send_tcp_message((ip, port), login_message)) # Print the response returned by the function 'send_tcp_message'


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


def register():
    '''
    Purpose:
        Function to register a new user with the server
    Returns:
        Nothing, this is a void function.
    '''
    print("\n[+] Registration")
    ip = input('[+] Enter IP address: ') or SERVER_IP_ADDRESS
    port = input('[+] Enter port: ') or SERVER_PORT
    port = int(port)

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
    print(send_tcp_message((ip, port), register_message))


def get_online_users():
    '''
    Purpose:
        Function to fetch the list of online users from the server
    Returns:
        Nothing, this is a void function.
    '''
    ip = input('[+] Enter IP address: ') or SERVER_IP_ADDRESS
    port = input('[+] Enter port: ') or SERVER_PORT
    port = int(port)
    message = f"get_online_users{SEPARATOR}"
    print(f"[+] Fetching online users...")
    print(send_tcp_message((ip, port), message))

def admin_login():
    '''
    Purpose:
        Function to log in as an admin using steganography.
        If the password is incorrect or left blank, redirect to a YouTube link.
    '''
    
    print("\n[+] Admin Login")
    ip = input('[+] Enter IP address: ') or SERVER_IP_ADDRESS
    port = input('[+] Enter port: ') or SERVER_PORT
    port = int(port)
    
    # Ask for the steganography image path
    image_path = input('[+] Enter the path to the steganography image: ')
    password = None  # Initialize password as None

    if image_path:
        try:
            # Decode the password from the image
            password = lsb.reveal(image_path)
            print(f"[+] Password found in image: {password}")
        except Exception as e:
            print(f"[-] Error decoding password from image: {e}")

    # If password is not decoded or left blank, start the countdown and redirect
    if not password:
        print("[-] Logging in ... have fun :)")
        countdown_sequence = 3  # Set the countdown duration (in seconds)
        for i in range(countdown_sequence, 0, -1):
            print(f"[-] Redirecting in {i} seconds ...")
            time.sleep(1)  # Wait for 1 second

        # Redirect to YouTube
        print("[-] Redirecting...")
        webbrowser.open("https://www.youtube.com/watch?v=dQw4w9WgXcQ&ab_channel=RickAstley")
        return

    # If password is decoded, send it to the server
    admin_login_message = f"admin_login{SEPARATOR}{ADMIN_USERNAME}{SEPARATOR}{password}"
    print(f"[+] Sending admin login message: {admin_login_message}")
    response = send_tcp_message((ip, port), admin_login_message)
    print(response)

def main():
    '''
    Purpose:
        Main function to provide a menu for the user
    '''
    while True:
        print("\n1. Login\n2. Register\n3. View Online Users\n4. Admin\n5. Exit")
        choice = input("Choose an option: ")
        if choice == "1":
            login()
        elif choice == "2":
            register()
        elif choice == "3":
            get_online_users()
        elif choice == "4":
            admin_login()
        elif choice == "5":
            break
        else:
            print("Invalid choice. Try again.")


if __name__ == '__main__':
    main() # Upon running this file, call the main function