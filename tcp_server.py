import socket
from threading import Thread
import hashlib


# Global variables
Server_IP = '127.0.0.1' # Localhost ; replace to IP address if needed
Server_PORT = 12000 # Port number ; replace with desired port number
BUFFER_SIZE = 1024 # The number of bytes to be received/sent at once

# List of tuples containing (peer_id, peer_password) of valid Peers
peer_list = [("czalpha", "password")] 

# Communication conventions
SEPARATOR = "<SEP>"


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
        while True:
            try:
                login_message = client_socket.recv(BUFFER_SIZE) # Receive the first 1024 bytes of data from the client
                decoded_login_message = login_message.decode() # Save the decoded login message for usage in the login process
                
                print(login_message)
                if not login_message: # If there's no data, break
                    break
                print(f"[+] Received Login Message: {login_message.decode()}") # Print received data to console
                
                if SEPARATOR not in decoded_login_message: # Check that the minimal formatting is there
                    print(f"[-] Peer sent incorrectly formatted login message. Did not contain separator phrase. Message was: {login_message}")
                    break
                
                try: # Try to parse the peer's id and hashed password from their message
                    peer_id, hashed_password = decoded_login_message.split(SEPARATOR)
                except ValueError: # Handle errors gracefully
                    print(f"[-] Invalid login format from {client_address}. Message: {decoded_login_message}")
                    break
                
                for peer in peer_list: # Iterate over valid peers and check for valid credentials
                    if peer[0] == peer_id and hashlib.sha256(peer[1].encode()).hexdigest() == hashed_password: # Check for valid credentials
                        print(f"[+] Peer: {peer_id} has successfully joined the network.")
                        client_socket.send("[+] LOGIN SUCCESSFUL!".encode()) # Let the Client know they have successfully logged in
                        return # Halt function for now
                
                client_socket.send("[-] LOGIN FAILED! Incorrect login credentials...".encode()) # Let the Client know they failed to log in
                
            except socket.error as e: # Handle errors gracefully
                print(f"[-] Socket error occurred while communicating with {client_address}: {e}")
                break
            except UnicodeDecodeError as e: # Handle errors gracefully
                print(f"[-] Error decoding data from {client_address}: {e}")
                continue
            
    # General exception handling
    except Exception as e:
        print(f"[-] Unexpected error occurred with client {client_address}: {e}")
    finally: # After everything is done
        try: # Try closing the connection to the given client
            client_socket.close()
            print(f"[-] Connection closed with {client_address}")
        except socket.error as e: # Handle errors gracefully
            print(f"[-] Error closing connection with {client_address}: {e}")


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
