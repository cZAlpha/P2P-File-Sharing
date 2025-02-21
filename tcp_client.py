from socket import *
import hashlib # For hashing passwords when logging in

# Global variables
BUFFER_SIZE = 1024 # The number of bytes to be received/sent at once

# Personal information for this client
PEER_ID = "czalpha"
PEER_PASSWORD = "password"

# Server information for easier connection (don't need to enter it every time)
SERVER_IP_ADDRESS = "127.0.0.1"
SERVER_PORT = 12000

# Communication conventions
SEPARATOR = "<SEP>"


def login(server_ip_address = SERVER_IP_ADDRESS, server_port = SERVER_PORT, peer_id = PEER_ID, peer_password = PEER_PASSWORD):
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
   if peer_id == "": # Default case handling
      print("Default args.")
      peer_id = PEER_ID
   peer_password = input('[+] Enter your password')
   if peer_password == "":
      print("Default args.")
      peer_password = PEER_PASSWORD
   
   # Login Message Construction
   hashed_password = hashlib.sha256(peer_password.encode()).hexdigest() # Hex digest of password (using byte digest requires more lines of code)
   login_message = peer_id + SEPARATOR + hashed_password # The login message being made
   print(f"[+] Sending the following login message to the server: {login_message}")
   print(send_tcp_message((ip, port), login_message)) # Print the response returned by the function 'send_tcp_message'

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
   
   return response.decode()


if __name__ == '__main__':
   login() # Upon running this file, call the login function