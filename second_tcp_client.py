from socket import *
import hashlib # For hashing passwords when logging in
import time

# Global variables
BUFFER_SIZE = 1024 # The number of bytes to be received/sent at once

# Personal information for this client
PEER_ID = "donczar"
PEER_PASSWORD = "password1"

# Server information for easier connection (don't need to enter it every time)
SERVER_IP_ADDRESS = "127.0.0.1"
SERVER_PORT = 12000

# Communication conventions
SEPARATOR = "<SEP>"

# File Variables
FILE_PATH = "./" # Same dir, hence ./
FILE_NAME = "hello" # Name of the file with no extension
FILE_EXTENSION = "txt" # Extension of the file (file type)


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
   
   print("\n[+] Client instance is now active.")
   print("    For default args., hit enter on prompts without typing anything\n")
   
   ip = input('[?] Enter IP address: ') or SERVER_IP_ADDRESS
   port_input = input('[?] Enter port: ')
   port = int(port_input) if port_input else SERVER_PORT
   peer_id = input('[?] Enter your Peer ID: ') or PEER_ID
   peer_password = input('[?] Enter your password: ') or PEER_PASSWORD
   
   # Persistent socket
   client_socket = socket(AF_INET, SOCK_STREAM)
   client_socket.connect((ip, port))

   hashed_password = hashlib.sha256(peer_password.encode()).hexdigest()
   login_message = peer_id + SEPARATOR + hashed_password
   print(f"[+] Sending login message: {login_message}")
   client_socket.send(login_message.encode())

   response = client_socket.recv(BUFFER_SIZE).decode()
   print(f"[+] Server response: {response}")
   return client_socket


def clearTerminal(newLines=20): # Prints newLines amount of new lines 
   for i in range(newLines):
      print("")


def getInput(client_socket): # This function will ask the user what they would like to do
   validInput = False # Loop variable
   while (not validInput):
      clearTerminal() # Clear the terminal
      print(f"[+] Logged in as {PEER_ID}", end="\n")
      print("")
      print("Type the option number and hit enter", end="\n")
      print("[?] What would you like to do?")
      print("    1: Send file")
      print("    2: Receive file")
      print("    3: Leave network")
      
      userInput = input("") # Prompt user input
      
      if (userInput == "1"): # Send file
         print(f"[+] Preparing to send file {FILE_NAME}.{FILE_EXTENSION}...")
         validInput = True
      elif (userInput == "2"): # Receive file
         print(f"[+] Waiting for file to be received...")
         validInput = True
      elif (userInput == "3"): # Leave network
         print(f"[-] Leaving network...")
         client_socket.close()
         validInput = True
      else:
         print(f"[!] ERROR, invalid input. Must be 1,2, or 3, but was: {userInput}")
         time.sleep(3)


if __name__ == '__main__':
   client_socket = login()  # Get the persistent socket after login
   getInput(client_socket)  # Pass it to handle disconnect