import threading
import time
import random
import socket
from tcp_client import create_persistent_connection, login
from tcp_server import start_server


# Server information
SERVER_IP_ADDRESS = "127.0.0.1"
SERVER_PORT = 12000

# Hardcoded user list
userList = [("czalpha", "D10686712"), ("wdonzcar", "sandwich1")]


def run_server():
   """Starts the server in a separate thread."""
   try:
      start_server()  # Call the existing function without modification
   except Exception as e:
      print(f"Server error: {e}")


def login_test():
   """
   Purpose: To test the functionality of the login function.
   Returns: True if login was successful, False otherwise.
   """

   print("Starting server up...")

   # Start the server in a separate thread
   server_thread = threading.Thread(target=run_server, daemon=True)
   server_thread.start()

   time.sleep(1)  # Wait a bit for the server to fully start

   print("Starting client up...")

   # Create a client socket and connect to the server
   client_socket = create_persistent_connection(SERVER_IP_ADDRESS, SERVER_PORT)

   time.sleep(0.5)

   # Select a random user
   username, password = random.choice(userList)
   user_server_info = ("127.0.0.1", 12094)  # Dummy info

   # Attempt login
   login_status = login(client_socket, user_server_info, username, password)

   print("Stopping server...")

   # Create a temporary socket to trigger server shutdown
   try:
      shutdown_socket = socket.create_connection((SERVER_IP_ADDRESS, SERVER_PORT), timeout=2)
      shutdown_socket.close()
   except Exception as e:
      print(f"Error closing server: {e}")

   return login_status


if __name__ == "__main__":
   num_of_tests = 10
   num_of_tests_passed = 0
   for _ in range(num_of_tests):
      if (login_test()):
         num_of_tests_passed += 1
         time.sleep(1) # Give a pause between tests
         for _ in range(20): # Put some white space in the console
            print("")
   print(f"Test Success Rate: {num_of_tests_passed/num_of_tests}")