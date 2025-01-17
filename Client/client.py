import os
import requests
import websocket
import threading


INDEX_SERVER = "http://localhost:3000" # The route and port to the indexing server (locally hosted for now)
INDEX_SERVER_ADDRESS = "localhost:3000" # Server address


def register_file(filename, peer_address):
   response = requests.post(f"{INDEX_SERVER}/register", json={
      "filename": filename,
      "peer": peer_address
   })
   print(response.json())


def fetch_peers(filename):
   response = requests.get(f"{INDEX_SERVER}/files/{filename}")
   print("Peers with file:", response.json().get("peers"))


def start_websocket(server_address):
   """Connect to a WebSocket server and enable messaging."""
   try:
      ws = websocket.WebSocket()
      ws.connect(f"ws://{server_address}")
      print(f"Connected to WebSocket server at {server_address}")

      # Listening thread to handle incoming messages
      def listen():
         while True:
               try:
                  message = ws.recv()
                  if message:
                     print(f"Received: {message}")
               except websocket.WebSocketConnectionClosedException:
                  print("Connection closed by the server.")
                  break
               except Exception as e:
                  print(f"Error receiving message: {e}")
                  break

      threading.Thread(target=listen, daemon=True).start()

      # Main loop for sending messages
      while True:
         message = input("Send a message (type 'exit' to disconnect): ")
         if message.lower() == "exit":
               print("Closing WebSocket connection...")
               ws.close()
               break
         ws.send(message)
   except Exception as e:
      print(f"Error connecting to WebSocket server: {e}")



if __name__ == "__main__":
   print("1. Register file")
   print("2. Fetch peers")
   print("3. Start WebSocket")
   print("4. Exit")
   choice = int(input("Choose an option: "))
   
   if choice == 1:
      filename = input("Enter filename to register: ")
      peer_address = input("Enter your WebSocket address (e.g., ws://127.0.0.1:9000): ")
      register_file(filename, peer_address)
   elif choice == 2:
      filename = input("Enter filename to fetch peers: ")
      fetch_peers(filename)
   elif choice == 3:
      server_address = input("Enter WebSocket server address (e.g., localhost:3000, enter nothing for default server address): ")
      if (server_address == ""): # If empty input, use default server address
         server_address = INDEX_SERVER_ADDRESS # Default server address
      start_websocket(server_address)
   elif choice == 4:
      print("\n", "Exiting...")
   else:
      print("Invalid choice. Exiting.")
