import socket
from threading import Thread

#Global variables
Server_IP = '127.0.0.1' #localhost ; replace to IP address if needed
Server_PORT = 12000 #port number ; replace with desired port number

def handle_client(client_socket, client_address):
    '''
    Function to handle client connection
    It receives data from client and sends it back to client
    '''
    try:
        print(f"Connection from {client_address}")
        while True:
            try:
                data = client_socket.recv(1024)
                if not data:
                    break
                print(f"Received data: {data.decode()}")
                client_socket.send(data)
            except socket.error as e:
                print(f"Socket error occurred while communicating with {client_address}: {e}")
                break
            except UnicodeDecodeError as e:
                print(f"Error decoding data from {client_address}: {e}")
                continue
    except Exception as e:
        print(f"Unexpected error occurred with client {client_address}: {e}")
    finally:
        try:
            client_socket.close()
            print(f"Connection closed with {client_address}")
        except socket.error as e:
            print(f"Error closing connection with {client_address}: {e}")
            
def start_server():
    '''
    Function to start server
    Once start it actively listens for incoming connections
    '''
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((Server_IP, Server_PORT))
    server_socket.listen(5)
    print(f"Server listening on {Server_IP}:{Server_PORT}")

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            client_thread = Thread(target=handle_client, args=(client_socket, client_address))
            client_thread.start()
    except KeyboardInterrupt:
        print("Server shutting down...")
    finally:
        server_socket.close()
        print("Server closed.")
        
if __name__ == "__main__":
    start_server()
