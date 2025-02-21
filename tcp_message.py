
from socket import *


Server_IP = '127.0.0.1' #localhost ; replace to IP address if needed
Server_PORT = 12000 #port number ; replace with desired port number

#creating client socket
def create_client_socket():
    client_socket = socket(AF_INET, SOCK_STREAM)
    return client_socket


#connecting to the client
def greeting_client(client_socket, Server_IP, Server_PORT):
    try:
        client_socket.connect((Server_IP, Server_PORT))
        print(f"Connecting to IP: {Server_IP} and Port: {Server_PORT}")
        init_message = "We are connected!"
        client_socket.send(init_message.encode())
    #error handling
    except Exception as e:
        print(f"There was an error connecting to the client:{e}")


#sending a message from server to client
def send_message_toclient(client_socket, message):
    try:
        message = input("Enter a message here: ")
        client_socket.send(message.encode())
        #confirmation that client has received the message
        ack = client_socket.recv(1024).decode()
        print(f"client received: {ack}")

    except Exception as e:
        print(f"Something went wrong, you cannot contact the client: {e}")


    #CLOSES THE SOCKET + error handling
    finally:
        try:
            client_socket.close()
            print(f"The connection has been closed with client")

        except error as e:
            print(f"There was a problem closing the connection: {e}")

#client receiving messages from server
def receive_server_messages(Server_IP, Server_PORT):

    client_socket = socket(AF_INET, SOCK_STREAM)
    try:
        client_socket.connect((Server_IP, Server_PORT))
        print("The client and server have been connected!")

        while True:
        # Receive message from server
            message = client_socket.recv(1024).decode()
            if not message:
                break

            print(f"The server sent the following message: {message}")

            # Send acknowledgment
            ack = "The message has been received"
            client_socket.send(ack.encode())

    except Exception as e:
        print(f"The message was not able to be received: {e}")

    finally:
        client_socket.close()
        print("The connection has been closed")


if __name__ == "__main__":
    state = input(f"Please enter if you are 'server' or 'client': ")
    Server_IP = input("Enter a server IP address: ")
    Server_PORT = int(input("Enter a server port number: "))

    #if they are the server they are SENDING to the client
    # if they are the client they are RECEIVING from the server
    if state == 'server':
        client_socket = socket(AF_INET, SOCK_STREAM)
        greeting_client(client_socket, Server_IP, Server_PORT)
        send_message_toclient(client_socket)

    elif state == 'client':
        receive_server_messages(Server_IP, Server_PORT)

    else:
        print(f" Please enter either 'server' or 'client': ")



