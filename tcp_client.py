from socket import *




def send_tcp_message(server,message):
   client_socket = socket(AF_INET,SOCK_STREAM)
   client_socket.connect(server)
   client_socket.send(message.encode())
   response = client_socket.recv(1048)
   return response.decode()




if __name__ == '__main__':
   ip = input('Enter IP address:')
   port = int(input('Enter port: '))
   message = input('Enter message: ')
   print(send_tcp_message((ip, port), message))
