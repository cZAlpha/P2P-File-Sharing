import tcp_client
from unittest.mock import Mock

client_socket = Mock()

if __name__ == '__main__':

    numOfTestsPassed = 0

    #task1
    expected = "d<SEP>user1<SEP>document<SEP>txt"
    actual = tcp_client.deregister_resource(client_socket,'user1', "document", "txt")
    if expected == actual:
        numOfTestsPassed += 1
        

    #task2
    expected = "d<SEP>user2<SEP>hello<SEP>pdf"
    actual = tcp_client.deregister_resource(client_socket, "user2", "hello", "pdf")
    if expected == actual:
        numOfTestsPassed += 1


    #task3
    expected = "d<SEP>user3<SEP>specialfile<SEP>py"
    actual = tcp_client.deregister_resource(client_socket,"user3", "specialfile", "py")
    if expected == actual:
        numOfTestsPassed += 1

    #task4
    expected = "d<SEP>user4<SEP>thisisafilename<SEP>docx"
    actual = tcp_client.deregister_resource(client_socket,"user4", "thisisafilename", "docx")
    if expected == actual:
        numOfTestsPassed += 1

    #test5
    expected = "d<SEP>user5<SEP>a<SEP>png"
    actual = tcp_client.deregister_resource(client_socket,"user5", "a", "png")
    if expected == actual:
        numOfTestsPassed += 1

    
    print(f"Test Success Rate: {((numOfTestsPassed/5) * 100)}")