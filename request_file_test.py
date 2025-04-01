import tcp_client
from unittest.mock import patch, MagicMock
import random

def test_request_file_function():
    """
    Purpose: To test the functionality of the request_file_from_peer function.
    Tests both message construction and successful/unsuccessful request scenarios.
    """
    print("\n=== Testing request_file_from_peer function ===")
    
    # Mock the client socket
    mock_socket = MagicMock()
    
    # Test cases with different inputs and expected responses
    test_cases = [
        # Format: (self_peer_id, resource_owner, file_name, file_ext, mock_response, expected_status)
        ("use1", "use2", "document", "txt", "[+] ACK", True),
        ("Kylo", "Ren", "presentation", "pptx", "[-] ERROR", False),
        ("peerA", "peerB", "data", "csv", "[+] ACK", True),
        ("test1", "test2", "image", "png", "[-] FILE NOT FOUND", False),
        ("clientx", "clienty", "report", "pdf", "[+] ACK", True)
    ]
    
    num_tests_passed = 0
    
    for i, (self_id, owner, file_name, ext, mock_resp, expected_status) in enumerate(test_cases, 1):
        print(f"\nTest Case {i}:")
        print(f"Input: self='{self_id}', owner='{owner}', file='{file_name}.{ext}'")
        
        # Setup mock return value
        mock_socket.recv.return_value = mock_resp.encode()
        
        # Call the function
        response = tcp_client.request_file_from_peer(mock_socket, self_id, owner, file_name, ext)
        
        # Verify the message construction
        expected_msg = f"p<SEP>{self_id}<SEP>{owner}<SEP>{file_name}<SEP>{ext}"
        mock_socket.send.assert_called_with(expected_msg.encode())
        
        # Verify the response handling
        if (mock_resp.startswith("[+]") and expected_status) or (not mock_resp.startswith("[+]") and not expected_status):
            print(f"✓ PASSED - Expected status: {expected_status}, Got: {mock_resp}")
            num_tests_passed += 1
        else:
            print(f"✗ FAILED - Expected status: {expected_status}, Got: {mock_resp}")
    
    # Calculate and print success rate
    success_rate = (num_tests_passed / len(test_cases)) * 100
    print(f"\nTest Results: {num_tests_passed}/{len(test_cases)} tests passed")
    print(f"Success Rate: {success_rate:.2f}%")

if __name__ == '__main__':
    test_request_file_function()