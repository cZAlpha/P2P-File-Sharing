from unittest import TestCase
import unittest

shared_resources = []


def register_resource(resource_peer_id, resource_file_name, resource_file_extension, resource_file_size):
    """
    Purpose: This function appends a resource to the shared_resources list
    Args:
        resource_peer_id: The peer ID of the Peer who has the resource
        resource_file_name: The name of the file to be deregistered
        resource_file_extension: The file extension
        resource_file_size: The size of the file in bytes
    Returns:
        True if resource was added to the list with no issues, otherwise false
    """

    # If all args were given
    if (resource_peer_id and resource_file_name and resource_file_extension and resource_file_size):
        resource = (resource_peer_id, resource_file_name, resource_file_extension, resource_file_size)
        # If the resource ain't a repeat, add it and return true
        if resource not in shared_resources:
            shared_resources.append(resource)
            return True
    # Otherwise return false
    return False


class TestResourceRegistration(unittest.TestCase):
    def setUp(self):
        global shared_resources
        shared_resources = []  # Reset shared resources before each test

    def test_register_resource_success(self):
        result = register_resource("peer1", "file1", ".txt", 1024)
        self.assertTrue(result)
        print("test_register_resource_success passed")

    def test_register_resource_duplicate(self):
        register_resource("peer1", "file1", ".txt", 1024)
        result = register_resource("peer1", "file1", ".txt", 1024)
        self.assertFalse(result)
        print("test_register_resource_duplicate passed")

    def test_register_resource_missing_fields(self):
        result = register_resource("peer1", "", ".txt", 1024)
        self.assertFalse(result)
        print("test_register_resource_missing_fields passed")


if __name__ == "__main__":
    suite = unittest.TestLoader().loadTestsFromTestCase(TestResourceRegistration)
    runner = unittest.TextTestRunner()
    runner.run(suite)