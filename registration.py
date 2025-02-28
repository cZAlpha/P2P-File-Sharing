def deregister(resource_peer_id, resource_file_name, resource_file_extension):
   """
   Purpose: This function returns a byte-encoded message to be sent to
            the indexing server by a Peer in order to register a file
            from the sharable files on the indexing server
   Args:
      resource_peer_id: The peer ID of the Peer who has the resource
      resource_file_name: The name of the file to be deregistered
      resource_file_extension: The file extension
   Returns: Byte encoded message that will tell the server what to de-register
   """
   # NOTE: The file extension should never include the '.', only the actual extension; i.e. "txt", "png", etc.
   SEPARATOR = "<SEP>" # Establish separator phrase
   message = ("r" + SEPARATOR + resource_peer_id + SEPARATOR + resource_file_name + SEPARATOR + resource_file_extension).encode() # Create the message
   return message