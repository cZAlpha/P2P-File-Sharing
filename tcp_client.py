from tkinter import filedialog, messagebox, scrolledtext, ttk
import tkinter as tk
from socket import *
import threading
import datetime
import hashlib  # For hashing passwords when logging in
import random
import time
import sys
import os


# NOTE:
# Noah's user's password is: D10686712
# Ceasar's user's password is: sandwich1

# Global variables
BUFFER_SIZE = 1024 # The number of bytes to be received/sent at once

# Personal information for this client
# PEER_ID = "czalpha"  # Commented out: No longer needed as users should input their credentials
# PEER_PASSWORD = "password"  # Commented out: No longer needed as users should input their credentials
USER_FILE_PATH = 'users.txt'  # Path to the file storing user ids and hashed passwords

# Server information for easier connection (don't need to enter it every time)
SERVER_IP_ADDRESS = "127.0.0.1"
SERVER_PORT = 12000

# Communication conventions
SEPARATOR = "<SEP>"


class P2PClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("P2P Client")
        self.root.geometry("900x650")
        
        # Configure modern theme
        self.root.tk.call('source', 'themes/azure.tcl')  # You'll need to include azure.tcl theme file
        self.root.tk.call('set_theme', 'dark')
        
        # Client state
        self.logged_in = False
        self.peer_id = ""
        self.client_socket = None
        self.peer_server_socket = None
        
        # Start the server in the background
        self.start_server()
        
        # Start the sync thread in the background
        self.synced_resources = []  # List of tuples (owner, name, ext, version)
        self.start_sync()
        
        # Create connection to main server
        self.connect_to_server()
        
        # Create initial UI
        self.show_login_screen()
    
    def connect_to_server(self):
        try:
            self.client_socket = create_persistent_connection(SERVER_IP_ADDRESS, SERVER_PORT)
        except Exception as e:
            messagebox.showerror("Connection Error", f"Failed to connect to server: {e}")
            self.root.quit()
    
    def start_server(self):
        """Starts the local server in a background thread."""
        def server_thread():
            self.peer_server_socket = start_server()
        
        threading.Thread(target=server_thread, daemon=True).start()
    
    def start_sync(self):
        """Starts the syncing background thread."""
        def sync_thread():
            self.start_sync_thread()
        
        threading.Thread(target=sync_thread, daemon=True).start()

    def show_login_screen(self, show_register=False):
        """Shows login or register screen based on parameter"""
        self.clear_window()
        
        main_frame = ttk.Frame(self.root, padding=(30, 20))
        main_frame.pack(expand=True, fill=tk.BOTH)
        
        # Header
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(pady=(0, 20))
        ttk.Label(header_frame, text="P2P File Sharing", font=('Helvetica', 16, 'bold')).pack()
        
        # Form frame
        form_frame = ttk.Frame(main_frame)
        form_frame.pack(fill=tk.X, pady=10)
        
        if show_register:
            self.create_register_form(form_frame)
        else:
            self.create_login_form(form_frame)
        
        # Switch between login/register
        switch_frame = ttk.Frame(main_frame)
        switch_frame.pack(fill=tk.X, pady=10)
        
        if show_register:
            ttk.Button(switch_frame, text="Back to Login", 
                        command=lambda: self.show_login_screen(False)).pack()
        else:
            ttk.Button(switch_frame, text="Register New Account", 
                        command=lambda: self.show_login_screen(True)).pack()
    
    def create_login_form(self, parent):
        """Creates the login form elements"""
        ttk.Label(parent, text="Peer ID:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.peer_id_entry = ttk.Entry(parent)
        self.peer_id_entry.grid(row=0, column=1, sticky=tk.EW, pady=5)
        
        ttk.Label(parent, text="Password:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.password_entry = ttk.Entry(parent, show="*")
        self.password_entry.grid(row=1, column=1, sticky=tk.EW, pady=5)
        
        # Bind Enter key to login
        self.password_entry.bind('<Return>', lambda e: self.handle_login())
        
        button_frame = ttk.Frame(parent)
        button_frame.grid(row=2, column=0, columnspan=2, pady=15)
        
        login_btn = ttk.Button(button_frame, text="Login", command=self.handle_login, 
                    style='Accent.TButton')
        login_btn.pack(side=tk.LEFT, padx=5)
        
        exit_btn = ttk.Button(button_frame, text="Exit", command=self.root.quit)
        exit_btn.pack(side=tk.LEFT, padx=5)
        
        parent.columnconfigure(1, weight=1)
    
    def create_register_form(self, parent):
        """Creates the registration form elements"""
        ttk.Label(parent, text="Choose Peer ID:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.reg_peer_entry = ttk.Entry(parent)
        self.reg_peer_entry.grid(row=0, column=1, sticky=tk.EW, pady=5)
        
        ttk.Label(parent, text="Password:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.reg_pass_entry = ttk.Entry(parent, show="*")
        self.reg_pass_entry.grid(row=1, column=1, sticky=tk.EW, pady=5)
        
        ttk.Label(parent, text="Confirm Password:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.reg_confirm_entry = ttk.Entry(parent, show="*")
        self.reg_confirm_entry.grid(row=2, column=1, sticky=tk.EW, pady=5)
        
        # Bind Enter key to register
        self.reg_confirm_entry.bind('<Return>', lambda e: self.handle_register())
        
        button_frame = ttk.Frame(parent)
        button_frame.grid(row=3, column=0, columnspan=2, pady=15)
        
        reg_btn = ttk.Button(button_frame, text="Register", command=self.handle_register,
                            style='Accent.TButton')
        reg_btn.pack(side=tk.LEFT, padx=5)
        
        cancel_btn = ttk.Button(button_frame, text="Cancel", 
                        command=lambda: self.show_login_screen(False))
        cancel_btn.pack(side=tk.LEFT, padx=5)
        
        parent.columnconfigure(1, weight=1)
    
    def create_main_ui(self):
        """Creates the main application UI after login."""
        self.clear_window()
        
        # Main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
        
        # Header with user info
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(header_frame, text=f"Logged in as: {self.peer_id}", font=('Helvetica', 10)).pack(side=tk.LEFT)
        
        # Logout button with icon and tooltip
        logout_btn = ttk.Button(header_frame, text="🚪", width=3, command=self.handle_logout)
        logout_btn.pack(side=tk.RIGHT)
        self.create_tooltip(logout_btn, "Logout")
        
        # Output console with modern styling
        console_frame = ttk.LabelFrame(main_frame, text="Activity Log", padding=10)
        console_frame.pack(expand=True, fill=tk.BOTH, pady=(0, 10))
        
        self.console = scrolledtext.ScrolledText(
            console_frame, 
            state='disabled', 
            height=15,
            font=('Consolas', 10),
            padx=10,
            pady=10,
            wrap=tk.WORD
        )
        self.console.pack(expand=True, fill=tk.BOTH)
        
        # Button grid with icons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=20)
        
        buttons = [
            ("👥", "Online Users", self.view_online_users),
            ("📂", "Shared Resources", self.view_shared_resources),
            ("↑", "Register Resource", self.register_resource),
            ("↓", "Deregister Resource", self.deregister_resource_prompt),
            ("🔍", "Request Resource", self.request_resource_prompt)
        ]
        
        for i, (icon, text, command) in enumerate(buttons):
            btn = ttk.Button(
                button_frame, 
                text=f"{icon} {text}", 
                command=command,
                style='TButton'
            )
            btn.grid(row=i//3, column=i%3, padx=5, pady=5, sticky=tk.NSEW)
            self.create_tooltip(btn, text)
            button_frame.columnconfigure(i%3, weight=1)
        
        button_frame.rowconfigure(0, weight=1)
        button_frame.rowconfigure(1, weight=1)
    
    def create_tooltip(self, widget, text):
        """Creates a tooltip for a widget"""
        tooltip = ttk.Label(self.root, text=text, background="#ffffe0", relief="solid", borderwidth=1)
        tooltip.pack_forget()
        
        def enter(event):
            x, y, _, _ = widget.bbox("insert")
            x += widget.winfo_rootx() + 25
            y -= widget.winfo_rooty() + 25
            tooltip.place(x=x, y=y)
        
        def leave(event):
            tooltip.place_forget()
        
        widget.bind("<Enter>", enter)
        widget.bind("<Leave>", leave)
    
    def clear_window(self):
        """Clears all widgets from the root window."""
        for widget in self.root.winfo_children():
            widget.destroy()
    
    def log_message(self, message):
        """Logs a message to the console."""
        self.console.configure(state='normal')
        self.console.insert(tk.END, f"{message}\n")
        self.console.configure(state='disabled')
        self.console.see(tk.END)
    
    def handle_login(self):
        """Handles the login process."""
        peer_id = self.peer_id_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not peer_id or not password:
            messagebox.showerror("Error", "Peer ID and password are required")
            return
        
        peer_server_info = self.peer_server_socket.getsockname()
        self.logged_in, self.peer_id = login(self.client_socket, peer_server_info, peer_id, password)
        
        if self.logged_in:
            self.create_main_ui()
            self.log_message(f"Successfully logged in as {self.peer_id}")
        else:
            messagebox.showerror("Login Failed", "Invalid credentials or server error")
    
    def handle_register(self):
        """Handles the registration process."""
        peer_id = self.reg_peer_entry.get().strip()
        password = self.reg_pass_entry.get().strip()
        confirm = self.reg_confirm_entry.get().strip()
        
        if not peer_id or not password:
            messagebox.showerror("Error", "Peer ID and password are required")
            return
            
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match")
            return
        
        if check_user_exists(peer_id):
            messagebox.showerror("Error", "Peer ID already exists")
            return
        
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        register_message = f"register{SEPARATOR}{peer_id}{SEPARATOR}{hashed_password}"
        response = send_tcp_message(self.client_socket, register_message)
        
        if response[1] == "+":
            messagebox.showinfo("Success", "Registration successful! Please log in.")
            self.show_login_screen(False)
        else:
            messagebox.showerror("Error", "Registration failed")
    
    def handle_logout(self):
        """Handles the logout process."""
        if logout(self.client_socket, self.peer_id):
            self.logged_in = False
            self.peer_id = ""
            self.show_login_screen(False)
    
    def view_online_users(self):
        """Displays online users."""
        response = get_online_users(self.client_socket)
        self.log_message(f"Online users: {response}")
    
    def view_shared_resources(self):
        """Displays shared resources."""
        response = get_shared_resources(self.client_socket)
        self.log_message(f"Shared resources: {response}")
    
    def register_resource(self):
        """Handles resource registration."""
        if not self.logged_in:
            messagebox.showerror("Error", "You must be logged in")
            return
            
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
            
        resource_file_name = os.path.splitext(os.path.basename(file_path))[0]
        resource_file_extension = os.path.splitext(file_path)[1][1:]
        resource_file_size = str(os.path.getsize(file_path))
        last_modified_timestamp = str(os.path.getmtime(file_path))
        
        message = (f"r{SEPARATOR}{self.peer_id}{SEPARATOR}{resource_file_name}"
                f"{SEPARATOR}{resource_file_extension}{SEPARATOR}{resource_file_size}"
                f"{SEPARATOR}{last_modified_timestamp}")
        
        response = send_tcp_message(self.client_socket, message)
        self.log_message(f"Resource registration response: {response}")
    
    def deregister_resource_prompt(self):
        """Shows a dialog to deregister a resource."""
        if not self.logged_in:
            messagebox.showerror("Error", "You must be logged in")
            return
            
        dialog = tk.Toplevel(self.root)
        dialog.title("Deregister Resource")
        dialog.geometry("400x300")
        
        ttk.Label(dialog, text="Resource Peer ID:").pack(pady=5)
        peer_id_entry = ttk.Entry(dialog)
        peer_id_entry.insert(0, self.peer_id)
        peer_id_entry.pack(fill=tk.X, padx=20, pady=5)
        
        ttk.Label(dialog, text="File Name:").pack(pady=5)
        file_name_entry = ttk.Entry(dialog)
        file_name_entry.pack(fill=tk.X, padx=20, pady=5)
        
        ttk.Label(dialog, text="File Extension:").pack(pady=5)
        file_ext_entry = ttk.Entry(dialog)
        file_ext_entry.pack(fill=tk.X, padx=20, pady=5)
        
        def do_deregister():
            peer_id = peer_id_entry.get().strip()
            file_name = file_name_entry.get().strip()
            file_ext = file_ext_entry.get().strip()
            
            if not peer_id or not file_name or not file_ext:
                messagebox.showerror("Error", "All fields are required")
                return
                
            response = deregister_resource(self.client_socket, peer_id, file_name, file_ext)
            if (response[1] == "+"): # Success
                self.log_message(f"Deregistered: {peer_id}'s {file_name}.{file_ext}")
            elif (response[1] == "-"): # Unsuccessful
                self.log_message(f"Could not deregister {peer_id}'s {file_name}.{file_ext}")
            else: # Error
                self.log_message(f"ERROR | Deregistration response: {response}")
            dialog.destroy()
        
        ttk.Button(dialog, text="Deregister", command=do_deregister).pack(pady=10)
    
    def request_resource_prompt(self):
        """Shows a dialog to request a resource."""
        if not self.logged_in:
            messagebox.showerror("Error", "You must be logged in")
            return
            
        dialog = tk.Toplevel(self.root)
        dialog.title("Request Resource")
        dialog.geometry("400x250")
        
        ttk.Label(dialog, text="Resource Owner Peer ID:").pack(pady=5)
        owner_entry = ttk.Entry(dialog)
        owner_entry.pack(fill=tk.X, padx=20, pady=5)
        
        ttk.Label(dialog, text="File Name:").pack(pady=5)
        file_name_entry = ttk.Entry(dialog)
        file_name_entry.pack(fill=tk.X, padx=20, pady=5)
        
        ttk.Label(dialog, text="File Extension:").pack(pady=5)
        file_ext_entry = ttk.Entry(dialog)
        file_ext_entry.pack(fill=tk.X, padx=20, pady=5)
        
        def do_request():
            owner = owner_entry.get().strip()
            file_name = file_name_entry.get().strip()
            file_ext = file_ext_entry.get().strip()
            
            if not owner or not file_name or not file_ext:
                messagebox.showerror("Error", "All fields are required")
                return
            
            # self_peer_id, resource_owner_peer_id, file_name, file_extension
            response = request_file_from_peer(self.client_socket, self.peer_id, owner, file_name, file_ext)
            if SEPARATOR in response:
                self.log_message(f"[+] Resource request response: {response}")
                response_parts = response.split(SEPARATOR)
                action = response_parts[0]
                if action == "a":
                    returned_peer_id = response_parts[1]
                    if owner != returned_peer_id:
                        self.log_message("[!] ERROR: Peer ID mismatch")
                        return
                    
                    peer_server_ip = response_parts[2]
                    peer_server_port = response_parts[3]
                    peer_resource_version_num = response_parts[4]
                    
                    self.log_message(f"Connecting to peer's server @ {peer_server_ip}:{peer_server_port}...")
                    status = connect_to_peer(peer_server_ip, peer_server_port, self.peer_id, 
                                owner, file_name, file_ext)
                    
                    if status:
                        self.log_message("[+] Resource received successfully!")
                        self.synced_resources.append((owner, file_name, file_ext, peer_resource_version_num)) # add the downloaded resource's information to the synced resources list
                        self.log_message("[+] Synced Resources List: ")
                        resource_number = 0 # Counter var
                        for resource in self.synced_resources:
                            self.log_message(f"    [{resource_number}] {resource}")
                            resource_number += 1
                    else:
                        self.log_message("[-] Failed to receive resource")
            
            dialog.destroy()
        
        ttk.Button(dialog, text="Request", command=do_request).pack(pady=10)
    
    def start_sync_thread(self):
        """
        Starts a background thread that periodically checks for updated versions
        of synced resources and automatically downloads them if available.
        """
        def sync_loop():
            while True:
                if self.logged_in and hasattr(self, 'synced_resources') and self.synced_resources:
                    try:
                        # Get current shared resources from server
                        shared_resources_response = get_shared_resources(self.client_socket)
                        
                        # Parse the response into a list of resources
                        shared_resources = eval(shared_resources_response)  # Caution: eval can be dangerous with untrusted input
                        
                        # Create a dictionary for quick lookup
                        server_resources = {}
                        for resource in shared_resources:
                            owner, name, ext, size, timestamp, version = resource
                            server_resources[(owner, name, ext)] = version
                        
                        # Check each synced resource for updates
                        for i, (owner, name, ext, local_version) in enumerate(self.synced_resources):
                            key = (owner, name, ext)
                            if key in server_resources:
                                server_version = server_resources[key]
                                if int(server_version) > int(local_version):
                                    self.log_message(f"[SYNC] Update available for {name}.{ext} (v{local_version} -> v{server_version})")
                                    
                                    # Request the updated resource
                                    response = request_file_from_peer(self.client_socket, self.peer_id, owner, name, ext)
                                    
                                    if SEPARATOR in response:
                                        response_parts = response.split(SEPARATOR)
                                        if len(response_parts) >= 5 and response_parts[0] == "a":
                                            peer_server_ip = response_parts[2]
                                            peer_server_port = response_parts[3]
                                            
                                            # Download the updated file
                                            if connect_to_peer(peer_server_ip, peer_server_port, self.peer_id, owner, name, ext):
                                                # Update local version in synced_resources
                                                self.synced_resources[i] = (owner, name, ext, server_version)
                                                self.log_message(f"[SYNC] Successfully updated {name}.{ext} to v{server_version}")
                                            else:
                                                self.log_message(f"[SYNC] Failed to download update for {name}.{ext}")
                    except Exception as e:
                        self.log_message(f"[SYNC ERROR] {str(e)}")
                
                # Wait before next sync check (e.g., every 30 seconds)
                time.sleep(30)
        
        # Start the sync thread
        sync_thread = threading.Thread(target=sync_loop, daemon=True)
        sync_thread.start()



def create_persistent_connection(ip, port):
    '''
    Purpose: 
        Establishes a persistent connection to the server.
    Args.:
        ip: The server's IP address
        port: The server's IP port
    Returns: 
        The client socket
    '''
    client_socket = socket(AF_INET, SOCK_STREAM)
    client_socket.connect((ip, port))
    return client_socket


def start_server():
    """
    Purpose: 
        Starts a simple server instance that accepts both text messages and files.
        Saves received files to the '/downloads/' directory.
    """
    port_number = random.randint(12000,12999) # Randomized port number
    server_socket = socket(AF_INET, SOCK_STREAM)
    server_socket.bind((SERVER_IP_ADDRESS, port_number))
    server_socket.listen(2)  # Allow only two connections (self, and optionally another peer)
    print(f"[tcp_client.py] Server started at {SERVER_IP_ADDRESS}:{port_number}")
    
    # Ensure the downloads directory exists
    os.makedirs("Downloads", exist_ok=True)
    
    def server_loop():
        while True:
            peer, addr = server_socket.accept()
            print(f"[tcp_client.py] Connection from {addr}")
            
            # Receive initial message (could be file metadata or normal message)
            message = peer.recv(BUFFER_SIZE).decode()
            
            if SEPARATOR not in message:
                print("[!] Incorrectly formatted message received. Was: ", message)
                peer.send("[!] Incorrectly formatted message. Your message needs <SEP> in it.")
                
            parts = message.split(SEPARATOR)
            action = parts[0] or None
            
            if action == "s" and len(parts) == 4: # If the other peer wishes to send you a file and their message is correctly formatted
                file_name = parts[1] or None
                file_extension = parts[2] or None
                file_size = parts[3] or None
                # Define the file's download path
                filepath = os.path.join("downloads", file_name + ".temp") # Put .temp to reduce instances of overwriting files
                print(f"[+] Receiving file: {file_name}")
                
                # Receive and save file in a loop
                with open(filepath, "wb") as file:
                    while True:
                        chunk = peer.recv(BUFFER_SIZE)
                        if not chunk:
                            break
                        file.write(chunk)
                
                print(f"[tcp_client.py] File saved: {filepath}")
            if action == "p" and len(parts) == 5: # If the other peer wishes to request a resource from you
                #p<SEP>client_0<SEP>client_1<SEP>Resource0<SEP>txt
                requesting_peer_id = parts[1] or None
                owner_peer_id = parts[2] or None # This should be your own peer id, maybe do some crosschecking to make sure its right
                file_name = parts[3] or None 
                file_extension = parts[4] or None 
                # Check for all required information 
                if (requesting_peer_id and owner_peer_id and file_name and file_extension): 
                    print(f"[+] Resource request received: {requesting_peer_id} requests {file_name}.{file_extension} from {owner_peer_id}")
                    # Send the resource to the requesting peer if conditions are met
                    resource_path = os.path.join("downloads", f"{file_name}.{file_extension}")
                    if os.path.exists(resource_path):
                        print(f"[+] Sending resource {file_name}.{file_extension} to peer {requesting_peer_id}")
                        
                        # Send the message containing file metadata
                        peer.send(f"s{SEPARATOR}{file_name}{SEPARATOR}{file_extension}{SEPARATOR}{os.path.getsize(resource_path)}".encode())
                        
                        # Send the file in chunks
                        with open(resource_path, "rb") as file:
                            while (chunk := file.read(BUFFER_SIZE)):
                                peer.send(chunk)
                        
                        print(f"[+] File {file_name}.{file_extension} sent to peer {requesting_peer_id}.")
                    else:
                        print(f"[!] Resource {file_name}.{file_extension} not found.")
                        peer.send("[!] Resource not found.".encode())
                else:
                    print("[!] Resource request message was not formatted correctly, was: ", message)
            else:
                print(f"[+] Received message: {message}") # Receive the message
                peer.send("[+] ACK from tcp_client.py".encode()) # Send an ACK
            
            peer.close() # Close the connection with the peer
    
    # Start the server loop on a separate thread
    server_thread = threading.Thread(target=server_loop, daemon=True)
    server_thread.start()
    
    return server_socket  # Keep a reference to the server socket


def connect_to_peer(peer_server_ip, peer_server_port, self_peer_id, owner_peer_id, resource_file_name, resource_file_extension):
    """
    Purpose: Connects to a peer server with given IP and port, and receives the file.
    Args.: 
        - peer_server_ip: The server IP of the resource owner
        - peer_server_port: The server port # of the resource owner
        - self_peer_id: Your peer id
        - owner_peer_id: The peer id of the resource owner
        - resource_file_name: The file name of the requested resource
        - resource_file_extension: The file ext. of the requested resource
    """ 
    print("[+] Connecting to peer...")
    time.sleep(2)  # Wait to ensure both servers are running
    try:
        # Connect to the resource owner's server
        client_socket = socket(AF_INET, SOCK_STREAM)
        client_socket.connect((peer_server_ip, int(peer_server_port)))
        print(f"[+] Connected to peer at {peer_server_ip}:{peer_server_port}.")
        
        # Format: p<SEP>client_0<SEP>client_1<SEP>Resource0<SEP>txt
        request_message = f"p{SEPARATOR}{self_peer_id}{SEPARATOR}{owner_peer_id}{SEPARATOR}{resource_file_name}{SEPARATOR}{resource_file_extension}".encode()
        print(f"[+] Sending message: {request_message}")
        # Send the request message to the resource owner
        client_socket.send(request_message)
        
        # Receive the file metadata
        metadata = client_socket.recv(BUFFER_SIZE).decode()
        print(f"[DEBUG] Metadata received: {metadata}")
        
        if SEPARATOR not in metadata:
            print("[!] Incorrectly formatted metadata received.")
            client_socket.close()
            return False
        
        parts = metadata.split(SEPARATOR)
        if parts[0] == "s" and len(parts) == 4:
            file_name = parts[1]
            file_extension = parts[2]
            file_size = int(parts[3])
            
            filepath = os.path.join("Downloads", file_name + "." + file_extension + ".temp")
            print(f"[+] Receiving file: {file_name}.{file_extension}")
            
            with open(filepath, "wb") as file:
                received_size = 0
                while received_size < file_size:
                    chunk = client_socket.recv(BUFFER_SIZE)
                    if not chunk:
                        break
                    file.write(chunk)
                    received_size += len(chunk)
            
            print(f"[+] File saved: {filepath}")
            client_socket.close()
            return True
        else:
            print("[!] Incorrect metadata format.")
            client_socket.close()
            return False
    
    except Exception as e:
        print(f"[!] Error connecting to peer @ {peer_server_ip}:{peer_server_port}, error: {e}")
        return False


def send_tcp_message(client_socket, message):
    '''
    Purpose: 
        Function that sends a TCP message to a given Server (IP)
    Args.:
        server: The server's IP address
        message: The message to send to the server
    Returns: 
        The string (decoded from byte string) response from the server
    '''
    client_socket.send(message.encode())
    response = client_socket.recv(BUFFER_SIZE).decode()
    return response


def login(client_socket, peer_server_info, peer_id="", peer_password=""):
    '''
    Purpose: 
        Function that logs the user into the server following our login protocol diagram
    Args: 
        client_socket: The socket that the peer uses to talk to the server
        peer_server_info: A tuple containing the following information -> (peer_server_ip, peer_server_port)
    Returns:
        A tuple containing (success_boolean, peer_id)
        success_boolean: True if success on login, otherwise false
        peer_id: The peer id of the user
    Notes:
        Login Message Format: "peer_id<SEP>peer_password" this is a byte string message that contains the id and password of the peer
        Passwords: Passwords are hashed before sending them to the server to avoid sending plain-text passwords over the network
    '''
    
    # Initial console logging
    print("\n", "[+] Client instance is now active.", sep="")
    
    if (peer_id == "" and peer_password == ""): # Default args. (not inputting them manually in the function call) will ask the user for their input
        peer_id = input('[+] Enter your Peer ID: ').strip()
        peer_password = input('[+] Enter your password: ').strip()
    
    # Login Message Construction
    hashed_password = hashlib.sha256(peer_password.encode()).hexdigest() # Hex digest of password (using byte digest requires more lines of code)
    login_message = f"login{SEPARATOR}{peer_id}{SEPARATOR}{hashed_password}{SEPARATOR}{peer_server_info}" # The login message being made
    print(f"[+] Sending the following login message to the server: {login_message}")
    response = send_tcp_message(client_socket, login_message)
    print(f"Response from server: {response}") # Print the response returned by the function 'send_tcp_message'
    
    if response[1] == "+": # Login Successful
        return True, peer_id
    else:
        return False, peer_id


def logout(client_socket, peer_id):
    '''
    Purpose: 
        Function that logs the user into the server following our login protocol diagram
    Args: 
        client_socket: The socket that the peer uses to talk to the server
    Returns:
        Nothing, this is a void function
    '''
    message = "logout" + SEPARATOR + peer_id
    response = send_tcp_message(client_socket, message)
    print(f"Response from server: {response}") # Print the response returned by the function 'send_tcp_message'
    # Handle return statement using response
    if response[1] == "+": # Login Successful
        return True, peer_id
    else:
        return False, peer_id


def check_user_exists(peer_id):
    """
    Check if the given peer_id already exists in the user file.
    """
    try:
        with open(USER_FILE_PATH, 'r') as file:
            for line in file:
                user_id, _ = line.strip().split(SEPARATOR)
                if user_id == peer_id:
                    return True
    except FileNotFoundError:
        return False  # If file doesn't exist, return False (no existing users)
    return False


def register(client_socket):
    '''
    Purpose:
        Function to register a new user with the server
    Args:
        client_socket: The socket that the peer uses to talk to the server
    Returns:
        True if registered successfully, false otherwise
    '''
    print("\n[+] Registration")
    
    # Loop var for peer_id getting
    loop_peer_id = True
    while loop_peer_id:
        peer_id = input('[+] Enter your Peer ID: ')
        
        # Check if the peer_id already exists in the file
        if check_user_exists(peer_id):
            print(f"[!] The Peer ID '{peer_id}' already exists. Please choose a different ID.")
        elif peer_id == "": # If blank user id
            print("[!] You cannot enter an empty string as a peer id!")
        else:
            loop_peer_id = False  # Valid peer_id, exit the loop
    
    peer_password = input('[+] Enter your password: ')
    hashed_password = hashlib.sha256(peer_password.encode()).hexdigest()
    register_message = f"register{SEPARATOR}{peer_id}{SEPARATOR}{hashed_password}"
    print(f"[+] Sending registration message: {register_message}")
    response = send_tcp_message(client_socket, register_message)
    
    if response[1] == "+": # Success
        return True
    else:
        return False


def get_online_users(client_socket):
    '''
    Purpose:
        Function to fetch the list of online users from the server
    Args:
        client_socket: The socket that the peer uses to talk to the server
    Returns:
        The response from the server
    '''
    message = f"get_online_users" + SEPARATOR
    print(f"[+] Fetching online users...")
    response = send_tcp_message(client_socket, message)
    print(f"[+] Online users fetched: {response}")
    return response


def get_shared_resources(client_socket):
    '''
    Purpose:
        Function to fetch the list of shared resources currently active in the P2P network
    Args:
        client_socket: The socket that the peer uses to talk to the server
    Returns:
        The response from the server
    '''
    message = f"l" + SEPARATOR
    print(f"[+] Fetching shared resources...")
    response = send_tcp_message(client_socket, message)
    print(f"[+] Shared resources fetched: {response}")
    return response


def register_resource(client_socket, resource_peer_id):
    """
    Opens a file selection dialog and registers the selected file.
    """
    
    print(f"DEBUG: Registering resource for peer_id: '{resource_peer_id}'")
    
    # Initialize Tkinter root window (kept hidden)
    root = tk.Tk()
    root.withdraw()
    
    # Open file selection dialog
    file_path = filedialog.askopenfilename()
    if not file_path:
        print("No file selected.")
        return None
    
    # Extract file details
    resource_file_name = os.path.splitext(os.path.basename(file_path))[0]
    resource_file_extension = os.path.splitext(file_path)[1][1:]  # Remove leading '.'
    resource_file_size = str(os.path.getsize(file_path))
    last_modified_timestamp = str(os.path.getmtime(file_path)) # Get last modified timestamp    
    
    SEPARATOR = "<SEP>"
    message = ("r" + SEPARATOR + resource_peer_id + SEPARATOR + resource_file_name + SEPARATOR + resource_file_extension + SEPARATOR + resource_file_size + SEPARATOR + last_modified_timestamp)
    
    response = send_tcp_message(client_socket, message)
    print(f"[+] Resource Registered: {response}")
    return response


def deregister_resource(client_socket, resource_peer_id, resource_file_name, resource_file_extension):
    """
    Purpose: This function returns a byte-encoded message to be sent to 
                the indexing server by a Peer in order to de-register a file
                from the sharable files on the indexing server
    Args:
        resource_peer_id: The peer ID of the Peer who has the resource
        resource_file_name: The name of the file to be deregistered
        resource_file_extension: The file extension
    Returns: Byte encoded message that will tell the server what to de-register
    """
    # NOTE: The file extension should never include the '.', only the actual extension; i.e. "txt", "png", etc.
    SEPARATOR = "<SEP>" # Establish separator phrase
    message = ("d" + SEPARATOR + resource_peer_id + SEPARATOR + resource_file_name + SEPARATOR + resource_file_extension)
    
    response = send_tcp_message(client_socket, message)
    print(f"[+] Resource Deregistered: {response}")
    return response


def request_file_from_peer(client_socket, self_peer_id, resource_owner, resource_file_name, resource_file_extension):
    """
    Purpose: Requests a file from another peer via the server.
    Args:
        server_socket: The connected server socket.
        resource_owner: The peer ID of the client who owns the file.
        resource_file_name: The requested file's name.
        resource_file_extension: The requested file's extension.
    Returns:
        The response from the server 
    """
    # Format: p, self_peer_id, resource_owner_peer_id, file_name, file_extension (commas are <SEP>)
    message = f"p{SEPARATOR}{self_peer_id}{SEPARATOR}{resource_owner}{SEPARATOR}{resource_file_name}{SEPARATOR}{resource_file_extension}"
    response = send_tcp_message(client_socket, message)
    return response

'''
def start_update_resources_thread(self):
    """
    Purpose: A thread created to run update_resources

    Returns: A thread object
    """
    def update_resources(shared_resources, client_socket, peer_id):
     """
    Purpose: This function automatically updates all resources shared every 30 seconds.
                
    Args:
        peer_id: The peer ID of the Peer 
        client_socket: The socket that the peer uses to talk to the server
        shared_resources: List of the resources shared
    Returns: returns updated resource
    """
    
    while True:
        try:
            shared_resources = get_shared_resources(client_socket)
        
            for resource in shared_resources:
                current_time = os.path.getmtime(file_path)

                if last_modified_timestamp[file_path] != current_time:
                    register_resource(client_socket, peer_id, resource)
                    last_modified_timestamp[file_path] = current_time

            #check every thirty seconds
            time.sleep(30)
        except Exception as e:
            print(f"There was an error updating the resources, error: {e}")


    #starting the thread to update the resources that have already been shared
    update_thread = threading.Thread(target= update_resources, daemon =True)
    update_thread.start()
    '''


def main():
    '''
    Purpose:
        Main function to provide a menu for the user and start up all required processes
    '''
    
    # Start the local server on a separate thread to ensure it runs independently
    peer_server_socket = start_server()  # This starts the server and stores the socket reference
    
    # Connect to the server and ensure connection persistence
    client_socket = create_persistent_connection(SERVER_IP_ADDRESS, SERVER_PORT) 
    
    logged_in = False # Keeps track of if the user is logged in or not
    
    peer_id = "" # The peer's id
    
    while True:  # Changed to loop infinitely until the user exits
        if not logged_in:
            print("\n1. Login\n2. Register\n3. Exit")
            choice = input("Choose an option: ")
            
            if choice == "1": # Log in
                logged_in, returned_peer_id = login(client_socket, peer_server_socket.getsockname())
                peer_id = returned_peer_id
                for _ in range(20): # Create some white space
                    print("")
            elif choice == "2": # Register
                register(client_socket)
                print("")  # Add a new line and then force them to login
                logged_in, returned_peer_id = login(client_socket)
                peer_id = returned_peer_id
            elif choice == "3": # Exit
                return  # Exit the program
            else:
                print("Invalid choice. Try again.")
        else:
            # Menu after the user is logged in
            print("\n1. View Online Users\n2. View Shared Resources\n3. Register a Resource\n4. Deregister Resource\n5. Request Resource\n6. Logout")
            choice = input("Choose an option: ")
            
            if choice == "1": # Get Online Users
                online_users = get_online_users(client_socket)
            elif choice == "2": # Get Shared Resources
                shared_resources = get_shared_resources(client_socket)
            elif choice == "3": # Register a Resource
                register_resource(client_socket, peer_id)
            elif choice == "4":  # Deregister Resource
                print("") # Add some white space
                resource_peer_id = input("[?] Enter resource peer ID: ")
                resource_file_name = input("[?] Enter resource file name: ")
                resource_file_extension = input("[?] Enter resource file extension: ")
                deregister_resource(client_socket, resource_peer_id, resource_file_name, resource_file_extension) # No need to keep var with returned value, as this function prints the server response itself
            elif choice == "5":
                resource_owner = input("[?] Enter resource owner peer id: ")
                resource_file_name = input("[?] Enter resource file name: ")
                resource_file_extension = input("[?] Enter resource file extension: ")
                
                # Server should respond with the other peer's server ip and port # if the resource is available
                response = request_file_from_peer(client_socket, peer_id, resource_owner, resource_file_name, resource_file_extension)
                print("[DEBUG] Response from server after requesting file was: ", response)
                if SEPARATOR not in response: # check for formatting
                    print("[!] ERROR: Server's response was not formatted correctly. Was: ", response, " | MUST have <SEP> in it!")
                else: # If the message was formatted correctly
                    response_parts = response.split(SEPARATOR)
                    action = response_parts[0]
                    if action == "a" and len(response_parts) == 4: # If request was successful (action was ACK)
                        returned_peer_id = response_parts[1]
                        if resource_owner != returned_peer_id: # Check that peer id's match
                            print("[!] ERROR: Requested resource owner's peer ID does not match ACK'ed peer id...")
                        peer_server_ip = response_parts[2]
                        peer_server_port = response_parts[3] 
                        print(f"[+] Resource request was successful! Trying to connect to peer's server @ {peer_server_ip}:{peer_server_port}...")
                        status = connect_to_peer(peer_server_ip, peer_server_port, peer_id, resource_owner, resource_file_name, resource_file_extension) # Connect to that peer's server and get the file
                        if status: # If it worked
                            print("[+] Resource was requested and received!")
                        else: # If it failed for any reason
                            print("[-] Resource was not able to be received.")
                    else:
                        print(f"[!] Resource request was unsuccessful, response from server was {response}")
            
            elif choice == "6": # Logout
                logout_status = logout(client_socket, peer_id)
                for _ in range(20): # Make some white space
                    print("")
                logged_in = False  # Reset logged_in to False to bring the user back to the login menu
            else:
                print("Invalid choice. Try again.")


def main():
    root = tk.Tk()
    app = P2PClientGUI(root)
    root.mainloop()

if __name__ == '__main__':
    main()