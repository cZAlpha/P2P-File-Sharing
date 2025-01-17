# P2P-File-Sharing
A peer to peer file sharing networking project for our Computer Networking class. Implemented using Python for Clients and JavaScript for the Server.
<br><br><br>

# How to get started after cloning

## Client Side
1. You must open a terminal and navigate inside of the 'Client' directory within the project
<br><br>
2. Make sure you have Python downloaded onto your computer
<br><br>
3. Create a python virtual environment by running the following command: 
<br>`python -m venv env` 
<br>_You may name it something else if you'd like but replace 'env' with your venv name_
<br><br>
4. Activate your virtual enviroment by running this command: 
<br>`source env/bin/activate` (this is different on Windows!)
<br><br>
5. Install all required packages by performing the following command:
<br> `pip install -r requirements.txt`
<br><br>
6. Run the Python file, if you encounter any errors it is likely that the previous step did not correctly install the right packages, you may need to manually using:
<br>`pip install <name of package>` to remedy this
<br><br>
7. If everything was done correctly and the Python gods looked upon you favorably, you should run the file and see it asking for your input. Stop the file from running any further or open a new terminal until you set the server up and have it running, otherwise it won't work for obvious reasons.


## Server Side
1. You must open a terminal and navigate to the 'Server' directory within this project.
<br><br>
2. Ensure you have Node.js installed on your computer and then run the following command to install all required packages (it installs all packages listed in the package.json file):
<br>`npm i`
<br><br>
3. Now that all packages have been installed, simply run the server.js file to start the server up using the following command:
<br>`node server.js`
<br><br>
4. You should the server start up in the terminal and it should also display the port with which it is appearing on. It should be port 3000 by default, do not change this value unless you also change the Client side Python file's reference to the address and port of the server.
<br><br>

# Start Up Procedures After Installation of Required Packages
#### 1. Start up the Client instance by running the Python file (you can do this through the terminal or IDE, doesn't matter). To do this programmaticaly, navigate to the 'Client' directory with an activated Python venv and run this command:
<br>`python client.py`
<br><br>
#### 2. Start up the Server instance by navigating to the 'Server' directory and running the following command in the terminal: 
<br>`node server.js`
<br><br>
#### 3. Now you should have two open terminals, both with active instances of the Client and Server respectively. You can use the input from the Python Client instance to communicate in various ways with the Server instance. For example, try websocket and just hit enter (do not enter anything for default server address). After a successful connection, you can communicate with the server using normal text!