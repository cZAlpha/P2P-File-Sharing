const express = require('express');
const WebSocket = require('ws');

const app = express();
const port = 3000;

// In-memory index for files and peers
const fileIndex = {}; // Example: { "file.txt": ["peer1", "peer2"] }

// HTTP server for serving metadata
app.use(express.json());

// Register a file with a peer
app.post('/register', (req, res) => {
   const { filename, peer } = req.body;
   if (!fileIndex[filename]) {
      fileIndex[filename] = [];
   }
   if (!fileIndex[filename].includes(peer)) {
      fileIndex[filename].push(peer);
   }

   // Notify WebSocket clients about the new file registration
   broadcastMessage(JSON.stringify({ type: 'file_registered', filename, peer }));

   res.status(200).send({ message: 'File registered successfully' });
});

// Retrieve peers for a specific file
app.get('/files/:filename', (req, res) => {
   const { filename } = req.params;
   const peers = fileIndex[filename] || [];
   res.status(200).send({ peers });
});

// WebSocket server for real-time updates
const wss = new WebSocket.Server({ noServer: true });

// Broadcast a message to all connected WebSocket clients
function broadcastMessage(message) {
   wss.clients.forEach((client) => {
      if (client.readyState === WebSocket.OPEN) {
         client.send(message);
      }
   });
}

// Handle WebSocket connections
wss.on('connection', (ws) => {
   console.log('New WebSocket connection established');

   ws.on('message', (message) => {
      console.log(`Received from client: ${message}`);

      // Example: Broadcast received messages to all clients
      broadcastMessage(message);
   });

   ws.send(JSON.stringify({ type: 'welcome', message: 'Connected to the P2P Indexing Server' }));
});

// Start the HTTP server and handle WebSocket upgrades
const server = app.listen(port, () => {
   console.log(`Server running on http://localhost:${port}`);
});

server.on('upgrade', (request, socket, head) => {
   wss.handleUpgrade(request, socket, head, (ws) => {
      wss.emit('connection', ws, request);
   });
});
