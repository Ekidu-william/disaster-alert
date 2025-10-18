const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const session = require('express-session');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
  secret: process.env.SESSION_SECRET || 'disaster-alert-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// MySQL Database Connection for Railway
const db = mysql.createConnection({
  host: process.env.MYSQLHOST || 'localhost',
  user: process.env.MYSQLUSER || 'root',
  password: process.env.MYSQLPASSWORD || 'your_password',
  database: process.env.MYSQLDATABASE || 'disaster_alert',
  port: process.env.MYSQLPORT || 3306,
  connectTimeout: 60000
});

// Connect with retry logic
function connectWithRetry() {
  db.connect((err) => {
    if (err) {
      console.error('Database connection failed:', err);
      console.log('Retrying in 5 seconds...');
      setTimeout(connectWithRetry, 5000);
    } else {
      console.log('Connected to MySQL database');
      createTables();
    }
  });
}

connectWithRetry();

// Handle connection errors
db.on('error', (err) => {
  console.error('Database error:', err);
  if (err.code === 'PROTOCOL_CONNECTION_LOST') {
    connectWithRetry();
  }
});

// Create tables if they don't exist
const createTables = () => {
  const responderTable = `
    CREATE TABLE IF NOT EXISTS responders (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(255) UNIQUE NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `;

  const disasterTable = `
    CREATE TABLE IF NOT EXISTS disasters (
      id INT AUTO_INCREMENT PRIMARY KEY,
      reporter_name VARCHAR(255) NOT NULL,
      reporter_phone VARCHAR(20) NOT NULL,
      disaster_type VARCHAR(100) NOT NULL,
      description TEXT,
      latitude DECIMAL(10, 8) NOT NULL,
      longitude DECIMAL(11, 8) NOT NULL,
      status VARCHAR(50) DEFAULT 'pending',
      responder_id INT,
      estimated_time VARCHAR(50),
      accepted_at TIMESTAMP NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (responder_id) REFERENCES responders(id)
    )
  `;

  db.query(responderTable, (err) => {
    if (err) console.error('Error creating responders table:', err);
    else console.log('Responders table ready');
  });

  db.query(disasterTable, (err) => {
    if (err) console.error('Error creating disasters table:', err);
    else console.log('Disasters table ready');
  });
};

// ==================== ROOT ROUTE ====================
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ==================== AUTHENTICATION ROUTES ====================

// Register Responder
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const query = 'INSERT INTO responders (username, email, password) VALUES (?, ?, ?)';
    db.query(query, [username, email, hashedPassword], (err, result) => {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY') {
          return res.status(400).json({ error: 'Username or email already exists' });
        }
        return res.status(500).json({ error: 'Registration failed' });
      }
      res.json({ message: 'Registration successful', userId: result.insertId });
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Login Responder
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  const query = 'SELECT * FROM responders WHERE username = ?';
  db.query(query, [username], async (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Login failed' });
    }

    if (results.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const responder = results[0];
    const validPassword = await bcrypt.compare(password, responder.password);

    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    req.session.responderId = responder.id;
    req.session.username = responder.username;

    res.json({ 
      message: 'Login successful',
      responder: {
        id: responder.id,
        username: responder.username,
        email: responder.email
      }
    });
  });
});

// Logout
app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ message: 'Logged out successfully' });
});

// Check authentication status
app.get('/api/auth/check', (req, res) => {
  if (req.session.responderId) {
    res.json({ 
      authenticated: true,
      responder: {
        id: req.session.responderId,
        username: req.session.username
      }
    });
  } else {
    res.json({ authenticated: false });
  }
});

// ==================== DISASTER REPORTING ROUTES ====================

// Report a disaster (no authentication required)
app.post('/api/report-disaster', (req, res) => {
  const { reporter_name, reporter_phone, disaster_type, description, latitude, longitude } = req.body;

  if (!reporter_name || !reporter_phone || !disaster_type || !latitude || !longitude) {
    return res.status(400).json({ error: 'All required fields must be provided' });
  }

  const query = `INSERT INTO disasters (reporter_name, reporter_phone, disaster_type, description, latitude, longitude) 
                 VALUES (?, ?, ?, ?, ?, ?)`;
  
  db.query(query, [reporter_name, reporter_phone, disaster_type, description, latitude, longitude], (err, result) => {
    if (err) {
      console.error('Error reporting disaster:', err);
      return res.status(500).json({ error: 'Failed to report disaster' });
    }

    const disasterId = result.insertId;
    
    // Get the newly created disaster
    db.query('SELECT * FROM disasters WHERE id = ?', [disasterId], (err, disasters) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to retrieve disaster' });
      }

      const disaster = disasters[0];
      
      // Emit to all connected responders
      io.emit('new-disaster', disaster);
      
      res.json({ 
        message: 'Disaster reported successfully',
        disasterId: disasterId,
        disaster: disaster
      });
    });
  });
});

// Get disaster status for reporter
app.get('/api/disaster-status/:id', (req, res) => {
  const disasterId = req.params.id;

  const query = `
    SELECT d.*, r.username as responder_name 
    FROM disasters d 
    LEFT JOIN responders r ON d.responder_id = r.id 
    WHERE d.id = ?
  `;

  db.query(query, [disasterId], (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to get disaster status' });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: 'Disaster not found' });
    }

    res.json(results[0]);
  });
});

// ==================== RESPONDER ROUTES ====================

// Get all disasters (requires authentication)
app.get('/api/disasters', (req, res) => {
  if (!req.session.responderId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const query = `
    SELECT d.*, r.username as responder_name 
    FROM disasters d 
    LEFT JOIN responders r ON d.responder_id = r.id 
    ORDER BY d.created_at DESC
  `;

  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to retrieve disasters' });
    }
    res.json(results);
  });
});

// Accept disaster request
app.post('/api/accept-disaster', (req, res) => {
  if (!req.session.responderId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { disaster_id, estimated_time } = req.body;
  const responder_id = req.session.responderId;

  if (!disaster_id || !estimated_time) {
    return res.status(400).json({ error: 'Disaster ID and estimated time are required' });
  }

  const query = `
    UPDATE disasters 
    SET status = 'accepted', responder_id = ?, estimated_time = ?, accepted_at = NOW() 
    WHERE id = ? AND status = 'pending'
  `;

  db.query(query, [responder_id, estimated_time, disaster_id], (err, result) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to accept disaster' });
    }

    if (result.affectedRows === 0) {
      return res.status(400).json({ error: 'Disaster already accepted or not found' });
    }

    // Get updated disaster info
    const getQuery = `
      SELECT d.*, r.username as responder_name 
      FROM disasters d 
      LEFT JOIN responders r ON d.responder_id = r.id 
      WHERE d.id = ?
    `;

    db.query(getQuery, [disaster_id], (err, disasters) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to retrieve updated disaster' });
      }

      const disaster = disasters[0];
      
      // Emit update to all clients
      io.emit('disaster-accepted', disaster);

      res.json({ 
        message: 'Disaster accepted successfully',
        disaster: disaster
      });
    });
  });
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// ==================== SOCKET.IO ====================

io.on('connection', (socket) => {
  console.log('New client connected:', socket.id);

  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});

// ==================== START SERVER ====================

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});