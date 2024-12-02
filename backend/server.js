const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const cors = require('cors');

const app = express();
const port = 5142;

app.use(cors());
app.use(bodyParser.json());

const connection = mysql.createConnection({
    host: 'localhost',
    user: 'lohithbodipati@gmail.com',     // Replace with your MySQL username
    password: 'LoboDaxter#129', // Replace with your MySQL password
    database: 'user_registration_db'
});

connection.connect((err) => {
    if (err) {
      console.error('Error connecting to the database: ', err);
      return;
    }
    console.log('Connected to MySQL database');
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
  
    // Query to find user by username
    const query = 'SELECT * FROM users WHERE username = ?';
    
    connection.query(query, [username], async (err, results) => {
      if (err) {
        console.error('Login error: ', err);
        return res.status(500).json({ message: 'Server error' });
      }
  
      // Check if user exists
      if (results.length === 0) {
        return res.status(401).json({ message: 'Invalid username or password' });
      }
  
      // Compare provided password with stored hash
      const user = results[0];
      const isMatch = await bcrypt.compare(password, user.password);
  
      if (isMatch) {
        // Successful login
        res.status(200).json({ 
          message: 'Login successful', 
          username: user.username,
          email: user.email 
        });
      } else {
        // Password doesn't match
        res.status(401).json({ message: 'Invalid username or password' });
      }
    });
});

app.post('/register', async (req, res) => {
const { username, email, password } = req.body;

try {
    // Hash the password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // SQL query to insert new user
    const query = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
    
    connection.query(query, [username, email, hashedPassword], (err, result) => {
    if (err) {
        console.error('Error registering user: ', err);
        if (err.code === 'ER_DUP_ENTRY') {
        return res.status(400).json({ message: 'Username or email already exists' });
        }
        return res.status(500).json({ message: 'Registration failed' });
    }

    res.status(201).json({ message: 'User registered successfully' });
    });
} catch (error) {
    console.error('Error hashing password: ', error);
    res.status(500).json({ message: 'Registration failed' });
}
});

// Start server
app.listen(port, () => {
console.log(`Server running on http://localhost:${port}`);
});