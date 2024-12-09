require('dotenv').config(); 
const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 3143;

app.use(cors());
app.use(bodyParser.json());

const connection = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

connection.connect((err) => {
    if (err) {
      console.error('Error connecting to the database: ', err);
      return;
    }
    console.log('Connected to MySQL database');
});

function generateMemberId(){
    return crypto.randomBytes(5).toString('hex').toUpperCase();
}

app.get('/member-info', (req, res) => {
    const { memberId } = req.query;

    if (!memberId) {
        return res.status(400).json({ message: 'Member ID is required' });
    }

    const query = `
        SELECT ingredient, beverage 
        FROM member_info 
        WHERE member_id = ?
    `;

    connection.query(query, [memberId], (err, results) => {
        if (err) {
            console.error('Error fetching member info:', err);
            return res.status(500).json({ message: 'Server error' });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: 'Member info not found' });
        }

        res.status(200).json(results[0]);
    });
});

app.post('/update-member-items', (req, res) => {
    const { memberId, ingredient, beverage } = req.body;

    if (!memberId) {
        return res.status(400).json({ message: 'Member ID is required' });
    }

    // Prepare the update query
    const query = `
        UPDATE member_info 
        SET ingredient = CONCAT_WS(', ', ingredient, ?), 
            beverage = CONCAT_WS(', ', beverage, ?) 
        WHERE member_id = ?
    `;

    connection.query(query, [ingredient || null, beverage || null, memberId], (err, result) => {
        if (err) {
            console.error('Error updating member items:', err);
            return res.status(500).json({ message: 'Server error' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Member not found' });
        }

        res.status(200).json({ message: 'Items updated successfully' });
    });
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
          email: user.email,
          memberId: user.member_id
        });
      } else {
        // Password doesn't match
        res.status(401).json({ message: 'Invalid username or password' });
      }
    });
});

app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    // Basic input validation
    if (!username || !email || !password) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    // Email validation (simple regex)
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ message: 'Invalid email format' });
    }

    try {
        // Hashing password
        const saltRounds = parseInt(process.env.SALT_ROUNDS) || 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        const memberId = generateMemberId();
        
        // Start a transaction to ensure both inserts succeed
        connection.beginTransaction((err) => {
            if (err) {
                console.error('Transaction start error:', err);
                return res.status(500).json({ message: 'Transaction start failed' });
            }

            // Query to insert row in "users" table
            const userQuery = 'INSERT INTO users (username, email, password, member_id) VALUES (?, ?, ?, ?)';
            
            connection.query(userQuery, [username, email, hashedPassword, memberId], (err, userResult) => {
                if (err) {
                    console.error('User insert error:', err);
                    return connection.rollback(() => {
                        if (err.code === 'ER_DUP_ENTRY') {
                            return res.status(400).json({ message: 'Username or email already exists' });
                        }
                        return res.status(500).json({ message: 'Registration failed' });
                    });
                }

                // Query to insert row in "member_info" table
                const memberInfoQuery = 'INSERT INTO member_info (member_id, registration_date) VALUES (?, NOW())';
                
                connection.query(memberInfoQuery, [memberId], (err, memberInfoResult) => {
                    if (err) {
                        console.error('Member info insert error:', err);
                        return connection.rollback(() => {
                            return res.status(500).json({ message: 'Member info registration failed' });
                        });
                    }

                    // Commit the transaction
                    connection.commit((err) => {
                        if (err) {
                            console.error('Transaction commit error:', err);
                            return connection.rollback(() => {
                                return res.status(500).json({ message: 'Transaction commit failed' });
                            });
                        }

                        res.status(201).json({ 
                            message: 'User registered successfully',
                            memberId: memberId 
                        });
                    });
                });
            });
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Registration failed' });
    }
});

// Start server
const server = app.listen(port, () => {
console.log(`Server running on http://localhost:${port}`);
});

//Handling shutting down server
process.on('SIGINT', () => {
    console.log('Closing MySQL connection...');
    connection.end((err) => {
        if (err) console.error('Error closing MySQL connection:', err);
        server.close(() => {
            console.log('Server closed');
            process.exit(0);
        });
    });
});