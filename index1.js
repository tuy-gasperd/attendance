const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const app = express();
app.use(bodyParser.urlencoded({ extended: false })); 
app.use(bodyParser.json()); 
app.use(express.json());
const port = 3000; // Adjust port number as needed

// Database credentials
const pool = mysql.createPool({
  host: 'bs0piznq0lms0seivyuj-mysql.services.clever-cloud.com',
  user: 'ucsi6wbl9mnuawj6',
  password: 'O4kpIJCVO85eOHEHbrGu',
  database: 'bs0piznq0lms0seivyuj'
});

// Middleware to verify token
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).send('Unauthorized access: Token missing');
  jwt.verify(token.replace('Bearer ', ''), 'gaspard', (err, decoded) => {
    if (err) {
      console.error(err);
      return res.status(403).send('Unauthorized access: Invalid or expired token');
    }
    req.userId = decoded.id;
    next();
  });
};


//testing api

app.get('/', (req, res) => {
  res.send('Hello World!')
})


// Get all data from a roles table
app.get('/students',verifyToken, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM students');
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error retrieving students');
  }
});

// Select Single role
app.get('/students/:id', verifyToken, async (req, res) => {
  const id = req.params.id;
  try {
    const [rows] = await pool.query('SELECT * FROM students WHERE id = ?', [id]);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error showing student');
  }
});

// Insert data into students table
app.post('/students', verifyToken, async (req, res) => {
  const { reg_no,name,address,email, password } = req.body; // Destructure data from request body
  if (!email || !password) {
    return res.status(400).send('Please provide all required fields (email,password)');
  }
  try {
    const [result] = await pool.query('INSERT INTO students SET ?', { reg_no,name,address,email, password });
    res.json({ message: `role inserted successfully with ID: ${result.insertId}` });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error inserting student');
  }
});

// Update role
app.put('/students/:id', verifyToken, async (req, res) => {
  const id = req.params.id;
  const { reg_no,name,address,email, password } = req.body; // Destructure data from request body
  if (!email || !password) {
    return res.status(400).send('Please provide all required fields ( email,password)');
  }
  try {
    const [result] = await pool.query('UPDATE students SET reg_no=?,name=?,address=?,email=?,password=? WHERE id = ?', [reg_no,name ,address,email,password,id]);
    res.json({ message: `role updated successfully with ID: ${req.params.id}` });  // Use ID from request params
  } catch (err) {
    console.error(err);
    res.status(500).send('Error updating role');
  }
});

// Delete role by ID
app.delete('/students/:id', verifyToken, async (req, res) => {
  const id = req.params.id;
  try {
    await pool.query('DELETE FROM students WHERE id = ?', [id]);
    res.json({ message: `Data with ID ${id} deleted successfully` });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error deleting role');
  }
});

// Login route
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const [users] = await pool.query('SELECT * FROM students WHERE email = ?', [email]);
    if (!users.length) {
      return res.status(404).send('User not found');
    }
    
    const user = users[0];
    // Compare the provided password with the hashed password in the database
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).send('Invalid password');
    }

    // Generate JWT token
    const token = jwt.sign({ id: user.id }, 'gaspard', { expiresIn: '1h' });

    // Send the token as response
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error logging in');
  }
});

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
