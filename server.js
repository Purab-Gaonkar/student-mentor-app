// server.js
const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// MySQL Connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root', // Your MySQL username
    password: 'password', // Your MySQL password
    database: 'mentoring_db', // Your MySQL database name
});

db.connect((err) => {
    if (err) throw err;
    console.log('MySQL connected');
});

// Middleware to verify token
// Middleware to verify token
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1]; // Get token from Authorization header
    if (!token) return res.sendStatus(403); // Forbidden if token is missing
    jwt.verify(token, 'secretkey', (err, user) => {
        if (err) return res.sendStatus(403); // Forbidden if token is invalid
        req.user = user; // Attach user information to request
        next();
    });
};


// Register
app.post('/api/register', async (req, res) => {
    const { email, password, name, interests } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    db.query('INSERT INTO users (email, password, name, interests) VALUES (?, ?, ?, ?)', [email, hashedPassword, name, interests], (error) => {
        if (error) return res.status(400).send('User already exists');
        res.status(201).send('User registered');
    });
});

// Login
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    db.query('SELECT * FROM users WHERE email = ?', [email], async (error, results) => {
        if (error || results.length === 0) return res.status(400).send('Invalid credentials');
        const user = results[0];
        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(400).send('Invalid credentials');
        const token = jwt.sign({ id: user.id }, 'secretkey', { expiresIn: '1h' });
        res.json({ token });
    });
});

// Get User Profile
app.get('/api/profile', verifyToken, (req, res) => {
    db.query('SELECT * FROM users WHERE id = ?', [req.user.id], (error, results) => {
        if (error) return res.status(400).send('Error fetching profile');
        res.json(results[0]);
    });
});

// Update Profile
app.put('/api/profile', verifyToken, (req, res) => {
    const { name, interests } = req.body;
    db.query('UPDATE users SET name = ?, interests = ? WHERE id = ?', [name, interests, req.user.id], (error) => {
        if (error) return res.status(400).send('Error updating profile');
        res.send('Profile updated');
    });
});

// Schedule Meeting
app.post('/api/meetings', verifyToken, (req, res) => {
    const { date, mentorId, menteeId } = req.body;
    db.query('INSERT INTO meetings (date, mentorId, menteeId) VALUES (?, ?, ?)', [date, mentorId, menteeId], (error) => {
        if (error) return res.status(400).send('Error scheduling meeting');
        res.status(201).send('Meeting scheduled');
    });
});

// Get Meetings
app.get('/api/meetings', verifyToken, (req, res) => {
    db.query('SELECT * FROM meetings WHERE mentorId = ? OR menteeId = ?', [req.user.id, req.user.id], (error, results) => {
        if (error) return res.status(400).send('Error fetching meetings');
        res.json(results);
    });
});

// Submit Feedback
app.post('/api/feedback', verifyToken, (req, res) => {
    const { feedback, meetingId } = req.body;
    db.query('INSERT INTO feedback (feedback, meetingId) VALUES (?, ?)', [feedback, meetingId], (error) => {
        if (error) return res.status(400).send('Error submitting feedback');
        res.status(201).send('Feedback submitted');
    });
});

// Get Feedback
app.get('/api/feedback', verifyToken, (req, res) => {
    db.query('SELECT * FROM feedback', (error, results) => {
        if (error) return res.status(400).send('Error fetching feedback');
        res.json(results);
    });
});



// Serve React app in production
app.use(express.static(path.join(__dirname, 'client/build')));
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'client/build', 'index.html'));
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
