const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors'); // เพิ่มบรรทัดนี้

const app = express();

// Middleware
app.use(express.json());
app.use(cors()); // เพิ่มบรรทัดนี้

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/Roombookings_System')
.then(() => console.log('Connected to MongoDB: Roombookings_System'))
.catch((err) => console.error('MongoDB connection error:', err));

// Example route
app.get('/', (req, res) => {
    res.send('Roombookings_System API running');
});

// Room Schema
const roomSchema = new mongoose.Schema({
    room_name: String,
    building: String,
    capacity: Number,
    type: String,
    facilities: [String],
    status: String
}, { collection: 'rooms' });

const Room = mongoose.model('Room', roomSchema);

// GET all rooms
app.get('/api/rooms', async (req, res) => {
    try {
        const rooms = await Room.find();
        res.json(rooms);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch rooms' });
    }
});

// JWT Secret Key
const JWT_SECRET = 'your_jwt_secret_key';

// User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, unique: true },
    password: String, // hashed password
    fullname: String,
    email: { type: String, unique: true },
    role: { type: String, enum: ['student', 'teacher'], required: true }
}, { collection: 'users' });

const User = mongoose.model('User', userSchema);

// Middleware: Verify JWT Token
function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token.' });
        req.user = user;
        next();
    });
}

// Register route
app.post('/api/regis', async (req, res) => {
    const { username, password, fullname, email, role } = req.body;
    if (!username || !password || !fullname || !email || !role) {
        return res.status(400).json({ error: 'All fields are required.' });
    }
    try {
        const existingUser = await User.findOne({ $or: [{ username }, { email }] });
        if (existingUser) return res.status(409).json({ error: 'Username or email already exists.' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, password: hashedPassword, fullname, email, role });
        await newUser.save();
        res.status(201).json({ message: 'User registered successfully.' });
    } catch (err) {
        res.status(500).json({ error: 'Registration failed.' });
    }
});

// Login route
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required.' });
    }
    try {
        const user = await User.findOne({ username });
        if (!user) return res.status(401).json({ error: 'Invalid credentials.' });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(401).json({ error: 'Invalid credentials.' });

        const token = jwt.sign(
            { id: user._id, username: user.username, role: user.role, fullname: user.fullname },
            JWT_SECRET,
            { expiresIn: '1h' }
        );
        res.json({ accessToken: token });
    } catch (err) {
        res.status(500).json({ error: 'Login failed.' });
    }
});

// Example protected sensor routes
app.get('/api/sensors', verifyToken, (req, res) => {
    res.json({ message: 'Sensor data (protected)' });
});

app.get('/api/get-sensors/latest-all', verifyToken, (req, res) => {
    res.json({ message: 'Latest all sensors data (protected)' });
});

// Start server
const PORT = 5001;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});