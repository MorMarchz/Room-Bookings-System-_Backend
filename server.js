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

// GET all users (only fullname and role)
app.get('/api/profile', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id, { password: 0, _id: 0, __v: 0 });
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json(user);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch profile' });
    }
});

// Booking Schema (เพิ่ม room_id, room_name, user_id, fullname)
const bookingSchema = new mongoose.Schema({
    start_datetime: { type: Date, required: true },
    end_datetime: { type: Date, required: true },
    duration_hours: { type: Number, required: true },
    status: { type: String, required: true },
    room_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Room', required: true },
    room_name: { type: String, required: true },
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    fullname: { type: String, required: true }
}, { collection: 'bookings' });

const Booking = mongoose.model('Booking', bookingSchema);

// Create booking API (ดึง room_name และ fullname จาก id ที่ส่งมา)
// แก้ไข Backend API ให้รับ room_name แทน room_id
app.post('/api/bookings', verifyToken, async (req, res) => {
    const { start_datetime, end_datetime, duration_hours, room_name } = req.body;
    
    // เปลี่ยนการ check required fields
    if (!start_datetime || !end_datetime || !duration_hours || !room_name) {
        return res.status(400).json({ error: 'กรุณากรอกข้อมูลให้ครบถ้วน' });
    }
    
    try {
        // หาห้องจาก room_name แทน room_id
        const room = await Room.findOne({ room_name: room_name });
        if (!room) {
            return res.status(404).json({ error: 'ไม่พบห้องที่ระบุ' });
        }

        // ตรวจสอบว่าห้องว่างหรือไม่
        if (room.status !== 'available') {
            return res.status(400).json({ error: 'ห้องไม่ว่าง ไม่สามารถจองได้' });
        }

        // ดึงข้อมูล user จาก token
        const user = await User.findById(req.user.id);
        if (!user) {
            return res.status(404).json({ error: 'ไม่พบข้อมูลผู้ใช้' });
        }

        // ตรวจสอบการจองที่ซ้อนทับ (optional)
        const overlappingBooking = await Booking.findOne({
            room_id: room._id,
            status: { $ne: 'cancelled' },
            $or: [
                {
                    start_datetime: { $lt: new Date(end_datetime) },
                    end_datetime: { $gt: new Date(start_datetime) }
                }
            ]
        });

        if (overlappingBooking) {
            return res.status(400).json({ error: 'ช่วงเวลานี้ห้องถูกจองแล้ว' });
        }

        const newBooking = new Booking({
            start_datetime: new Date(start_datetime),
            end_datetime: new Date(end_datetime),
            duration_hours,
            status: 'confirmed', // ตั้งค่า default status
            room_id: room._id,
            room_name: room.room_name,
            user_id: user._id,
            fullname: user.fullname
        });
        
        await newBooking.save();
        
        res.status(201).json({ 
            message: 'จองห้องสำเร็จ', 
            booking: newBooking 
        });
        
    } catch (err) {
        console.error('Booking error:', err);
        res.status(500).json({ error: 'เกิดข้อผิดพลาดในระบบ' });
    }
});

// Start server
const PORT = 5001;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});