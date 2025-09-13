const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// ตั้งค่า timezone เป็นประเทศไทย
process.env.TZ = 'Asia/Bangkok';

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

// User Schema (เพิ่ม profile_image)
const userSchema = new mongoose.Schema({
    username: { type: String, unique: true },
    password: String, // hashed password
    fullname: String,
    email: { type: String, unique: true },
    role: { type: String, enum: ['student', 'teacher', 'admin'], required: true },
    profile_image: { type: String, default: null }, // เพิ่มฟิลด์นี้
    created_at: { type: Date, default: Date.now } // วันที่สร้างบัญชีอัตโนมัติ
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
        const newUser = new User({ 
            username, 
            password: hashedPassword, 
            fullname, 
            email, 
            role 
            // created_at จะถูกสร้างอัตโนมัติ
        });
        await newUser.save();
        res.status(201).json({ 
            message: 'User registered successfully.',
            user: {
                username: newUser.username,
                fullname: newUser.fullname,
                email: newUser.email,
                role: newUser.role,
                created_at: newUser.created_at
            }
        });
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

// Booking Schema (เพิ่ม created_at สำหรับวันที่ยืม)
const bookingSchema = new mongoose.Schema({
    start_datetime: { type: Date, required: true },
    end_datetime: { type: Date, required: true },
    duration_hours: { type: Number, required: true },
    status: { type: String, required: true },
    room_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Room', required: true },
    room_name: { type: String, required: true },
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    fullname: { type: String, required: true },
    created_at: { type: Date, default: Date.now } // วันที่ยืม/จองอัตโนมัติ
}, { collection: 'bookings' });

const Booking = mongoose.model('Booking', bookingSchema);

// Create booking API (มีการบอกวันที่ยืมอัตโนมัติ)
app.post('/api/bookings', verifyToken, async (req, res) => {
    const { start_datetime, end_datetime, duration_hours, status, room_id } = req.body;
    if (!start_datetime || !end_datetime || !duration_hours || !status || !room_id) {
        return res.status(400).json({ error: 'All fields are required.' });
    }
    try {
        // ดึงข้อมูลห้อง
        const room = await Room.findById(room_id);
        if (!room) return res.status(404).json({ error: 'Room not found.' });

        // ดึงข้อมูล user จาก token
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ error: 'User not found.' });

        const newBooking = new Booking({
            start_datetime,
            end_datetime,
            duration_hours,
            status,
            room_id: room._id,
            room_name: room.room_name,
            user_id: user._id,
            fullname: user.fullname
            // created_at จะถูกสร้างอัตโนมัติ
        });
        await newBooking.save();
        res.status(201).json({ 
            message: 'Booking created successfully.', 
            booking: newBooking 
        });
    } catch (err) {
        res.status(500).json({ error: 'Failed to create booking.' });
    }
});

// GET booking list for logged in user
app.get('/api/bookings_list', verifyToken, async (req, res) => {
    try {
        let bookings;
        if (req.user.role === 'admin') {
            // Admin เห็นทุก booking
            bookings = await Booking.find({});
        } else {
            // User ปกติเห็นแค่ของตัวเอง
            bookings = await Booking.find({ user_id: req.user.id });
        }
        res.json(bookings);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch bookings' });
    }
});

// PUT update booking for logged in user
app.put('/api/bookings_list/update/:id', verifyToken, async (req, res) => {
    const bookingId = req.params.id;
    const { start_datetime, end_datetime, duration_hours, status, room_id } = req.body;
    
    try {
        // ตรวจสอบว่า booking นี้เป็นของ user ที่ login หรือไม่
        const existingBooking = await Booking.findOne({ 
            _id: bookingId, 
            user_id: req.user.id 
        });
        
        if (!existingBooking) {
            return res.status(404).json({ error: 'Booking not found or you do not have permission to edit this booking.' });
        }

        // ถ้ามีการส่ง room_id มาใหม่ ให้ดึงชื่อห้องใหม่
        let updateData = { start_datetime, end_datetime, duration_hours, status };
        
        if (room_id && room_id !== existingBooking.room_id.toString()) {
            const room = await Room.findById(room_id);
            if (!room) return res.status(404).json({ error: 'Room not found.' });
            updateData.room_id = room._id;
            updateData.room_name = room.room_name;
        }

        const updatedBooking = await Booking.findByIdAndUpdate(
            bookingId, 
            updateData, 
            { new: true }
        );

        res.json({ 
            message: 'Booking updated successfully.', 
            booking: updatedBooking 
        });
    } catch (err) {
        res.status(500).json({ error: 'Failed to update booking.' });
    }
});

// DELETE booking for logged in user
app.delete('/api/bookings_list/delete/:id', verifyToken, async (req, res) => {
    const bookingId = req.params.id;
    
    try {
        // ตรวจสอบว่า booking นี้เป็นของ user ที่ login หรือไม่
        const existingBooking = await Booking.findOne({ 
            _id: bookingId, 
            user_id: req.user.id 
        });
        
        if (!existingBooking) {
            return res.status(404).json({ error: 'Booking not found or you do not have permission to delete this booking.' });
        }

        // ลบ booking
        await Booking.findByIdAndDelete(bookingId);

        res.json({ 
            message: 'Booking deleted successfully.',
            deleted_booking: {
                id: existingBooking._id,
                room_name: existingBooking.room_name,
                start_datetime: existingBooking.start_datetime,
                end_datetime: existingBooking.end_datetime
            }
        });
    } catch (err) {
        res.status(500).json({ error: 'Failed to delete booking.' });
    }
});

// PUT update status in rooms or bookings (admin only)
app.put('/api/admin_update/:id', verifyToken, async (req, res) => {
    const { status, type } = req.body; // type: 'room' หรือ 'booking'
    const { id } = req.params;

    if (!status || !type) {
        return res.status(400).json({ error: 'status and type are required.' });
    }

    try {
        let updatedDoc = null;

        if (type === 'room') {
            // ตรวจสอบว่าเป็น admin
            if (req.user.role !== 'admin') {
                return res.status(403).json({ error: 'Access denied. Admin only.' });
            }
            
            updatedDoc = await Room.findByIdAndUpdate(
                id,
                { status },
                { new: true }
            );
            if (!updatedDoc) return res.status(404).json({ error: 'Room not found.' });
            
        } else if (type === 'booking') {
            // ให้ admin อนุมัติ booking ของใครก็ได้, user ปกติแก้ได้เฉพาะของตัวเอง
            if (req.user.role === 'admin') {
                // Admin สามารถอนุมัติ booking ใดก็ได้
                updatedDoc = await Booking.findByIdAndUpdate(
                    id,
                    { status },
                    { new: true }
                );
                if (!updatedDoc) return res.status(404).json({ error: 'Booking not found.' });
                
                // 🔥 เพิ่มส่วนนี้: อัพเดท room status เมื่ออนุมัติ booking
                if (status === 'approved') {
                    await Room.findByIdAndUpdate(
                        updatedDoc.room_id,
                        { status: 'booked' }, // เปลี่ยน room status เป็น 'booked'
                        { new: true }
                    );
                    console.log(`Room ${updatedDoc.room_name} status updated to 'booked'`);
                } else if (status === 'cancelled' || status === 'rejected') {
                    // ถ้ายกเลิกหรือปฏิเสธ ให้ room กลับเป็นว่าง
                    await Room.findByIdAndUpdate(
                        updatedDoc.room_id,
                        { status: 'available' },
                        { new: true }
                    );
                    console.log(`Room ${updatedDoc.room_name} status updated to 'available'`);
                }
                
            } else {
                // User ปกติแก้ได้เฉพาะของตัวเอง
                const booking = await Booking.findOne({ _id: id, user_id: req.user.id });
                if (!booking) return res.status(404).json({ error: 'Booking not found or you do not have permission.' });

                updatedDoc = await Booking.findByIdAndUpdate(
                    id,
                    { status },
                    { new: true }
                );
                
                // User ยกเลิก booking ของตัวเอง
                if (status === 'cancelled') {
                    await Room.findByIdAndUpdate(
                        updatedDoc.room_id,
                        { status: 'available' },
                        { new: true }
                    );
                }
            }
        } else {
            return res.status(400).json({ error: 'Invalid type. Must be "room" or "booking".' });
        }

        res.json({
            message: `${type} status updated successfully.`,
            updated: updatedDoc
        });
    } catch (err) {
        console.error('Error updating status:', err);
        res.status(500).json({ error: 'Failed to update status.' });
    }
});

// DELETE booking for admin (can delete any booking)
app.delete('/api/admin/booking/:id', verifyToken, async (req, res) => {
    const bookingId = req.params.id;
    
    try {
        // ตรวจสอบว่าเป็น admin
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Access denied. Admin only.' });
        }

        // หา booking ที่จะลบ
        const existingBooking = await Booking.findById(bookingId);
        if (!existingBooking) {
            return res.status(404).json({ error: 'Booking not found.' });
        }

        // ลบ booking
        await Booking.findByIdAndDelete(bookingId);

        // 🔥 อัพเดท room status กลับเป็นว่าง
        await Room.findByIdAndUpdate(
            existingBooking.room_id,
            { status: 'available' },
            { new: true }
        );

        console.log(`Admin deleted booking: ${existingBooking.room_name} - Room status updated to 'available'`);

        res.json({ 
            message: 'Booking deleted successfully by admin.',
            deleted_booking: {
                id: existingBooking._id,
                room_name: existingBooking.room_name,
                room_id: existingBooking.room_id,
                user_fullname: existingBooking.fullname,
                start_datetime: existingBooking.start_datetime,
                end_datetime: existingBooking.end_datetime,
                status: existingBooking.status
            },
            room_status_updated: 'available'
        });
    } catch (err) {
        console.error('Error deleting booking (admin):', err);
        res.status(500).json({ error: 'Failed to delete booking.' });
    }
});

// ตั้งค่า multer สำหรับการอัพโหลดรูปภาพ
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadPath = 'uploads/profile/';
        // สร้างโฟลเดอร์ถ้ายังไม่มี
        if (!fs.existsSync(uploadPath)) {
            fs.mkdirSync(uploadPath, { recursive: true });
        }
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, 'profile-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const fileFilter = (req, file, cb) => {
    // อนุญาตเฉพาะไฟล์รูปภาพ
    if (file.mimetype.startsWith('image/')) {
        cb(null, true);
    } else {
        cb(new Error('Only image files are allowed!'), false);
    }
};

const upload = multer({ 
    storage: storage,
    fileFilter: fileFilter,
    limits: {
        fileSize: 5 * 1024 * 1024 // จำกัดขนาดไฟล์ 5MB
    }
});

// PUT upload profile image
app.put('/api/user/image', verifyToken, upload.single('profile_image'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No image file uploaded.' });
        }

        // อัพเดทข้อมูล user ด้วยชื่อไฟล์รูปภาพ
        const imagePath = req.file.filename;
        const updatedUser = await User.findByIdAndUpdate(
            req.user.id,
            { profile_image: imagePath },
            { new: true, select: '-password' }
        );

        if (!updatedUser) {
            return res.status(404).json({ error: 'User not found.' });
        }

        res.json({
            message: 'Profile image uploaded successfully.',
            user: {
                id: updatedUser._id,
                username: updatedUser.username,
                fullname: updatedUser.fullname,
                email: updatedUser.email,
                role: updatedUser.role,
                profile_image: updatedUser.profile_image,
                image_url: `http://localhost:5001/uploads/profile/${updatedUser.profile_image}`
            }
        });
    } catch (err) {
        console.error('Error uploading image:', err);
        res.status(500).json({ error: 'Failed to upload profile image.' });
    }
});

// Error handling middleware สำหรับ multer
app.use((error, req, res, next) => {
    if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ error: 'File too large (max 5MB)' });
        }
        if (error.code === 'LIMIT_UNEXPECTED_FILE') {
            return res.status(400).json({ error: 'Invalid field name. Use "profile_image"' });
        }
    }
    res.status(500).json({ error: error.message });
});

// Serve static files (สำหรับแสดงรูปภาพ)
app.use('/uploads', express.static('uploads'));

// Start server
const PORT = 5001;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});