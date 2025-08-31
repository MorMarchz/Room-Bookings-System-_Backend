const express = require('express');
const mongoose = require('mongoose');

const app = express();

// Middleware
app.use(express.json());

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

// Start server
const PORT = 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});