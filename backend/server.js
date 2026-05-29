require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// Koneksi MySQL
const db = mysql.createPool(process.env.MYSQL_URL);
const promiseDb = db.promise();

// Secret key JWT
const JWT_SECRET = process.env.JWT_SECRET || 'rahasia_kostnest_super';

// Middleware verifikasi token
const authenticate = async (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.userId = decoded.userId;
        next();
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
};

// ========== AUTH ENDPOINTS ==========
// Register
app.post('/api/register', async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'Semua field wajib diisi' });
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await promiseDb.execute(
            'INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
            [name, email, hashedPassword]
        );
        const token = jwt.sign({ userId: result.insertId, email, name }, JWT_SECRET, { expiresIn: '1d' });
        res.json({ success: true, user: { id: result.insertId, name, email }, token });
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: 'Email sudah terdaftar' });
        res.status(500).json({ error: 'Server error' });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email dan password wajib' });
    try {
        const [rows] = await promiseDb.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (rows.length === 0) return res.status(401).json({ error: 'Email atau password salah' });
        const user = rows[0];
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(401).json({ error: 'Email atau password salah' });
        const token = jwt.sign({ userId: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '1d' });
        res.json({ success: true, user: { id: user.id, name: user.name, email: user.email }, token });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ========== ROOMS ==========
app.get('/api/rooms', async (req, res) => {
    try {
        const [rows] = await promiseDb.execute(
            'SELECT id, name, price, description, image_icon, bg_color FROM rooms'
        );

        res.json(rows);

    } catch (err) {

        console.error("MYSQL ERROR:", err);

        res.status(500).json({
            error: 'Gagal mengambil data kamar',
            detail: err.message
        });
    }
});

// ========== BOOKINGS ==========
app.get('/api/bookings', authenticate, async (req, res) => {
    try {
        const [rows] = await promiseDb.execute(
            `SELECT b.id, b.room_id, b.check_in, b.check_out, b.status, b.created_at,
                    r.name as room_name, r.price as room_price
             FROM bookings b
             JOIN rooms r ON b.room_id = r.id
             WHERE b.user_id = ? AND b.status = 'active'
             ORDER BY b.created_at DESC`,
            [req.userId]
        );
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: 'Gagal mengambil booking' });
    }
});

app.post('/api/bookings', authenticate, async (req, res) => {
    const { roomId, checkIn, checkOut } = req.body;
    if (!roomId || !checkIn || !checkOut) return res.status(400).json({ error: 'Data booking tidak lengkap' });
    if (new Date(checkIn) >= new Date(checkOut)) return res.status(400).json({ error: 'Check-out harus setelah check-in' });
    try {
        const [result] = await promiseDb.execute(
            'INSERT INTO bookings (user_id, room_id, check_in, check_out, status) VALUES (?, ?, ?, ?, ?)',
            [req.userId, roomId, checkIn, checkOut, 'active']
        );
        res.json({ success: true, bookingId: result.insertId });
    } catch (err) {
        res.status(500).json({ error: 'Gagal membuat booking' });
    }
});

app.delete('/api/bookings/:id', authenticate, async (req, res) => {
    const bookingId = req.params.id;
    try {
        const [result] = await promiseDb.execute(
            'UPDATE bookings SET status = "cancelled" WHERE id = ? AND user_id = ?',
            [bookingId, req.userId]
        );
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Booking tidak ditemukan' });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Gagal membatalkan booking' });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Backend berjalan di port ${PORT}`);
});