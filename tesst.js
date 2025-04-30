const express = require('express');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const bodyParser = require('body-parser');
require('dotenv').config();
const app = express();
app.use(cors());
app.use(bodyParser.json());
import {get_training_centers_name,get_companies_name} from './functions.js'

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '1234',
  database: 'tamkeen'
});

db.connect(err => {
  if (err) throw err;
  console.log('MySQL Connected...');
});
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/'); // تأكد أن مجلد uploads موجود
  },
  filename: function (req, file, cb) {
    const uniqueName = Date.now() + '-' + file.originalname;
    cb(null, uniqueName);
  }
});
const upload = multer({ storage: storage });
app.post('/loginEmail', (req, res) => {
  const { email, password } = req.body;

  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err || results.length === 0) return res.status(400).json({ error: 'User not found' });
    
    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });
    
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET);
    res.json({ token, user: { name: user.name, email: user.email } });
  });
});
app.post('/loginPhone', (req, res) => {
  const { phone, password } = req.body;

  db.query('SELECT * FROM users WHERE phone = ?', [phone], async (err, results) => {
    if (err || results.length === 0) return res.status(400).json({ error: 'User not found' });
    
    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });
    
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET);
    res.json({ token, user: { name: user.name, phone: user.phone } });
  });
});
app.post('/signuptrainers', async (req, res) => {
  const { name, email, password } = req.body;

  console.log("Received:", { name, email, password }); // Debugging test nash na3rafe wash rak ba3thli

  if (!name || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
  }

  try {
      const hashedPassword = await bcrypt.hash(password, 10);

      db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
          if (err) {
              console.error('Database error:', err);
              return res.status(500).json({ error: 'Database error' });
          }

          if (results.length > 0) {
              return res.status(400).json({ error: 'Email already exists' });
          }

          db.query('INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
              [name, email, hashedPassword], (err, result) => {
                  if (err) {
                      console.error('Insert error:', err);
                      return res.status(500).json({ error: 'Error creating user' });
                  }
                  res.json({ message: 'User registered successfully' });
              });
      });
  } catch (error) {
      console.error('Hashing error:', error);
      res.status(500).json({ error: 'Server error' });
  }
});


app.listen(3000, () => console.log('Server running on port 3000'));