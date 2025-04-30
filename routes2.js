import express from 'express';
import mysql from 'mysql2/promise';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();
const router = express.Router();

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ error: 'Access denied' });

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Invalid token' });
    req.userId = decoded.id; // Store user ID from token
    next();
  });
};

// Middleware to verify admin role (optional, uncomment to restrict POST/PUT/DELETE to admins)
// const verifyAdmin = async (req, res, next) => {
//   try {
//     const [user] = await pool.query('SELECT role FROM users WHERE id = ?', [req.userId]);
//     if (user.length === 0 || user[0].role !== 'admin') {
//       return res.status(403).json({ error: 'Unauthorized: Admin access required' });
//     }
//     next();
//   } catch (error) {
//     console.error('Error:', error);
//     res.status(500).json({ error: 'Server error' });
//   }
// };

// GET /notifications - Retrieve a list of all notifications
router.get('/notifications', verifyToken, /* verifyAdmin, */ async (req, res) => {
  try {
    const [results] = await pool.query(
      'SELECT id, user_id, content, is_read, created_at, updated_at FROM notifications'
    );
    res.json(results);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /notifications/:id - Retrieve details of a specific notification
router.get('/notifications/:id', verifyToken, async (req, res) => {
  try {
    const [results] = await pool.query(
      'SELECT id, user_id, content, is_read, created_at, updated_at FROM notifications WHERE id = ?',
      [req.params.id]
    );
    if (results.length === 0) return res.status(404).json({ error: 'Notification not found' });

    // Optionally restrict access to the notification's user or admin
    // if (results[0].user_id !== req.userId) {
    //   const [user] = await pool.query('SELECT role FROM users WHERE id = ?', [req.userId]);
    //   if (user.length === 0 || user[0].role !== 'admin') {
    //     return res.status(403).json({ error: 'Unauthorized to view this notification' });
    //   }
    // }

    res.json(results[0]);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /notifications - Create a new notification
router.post('/notifications', verifyToken, /* verifyAdmin, */ async (req, res) => {
  const { user_id, content, is_read } = req.body;

  // Validate required fields
  if (!user_id || !content) {
    return res.status(400).json({ error: 'User ID and content are required' });
  }

  try {
    // Check if the user exists
    const [existingUser] = await pool.query('SELECT id FROM users WHERE id = ?', [user_id]);
    if (existingUser.length === 0) return res.status(404).json({ error: 'User not found' });

    // Insert the new notification
    const [result] = await pool.query(
      'INSERT INTO notifications (user_id, content, is_read, created_at) VALUES (?, ?, ?, NOW())',
      [user_id, content, is_read || false]
    );

    res.json({ message: 'Notification created successfully', notificationId: result.insertId });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// PUT /notifications/:id - Update a specific notification
router.put('/notifications/:id', verifyToken, /* verifyAdmin, */ async (req, res) => {
  const { user_id, content, is_read } = req.body;

  // Validate required fields
  if (!user_id || !content) {
    return res.status(400).json({ error: 'User ID and content are required' });
  }

  try {
    // Check if the notification exists
    const [existingNotification] = await pool.query('SELECT id FROM notifications WHERE id = ?', [req.params.id]);
    if (existingNotification.length === 0) return res.status(404).json({ error: 'Notification not found' });

    // Check if the user exists
    const [existingUser] = await pool.query('SELECT id FROM users WHERE id = ?', [user_id]);
    if (existingUser.length === 0) return res.status(404).json({ error: 'User not found' });

    // Update the notification
    await pool.query(
      'UPDATE notifications SET user_id = ?, content = ?, is_read = ? WHERE id = ?',
      [user_id, content, is_read || false, req.params.id]
    );

    res.json({ message: 'Notification updated successfully' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// DELETE /notifications/:id - Delete a specific notification
router.delete('/notifications/:id', verifyToken, /* verifyAdmin, */ async (req, res) => {
  try {
    // Check if the notification exists
    const [existingNotification] = await pool.query('SELECT id FROM notifications WHERE id = ?', [req.params.id]);
    if (existingNotification.length === 0) return res.status(404).json({ error: 'Notification not found' });

    // Delete the notification
    await pool.query('DELETE FROM notifications WHERE id = ?', [req.params.id]);

    res.json({ message: 'Notification deleted successfully' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /users/:id/notifications - Retrieve all notifications for a specific user
router.get('/users/:id/notifications', verifyToken, async (req, res) => {
  try {
    // Check if the user exists
    const [existingUser] = await pool.query('SELECT id FROM users WHERE id = ?', [req.params.id]);
    if (existingUser.length === 0) return res.status(404).json({ error: 'User not found' });

    // Optionally restrict access to the user themselves or admin
    // if (req.params.id != req.userId) {
    //   const [user] = await pool.query('SELECT role FROM users WHERE id = ?', [req.userId]);
    //   if (user.length === 0 || user[0].role !== 'admin') {
    //     return res.status(403).json({ error: 'Unauthorized to view this user’s notifications' });
    //   }
    // }

    // Retrieve notifications for the user
    const [results] = await pool.query(
      'SELECT id, user_id, content, is_read, created_at, updated_at FROM notifications WHERE user_id = ?',
      [req.params.id]
    );

    res.json(results);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

export default router;