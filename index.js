import express from 'express';
import mysql from 'mysql2/promise';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import cors from 'cors';
import bodyParser from 'body-parser';
import dotenv from 'dotenv';
import multer from 'multer';
dotenv.config();
const app = express();
app.use(cors());
//mysql://root:TVAOndFQwpcGoaNYVNdknpaZBTWJavpM@ballast.proxy.rlwy.net:18253/tamkeen
app.use(bodyParser.json());
import {get_training_centers_name,get_companies_name} from './functions.js'
const dbConfig = {
  host: process.env.DB_HOST || 'ballast.proxy.rlwy.net',
  user: process.env.DB_USER || 'root',
  port: process.env.DB_PORT || 18253,
  password: process.env.DB_PASSWORD || 'TVAOndFQwpcGoaNYVNdknpaZBTWJavpM',
  database: process.env.DB_NAME || 'tamkeen',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};
const pool = mysql.createPool(dbConfig);
async function testConnection() {
  let connection;
  try {
    connection = await pool.getConnection();
    console.log('MySQL Connected...');
    await connection.ping();
    console.log('Database connection test successful');
  } catch (err) {
    console.error('Database connection failed:', err.message);
    if (err.code === 'ER_BAD_DB_ERROR') {
      console.error('الخطأ: قاعدة البيانات غير موجودة! يرجى إنشاؤها أولاً.');
    } else if (err.code === 'ER_ACCESS_DENIED_ERROR') {
      console.error('الخطأ: بيانات الدخول خاطئة! تحقق من اسم المستخدم وكلمة السر.');
    }
    process.exit(1);
  } finally {
    if (connection) connection.release();
  }
}
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    const uniqueName = Date.now() + '-' + file.originalname;
    cb(null, uniqueName);
  }
});
const upload = multer({ storage: storage });

const verifyToken = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ error: 'Access denied' });

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Invalid token' });
    req.userId = decoded.id;
    req.entity_type = decoded.entity_type;
    next(); 
  });
};

app.post('/loginEmail', async (req, res) => {
  const { email, password } = req.body;
  try {
    if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });

    // Query each table for the email
    const [users] = await pool.query('SELECT id, first_name, last_name, email, password FROM users WHERE email = ?', [email]);
    const [companies] = await pool.query('SELECT id, name, email, password FROM companies WHERE email = ?', [email]);
    const [training_centers] = await pool.query('SELECT id, name, email, password FROM training_centers WHERE email = ?', [email]);
    const [trainers] = await pool.query('SELECT id, first_name, last_name, email, passsword AS password FROM trainers WHERE email = ?', [email]);

    let user = null;
    let entity_type = '';

    // Check which table the user was found in
    if (users.length > 0) {
      user = users[0];
      entity_type = 'users';
    } else if (companies.length > 0) {
      user = companies[0];
      entity_type = 'companies';
    } else if (training_centers.length > 0) {
      user = training_centers[0];
      entity_type = 'training_centers';
    } else if (trainers.length > 0) {
      user = trainers[0];
      entity_type = 'trainers';
    }

    if (!user) return res.status(400).json({ error: 'User not found' });

    // Verify password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

    // Generate JWT token
    const token = jwt.sign({ id: user.id, entity_type }, process.env.ACCESS_TOKEN_SECRET);

    // Prepare user data for response
    const userData = {
      id: user.id,
      email: user.email,
      name: entity_type === 'users' || entity_type === 'trainers' ? `${user.first_name} ${user.last_name}` : user.name,
      entity_type
    };

    res.json({ token, user: userData });
  } catch (err) {
    console.error('Error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

app.post('/loginPhone', async (req, res) => {
  const { phone, password } = req.body;
  try {
    if (!phone || !password) return res.status(400).json({ error: 'Phone and password are required' });

    // Query each table for the phone
    const [users] = await pool.query('SELECT id, first_name, last_name, phone, password FROM users WHERE phone = ?', [phone]);
    const [companies] = await pool.query('SELECT id, name, phone, password FROM companies WHERE phone = ?', [phone]);
    const [training_centers] = await pool.query('SELECT id, name, phone, password FROM training_centers WHERE phone = ?', [phone]);
    const [trainers] = await pool.query('SELECT id, first_name, last_name, phone, passsword AS password FROM trainers WHERE phone = ?', [phone]);

    let user = null;
    let entity_type = '';

    // Check which table the user was found in
    if (users.length > 0) {
      user = users[0];
      entity_type = 'users';
    } else if (companies.length > 0) {
      user = companies[0];
      entity_type = 'companies';
    } else if (training_centers.length > 0) {
      user = training_centers[0];
      entity_type = 'training_centers';
    } else if (trainers.length > 0) {
      user = trainers[0];
      entity_type = 'trainers';
    }

    if (!user) return res.status(400).json({ error: 'User not found' });

    // Verify password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

    // Generate JWT token
    const token = jwt.sign({ id: user.id, entity_type }, process.env.ACCESS_TOKEN_SECRET);

    // Prepare user data for response
    const userData = {
      id: user.id,
      phone: user.phone,
      name: entity_type === 'users' || entity_type === 'trainers' ? `${user.first_name} ${user.last_name}` : user.name,
      entity_type
    };

    res.json({ token, user: userData });
  } catch (err) {
    console.error('Error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

app.post(
  '/signuptrainers',
  upload.fields([
    { name: 'cv', maxCount: 1 },
    { name: 'certificated', maxCount: 1 },
    { name: 'profile_picture', maxCount: 1 },
  ]),
  async (req, res) => {
    const {
      first_name,
      last_name,
      email,
      date_of_birth,
      gender,
      wilaya,
      Commune,
      Street,
      education_level,
      interests,
      other_skill,
      phone,
      specialty,
      password,
    } = req.body;

    const files = req.files;

    if (
      !first_name ||
      !last_name ||
      !email ||
      !date_of_birth ||
      !gender ||
      !wilaya ||
      !Commune ||
      !Street ||
      !education_level ||
      !interests ||
      !phone ||
      !specialty ||
      !password ||
      !files.cv ||
      !files.certificated ||
      !files.profile_picture
    ) {
      return res.status(400).json({ error: 'All fields are required, including files' });
    }

    try {
      const hashedPassword = await bcrypt.hash(password, 10);

      const [existingTrainer] = await pool.query('SELECT * FROM trainers WHERE email = ?', [email]);
      if (existingTrainer.length > 0) {
        return res.status(400).json({ error: 'Email already exists' });
      }

      const cvPath = files.cv[0].path;
      const certificatedPath = files.certificated[0].path;
      const profilePicturePath = files.profile_picture[0].path;

      await pool.query(
        `INSERT INTO trainers 
        (first_name, last_name, email, date_of_birth, gender, wilaya, Commune, Street, 
        education_level, interests, other_skill, profile_picture, certificated, cv, phone, specialty, passsword, created_at) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
        [
          first_name,
          last_name,
          email,
          date_of_birth,
          gender,
          wilaya,
          Commune,
          Street,
          education_level,
          interests,
          other_skill,
          profilePicturePath,
          certificatedPath,
          cvPath,
          phone,
          specialty,
          hashedPassword,
        ]
      );

      res.json({ message: 'Trainer registered successfully' });
    } catch (error) {
      console.error('Error:', error);
      res.status(500).json({ error: 'Server error' });
    }
  }
);

app.post(
  '/signupcenter',
  upload.single('logo'),
  async (req, res) => {
    const {
      name,
      email,
      password,
      phone,
      address,
      numero_commerce,
      type,
      wilaya,
      Commune,
      speciality,
      website,
      facebook,
      instagram,
      x,
      linkedin,
    } = req.body;
    const file = req.file;

    if (
      !name ||
      !email ||
      !password ||
      !phone ||
      !address ||
      !numero_commerce ||
      !type ||
      !wilaya ||
      !Commune ||
      !speciality ||
      !website ||
      !file
    ) {
      return res.status(400).json({ error: 'All fields are required, including the logo file' });
    }

    try {
      const hashedPassword = await bcrypt.hash(password, 10);

      const [existingCenter] = await pool.query('SELECT * FROM training_centers WHERE email = ?', [email]);
      if (existingCenter.length > 0) {
        return res.status(400).json({ error: 'Email already exists' });
      }

      const logoPath = file.path;

      await pool.query(
        `INSERT INTO training_centers 
        (name, email, password, phone, address, numero_commerce, type, wilaya, Commune, speciality, website, facebook, instagram, x, linkedin, logo, created_at) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
        [
          name,
          email,
          hashedPassword,
          phone,
          address,
          numero_commerce,
          type,
          wilaya,
          Commune,
          speciality,
          website,
          facebook,
          instagram,
          x,
          linkedin,
          logoPath,
        ]
      );

      res.json({ message: 'Training center registered successfully' });
    } catch (error) {
      console.error('Error:', error);
      res.status(500).json({ error: 'Server error' });
    }
  }
);

app.post(
  '/signupcompanies',
  upload.single('logo'),
  async (req, res) => {
    const {
      name,
      email,
      password,
      phone,
      domain,
      size,
      website,
      wilaya,
      Commune,
      numero_commerce,
      address,
      location,
    } = req.body;
    const file = req.file;

    if (
      !name ||
      !email ||
      !password ||
      !phone ||
      !domain ||
      !size ||
      !website ||
      !wilaya ||
      !Commune ||
      !numero_commerce ||
      !address ||
      !location ||
      !file
    ) {
      return res.status(400).json({ error: 'All fields are required, including the logo file' });
    }

    try {
      const hashedPassword = await bcrypt.hash(password, 10);

      const [existingCompany] = await pool.query('SELECT * FROM companies WHERE email = ?', [email]);
      if (existingCompany.length > 0) {
        return res.status(400).json({ error: 'Email already exists' });
      }

      const logoPath = file.path;

      await pool.query(
        `INSERT INTO companies 
        (name, email, password, phone, domain, size, website, wilaya, Commune, numero_commerce, address, location, logo, created_at) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
        [
          name,
          email,
          hashedPassword,
          phone,
          domain,
          size,
          website,
          wilaya,
          Commune,
          numero_commerce,
          address,
          location,
          logoPath,
        ]
      );

      res.json({ message: 'Company registered successfully' });
    } catch (error) {
      console.error('Error:', error);
      res.status(500).json({ error: 'Server error' });
    }
  }
);

app.post(
  '/signupuser',
  upload.fields([
    { name: 'profile_picture', maxCount: 1 },
    { name: 'cv', maxCount: 1 },
    { name: 'certificate', maxCount: 1 },
  ]),
  async (req, res) => {
    const {
      first_name,
      last_name,
      email,
      password,
      phone,
      address,
      user_type,
      level_of_education,
      receive_notifications,
      notification_type,
    } = req.body;
    const files = req.files;

    if (
      !first_name ||
      !last_name ||
      !email ||
      !password ||
      !phone ||
      !address ||
      !user_type ||
      !level_of_education ||
      !files.profile_picture ||
      !files.cv ||
      !files.certificate
    ) {
      return res.status(400).json({ error: 'All fields are required, including profile picture, CV, and certificate files' });
    }
    try {
      const hashedPassword = await bcrypt.hash(password, 10);

      const [existingUser] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
      if (existingUser.length > 0) {
        return res.status(400).json({ error: 'Email already exists' });
      }

      const profilePicturePath = files.profile_picture[0].path;
      const cvPath = files.cv[0].path;
      const certificatePath = files.certificate[0].path;

      await pool.query(
        `INSERT INTO users 
        (first_name, last_name, email, password, phone, address, user_type, level_of_education, profile_picture, cv, certificate, receive_notifications, notification_type, created_at) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
        [
          first_name,
          last_name,
          email,
          hashedPassword,
          phone,
          address,
          user_type,
          level_of_education,
          profilePicturePath,
          cvPath,
          certificatePath,
          receive_notifications === 'true',
          notification_type,
        ]
      );

      res.json({ message: 'User registered successfully' });
    } catch (error) {
      console.error('Error:', error);
      res.status(500).json({ error: 'Server error' });
    }
  }
);

app.get('/users/:id', verifyToken, async (req, res) => {
  try {
    const [results] = await pool.query('SELECT id, first_name, last_name, email, phone, address, user_type, level_of_education, profile_picture, cv, certificate, receive_notifications, notification_type, created_at FROM users WHERE id = ?', [req.params.id]);
    if (results.length === 0) return res.status(404).json({ error: 'User not found' });

    res.json(results[0]);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/users/:id', verifyToken, upload.fields([
  { name: 'profile_picture', maxCount: 1 },
  { name: 'cv', maxCount: 1 },
  { name: 'certificate', maxCount: 1 },
]), async (req, res) => {
  const {
    first_name,
    last_name,
    email,
    password,
    phone,
    address,
    user_type,
    level_of_education,
    receive_notifications,
    notification_type
  } = req.body;
  const files = req.files;

  if (!first_name || !last_name || !email || !phone || !address || !user_type || !level_of_education) {
    return res.status(400).json({ error: 'Required fields are missing' });
  }

  try {
    const [existingUser] = await pool.query('SELECT id, password, profile_picture, cv, certificate FROM users WHERE id = ?', [req.params.id]);
    if (existingUser.length === 0) return res.status(404).json({ error: 'User not found' });

    const [emailCheck] = await pool.query('SELECT id FROM users WHERE email = ? AND id != ?', [email, req.params.id]);
    if (emailCheck.length > 0) return res.status(400).json({ error: 'Email already exists' });

    const updateData = {
      first_name,
      last_name,
      email,
      phone,
      address,
      user_type,
      level_of_education,
      receive_notifications: receive_notifications === 'true',
      notification_type: notification_type || null,
      profile_picture: files.profile_picture ? files.profile_picture[0].path : existingUser[0].profile_picture,
      cv: files.cv ? files.cv[0].path : existingUser[0].cv,
      certificate: files.certificate ? files.certificate[0].path : existingUser[0].certificate
    };

    if (password) {
      updateData.password = await bcrypt.hash(password, 10);
    } else {
      updateData.password = existingUser[0].password;
    }

    await pool.query(
      `UPDATE users SET 
        first_name = ?, last_name = ?, email = ?, password = ?, phone = ?, address = ?, 
        user_type = ?, level_of_education = ?, profile_picture = ?, cv = ?, certificate = ?, 
        receive_notifications = ?, notification_type = ?
       WHERE id = ?`,
      [
        updateData.first_name,
        updateData.last_name,
        updateData.email,
        updateData.password,
        updateData.phone,
        updateData.address,
        updateData.user_type,
        updateData.level_of_education,
        updateData.profile_picture,
        updateData.cv,
        updateData.certificate,
        updateData.receive_notifications,
        updateData.notification_type,
        req.params.id
      ]
    );

    res.json({ message: 'User updated successfully' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/users/:id', verifyToken, async (req, res) => {
  try {
    const [existingUser] = await pool.query('SELECT id FROM users WHERE id = ?', [req.params.id]);
    if (existingUser.length === 0) return res.status(404).json({ error: 'User not found' });

    await pool.query('DELETE FROM users WHERE id = ?', [req.params.id]);

    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/users/:id/interests', verifyToken, async (req, res) => {
  try {
    const [results] = await pool.query(
      `SELECT i.id, i.name 
       FROM interests i
       JOIN user_interests ui ON i.id = ui.interest_id
       WHERE ui.user_id = ?`,
      [req.params.id]
    );
    if (results.length === 0) return res.status(404).json({ error: 'No interests found for this user' });

    res.json(results);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/users/:id/interests', verifyToken, async (req, res) => {
  const { interest_id } = req.body;

  if (!interest_id) return res.status(400).json({ error: 'Interest ID is required' });

  try {
    const [existingUser] = await pool.query('SELECT id FROM users WHERE id = ?', [req.params.id]);
    if (existingUser.length === 0) return res.status(404).json({ error: 'User not found' });

    const [existingInterest] = await pool.query('SELECT id FROM interests WHERE id = ?', [interest_id]);
    if (existingInterest.length === 0) return res.status(404).json({ error: 'Interest not found' });

    const [existingUserInterest] = await pool.query(
      'SELECT id FROM user_interests WHERE user_id = ? AND interest_id = ?',
      [req.params.id, interest_id]
    );
    if (existingUserInterest.length > 0) return res.status(400).json({ error: 'Interest already added for this user' });

    await pool.query(
      'INSERT INTO user_interests (user_id, interest_id) VALUES (?, ?)',
      [req.params.id, interest_id]
    );

    res.json({ message: 'Interest added successfully' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/users/:id/interests/:interestId', verifyToken, async (req, res) => {
  try {
    const [existingUser] = await pool.query('SELECT id FROM users WHERE id = ?', [req.params.id]);
    if (existingUser.length === 0) return res.status(404).json({ error: 'User not found' });

    const [existingInterest] = await pool.query('SELECT id FROM interests WHERE id = ?', [req.params.interestId]);
    if (existingInterest.length === 0) return res.status(404).json({ error: 'Interest not found' });

    const [existingUserInterest] = await pool.query(
      'SELECT id FROM user_interests WHERE user_id = ? AND interest_id = ?',
      [req.params.id, req.params.interestId]
    );
    if (existingUserInterest.length === 0) return res.status(404).json({ error: 'Interest not found for this user' });

    await pool.query(
      'DELETE FROM user_interests WHERE user_id = ? AND interest_id = ?',
      [req.params.id, req.params.interestId]
    );

    res.json({ message: 'Interest removed successfully' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/logout', verifyToken, async (req, res) => {
  const token = req.headers.authorization;

  try {
    await pool.query(
      'INSERT INTO tokens (token, type, user_id, created_at) VALUES (?, ?, ?, NOW())',
      [token, 'blacklisted', req.userId]
    );

    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/companies', verifyToken, async (req, res) => {
  try {
    const [results] = await pool.query(
      'SELECT id, name, email, domain, size, website, wilaya, Commune, numero_commerce, phone, address, logo, created_at FROM companies'
    );
    res.json(results);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/companies/:id', verifyToken, async (req, res) => {
  try {
    const [results] = await pool.query(
      'SELECT id, name, email, domain, size, website, wilaya, Commune, numero_commerce, phone, address, logo, created_at FROM companies WHERE id = ?',
      [req.params.id]
    );
    if (results.length === 0) return res.status(404).json({ error: 'Company not found' });

    res.json(results[0]);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/companies/:id', verifyToken, upload.single('logo'), async (req, res) => {
  const {
    name,
    email,
    password,
    domain,
    size,
    website,
    wilaya,
    Commune,
    numero_commerce,
    phone,
    address
  } = req.body;
  const file = req.file;

  if (!name || !email || !domain || !size || !website || !wilaya || !Commune || !numero_commerce || !phone || !address) {
    return res.status(400).json({ error: 'All required fields must be provided' });
  }

  try {
    const [existingCompany] = await pool.query('SELECT id, password, logo FROM companies WHERE id = ?', [req.params.id]);
    if (existingCompany.length === 0) return res.status(404).json({ error: 'Company not found' });

    const [emailCheck] = await pool.query('SELECT id FROM companies WHERE email = ? AND id != ?', [email, req.params.id]);
    if (emailCheck.length > 0) return res.status(400).json({ error: 'Email already exists' });

    const updateData = {
      name,
      email,
      domain,
      size,
      website,
      wilaya,
      Commune,
      numero_commerce,
      phone,
      address
    };

    if (password) {
      updateData.password = await bcrypt.hash(password, 10);
    } else {
      updateData.password = existingCompany[0].password;
    }

    if (file) {
      updateData.logo = file.path;
    } else {
      updateData.logo = existingCompany[0].logo;
    }

    await pool.query(
      `UPDATE companies SET 
        name = ?, email = ?, password = ?, domain = ?, size = ?, website = ?, 
        wilaya = ?, Commune = ?, numero_commerce = ?, phone = ?, address = ?, logo = ?
       WHERE id = ?`,
      [
        updateData.name,
        updateData.email,
        updateData.password,
        updateData.domain,
        updateData.size,
        updateData.website,
        updateData.wilaya,
        updateData.Commune,
        updateData.numero_commerce,
        updateData.phone,
        updateData.address,
        updateData.logo,
        req.params.id
      ]
    );

    res.json({ message: 'Company updated successfully' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/companies/:id', verifyToken, async (req, res) => {
  try {
    const [existingCompany] = await pool.query('SELECT id FROM companies WHERE id = ?', [req.params.id]);
    if (existingCompany.length === 0) return res.status(404).json({ error: 'Company not found' });

    await pool.query('DELETE FROM companies WHERE id = ?', [req.params.id]);

    res.json({ message: 'Company deleted successfully' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/get_companies_name', verifyToken, async (req, res) => {
  try {
    const [results] = await pool.query('SELECT name FROM companies');
    res.json(results.map(row => row.name));
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/training_centers', verifyToken, async (req, res) => {
  try {
    const [results] = await pool.query(
      'SELECT id, name, email, phone, numero_commerce, type, wilaya, Commune, speciality, website, facebook, instagram, X, linkedin, address, logo, created_at FROM training_centers'
    );
    res.json(results);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/training_centers/:id', verifyToken, async (req, res) => {
  try {
    const [results] = await pool.query(
      'SELECT id, name, email, phone, numero_commerce, type, wilaya, Commune, speciality, website, facebook, instagram, X, linkedin, address, logo, created_at FROM training_centers WHERE id = ?',
      [req.params.id]
    );
    if (results.length === 0) return res.status(404).json({ error: 'Training center not found' });

    res.json(results[0]);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/training_centers/:id', verifyToken, upload.single('logo'), async (req, res) => {
  const {
    name,
    email,
    password,
    phone,
    numero_commerce,
    type,
    wilaya,
    Commune,
    speciality,
    website,
    facebook,
    instagram,
    X,
    linkedin,
    address
  } = req.body;
  const file = req.file;

  if (!name || !email || !phone || !numero_commerce || !type || !wilaya || !Commune || !speciality || !website || !address) {
    return res.status(400).json({ error: 'All required fields must be provided' });
  }

  try {
    const [existingCenter] = await pool.query('SELECT id, password, logo FROM training_centers WHERE id = ?', [req.params.id]);
    if (existingCenter.length === 0) return res.status(404).json({ error: 'Training center not found' });

    const [emailCheck] = await pool.query('SELECT id FROM training_centers WHERE email = ? AND id != ?', [email, req.params.id]);
    if (emailCheck.length > 0) return res.status(400).json({ error: 'Email already exists' });

    const updateData = {
      name,
      email,
      phone,
      numero_commerce,
      type,
      wilaya,
      Commune,
      speciality,
      website,
      facebook: facebook || null,
      instagram: instagram || null,
      X: X || null,
      linkedin: linkedin || null,
      address
    };

    if (password) {
      updateData.password = await bcrypt.hash(password, 10);
    } else {
      updateData.password = existingCenter[0].password;
    }

    if (file) {
      updateData.logo = file.path;
    } else {
      updateData.logo = existingCenter[0].logo;
    }

    await pool.query(
      `UPDATE training_centers SET 
        name = ?, email = ?, password = ?, phone = ?, numero_commerce = ?, type = ?, 
        wilaya = ?, Commune = ?, speciality = ?, website = ?, facebook = ?, instagram = ?, 
        X = ?, linkedin = ?, address = ?, logo = ?
       WHERE id = ?`,
      [
        updateData.name,
        updateData.email,
        updateData.password,
        updateData.phone,
        updateData.numero_commerce,
        updateData.type,
        updateData.wilaya,
        updateData.Commune,
        updateData.speciality,
        updateData.website,
        updateData.facebook,
        updateData.instagram,
        updateData.X,
        updateData.linkedin,
        updateData.address,
        updateData.logo,
        req.params.id
      ]
    );

    res.json({ message: 'Training center updated successfully' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/training_centers/:id', verifyToken, async (req, res) => {
  try {
    const [existingCenter] = await pool.query('SELECT id FROM training_centers WHERE id = ?', [req.params.id]);
    if (existingCenter.length === 0) return res.status(404).json({ error: 'Training center not found' });

    await pool.query('DELETE FROM training_centers WHERE id = ?', [req.params.id]);

    res.json({ message: 'Training center deleted successfully' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/get_training_centers_name', verifyToken, async (req, res) => {
  try {
    const [results] = await pool.query('SELECT name FROM training_centers');
    res.json(results.map(row => row.name));
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/trainers', verifyToken, async (req, res) => {
  try {
    const [results] = await pool.query(
      'SELECT id, first_name, last_name, email, date_of_birth, gender, wilaya, Commune, Street, education_level, interests, other_skill, profile_picture, certificated, cv, phone, specialty, created_at FROM trainers'
    );
    res.json(results);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/trainers/:id', verifyToken, async (req, res) => {
  try {
    const [results] = await pool.query(
      'SELECT id, first_name, last_name, email, date_of_birth, gender, wilaya, Commune, Street, education_level, interests, other_skill, profile_picture, certificated, cv, phone, specialty, created_at FROM trainers WHERE id = ?',
      [req.params.id]
    );
    if (results.length === 0) return res.status(404).json({ error: 'Trainer not found' });

    res.json(results[0]);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put(
  '/trainers/:id',
  verifyToken,
  upload.fields([
    { name: 'profile_picture', maxCount: 1 },
    { name: 'cv', maxCount: 1 },
    { name: 'certificated', maxCount: 1 }
  ]),
  async (req, res) => {
    const {
      first_name,
      last_name,
      email,
      date_of_birth,
      gender,
      wilaya,
      Commune,
      Street,
      education_level,
      interests,
      other_skill,
      phone,
      specialty,
      password
    } = req.body;
    const files = req.files;

    if (
      !first_name ||
      !last_name ||
      !email ||
      !date_of_birth ||
      !gender ||
      !wilaya ||
      !Commune ||
      !Street ||
      !education_level ||
      !interests ||
      !phone ||
      !specialty
    ) {
      return res.status(400).json({ error: 'All required fields must be provided' });
    }

    try {
      const [existingTrainer] = await pool.query('SELECT id, passsword, profile_picture, cv, certificated FROM trainers WHERE id = ?', [req.params.id]);
      if (existingTrainer.length > 0) return res.status(404).json({ error: 'Trainer not found' });

      const [emailCheck] = await pool.query('SELECT id FROM trainers WHERE email = ? AND id != ?', [email, req.params.id]);
      if (emailCheck.length > 0) return res.status(400).json({ error: 'Email already exists' });

      const updateData = {
        first_name,
        last_name,
        email,
        date_of_birth,
        gender,
        wilaya,
        Commune,
        Street,
        education_level,
        interests,
        other_skill: other_skill || null,
        phone,
        specialty
      };

      if (password) {
        updateData.password = await bcrypt.hash(password, 10);
      } else {
        updateData.password = existingTrainer[0].passsword;
      }

      updateData.profile_picture = files.profile_picture ? files.profile_picture[0].path : existingTrainer[0].profile_picture;
      updateData.cv = files.cv ? files.cv[0].path : existingTrainer[0].cv;
      updateData.certificated = files.certificated ? files.certificated[0].path : existingTrainer[0].certificated;

      await pool.query(
        `UPDATE trainers SET 
          first_name = ?, last_name = ?, email = ?, date_of_birth = ?, gender = ?, 
          wilaya = ?, Commune = ?, Street = ?, education_level = ?, interests = ?, 
          other_skill = ?, profile_picture = ?, certificated = ?, cv = ?, phone = ?, 
          specialty = ?, passsword = ?
         WHERE id = ?`,
        [
          updateData.first_name,
          updateData.last_name,
          updateData.email,
          updateData.date_of_birth,
          updateData.gender,
          updateData.wilaya,
          updateData.Commune,
          updateData.Street,
          updateData.education_level,
          updateData.interests,
          updateData.other_skill,
          updateData.profile_picture,
          updateData.certificated,
          updateData.cv,
          updateData.phone,
          updateData.specialty,
          updateData.password,
          req.params.id
        ]
      );

      res.json({ message: 'Trainer updated successfully' });
    } catch (error) {
      console.error('Error:', error);
      res.status(500).json({ error: 'Server error' });
    }
  }
);

app.delete('/trainers/:id', verifyToken, async (req, res) => {
  try {
    const [existingTrainer] = await pool.query('SELECT id FROM trainers WHERE id = ?', [req.params.id]);
    if (existingTrainer.length === 0) return res.status(404).json({ error: 'Trainer not found' });

    await pool.query('DELETE FROM trainers WHERE id = ?', [req.params.id]);

    res.json({ message: 'Trainer deleted successfully' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/internships', verifyToken, async (req, res) => {
  try {
    const [results] = await pool.query(
      'SELECT id, company_id, title, description, category_id, type, mode, duration, location, start_date, end_date, image, created_at FROM internships'
    );
    res.json(results);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/internships/:id', verifyToken, async (req, res) => {
  try {
    const [results] = await pool.query(
      'SELECT id, company_id, title, description, category_id, type, mode, duration, location, start_date, end_date, image, created_at FROM internships WHERE id = ?',
      [req.params.id]
    );
    if (results.length === 0) return res.status(404).json({ error: 'Internship not found' });

    res.json(results[0]);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/internships', verifyToken, upload.single('image'), async (req, res) => {
  const {
    title,
    description,
    category_id,
    type,
    mode,
    duration,
    location,
    start_date,
    end_date
  } = req.body;
  const file = req.file;

  if (!title || !description || !category_id || !type || !mode || !duration || !location || !start_date || !end_date) {
    return res.status(400).json({ error: 'All required fields must be provided' });
  }

  if (req.entity_type !== 'companies') {
    return res.status(403).json({ error: 'Only companies can create internships' });
  }

  try {
    const company_id = req.userId;

    const [existingCompany] = await pool.query('SELECT id FROM companies WHERE id = ?', [company_id]);
    if (existingCompany.length === 0) return res.status(404).json({ error: 'Company not found' });

    const internshipData = {
      company_id,
      title,
      description,
      category_id,
      type,
      mode,
      duration,
      location,
      start_date,
      end_date,
      image: file ? file.path : null
    };

    const [result] = await pool.query(
      `INSERT INTO internships (company_id, title, description, category_id, type, mode, duration, location, start_date, end_date, image, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
      [
        internshipData.company_id,
        internshipData.title,
        internshipData.description,
        internshipData.category_id,
        internshipData.type,
        internshipData.mode,
        internshipData.duration,
        internshipData.location,
        internshipData.start_date,
        internshipData.end_date,
        internshipData.image
      ]
    );

    res.json({ message: 'Internship created successfully', internshipId: result.insertId });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/internships/:id', verifyToken, upload.single('image'), async (req, res) => {
  const {
    title,
    description,
    category_id,
    type,
    mode,
    duration,
    location,
    start_date,
    end_date
  } = req.body;
  const file = req.file;

  if (!title || !description || !category_id || !type || !mode || !duration || !location || !start_date || !end_date) {
    return res.status(400).json({ error: 'All required fields must be provided' });
  }

  if (req.entity_type !== 'companies') {
    return res.status(403).json({ error: 'Only companies can update internships' });
  }

  try {
    const company_id = req.userId;

    const [existingInternship] = await pool.query('SELECT company_id, image FROM internships WHERE id = ?', [req.params.id]);
    if (existingInternship.length === 0) return res.status(404).json({ error: 'Internship not found' });

    const [existingCompany] = await pool.query('SELECT id FROM companies WHERE id = ?', [company_id]);
    if (existingCompany.length === 0) return res.status(404).json({ error: 'Company not found' });

    const updateData = {
      company_id,
      title,
      description,
      category_id,
      type,
      mode,
      duration,
      location,
      start_date,
      end_date,
      image: file ? file.path : existingInternship[0].image
    };

    await pool.query(
      `UPDATE internships SET 
        company_id = ?, title = ?, description = ?, category_id = ?, type = ?, 
        mode = ?, duration = ?, location = ?, start_date = ?, end_date = ?, image = ?
       WHERE id = ?`,
      [
        updateData.company_id,
        updateData.title,
        updateData.description,
        updateData.category_id,
        updateData.type,
        updateData.mode,
        updateData.duration,
        updateData.location,
        updateData.start_date,
        updateData.end_date,
        updateData.image,
        req.params.id
      ]
    );

    res.json({ message: 'Internship updated successfully' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/internships/:id', verifyToken, async (req, res) => {
  try {
    const [existingInternship] = await pool.query('SELECT id FROM internships WHERE id = ?', [req.params.id]);
    if (existingInternship.length === 0) return res.status(404).json({ error: 'Internship not found' });

    await pool.query('DELETE FROM internships WHERE id = ?', [req.params.id]);

    res.json({ message: 'Internship deleted successfully' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/companies/:id/internships', verifyToken, async (req, res) => {
  try {
    const [existingCompany] = await pool.query('SELECT id FROM companies WHERE id = ?', [req.params.id]);
    if (existingCompany.length === 0) return res.status(404).json({ error: 'Company not found' });

    const [results] = await pool.query(
      'SELECT id, company_id, title, description, category_id, type, mode, duration, location, start_date, end_date, image, created_at FROM internships WHERE company_id = ?',
      [req.params.id]
    );

    res.json(results);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/training_programs', verifyToken, async (req, res) => {
  try {
    const [results] = await pool.query(
      'SELECT id, center_id, title, description, category_id, type, mode, duration, location, start_date, end_date, image, created_at FROM training_programs'
    );
    res.json(results);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/training_programs/:id', verifyToken, async (req, res) => {
  try {
    const [results] = await pool.query(
      'SELECT id, center_id, title, description, category_id, type, mode, duration, location, start_date, end_date, image, created_at FROM training_programs WHERE id = ?',
      [req.params.id]
    );
    if (results.length === 0) return res.status(404).json({ error: 'Training program not found' });

    res.json(results[0]);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/training_programs', verifyToken, upload.single('image'), async (req, res) => {
  const {
    title,
    description,
    category_id,
    type,
    mode,
    duration,
    location,
    start_date,
    end_date
  } = req.body;
  const file = req.file;

  if (!title || !description || !category_id || !type || !mode || !duration || !location || !start_date || !end_date) {
    return res.status(400).json({ error: 'All required fields must be provided' });
  }

  if (req.entity_type !== 'training_centers') {
    return res.status(403).json({ error: 'Only training centers can create training programs' });
  }

  try {
    const center_id = req.userId;

    const [existingCenter] = await pool.query('SELECT id FROM training_centers WHERE id = ?', [center_id]);
    if (existingCenter.length === 0) return res.status(404).json({ error: 'Training center not found' });

    const programData = {
      center_id,
      title,
      description,
      category_id,
      type,
      mode,
      duration,
      location,
      start_date,
      end_date,
      image: file ? file.path : null
    };

    const [result] = await pool.query(
      `INSERT INTO training_programs (center_id, title, description, category_id, type, mode, duration, location, start_date, end_date, image, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
      [
        programData.center_id,
        programData.title,
        programData.description,
        programData.category_id,
        programData.type,
        programData.mode,
        programData.duration,
        programData.location,
        programData.start_date,
        programData.end_date,
        programData.image
      ]
    );

    res.json({ message: 'Training program created successfully', programId: result.insertId });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/training_programs/:id', verifyToken, upload.single('image'), async (req, res) => {
  const {
    title,
    description,
    category_id,
    type,
    mode,
    duration,
    location,
    start_date,
    end_date
  } = req.body;
  const file = req.file;

  if (!title || !description || !category_id || !type || !mode || !duration || !location || !start_date || !end_date) {
    return res.status(400).json({ error: 'All required fields must be provided' });
  }

  if (req.entity_type !== 'training_centers') {
    return res.status(403).json({ error: 'Only training centers can update training programs' });
  }

  try {
    const center_id = req.userId;

    const [existingProgram] = await pool.query('SELECT center_id, image FROM training_programs WHERE id = ?', [req.params.id]);
    if (existingProgram.length === 0) return res.status(404).json({ error: 'Training program not found' });

    const [existingCenter] = await pool.query('SELECT id FROM training_centers WHERE id = ?', [center_id]);
    if (existingCenter.length === 0) return res.status(404).json({ error: 'Training center not found' });

    const updateData = {
      center_id,
      title,
      description,
      category_id,
      type,
      mode,
      duration,
      location,
      start_date,
      end_date,
      image: file ? file.path : existingProgram[0].image
    };

    await pool.query(
      `UPDATE training_programs SET 
        center_id = ?, title = ?, description = ?, category_id = ?, type = ?, 
        mode = ?, duration = ?, location = ?, start_date = ?, end_date = ?, image = ?
       WHERE id = ?`,
      [
        updateData.center_id,
        updateData.title,
        updateData.description,
        updateData.category_id,
        updateData.type,
        updateData.mode,
        updateData.duration,
        updateData.location,
        updateData.start_date,
        updateData.end_date,
        updateData.image,
        req.params.id
      ]
    );

    res.json({ message: 'Training program updated successfully' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/training_programs/:id', verifyToken, async (req, res) => {
  try {
    const [existingProgram] = await pool.query('SELECT id FROM training_programs WHERE id = ?', [req.params.id]);
    if (existingProgram.length === 0) return res.status(404).json({ error: 'Training program not found' });

    await pool.query('DELETE FROM training_programs WHERE id = ?', [req.params.id]);

    res.json({ message: 'Training program deleted successfully' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/training_centers/:id/programs', verifyToken, async (req, res) => {
  try {
    const [existingCenter] = await pool.query('SELECT id FROM training_centers WHERE id = ?', [req.params.id]);
    if (existingCenter.length === 0) return res.status(404).json({ error: 'Training center not found' });

    const [results] = await pool.query(
      'SELECT id, center_id, title, description, category_id, type, mode, duration, location, start_date, end_date, image, created_at FROM training_programs WHERE center_id = ?',
      [req.params.id]
    );

    res.json(results);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/training_programs/:id/trainers', verifyToken, async (req, res) => {
  try {
    const [existingProgram] = await pool.query('SELECT id FROM training_programs WHERE id = ?', [req.params.id]);
    if (existingProgram.length === 0) return res.status(404).json({ error: 'Training program not found' });

    const [results] = await pool.query(
      `SELECT t.id, t.first_name, t.last_name, t.email, t.date_of_birth, t.gender, t.wilaya, t.Commune, t.Street, 
              t.education_level, t.interests, t.other_skill, t.profile_picture, t.certificated, t.cv, t.phone, t.specialty, t.created_at
       FROM trainers t
       JOIN program_trainers pt ON t.id = pt.trainer_id
       WHERE pt.training_program_id = ?`,
      [req.params.id]
    );

    res.json(results);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/training_programs/:id/trainers', verifyToken, async (req, res) => {
  const { trainer_id } = req.body;

  if (!trainer_id) return res.status(400).json({ error: 'Trainer ID is required' });

  try {
    const [existingProgram] = await pool.query('SELECT id FROM training_programs WHERE id = ?', [req.params.id]);
    if (existingProgram.length === 0) return res.status(404).json({ error: 'Training program not found' });

    const [existingTrainer] = await pool.query('SELECT id FROM trainers WHERE id = ?', [trainer_id]);
    if (existingTrainer.length === 0) return res.status(404).json({ error: 'Trainer not found' });

    const [existingAssignment] = await pool.query(
      'SELECT id FROM program_trainers WHERE training_program_id = ? AND trainer_id = ?',
      [req.params.id, trainer_id]
    );
    if (existingAssignment.length > 0) return res.status(400).json({ error: 'Trainer already assigned to this program' });

    await pool.query(
      'INSERT INTO program_trainers (trainer_id, training_program_id) VALUES (?, ?)',
      [trainer_id, req.params.id]
    );

    res.json({ message: 'Trainer assigned successfully' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/training_programs/:id/trainers/:trainerId', verifyToken, async (req, res) => {
  try {
    const [existingProgram] = await pool.query('SELECT id FROM training_programs WHERE id = ?', [req.params.id]);
    if (existingProgram.length === 0) return res.status(404).json({ error: 'Training program not found' });

    const [existingTrainer] = await pool.query('SELECT id FROM trainers WHERE id = ?', [req.params.trainerId]);
    if (existingTrainer.length === 0) return res.status(404).json({ error: 'Trainer not found' });

    const [existingAssignment] = await pool.query(
      'SELECT id FROM program_trainers WHERE training_program_id = ? AND trainer_id = ?',
      [req.params.id, req.params.trainerId]
    );
    if (existingAssignment.length === 0) return res.status(404).json({ error: 'Trainer not assigned to this program' });

    await pool.query(
      'DELETE FROM program_trainers WHERE training_program_id = ? AND trainer_id = ?',
      [req.params.id, req.params.trainerId]
    );

    res.json({ message: 'Trainer removed successfully' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/internship_applications', verifyToken, async (req, res) => {
  try {
    const [results] = await pool.query(
      'SELECT id, user_id, internship_id, education_level, cv, certificate, status, created_at FROM internship_applications'
    );
    res.json(results);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/internship_applications/:id', verifyToken, async (req, res) => {
  try {
    const [results] = await pool.query(
      'SELECT id, user_id, internship_id, education_level, cv, certificate, status, created_at FROM internship_applications WHERE id = ?',
      [req.params.id]
    );
    if (results.length === 0) return res.status(404).json({ error: 'Internship application not found' });

    res.json(results[0]);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/internship_applications', verifyToken, async (req, res) => {
  const { internship_id, status } = req.body;

  if (!internship_id) {
    return res.status(400).json({ error: 'Internship ID is required' });
  }

  try {
    const [existingUser] = await pool.query('SELECT id, level_of_education, cv, certificate FROM users WHERE id = ?', [req.userId]);
    if (existingUser.length === 0) return res.status(404).json({ error: 'User not found' });

    const [existingInternship] = await pool.query('SELECT id FROM internships WHERE id = ?', [internship_id]);
    if (existingInternship.length === 0) return res.status(404).json({ error: 'Internship not found' });

    const [existingApplication] = await pool.query(
      'SELECT id FROM internship_applications WHERE user_id = ? AND internship_id = ?',
      [req.userId, internship_id]
    );
    if (existingApplication.length > 0) return res.status(400).json({ error: 'User has already applied to this internship' });

    const [result] = await pool.query(
      `INSERT INTO internship_applications (user_id, internship_id, education_level, cv, certificate, status, created_at)
       VALUES (?, ?, ?, ?, ?, ?, NOW())`,
      [
        req.userId,
        internship_id,
        existingUser[0].level_of_education,
        existingUser[0].cv,
        existingUser[0].certificate,
        status || 'pending'
      ]
    );

    res.json({ message: 'Internship application created successfully', applicationId: result.insertId });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/internship_applications/:id', verifyToken, async (req, res) => {
  const { education_level, status } = req.body;

  if (!education_level || !status) {
    return res.status(400).json({ error: 'Education level and status are required' });
  }

  try {
    const [existingApplication] = await pool.query('SELECT user_id FROM internship_applications WHERE id = ?', [req.params.id]);
    if (existingApplication.length === 0) return res.status(404).json({ error: 'Internship application not found' });

    await pool.query(
      `UPDATE internship_applications SET education_level = ?, status = ? WHERE id = ?`,
      [education_level, status, req.params.id]
    );

    res.json({ message: 'Internship application updated successfully' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/internship_applications/:id', verifyToken, async (req, res) => {
  try {
    const [existingApplication] = await pool.query('SELECT user_id FROM internship_applications WHERE id = ?', [req.params.id]);
    if (existingApplication.length === 0) return res.status(404).json({ error: 'Internship application not found' });

    await pool.query('DELETE FROM internship_applications WHERE id = ?', [req.params.id]);

    res.json({ message: 'Internship application deleted successfully' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/users/:id/internship_applications', verifyToken, async (req, res) => {
  try {
    const [existingUser] = await pool.query('SELECT id FROM users WHERE id = ?', [req.params.id]);
    if (existingUser.length === 0) return res.status(404).json({ error: 'User not found' });

    const [results] = await pool.query(
      'SELECT id, user_id, internship_id, education_level, cv, certificate, status, created_at FROM internship_applications WHERE user_id = ?',
      [req.params.id]
    );

    res.json(results);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/program_applications', verifyToken, async (req, res) => {
  try {
    const [results] = await pool.query(
      'SELECT id, user_id, training_program_id, education_level, profile_picture, cv, certificate, status, created_at FROM program_applications'
    );
    res.json(results);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/program_applications/:id', verifyToken, async (req, res) => {
  try {
    const [results] = await pool.query(
      'SELECT id, user_id, training_program_id, education_level, profile_picture, cv, certificate, status, created_at FROM program_applications WHERE id = ?',
      [req.params.id]
    );
    if (results.length === 0) return res.status(404).json({ error: 'Training program application not found' });

    res.json(results[0]);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/program_applications', verifyToken, async (req, res) => {
  const { training_program_id, status } = req.body;

  if (!training_program_id) {
    return res.status(400).json({ error: 'Training program ID is required' });
  }

  try {
    const [existingUser] = await pool.query('SELECT id, level_of_education, profile_picture, cv, certificate FROM users WHERE id = ?', [req.userId]);
    if (existingUser.length === 0) return res.status(404).json({ error: 'User not found' });

    const [existingProgram] = await pool.query('SELECT id FROM training_programs WHERE id = ?', [training_program_id]);
    if (existingProgram.length === 0) return res.status(404).json({ error: 'Training program not found' });

    const [existingApplication] = await pool.query(
      'SELECT id FROM program_applications WHERE user_id = ? AND training_program_id = ?',
      [req.userId, training_program_id]
    );
    if (existingApplication.length > 0) return res.status(400).json({ error: 'User has already applied to this training program' });

    const [result] = await pool.query(
      `INSERT INTO program_applications (user_id, training_program_id, education_level, profile_picture, cv, certificate, status, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, NOW())`,
      [
        req.userId,
        training_program_id,
        existingUser[0].level_of_education,
        existingUser[0].profile_picture,
        existingUser[0].cv,
        existingUser[0].certificate,
        status || 'pending'
      ]
    );

    res.json({ message: 'Training program application created successfully', applicationId: result.insertId });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/program_applications/:id', verifyToken, async (req, res) => {
  const { education_level, status } = req.body;

  if (!education_level || !status) {
    return res.status(400).json({ error: 'Education level and status are required' });
  }

  try {
    const [existingApplication] = await pool.query('SELECT user_id FROM program_applications WHERE id = ?', [req.params.id]);
    if (existingApplication.length === 0) return res.status(404).json({ error: 'Training program application not found' });

    await pool.query(
      `UPDATE program_applications SET education_level = ?, status = ? WHERE id = ?`,
      [education_level, status, req.params.id]
    );

    res.json({ message: 'Training program application updated successfully' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/program_applications/:id', verifyToken, async (req, res) => {
  try {
    const [existingApplication] = await pool.query('SELECT user_id FROM program_applications WHERE id = ?', [req.params.id]);
    if (existingApplication.length === 0) return res.status(404).json({ error: 'Training program application not found' });

    await pool.query('DELETE FROM program_applications WHERE id = ?', [req.params.id]);

    res.json({ message: 'Training program application deleted successfully' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/users/:id/program_applications', verifyToken, async (req, res) => {
  try {
    const [existingUser] = await pool.query('SELECT id FROM users WHERE id = ?', [req.params.id]);
    if (existingUser.length === 0) return res.status(404).json({ error: 'User not found' });

    const [results] = await pool.query(
      'SELECT id, user_id, training_program_id, education_level, profile_picture, cv, certificate, status, created_at FROM program_applications WHERE user_id = ?',
      [req.params.id]
    );

    res.json(results);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/interests', verifyToken, async (req, res) => {
  try {
    const [results] = await pool.query('SELECT id, name, created_at FROM interests');
    res.json(results);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/companies/:id/internship_applications', verifyToken, async (req, res) => {
  const companyId = req.params.id;

  try {
    const [existingCompany] = await pool.query('SELECT id FROM companies WHERE id = ?', [companyId]);
    if (existingCompany.length === 0) {
      return res.status(404).json({ error: 'الشركة غير موجودة' });
    }

    if (req.companyId !== parseInt(companyId) && !req.isAdmin) {
      return res.status(403).json({ error: 'غير مصرح لك برؤية طلبات هذه الشركة' });
    }

    const [applications] = await pool.query(
      `
      SELECT 
        ia.id AS application_id,
        ia.education_level,
        ia.cv,
        ia.certificate,
        ia.status,
        ia.created_at AS application_date,
        i.id AS internship_id,
        i.title AS internship_title,
        u.id AS user_id,
        u.first_name,
        u.last_name,
        u.email,
        u.phone
      FROM internship_applications ia
      INNER JOIN internships i ON ia.internship_id = i.id
      INNER JOIN users u ON ia.user_id = u.id
      WHERE i.company_id = ?
      ORDER BY ia.created_at DESC
      `,
      [companyId]
    );

    if (applications.length === 0) {
      return res.status(200).json({ message: 'لا توجد طلبات تدريب داخلي لهذه الشركة', applications: [] });
    }

    res.json({
      message: 'تم استرجاع طلبات التدريب الداخلي بنجاح',
      applications
    });
  } catch (error) {
    console.error('خطأ في استرجاع طلبات التدريب الداخلي:', {
      companyId,
      error: error.message
    });
    res.status(500).json({ error: 'خطأ في الخادم' });
  }
});

app.get('/training_centers/:id/program_applications', verifyToken, async (req, res) => {
  const centerId = req.params.id;

  try {
    const [existingCenter] = await pool.query('SELECT id FROM training_centers WHERE id = ?', [centerId]);
    if (existingCenter.length === 0) {
      return res.status(404).json({ error: 'مركز التدريب غير موجود' });
    }

    if (req.centerId !== parseInt(centerId) && !req.isAdmin) {
      return res.status(403).json({ error: 'غير مصرح لك برؤية طلبات هذا المركز' });
    }

    const [applications] = await pool.query(
      `
      SELECT 
        pa.id AS application_id,
        pa.education_level,
        pa.profile_picture,
        pa.cv,
        pa.certificate,
        pa.status,
        pa.created_at AS application_date,
        tp.id AS program_id,
        tp.title AS program_title,
        u.id AS user_id,
        u.first_name,
        u.last_name,
        u.email,
        u.phone
      FROM program_applications pa
      INNER JOIN training_programs tp ON pa.training_program_id = tp.id
      INNER JOIN users u ON pa.user_id = u.id
      WHERE tp.center_id = ?
      ORDER BY pa.created_at DESC
      `,
      [centerId]
    );

    if (applications.length === 0) {
      return res.status(200).json({ message: 'لا توجد طلبات برامج تدريبية لهذا المركز', applications: [] });
    }

    res.json({
      message: 'تم استرجاع طلبات البرامج التدريبية بنجاح',
      applications
    });
  } catch (error) {
    console.error('خطأ في استرجاع طلبات البرامج التدريبية:', {
      centerId,
      error: error.message
    });
    res.status(500).json({ error: 'خطأ في الخادم' });
  }
});

app.listen(3000, () => console.log('Server running on port 3000'));