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
app.use(bodyParser.json());
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
export async function get_training_centers_name(){
    const [rows] = await pool.query(`
        SELECT name
        FROM training_centers
        `);
    return rows
}
export async function get_companies_name(){
    const [rows] = await pool.query(`
        SELECT name
        FROM companies
        `);
    return rows
}
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
    let user = null;
    let entity_type = '';
    const [users] = await pool.query(
      'SELECT id, first_name, last_name, email, password, phone, street, user_type, level_of_education, profile_picture, cv, certificate, receive_notifications, notification_type, wilaya, commune, skills, interserte FROM users WHERE email = ?',
      [email]
    );
    const [companies] = await pool.query(
      'SELECT id, name, email, password, phone, domain, size, website, wilaya, commune, numero_commerce, street, location, logo FROM companies WHERE email = ?',
      [email]
    );
    const [training_centers] = await pool.query(
      'SELECT id, name, email, password, phone, street, numero_commerce, type, wilaya, commune, speciality, website, facebook, instagram, X, linkedin, logo FROM training_centers WHERE email = ?',
      [email]
    );
    const [trainers] = await pool.query(
      'SELECT id, first_name, last_name, email, password, date_of_birth, gender, wilaya, commune, street, education_level, interests, other_skill, profile_picture, certificated, cv, phone, specialty FROM trainers WHERE email = ?',
      [email]
    );
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
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, entity_type }, process.env.ACCESS_TOKEN_SECRET);
    const userData = {
      id: user.id,
      email: user.email,
      name: entity_type === 'users' || entity_type === 'trainers' ? `${user.first_name} ${user.last_name}` : user.name,
      entity_type,
      phone: user.phone || '/',
      street: user.street || '/',
      profile_picture: user.profile_picture || user.logo || '/',
      ...(entity_type === 'users' && {
        user_type: user.user_type || '/',
        level_of_education: user.level_of_education || '/',
        cv: user.cv || '/',
        certificate: user.certificate || '/',
        receive_notifications: Boolean(user.receive_notifications),
        notification_type: user.notification_type || '/',
        wilaya: user.wilaya || '/',
        commune: user.commune || '/',
        skills: user.skills || '/',
        interserte: user.interserte || '/'
      }),
      ...(entity_type === 'companies' && {
        domain: user.domain || '/',
        size: user.size || '/',
        website: user.website || '/',
        wilaya: user.wilaya || '/',
        commune: user.commune || '/',
        numero_commerce: user.numero_commerce || '/',
        location: user.location || '/',
        logo: user.logo || '/'
      }),
      ...(entity_type === 'training_centers' && {
        numero_commerce: user.numero_commerce || '/',
        type: user.type || '/',
        wilaya: user.wilaya || '/',
        commune: user.commune || '/',
        speciality: user.speciality || '/',
        website: user.website || '/',
        facebook: user.facebook || '/',
        instagram: user.instagram || '/',
        X: user.X || '/',
        linkedin: user.linkedin || '/',
        logo: user.logo || '/'
      }),
      ...(entity_type === 'trainers' && {
        date_of_birth: user.date_of_birth ? user.date_of_birth.toISOString().split('T')[0] : '/',
        gender: user.gender || '/',
        wilaya: user.wilaya || '/',
        commune: user.commune || '/',
        street: user.street || '/',
        education_level: user.education_level || '/',
        interests: user.interests || '/',
        other_skill: user.other_skill || '/',
        certificated: user.certificated || '/',
        cv: user.cv || '/',
        specialty: user.specialty || '/'
      })
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
    let user = null;
    let entity_type = '';
    const [users] = await pool.query(
      'SELECT id, first_name, last_name, phone, password, email, street, user_type, level_of_education, profile_picture, cv, certificate, receive_notifications, notification_type, wilaya, commune, skills, interserte FROM users WHERE phone = ?',
      [phone]
    );
    const [companies] = await pool.query(
      'SELECT id, name, phone, password, email, domain, size, website, wilaya, commune, numero_commerce, street, location, logo FROM companies WHERE phone = ?',
      [phone]
    );
    const [training_centers] = await pool.query(
      'SELECT id, name, phone, password, email, street, numero_commerce, type, wilaya, commune, speciality, website, facebook, instagram, X, linkedin, logo FROM training_centers WHERE phone = ?',
      [phone]
    );
    const [trainers] = await pool.query(
      'SELECT id, first_name, last_name, phone, password, email, date_of_birth, gender, wilaya, commune, street, education_level, interests, other_skill, profile_picture, certificated, cv, specialty FROM trainers WHERE phone = ?',
      [phone]
    );
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
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, entity_type }, process.env.ACCESS_TOKEN_SECRET);
    const userData = {
      id: user.id,
      phone: user.phone,
      name: entity_type === 'users' || entity_type === 'trainers' ? `${user.first_name} ${user.last_name}` : user.name,
      entity_type,
      email: user.email || '/',
      street: user.street || '/',
      profile_picture: user.profile_picture || user.logo || '/',
      ...(entity_type === 'users' && {
        user_type: user.user_type || '/',
        level_of_education: user.level_of_education || '/',
        cv: user.cv || '/',
        certificate: user.certificate || '/',
        receive_notifications: Boolean(user.receive_notifications),
        notification_type: user.notification_type || '/',
        wilaya: user.wilaya || '/',
        commune: user.commune || '/',
        skills: user.skills || '/',
        interserte: user.interserte || '/'
      }),
      ...(entity_type === 'companies' && {
        domain: user.domain || '/',
        size: user.size || '/',
        website: user.website || '/',
        wilaya: user.wilaya || '/',
        commune: user.commune || '/',
        numero_commerce: user.numero_commerce || '/',
        location: user.location || '/',
        logo: user.logo || '/'
      }),
      ...(entity_type === 'training_centers' && {
        numero_commerce: user.numero_commerce || '/',
        type: user.type || '/',
        wilaya: user.wilaya || '/',
        commune: user.commune || '/',
        speciality: user.speciality || '/',
        website: user.website || '/',
        facebook: user.facebook || '/',
        instagram: user.instagram || '/',
        X: user.X || '/',
        linkedin: user.linkedin || '/',
        logo: user.logo || '/'
      }),
      ...(entity_type === 'trainers' && {
        date_of_birth: user.date_of_birth ? user.date_of_birth.toISOString().split('T')[0] : '/',
        gender: user.gender || '/',
        wilaya: user.wilaya || '/',
        commune: user.commune || '/',
        street: user.street || '/',
        education_level: user.education_level || '/',
        interests: user.interests || '/',
        other_skill: user.other_skill || '/',
        certificated: user.certificated || '/',
        cv: user.cv || '/',
        specialty: user.specialty || '/'
      })
    };
    res.json({ token, user: userData });
  } catch (err) {
    console.error('Error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});
app.post(
  '/signupuser',
  upload.fields([
    { name: 'profile_picture', maxCount: 1 },
    { name: 'cv', maxCount: 1 },
    { name: 'certificate', maxCount: 1 },
  ]),
  async (req, res) => {
    const {
      first_name = '/',
      last_name = '/',
      email = '/',
      password = '/',
      phone = '/',
      street = '/',
      user_type = '/',
      level_of_education = '/',
      receive_notifications = false,
      notification_type = '/',
      wilaya = '/',
      commune = '/',
      skills = '/',
      interserte = '/'
    } = req.body;
    const files = req.files;
    try {
      const hashedPassword = password !== '/' ? await bcrypt.hash(password, 10) : '/';
      const [existingUser] = await pool.query('SELECT id FROM users WHERE email = ? AND email != ?', [email, '/']);
      if (existingUser.length > 0) {
        return res.status(400).json({ error: 'Email already exists' });
      }
      const profilePicturePath = files.profile_picture ? files.profile_picture[0].path : '/';
      const cvPath = files.cv ? files.cv[0].path : '/';
      const certificatePath = files.certificate ? files.certificate[0].path : '/';
      const [result] = await pool.query(
        `INSERT INTO users 
        (first_name, last_name, email, password, phone, street, user_type, level_of_education, 
         profile_picture, cv, certificate, receive_notifications, notification_type, wilaya, commune, skills, interserte, created_at) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
        [
          first_name,
          last_name,
          email,
          hashedPassword,
          phone,
          street,
          user_type,
          level_of_education,
          profilePicturePath,
          cvPath,
          certificatePath,
          receive_notifications === 'true' || receive_notifications === true ? 1 : 0,
          notification_type,
          wilaya,
          commune,
          skills,
          interserte,
        ]
      );
      res.json({ message: 'User registered successfully', userId: result.insertId });
    } catch (error) {
      console.error('Error:', error);
      res.status(500).json({ error: 'Server error' });
    }
  }
);
app.post(
  '/signuptrainers',
  upload.fields([
    { name: 'cv', maxCount: 1 },
    { name: 'certificated', maxCount: 1 },
    { name: 'profile_picture', maxCount: 1 },
  ]),
  async (req, res) => {
    const {
      first_name = '/',
      last_name = '/',
      email = '/',
      password = '/',
      date_of_birth = '/',
      gender = '/',
      wilaya = '/',
      commune = '/',
      street = '/',
      education_level = '/',
      interests = '/',
      other_skill = '/',
      phone = '/',
      specialty = '/'
    } = req.body;
    const files = req.files;
    try {
      const hashedPassword = password !== '/' ? await bcrypt.hash(password, 10) : '/';
      const [existingTrainer] = await pool.query('SELECT id FROM trainers WHERE email = ? AND email != ?', [email, '/']);
      if (existingTrainer.length > 0) {
        return res.status(400).json({ error: 'Email already exists' });
      }
      const cvPath = files.cv ? files.cv[0].path : '/';
      const certificatedPath = files.certificated ? files.certificated[0].path : '/';
      const profilePicturePath = files.profile_picture ? files.profile_picture[0].path : '/';
      const [result] = await pool.query(
        `INSERT INTO trainers 
        (first_name, last_name, email, password, date_of_birth, gender, wilaya, commune, street, 
         education_level, interests, other_skill, profile_picture, certificated, cv, phone, specialty, created_at) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
        [
          first_name,
          last_name,
          email,
          hashedPassword,
          date_of_birth,
          gender,
          wilaya,
          commune,
          street,
          education_level,
          interests,
          other_skill,
          profilePicturePath,
          certificatedPath,
          cvPath,
          phone,
          specialty,
        ]
      );
      res.json({ message: 'Trainer registered successfully', trainerId: result.insertId });
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
      name = '/',
      email = '/',
      password = '/',
      phone = '/',
      street = '/',
      numero_commerce = '/',
      type = '/',
      wilaya = '/',
      commune = '/',
      speciality = '/',
      website = '/',
      facebook = '/',
      instagram = '/',
      X = '/',
      linkedin = '/'
    } = req.body;
    const file = req.file;
    try {
      const hashedPassword = password !== '/' ? await bcrypt.hash(password, 10) : '/';
      const [existingCenter] = await pool.query('SELECT id FROM training_centers WHERE email = ? AND email != ?', [email, '/']);
      if (existingCenter.length > 0) {
        return res.status(400).json({ error: 'Email already exists' });
      }
      const logoPath = file ? file.path : '/';
      const [result] = await pool.query(
        `INSERT INTO training_centers 
        (name, email, password, phone, street, numero_commerce, type, wilaya, commune, speciality, 
         website, facebook, instagram, X, linkedin, logo, created_at) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
        [
          name,
          email,
          hashedPassword,
          phone,
          street,
          numero_commerce,
          type,
          wilaya,
          commune,
          speciality,
          website,
          facebook,
          instagram,
          X,
          linkedin,
          logoPath,
        ]
      );
      res.json({ message: 'Training center registered successfully', centerId: result.insertId });
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
      name = '/',
      email = '/',
      password = '/',
      phone = '/',
      domain = '/',
      size = '/',
      website = '/',
      wilaya = '/',
      commune = '/',
      numero_commerce = '/',
      street = '/',
      location = '/'
    } = req.body;
    const file = req.file;
    try {
      const hashedPassword = password !== '/' ? await bcrypt.hash(password, 10) : '/';
      const [existingCompany] = await pool.query('SELECT id FROM companies WHERE email = ? AND email != ?', [email, '/']);
      if (existingCompany.length > 0) {
        return res.status(400).json({ error: 'Email already exists' });
      }
      const logoPath = file ? file.path : '/';
      const [result] = await pool.query(
        `INSERT INTO companies 
        (name, email, password, phone, domain, size, website, wilaya, commune, numero_commerce, street, location, logo, created_at) 
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
          commune,
          numero_commerce,
          street,
          location,
          logoPath,
        ]
      );
      res.json({ message: 'Company registered successfully', companyId: result.insertId });
    } catch (error) {
      console.error('Error:', error);
      res.status(500).json({ error: 'Server error' });
    }
  }
);
app.get('/users/:id', verifyToken, async (req, res) => {
  try {
    const [results] = await pool.query(
      'SELECT id, first_name, last_name, email, phone, street, user_type, level_of_education, profile_picture, cv, certificate, receive_notifications, notification_type, wilaya, commune, skills, interserte, created_at FROM users WHERE id = ?',
      [req.params.id]
    );
    if (results.length === 0) return res.status(404).json({ error: 'User not found' });
    const user = results[0];
    res.json({
      id: user.id,
      first_name: user.first_name || '/',
      last_name: user.last_name || '/',
      email: user.email || '/',
      phone: user.phone || '/',
      street: user.street || '/',
      user_type: user.user_type || '/',
      level_of_education: user.level_of_education || '/',
      profile_picture: user.profile_picture || '/',
      cv: user.cv || '/',
      certificate: user.certificate || '/',
      receive_notifications: Boolean(user.receive_notifications),
      notification_type: user.notification_type || '/',
      wilaya: user.wilaya || '/',
      commune: user.commune || '/',
      skills: user.skills || '/',
      interserte: user.interserte || '/',
      created_at: user.created_at.toISOString()
    });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});
app.put(
  '/users/:id',
  verifyToken,
  upload.fields([
    { name: 'profile_picture', maxCount: 1 },
    { name: 'cv', maxCount: 1 },
    { name: 'certificate', maxCount: 1 },
  ]),
  async (req, res) => {
    const {
      first_name = '/',
      last_name = '/',
      email = '/',
      password = '/',
      phone = '/',
      street = '/',
      user_type = '/',
      level_of_education = '/',
      receive_notifications = false,
      notification_type = '/',
      wilaya = '/',
      commune = '/',
      skills = '/',
      interserte = '/'
    } = req.body;
    const files = req.files;
    try {
      const [existingUser] = await pool.query(
        'SELECT id, password, profile_picture, cv, certificate FROM users WHERE id = ?',
        [req.params.id]
      );
      if (existingUser.length === 0) return res.status(404).json({ error: 'User not found' });
      const [emailCheck] = await pool.query(
        'SELECT id FROM users WHERE email = ? AND id != ? AND email != ?',
        [email, req.params.id, '/']
      );
      if (emailCheck.length > 0) return res.status(400).json({ error: 'Email already exists' });
      const updateData = {
        first_name,
        last_name,
        email,
        phone,
        street,
        user_type,
        level_of_education,
        receive_notifications: receive_notifications === 'true' || receive_notifications === true ? 1 : 0,
        notification_type,
        wilaya,
        commune,
        skills,
        interserte,
        profile_picture: files.profile_picture ? files.profile_picture[0].path : existingUser[0].profile_picture || '/',
        cv: files.cv ? files.cv[0].path : existingUser[0].cv || '/',
        certificate: files.certificate ? files.certificate[0].path : existingUser[0].certificate || '/'
      };
      updateData.password = password !== '/' ? await bcrypt.hash(password, 10) : existingUser[0].password;
      await pool.query(
        `UPDATE users SET 
        first_name = ?, last_name = ?, email = ?, password = ?, phone = ?, street = ?, 
        user_type = ?, level_of_education = ?, profile_picture = ?, cv = ?, certificate = ?, 
        receive_notifications = ?, notification_type = ?, wilaya = ?, commune = ?, skills = ?, interserte = ?
        WHERE id = ?`,
        [
          updateData.first_name,
          updateData.last_name,
          updateData.email,
          updateData.password,
          updateData.phone,
          updateData.street,
          updateData.user_type,
          updateData.level_of_education,
          updateData.profile_picture,
          updateData.cv,
          updateData.certificate,
          updateData.receive_notifications,
          updateData.notification_type,
          updateData.wilaya,
          updateData.commune,
          updateData.skills,
          updateData.interserte,
          req.params.id
        ]
      );
      res.json({ message: 'User updated successfully' });
    } catch (error) {
      console.error('Error:', error);
      res.status(500).json({ error: 'Server error' });
    }
  }
);
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
app.post('/logout', verifyToken, async (req, res) => {
  const token = req.headers.authorization;
  try {
    await pool.query(
      'INSERT INTO tokens (token, type, user_id) VALUES (?, ?, ?)',
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
      'SELECT id, name, email, domain, size, website, wilaya, commune, numero_commerce, phone, street, location, logo, created_at FROM companies'
    );
    res.json(results.map(row => ({
      id: row.id,
      name: row.name || '/',
      email: row.email || '/',
      domain: row.domain || '/',
      size: row.size || '/',
      website: row.website || '/',
      wilaya: row.wilaya || '/',
      commune: row.commune || '/',
      numero_commerce: row.numero_commerce || '/',
      phone: row.phone || '/',
      street: row.street || '/',
      location: row.location || '/',
      logo: row.logo || '/',
      created_at: row.created_at.toISOString()
    })));
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});
app.get('/companies/:id', verifyToken, async (req, res) => {
  try {
    const [results] = await pool.query(
      'SELECT id, name, email, domain, size, website, wilaya, commune, numero_commerce, phone, street, location, logo, created_at FROM companies WHERE id = ?',
      [req.params.id]
    );
    if (results.length === 0) return res.status(404).json({ error: 'Company not found' });
    const company = results[0];
    res.json({
      id: company.id,
      name: company.name || '/',
      email: company.email || '/',
      domain: company.domain || '/',
      size: company.size || '/',
      website: company.website || '/',
      wilaya: company.wilaya || '/',
      commune: company.commune || '/',
      numero_commerce: company.numero_commerce || '/',
      phone: company.phone || '/',
      street: company.street || '/',
      location: company.location || '/',
      logo: company.logo || '/',
      created_at: company.created_at.toISOString()
    });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});
app.put(
  '/companies/:id',
  verifyToken,
  upload.single('logo'),
  async (req, res) => {
    const {
      name = '/',
      email = '/',
      password = '/',
      domain = '/',
      size = '/',
      website = '/',
      wilaya = '/',
      commune = '/',
      numero_commerce = '/',
      phone = '/',
      street = '/',
      location = '/'
    } = req.body;
    const file = req.file;
    try {
      const [existingCompany] = await pool.query('SELECT id, password, logo FROM companies WHERE id = ?', [req.params.id]);
      if (existingCompany.length === 0) return res.status(404).json({ error: 'Company not found' });
      const [emailCheck] = await pool.query('SELECT id FROM companies WHERE email = ? AND id != ? AND email != ?', [email, req.params.id, '/']);
      if (emailCheck.length > 0) return res.status(400).json({ error: 'Email already exists' });
      const updateData = {
        name,
        email,
        domain,
        size,
        website,
        wilaya,
        commune,
        numero_commerce,
        phone,
        street,
        location,
        logo: file ? file.path : existingCompany[0].logo || '/'
      };
      updateData.password = password !== '/' ? await bcrypt.hash(password, 10) : existingCompany[0].password;
      await pool.query(
        `UPDATE companies SET 
        name = ?, email = ?, password = ?, domain = ?, size = ?, website = ?, 
        wilaya = ?, commune = ?, numero_commerce = ?, phone = ?, street = ?, location = ?, logo = ?
        WHERE id = ?`,
        [
          updateData.name,
          updateData.email,
          updateData.password,
          updateData.domain,
          updateData.size,
          updateData.website,
          updateData.wilaya,
          updateData.commune,
          updateData.numero_commerce,
          updateData.phone,
          updateData.street,
          updateData.location,
          updateData.logo,
          req.params.id
        ]
      );
      res.json({ message: 'Company updated successfully' });
    } catch (error) {
      console.error('Error:', error);
      res.status(500).json({ error: 'Server error' });
    }
  }
);
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
      'SELECT id, name, email, phone, street, numero_commerce, type, wilaya, commune, speciality, website, facebook, instagram, X, linkedin, logo, created_at FROM training_centers'
    );
    res.json(results.map(row => ({
      id: row.id,
      name: row.name || '/',
      email: row.email || '/',
      phone: row.phone || '/',
      street: row.street || '/',
      numero_commerce: row.numero_commerce || '/',
      type: row.type || '/',
      wilaya: row.wilaya || '/',
      commune: row.commune || '/',
      speciality: row.speciality || '/',
      website: row.website || '/',
      facebook: row.facebook || '/',
      instagram: row.instagram || '/',
      X: row.X || '/',
      linkedin: row.linkedin || '/',
      logo: row.logo || '/',
      created_at: row.created_at.toISOString()
    })));
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});
app.get('/training_centers/:id', verifyToken, async (req, res) => {
  try {
    const [results] = await pool.query(
      'SELECT id, name, email, phone, street, numero_commerce, type, wilaya, commune, speciality, website, facebook, instagram, X, linkedin, logo, created_at FROM training_centers WHERE id = ?',
      [req.params.id]
    );
    if (results.length === 0) return res.status(404).json({ error: 'Training center not found' });
    const center = results[0];
    res.json({
      id: center.id,
      name: center.name || '/',
      email: center.email || '/',
      phone: center.phone || '/',
      street: center.street || '/',
      numero_commerce: center.numero_commerce || '/',
      type: center.type || '/',
      wilaya: center.wilaya || '/',
      commune: center.commune || '/',
      speciality: center.speciality || '/',
      website: center.website || '/',
      facebook: center.facebook || '/',
      instagram: center.instagram || '/',
      X: center.X || '/',
      linkedin: center.linkedin || '/',
      logo: center.logo || '/',
      created_at: center.created_at.toISOString()
    });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});
app.put(
  '/training_centers/:id',
  verifyToken,
  upload.single('logo'),
  async (req, res) => {
    const {
      name = '/',
      email = '/',
      password = '/',
      phone = '/',
      street = '/',
      numero_commerce = '/',
      type = '/',
      wilaya = '/',
      commune = '/',
      speciality = '/',
      website = '/',
      facebook = '/',
      instagram = '/',
      X = '/',
      linkedin = '/'
    } = req.body;
    const file = req.file;
    try {
      const [existingCenter] = await pool.query('SELECT id, password, logo FROM training_centers WHERE id = ?', [req.params.id]);
      if (existingCenter.length === 0) return res.status(404).json({ error: 'Training center not found' });
      const [emailCheck] = await pool.query('SELECT id FROM training_centers WHERE email = ? AND id != ? AND email != ?', [email, req.params.id, '/']);
      if (emailCheck.length > 0) return res.status(400).json({ error: 'Email already exists' });
      const updateData = {
        name,
        email,
        phone,
        street,
        numero_commerce,
        type,
        wilaya,
        commune,
        speciality,
        website,
        facebook,
        instagram,
        X,
        linkedin,
        logo: file ? file.path : existingCenter[0].logo || '/'
      };
      updateData.password = password !== '/' ? await bcrypt.hash(password, 10) : existingCenter[0].password;
      await pool.query(
        `UPDATE training_centers SET 
        name = ?, email = ?, password = ?, phone = ?, street = ?, numero_commerce = ?, type = ?, 
        wilaya = ?, commune = ?, speciality = ?, website = ?, facebook = ?, instagram = ?, X = ?, linkedin = ?, logo = ?
        WHERE id = ?`,
        [
          updateData.name,
          updateData.email,
          updateData.password,
          updateData.phone,
          updateData.street,
          updateData.numero_commerce,
          updateData.type,
          updateData.wilaya,
          updateData.commune,
          updateData.speciality,
          updateData.website,
          updateData.facebook,
          updateData.instagram,
          updateData.X,
          updateData.linkedin,
          updateData.logo,
          req.params.id
        ]
      );
      res.json({ message: 'Training center updated successfully' });
    } catch (error) {
      console.error('Error:', error);
      res.status(500).json({ error: 'Server error' });
    }
  }
);
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
      'SELECT id, first_name, last_name, email, date_of_birth, gender, wilaya, commune, street, education_level, interests, other_skill, profile_picture, certificated, cv, phone, specialty, created_at FROM trainers'
    );
    res.json(results.map(row => ({
      id: row.id,
      first_name: row.first_name || '/',
      last_name: row.last_name || '/',
      email: row.email || '/',
      date_of_birth: row.date_of_birth ? row.date_of_birth.toISOString().split('T')[0] : '/',
      gender: row.gender || '/',
      wilaya: row.wilaya || '/',
      commune: row.commune || '/',
      street: row.street || '/',
      education_level: row.education_level || '/',
      interests: row.interests || '/',
      other_skill: row.other_skill || '/',
      profile_picture: row.profile_picture || '/',
      certificated: row.certificated || '/',
      cv: row.cv || '/',
      phone: row.phone || '/',
      specialty: row.specialty || '/',
      created_at: row.created_at.toISOString()
    })));
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});
app.get('/trainers/:id', verifyToken, async (req, res) => {
  try {
    const [results] = await pool.query(
      'SELECT id, first_name, last_name, email, date_of_birth, gender, wilaya, commune, street, education_level, interests, other_skill, profile_picture, certificated, cv, phone, specialty, created_at FROM trainers WHERE id = ?',
      [req.params.id]
    );
    if (results.length === 0) return res.status(404).json({ error: 'Trainer not found' });
    const trainer = results[0];
    res.json({
      id: trainer.id,
      first_name: trainer.first_name || '/',
      last_name: trainer.last_name || '/',
      email: trainer.email || '/',
      date_of_birth: trainer.date_of_birth ? trainer.date_of_birth.toISOString().split('T')[0] : '/',
      gender: trainer.gender || '/',
      wilaya: trainer.wilaya || '/',
      commune: trainer.commune || '/',
      street: trainer.street || '/',
      education_level: trainer.education_level || '/',
      interests: trainer.interests || '/',
      other_skill: trainer.other_skill || '/',
      profile_picture: trainer.profile_picture || '/',
      certificated: trainer.certificated || '/',
      cv: trainer.cv || '/',
      phone: trainer.phone || '/',
      specialty: trainer.specialty || '/',
      created_at: trainer.created_at.toISOString()
    });
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
      first_name = '/',
      last_name = '/',
      email = '/',
      password = '/',
      date_of_birth = '/',
      gender = '/',
      wilaya = '/',
      commune = '/',
      street = '/',
      education_level = '/',
      interests = '/',
      other_skill = '/',
      phone = '/',
      specialty = '/'
    } = req.body;
    const files = req.files;
    try {
      const [existingTrainer] = await pool.query(
        'SELECT id, password, profile_picture, cv, certificated FROM trainers WHERE id = ?',
        [req.params.id]
      );
      if (existingTrainer.length === 0) return res.status(404).json({ error: 'Trainer not found' });
      const [emailCheck] = await pool.query(
        'SELECT id FROM trainers WHERE email = ? AND id != ? AND email != ?',
        [email, req.params.id, '/']
      );
      if (emailCheck.length > 0) return res.status(400).json({ error: 'Email already exists' });
      const updateData = {
        first_name,
        last_name,
        email,
        date_of_birth,
        gender,
        wilaya,
        commune,
        street,
        education_level,
        interests,
        other_skill,
        phone,
        specialty,
        profile_picture: files.profile_picture ? files.profile_picture[0].path : existingTrainer[0].profile_picture || '/',
        cv: files.cv ? files.cv[0].path : existingTrainer[0].cv || '/',
        certificated: files.certificated ? files.certificated[0].path : existingTrainer[0].certificated || '/'
      };
      updateData.password = password !== '/' ? await bcrypt.hash(password, 10) : existingTrainer[0].password;
      await pool.query(
        `UPDATE trainers SET 
        first_name = ?, last_name = ?, email = ?, password = ?, date_of_birth = ?, gender = ?, 
        wilaya = ?, commune = ?, street = ?, education_level = ?, interests = ?, other_skill = ?, 
        profile_picture = ?, certificated = ?, cv = ?, phone = ?, specialty = ?
        WHERE id = ?`,
        [
          updateData.first_name,
          updateData.last_name,
          updateData.email,
          updateData.password,
          updateData.date_of_birth,
          updateData.gender,
          updateData.wilaya,
          updateData.commune,
          updateData.street,
          updateData.education_level,
          updateData.interests,
          updateData.other_skill,
          updateData.profile_picture,
          updateData.certificated,
          updateData.cv,
          updateData.phone,
          updateData.specialty,
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
      'SELECT id, company_id, title, description, category_id, requirement, domain, duration, location, start_date, end_date, image, created_at FROM internships'
    );
    res.json(results.map(row => ({
      id: row.id,
      company_id: row.company_id,
      title: row.title || '/',
      description: row.description || '/',
      category_id: row.category_id || null,
      requirement: row.requirement || '/',
      domain: row.domain || '/',
      duration: row.duration || '/',
      location: row.location || '/',
      start_date: row.start_date ? row.start_date.toISOString().split('T')[0] : '/',
      end_date: row.end_date ? row.end_date.toISOString().split('T')[0] : '/',
      image: row.image || '/',
      created_at: row.created_at.toISOString()
    })));
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});
app.get('/internships/:id', verifyToken, async (req, res) => {
  try {
    const [results] = await pool.query(
      'SELECT id, company_id, title, description, category_id, requirement, domain, duration, location, start_date, end_date, image, created_at FROM internships WHERE id = ?',
      [req.params.id]
    );
    if (results.length === 0) return res.status(404).json({ error: 'Internship not found' });
    const internship = results[0];
    res.json({
      id: internship.id,
      company_id: internship.company_id,
      title: internship.title || '/',
      description: internship.description || '/',
      category_id: internship.category_id || null,
      requirement: internship.requirement || '/',
      domain: internship.domain || '/',
      duration: internship.duration || '/',
      location: internship.location || '/',
      start_date: internship.start_date ? internship.start_date.toISOString().split('T')[0] : '/',
      end_date: internship.end_date ? internship.end_date.toISOString().split('T')[0] : '/',
      image: internship.image || '/',
      created_at: internship.created_at.toISOString()
    });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});
app.post(
  '/internships',
  verifyToken,
  upload.single('image'),
  async (req, res) => {
    const {
      title = '/',
      description = '/',
      category_id = null,
      requirement = '/',
      domain = '/',
      duration = '/',
      location = '/',
      start_date = '/',
      end_date = '/'
    } = req.body;
    const file = req.file;
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
        requirement,
        domain,
        duration,
        location,
        start_date,
        end_date,
        image: file ? file.path : '/'
      };
      const [result] = await pool.query(
        `INSERT INTO internships 
        (company_id, title, description, category_id, requirement, domain, duration, location, start_date, end_date, image, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
        [
          internshipData.company_id,
          internshipData.title,
          internshipData.description,
          internshipData.category_id,
          internshipData.requirement,
          internshipData.domain,
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
  }
);
app.put(
  '/internships/:id',
  verifyToken,
  upload.single('image'),
  async (req, res) => {
    const {
      title = '/',
      description = '/',
      category_id = null,
      requirement = '/',
      domain = '/',
      duration = '/',
      location = '/',
      start_date = '/',
      end_date = '/'
    } = req.body;
    const file = req.file;
    if (req.entity_type !== 'companies') {
      return res.status(403).json({ error: 'Only companies can update internships' });
    }
    try {
      const company_id = req.userId;
      const [existingInternship] = await pool.query('SELECT company_id, image FROM internships WHERE id = ?', [req.params.id]);
      if (existingInternship.length === 0) return res.status(404).json({ error: 'Internship not found' });
      if (existingInternship[0].company_id !== company_id) return res.status(403).json({ error: 'Not authorized to update this internship' });
      const updateData = {
        title,
        description,
        category_id,
        requirement,
        domain,
        duration,
        location,
        start_date,
        end_date,
        image: file ? file.path : existingInternship[0].image || '/'
      };
      await pool.query(
        `UPDATE internships SET 
        title = ?, description = ?, category_id = ?, requirement = ?, domain = ?, 
        duration = ?, location = ?, start_date = ?, end_date = ?, image = ?
        WHERE id = ?`,
        [
          updateData.title,
          updateData.description,
          updateData.category_id,
          updateData.requirement,
          updateData.domain,
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
  }
);
app.delete('/internships/:id', verifyToken, async (req, res) => {
  if (req.entity_type !== 'companies') {
    return res.status(403).json({ error: 'Only companies can delete internships' });
  }
  try {
    const company_id = req.userId;
    const [existingInternship] = await pool.query('SELECT company_id FROM internships WHERE id = ?', [req.params.id]);
    if (existingInternship.length === 0) return res.status(404).json({ error: 'Internship not found' });
    if (existingInternship[0].company_id !== company_id) return res.status(403).json({ error: 'Not authorized to delete this internship' });
    await pool.query('DELETE FROM internships WHERE id = ?', [req.params.id]);
    res.json({ message: 'Internship deleted successfully' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});
app.get('/companies/:id/internships', verifyToken, async (req, res) => {
  try {
    const companyId = req.params.id;
    const [existingCompany] = await pool.query('SELECT id FROM companies WHERE id = ?', [companyId]);
    if (existingCompany.length === 0) return res.status(404).json({ error: 'Company not found' });
    const [results] = await pool.query(
      'SELECT id, company_id, title, description, category_id, requirement, domain, duration, location, start_date, end_date, image, created_at FROM internships WHERE company_id = ?',
      [companyId]
    );
    res.json(results.map(row => ({
      id: row.id,
      company_id: row.company_id,
      title: row.title || '/',
      description: row.description || '/',
      category_id: row.category_id || null,
      requirement: row.requirement || '/',
      domain: row.domain || '/',
      duration: row.duration || '/',
      location: row.location || '/',
      start_date: row.start_date ? row.start_date.toISOString().split('T')[0] : '/',
      end_date: row.end_date ? row.end_date.toISOString().split('T')[0] : '/',
      image: row.image || '/',
      created_at: row.created_at.toISOString()
    })));
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});
app.get('/training_programs', verifyToken, async (req, res) => {
  try {
    const [results] = await pool.query(
      'SELECT id, center_id, title, description, category_id, type, domain, duration, location, start_date, end_date, image, created_at FROM training_programs'
    );
    res.json(results.map(row => ({
      id: row.id,
      center_id: row.center_id,
      title: row.title || '/',
      description: row.description || '/',
      category_id: row.category_id || null,
      type: row.type || '/',
      domain: row.domain || '/',
      duration: row.duration || '/',
      location: row.location || '/',
      start_date: row.start_date ? row.start_date.toISOString().split('T')[0] : '/',
      end_date: row.end_date ? row.end_date.toISOString().split('T')[0] : '/',
      image: row.image || '/',
      created_at: row.created_at.toISOString()
    })));
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});
app.get('/training_programs/:id', verifyToken, async (req, res) => {
  try {
    const [results] = await pool.query(
      'SELECT id, center_id, title, description, category_id, type, domain, duration, location, start_date, end_date, image, created_at FROM training_programs WHERE id = ?',
      [req.params.id]
    );
    if (results.length === 0) return res.status(404).json({ error: 'Training program not found' });
    const program = results[0];
    res.json({
      id: program.id,
      center_id: program.center_id,
      title: program.title || '/',
      description: program.description || '/',
      category_id: program.category_id || null,
      type: program.type || '/',
      domain: program.domain || '/',
      duration: program.duration || '/',
      location: program.location || '/',
      start_date: program.start_date ? program.start_date.toISOString().split('T')[0] : '/',
      end_date: program.end_date ? program.end_date.toISOString().split('T')[0] : '/',
      image: program.image || '/',
      created_at: program.created_at.toISOString()
    });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});
app.post(
  '/training_programs',
  verifyToken,
  upload.single('image'),
  async (req, res) => {
    const {
      title = '/',
      description = '/',
      category_id = null,
      type = '/',
      domain = '/',
      duration = '/',
      location = '/',
      start_date = '/',
      end_date = '/'
    } = req.body;
    const file = req.file;
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
        domain,
        duration,
        location,
        start_date,
        end_date,
        image: file ? file.path : '/'
      };
      const [result] = await pool.query(
        `INSERT INTO training_programs 
        (center_id, title, description, category_id, type, domain, duration, location, start_date, end_date, image, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
        [
          programData.center_id,
          programData.title,
          programData.description,
          programData.category_id,
          programData.type,
          programData.domain,
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
  }
);
app.put(
  '/training_programs/:id',
  verifyToken,
  upload.single('image'),
  async (req, res) => {
    const {
      title = '/',
      description = '/',
      category_id = null,
      type = '/',
      domain = '/',
      duration = '/',
      location = '/',
      start_date = '/',
      end_date = '/'
    } = req.body;
    const file = req.file;
    if (req.entity_type !== 'training_centers') {
      return res.status(403).json({ error: 'Only training centers can update training programs' });
    }
    try {
      const center_id = req.userId;
      const [existingProgram] = await pool.query('SELECT center_id, image FROM training_programs WHERE id = ?', [req.params.id]);
      if (existingProgram.length === 0) return res.status(404).json({ error: 'Training program not found' });
      if (existingProgram[0].center_id !== center_id) return res.status(403).json({ error: 'Not authorized to update this training program' });
      const updateData = {
        title,
        description,
        category_id,
        type,
        domain,
        duration,
        location,
        start_date,
        end_date,
        image: file ? file.path : existingProgram[0].image || '/'
      };
      await pool.query(
        `UPDATE training_programs SET 
        title = ?, description = ?, category_id = ?, type = ?, domain = ?, 
        duration = ?, location = ?, start_date = ?, end_date = ?, image = ?
        WHERE id = ?`,
        [
          updateData.title,
          updateData.description,
          updateData.category_id,
          updateData.type,
          updateData.domain,
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
  }
);
app.delete('/training_programs/:id', verifyToken, async (req, res) => {
  if (req.entity_type !== 'training_centers') {
    return res.status(403).json({ error: 'Only training centers can delete training programs' });
  }
  try {
    const center_id = req.userId;
    const [existingProgram] = await pool.query('SELECT center_id FROM training_programs WHERE id = ?', [req.params.id]);
    if (existingProgram.length === 0) return res.status(404).json({ error: 'Training program not found' });
    if (existingProgram[0].center_id !== center_id) return res.status(403).json({ error: 'Not authorized to delete this training program' });
    await pool.query('DELETE FROM training_programs WHERE id = ?', [req.params.id]);
    res.json({ message: 'Training program deleted successfully' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});
app.get('/training_centers/:id/training_programs', verifyToken, async (req, res) => {
  try {
    const centerId = req.params.id;
    const [existingCenter] = await pool.query('SELECT id FROM training_centers WHERE id = ?', [centerId]);
    if (existingCenter.length === 0) return res.status(404).json({ error: 'Training center not found' });
    const [results] = await pool.query(
      'SELECT id, center_id, title, description, category_id, type, domain, duration, location, start_date, end_date, image, created_at FROM training_programs WHERE center_id = ?',
      [centerId]
    );
    res.json(results.map(row => ({
      id: row.id,
      center_id: row.center_id,
      title: row.title || '/',
      description: row.description || '/',
      category_id: row.category_id || null,
      type: row.type || '/',
      domain: row.domain || '/',
      duration: row.duration || '/',
      location: row.location || '/',
      start_date: row.start_date ? row.start_date.toISOString().split('T')[0] : '/',
      end_date: row.end_date ? row.end_date.toISOString().split('T')[0] : '/',
      image: row.image || '/',
      created_at: row.created_at.toISOString()
    })));
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});
app.delete('/internship_applications/:id', verifyToken, async (req, res) => {
  try {
    const [existingApplication] = await pool.query('SELECT user_id, internship_id FROM internship_applications WHERE id = ?', [req.params.id]);
    if (existingApplication.length === 0) return res.status(404).json({ error: 'طلب التدريب الداخلي غير موجود' });

    const [internship] = await pool.query('SELECT company_id FROM internships WHERE id = ?', [existingApplication[0].internship_id]);
    if (internship.length === 0) return res.status(404).json({ error: 'التدريب الداخلي غير موجود' });

    if (req.entity_type === 'users' && req.userId !== existingApplication[0].user_id) {
      return res.status(403).json({ error: 'غير مصرح لك بحذف هذا الطلب' });
    }
    if (req.entity_type === 'companies' && req.userId !== internship[0].company_id) {
      return res.status(403).json({ error: 'غير مصرح لك بحذف طلبات هذا التدريب' });
    }
    if (req.entity_type !== 'users' && req.entity_type !== 'companies') {
      return res.status(403).json({ error: 'غير مصرح لك بحذف طلبات التدريب' });
    }

    await pool.query('DELETE FROM internship_applications WHERE id = ?', [req.params.id]);

    res.json({ message: 'تم حذف طلب التدريب الداخلي بنجاح' });
  } catch (error) {
    console.error('خطأ في حذف طلب التدريب الداخلي:', error);
    res.status(500).json({ error: 'خطأ في الخادم' });
  }
});
app.get('/users/:id/internship_applications', verifyToken, async (req, res) => {
  try {
    const userId = req.params.id;
    const [existingUser] = await pool.query('SELECT id FROM users WHERE id = ?', [userId]);
    if (existingUser.length === 0) return res.status(404).json({ error: 'المستخدم غير موجود' });

    if (req.entity_type === 'users' && req.userId !== parseInt(userId)) {
      return res.status(403).json({ error: 'غير مصرح لك برؤية طلبات هذا المستخدم' });
    }

    const [results] = await pool.query(
      `
      SELECT 
        ia.id AS application_id,
        ia.user_id,
        ia.internship_id,
        ia.education_level,
        ia.cv,
        ia.certificate,
        ia.status,
        ia.created_at AS application_date,
        i.title AS internship_title,
        c.name AS company_name
      FROM internship_applications ia
      INNER JOIN internships i ON ia.internship_id = i.id
      INNER JOIN companies c ON i.company_id = c.id
      WHERE ia.user_id = ?
      ORDER BY ia.created_at DESC
      `,
      [userId]
    );

    res.json(results.map(row => ({
      application_id: row.application_id,
      user_id: row.user_id,
      internship_id: row.internship_id,
      education_level: row.education_level || '/',
      cv: row.cv || '/',
      certificate: row.certificate || '/',
      status: row.status || 'pending',
      application_date: row.application_date.toISOString(),
      internship_title: row.internship_title || '/',
      company_name: row.company_name || '/'
    })));
  } catch (error) {
    console.error('خطأ في استرجاع طلبات التدريب الداخلي:', error);
    res.status(500).json({ error: 'خطأ في الخادم' });
  }
});
app.get('/program_applications', verifyToken, async (req, res) => {
  if (req.entity_type !== 'training_centers' && req.entity_type !== 'users') {
    return res.status(403).json({ error: 'غير مصرح لك برؤية جميع طلبات البرامج التدريبية' });
  }
  try {
    const [results] = await pool.query(
      `
      SELECT 
        pa.id AS application_id,
        pa.user_id,
        pa.training_program_id,
        pa.education_level,
        pa.profile_picture,
        pa.cv,
        pa.certificate,
        pa.status,
        pa.created_at AS application_date,
        tp.title AS program_title,
        tc.name AS center_name
      FROM program_applications pa
      INNER JOIN training_programs tp ON pa.training_program_id = tp.id
      INNER JOIN training_centers tc ON tp.center_id = tc.id
      ORDER BY pa.created_at DESC
      `
    );

    res.json(results.map(row => ({
      application_id: row.application_id,
      user_id: row.user_id,
      training_program_id: row.training_program_id,
      education_level: row.education_level || '/',
      profile_picture: row.profile_picture || '/',
      cv: row.cv || '/',
      certificate: row.certificate || '/',
      status: row.status || 'pending',
      application_date: row.application_date.toISOString(),
      program_title: row.program_title || '/',
      center_name: row.center_name || '/'
    })));
  } catch (error) {
    console.error('خطأ في استرجاع طلبات البرامج التدريبية:', error);
    res.status(500).json({ error: 'خطأ في الخادم' });
  }
});
app.get('/program_applications/:id', verifyToken, async (req, res) => {
  try {
    const [results] = await pool.query(
      `
      SELECT 
        pa.id AS application_id,
        pa.user_id,
        pa.training_program_id,
        pa.education_level,
        pa.profile_picture,
        pa.cv,
        pa.certificate,
        pa.status,
        pa.created_at AS application_date,
        tp.title AS program_title,
        tc.name AS center_name
      FROM program_applications pa
      INNER JOIN training_programs tp ON pa.training_program_id = tp.id
      INNER JOIN training_centers tc ON tp.center_id = tc.id
      WHERE pa.id = ?
      `,
      [req.params.id]
    );
    if (results.length === 0) return res.status(404).json({ error: 'طلب البرنامج التدريبي غير موجود' });

    const application = results[0];
    if (req.entity_type === 'users' && req.userId !== application.user_id) {
      return res.status(403).json({ error: 'غير مصرح لك برؤية هذا الطلب' });
    }
    if (req.entity_type === 'training_centers') {
      const [program] = await pool.query('SELECT center_id FROM training_programs WHERE id = ?', [application.training_program_id]);
      if (program.length === 0 || program[0].center_id !== req.userId) {
        return res.status(403).json({ error: 'غير مصرح لك برؤية طلبات هذا البرنامج' });
      }
    }

    res.json({
      application_id: application.application_id,
      user_id: application.user_id,
      training_program_id: application.training_program_id,
      education_level: application.education_level || '/',
      profile_picture: application.profile_picture || '/',
      cv: application.cv || '/',
      certificate: application.certificate || '/',
      status: application.status || 'pending',
      application_date: application.application_date.toISOString(),
      program_title: application.program_title || '/',
      center_name: application.center_name || '/'
    });
  } catch (error) {
    console.error('خطأ في استرجاع طلب البرنامج التدريبي:', error);
    res.status(500).json({ error: 'خطأ في الخادم' });
  }
});
app.post('/program_applications', verifyToken, async (req, res) => {
  const { training_program_id, status = 'pending' } = req.body;

  if (!training_program_id) {
    return res.status(400).json({ error: 'معرف البرنامج التدريبي مطلوب' });
  }
  if (req.entity_type !== 'users') {
    return res.status(403).json({ error: 'فقط المستخدمون يمكنهم التقديم للبرامج التدريبية' });
  }

  try {
    const [existingUser] = await pool.query('SELECT id, level_of_education, profile_picture, cv, certificate FROM users WHERE id = ?', [req.userId]);
    if (existingUser.length === 0) return res.status(404).json({ error: 'المستخدم غير موجود' });

    const [existingProgram] = await pool.query('SELECT id FROM training_programs WHERE id = ?', [training_program_id]);
    if (existingProgram.length === 0) return res.status(404).json({ error: 'البرنامج التدريبي غير موجود' });

    const [existingApplication] = await pool.query(
      'SELECT id FROM program_applications WHERE user_id = ? AND training_program_id = ?',
      [req.userId, training_program_id]
    );
    if (existingApplication.length > 0) return res.status(400).json({ error: 'لقد قمت بالفعل بالتقديم لهذا البرنامج التدريبي' });

    const [result] = await pool.query(
      `INSERT INTO program_applications (user_id, training_program_id, education_level, profile_picture, cv, certificate, status, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, NOW())`,
      [
        req.userId,
        training_program_id,
        existingUser[0].level_of_education || '/',
        existingUser[0].profile_picture || '/',
        existingUser[0].cv || '/',
        existingUser[0].certificate || '/',
        status
      ]
    );

    res.json({ message: 'تم إنشاء طلب البرنامج التدريبي بنجاح', applicationId: result.insertId });
  } catch (error) {
    console.error('خطأ في إنشاء طلب البرنامج التدريبي:', error);
    res.status(500).json({ error: 'خطأ في الخادم' });
  }
});
app.put('/program_applications/:id', verifyToken, async (req, res) => {
  const { education_level = '/', status = 'pending' } = req.body;

  try {
    const [existingApplication] = await pool.query('SELECT user_id, training_program_id FROM program_applications WHERE id = ?', [req.params.id]);
    if (existingApplication.length === 0) return res.status(404).json({ error: 'طلب البرنامج التدريبي غير موجود' });

    if (req.entity_type === 'users' && req.userId !== existingApplication[0].user_id) {
      return res.status(403).json({ error: 'غير مصرح لك بتحديث هذا الطلب' });
    }
    if (req.entity_type === 'training_centers') {
      const [program] = await pool.query('SELECT center_id FROM training