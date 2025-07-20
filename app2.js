require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');
const cors = require('cors');

const app = express();
app.use(bodyParser.json());
app.use(cookieParser());

app.use(cors({
    origin: ['http://127.0.0.1:5500', 'http://localhost:5500'],
    credentials: true
  }));
  

const SECRET = process.env.JWT_SECRET || 'your-secret-key';
const OTP_EXPIRY_MS = 5 * 60 * 1000; 
const TOKEN_EXPIRY = '15m';

const USERS_FILE = './users.json';
const OTP_FILE = './otp.json';


const readJSON = (filename) => {
  if (!fs.existsSync(filename)) return [];
  return JSON.parse(fs.readFileSync(filename));
};

const writeJSON = (filename, data) => {
  fs.writeFileSync(filename, JSON.stringify(data, null, 2));
};


const authenticate = (req, res, next) => {
  const token = req.cookies.sessionToken;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Forbidden' });
    req.user = user;
    next();
  });
};

function isValidPassword(password) {
  const minLength = 8;
  const upperCase = /[A-Z]/;
  const lowerCase = /[a-z]/;
  const number = /[0-9]/;
  const specialChar = /[!@#$%^&*(),.?":{}|<>]/;

  return password.length >= minLength &&
         upperCase.test(password) &&
         lowerCase.test(password) &&
         number.test(password) &&
         specialChar.test(password);
}

app.post('/signup', (req, res) => {
  const { name, email, password, mobile } = req.body;

  // Password Constraint Check
  if (!isValidPassword(password)) {
    return res.status(400).json({ 
      error: 'Password must be at least 8 characters long, contain uppercase, lowercase, number, and special character.' 
    });
  }

  const users = readJSON(USERS_FILE);
  if (users.find(u => u.email === email)) {
    return res.status(400).json({ error: 'Email already exists' });
  }
  if (mobile && users.find(u => u.mobile === mobile)) {
    return res.status(400).json({ error: 'Mobile number already exists' });
  }

  const userId = crypto.randomUUID();
  users.push({ id: userId, name, email, password, mobile });
  writeJSON(USERS_FILE, users);

  const otp = Math.floor(100000 + Math.random() * 900000);
  const otpStore = readJSON(OTP_FILE);
  otpStore.push({
    userId,
    otp,
    expiresAt: Date.now() + OTP_EXPIRY_MS
  });
  writeJSON(OTP_FILE, otpStore);

  console.log(`OTP for ${email}: ${otp} (valid for 5 mins)`);
  res.json({ message: 'User registered. OTP sent.' });
});



app.post('/verify-otp', (req, res) => {
  const { identifier, otp } = req.body;

  const users = readJSON(USERS_FILE);
  const user = users.find(u => u.email === identifier || u.mobile === identifier);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const otpStore = readJSON(OTP_FILE);
  const recordIndex = otpStore.findIndex(r => r.userId === user.id && r.otp === parseInt(otp));

  if (recordIndex === -1) return res.status(400).json({ error: 'Invalid OTP' });

  if (Date.now() > otpStore[recordIndex].expiresAt) {
    return res.status(410).json({ error: 'OTP expired' });
  }

  otpStore.splice(recordIndex, 1);
  writeJSON(OTP_FILE, otpStore);

  res.json({ message: 'OTP verified' });
});


app.post('/login', (req, res) => {
  const { identifier, password } = req.body;

  const users = readJSON(USERS_FILE);
  const user = users.find(u =>
    (u.email === identifier || u.mobile === identifier) && u.password === password
  );
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ id: user.id, email: user.email }, SECRET, { expiresIn: TOKEN_EXPIRY });

  res.cookie('sessionToken', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 15 * 60 * 1000
  });

  res.json({ message: 'Login successful' });
});


app.post('/refresh-token', (req, res) => {
  const { refreshToken } = req.body;


  if (!refreshToken) {
    return res.status(401).json({ error: 'Refresh token required' });
  }

  const token = jwt.sign({ id: 'demo-user', email: 'demo@example.com' }, SECRET, { expiresIn: TOKEN_EXPIRY });

  res.cookie('sessionToken', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 15 * 60 * 1000
  });

  res.json({ message: 'Token refreshed' });
});

app.get('/protected', authenticate, (req, res) => {
  res.json({ message: 'Protected data', user: req.user });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
