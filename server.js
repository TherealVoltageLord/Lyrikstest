const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcryptjs');
const path = require('path');
const multer = require('multer');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://cdnjs.cloudflare.com", "https://fonts.gstatic.com"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
      imgSrc: ["'self'", "data:", "https:"]
    }
  }
}));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use(limiter);

mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log('Connected to MongoDB Atlas');
}).catch(err => {
  console.error('MongoDB connection error:', err);
});

const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  balance: { type: Number, default: 0 },
  verified: { type: Boolean, default: false },
  bio: { type: String, default: '' },
  profilePic: { type: String, default: '' },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  referralCode: { type: String, unique: true },
  referredBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  stats: {
    wins: { type: Number, default: 0 },
    losses: { type: Number, default: 0 },
    streaks: { type: Number, default: 0 },
    lastWin: { type: Date },
    lockedUntil: { type: Date }
  },
  notifications: [{
    message: String,
    date: { type: Date, default: Date.now },
    read: { type: Boolean, default: false }
  }]
});

const TransactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['deposit', 'withdraw', 'gift'], required: true },
  amount: { type: Number, required: true },
  status: { type: String, enum: ['Pending', 'Approved', 'Declined', 'Completed'], default: 'Pending' },
  date: { type: Date, default: Date.now },
  recipientId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
});

const GameSchema = new mongoose.Schema({
  gameName: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  bet: { type: Number, required: true },
  result: { type: String, enum: ['Win', 'Lose', 'Draw'], required: true },
  payout: { type: Number, default: 0 },
  date: { type: Date, default: Date.now }
});

const AnnouncementSchema = new mongoose.Schema({
  message: { type: String, required: true },
  date: { type: Date, default: Date.now }
});

const AuditSchema = new mongoose.Schema({
  adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  action: String,
  targetId: mongoose.Schema.Types.ObjectId,
  details: mongoose.Schema.Types.Mixed,
  date: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);
const Game = mongoose.model('Game', GameSchema);
const Announcement = mongoose.model('Announcement', AnnouncementSchema);
const Audit = mongoose.model('Audit', AuditSchema);

app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    ttl: 24 * 60 * 60
  }),
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 24 * 60 * 60 * 1000
  }
}));

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'public/uploads/')
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname)
  }
});

const fileFilter = (req, file, cb) => {
  if (file.mimetype.startsWith('image/')) {
    cb(null, true);
  } else {
    cb(new Error('Only images are allowed'), false);
  }
};

const upload = multer({ storage, fileFilter, limits: { fileSize: 5 * 1024 * 1024 } });

function isSaturday() {
  return new Date().getDay() === 6;
}

function validatePassword(password) {
  if (password.length < 8) {
    return 'Password must be at least 8 characters long';
  }
  if (!/[A-Z]/.test(password)) {
    return 'Password must contain at least one uppercase letter';
  }
  if (!/[0-9]/.test(password)) {
    return 'Password must contain at least one number';
  }
  if (!/[^A-Za-z0-9]/.test(password)) {
    return 'Password must contain at least one special character';
  }
  return null;
}

function generateReferralCode() {
  return Math.random().toString(36).substring(2, 10).toUpperCase();
}

async function requireAuth(req, res, next) {
  if (req.session.userId) {
    try {
      const user = await User.findById(req.session.userId);
      if (user) {
        req.user = user;
        next();
        return;
      }
    } catch (error) {
      console.error('Error fetching user in requireAuth:', error);
    }
  }
  res.status(401).json({ success: false, message: 'Authentication required' });
}

async function requireAdmin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ success: false, message: 'Authentication required' });
  }
  
  try {
    const user = await User.findById(req.session.userId);
    if (user && user.role === 'admin') {
      req.user = user;
      next();
    } else {
      res.status(403).json({ success: false, message: 'Admin access required' });
    }
  } catch (error) {
    console.error('Error fetching user in requireAdmin:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
}

async function logAdminAction(adminId, action, targetId, details = {}) {
  try {
    const admin = await User.findById(adminId);
    await Audit.create({
      adminId,
      action,
      targetId,
      details: { ...details, adminUsername: admin.username }
    });
  } catch (error) {
    console.error('Error logging admin action:', error);
  }
}

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/dashboard', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/profile', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'profile.html'));
});

app.get('/games', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'games.html'));
});

app.get('/memory-game', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'memory-game.html'));
});

app.get('/rock-paper-scissors', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'rock-paper-scissors.html'));
});

app.get('/tic-tac-toe', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'tic-tac-toe.html'));
});

app.get('/aviator', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'aviator.html'));
});

app.get('/slot-machine', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'slot-machine.html'));
});

app.get('/blackjack', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'blackjack.html'));
});

app.get('/dice-duel', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dice-duel.html'));
});

app.get('/coin-flip', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'coin-flip.html'));
});

app.get('/transactions', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'transactions.html'));
});

app.get('/leaderboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'leaderboard.html'));
});

app.get('/rewards', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'rewards.html'));
});

app.get('/admin', requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/admin/users', requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin-users.html'));
});

app.get('/admin/transactions', requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin-transactions.html'));
});

app.get('/admin/announcements', requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin-announcements.html'));
});

app.get('/admin/analytics', requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin-analytics.html'));
});

app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password, referralCode } = req.body;
    
    if (!username || !email || !password) {
      return res.status(400).json({ success: false, message: 'All fields are required' });
    }
    
    const passwordError = validatePassword(password);
    if (passwordError) {
      return res.status(400).json({ success: false, message: passwordError });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const referral = generateReferralCode();
    
    const userData = { 
      username, 
      email, 
      password: hashedPassword, 
      referralCode: referral 
    };
    
    if (referralCode) {
      const referrer = await User.findOne({ referralCode });
      if (referrer) {
        userData.referredBy = referrer._id;
      }
    }
    
    const user = new User(userData);
    await user.save();
    
    if (user.referredBy) {
      await User.findByIdAndUpdate(user.referredBy, {
        $inc: { balance: 500 },
        $push: { notifications: { message: `You received 500 bonus for referring ${username}` } }
      });
      
      await User.findByIdAndUpdate(user._id, {
        $inc: { balance: 300 },
        $push: { notifications: { message: 'You received 300 bonus for using a referral code' } }
      });
    }
    
    req.session.userId = user._id;
    req.session.role = user.role;
    
    res.json({ success: true, message: 'Registration successful' });
  } catch (error) {
    if (error.code === 11000) {
      const field = Object.keys(error.keyValue)[0];
      res.status(400).json({ success: false, message: `${field} already exists` });
    } else {
      console.error('Registration error:', error);
      res.status(500).json({ success: false, message: 'Registration failed' });
    }
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'Username and password are required' });
    }
    
    const user = await User.findOne({ username });
    if (user && await bcrypt.compare(password, user.password)) {
      req.session.userId = user._id;
      req.session.role = user.role;
      
      res.json({ success: true, message: 'Login successful' });
    } else {
      res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, message: 'Login error' });
  }
});

app.get('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).json({ success: false, message: 'Logout failed' });
    }
    res.json({ success: true, message: 'Logout successful' });
  });
});

app.post('/api/deposit', requireAuth, async (req, res) => {
  try {
    const { amount } = req.body;
    
    if (!amount || amount <= 0) {
      return res.status(400).json({ success: false, message: 'Invalid amount' });
    }
    
    const transaction = new Transaction({
      userId: req.session.userId,
      type: 'deposit',
      amount,
      status: 'Pending'
    });
    await transaction.save();
    
    res.json({ success: true, message: 'Deposit request submitted' });
  } catch (error) {
    console.error('Deposit error:', error);
    res.status(500).json({ success: false, message: 'Deposit failed' });
  }
});

app.post('/api/withdraw', requireAuth, async (req, res) => {
  try {
    if (!isSaturday()) {
      return res.status(400).json({ success: false, message: 'Withdrawals are only allowed on Saturdays' });
    }
    
    const { amount } = req.body;
    
    if (!amount || amount <= 0) {
      return res.status(400).json({ success: false, message: 'Invalid amount' });
    }
    
    const user = await User.findById(req.session.userId);
    if (user.balance < amount) {
      return res.status(400).json({ success: false, message: 'Insufficient balance' });
    }
    
    const transaction = new Transaction({
      userId: req.session.userId,
      type: 'withdraw',
      amount,
      status: 'Pending'
    });
    await transaction.save();
    
    res.json({ success: true, message: 'Withdrawal request submitted' });
  } catch (error) {
    console.error('Withdrawal error:', error);
    res.status(500).json({ success: false, message: 'Withdrawal failed' });
  }
});

app.get('/api/transactions', requireAuth, async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const skip = (page - 1) * limit;
    
    const transactions = await Transaction.find({ 
      $or: [
        { userId: req.session.userId },
        { recipientId: req.session.userId }
      ]
    })
    .sort({ date: -1 })
    .skip(skip)
    .limit(parseInt(limit));
    
    const total = await Transaction.countDocuments({ 
      $or: [
        { userId: req.session.userId },
        { recipientId: req.session.userId }
      ]
    });
    
    res.json({ success: true, data: transactions, total, page: parseInt(page), limit: parseInt(limit) });
  } catch (error) {
    console.error('Transactions fetch error:', error);
    res.status(500).json({ success: false, message: 'Error fetching transactions' });
  }
});

app.post('/api/game-result', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId);
    
    if (user.stats.lockedUntil && user.stats.lockedUntil > new Date()) {
      return res.status(400).json({ 
        success: false, 
        message: 'Account temporarily locked due to winning streak. Try again later.' 
      });
    }
    
    const { gameName, bet, result, payout } = req.body;
    
    if (user.balance < bet) {
      return res.status(400).json({ success: false, message: 'Insufficient balance' });
    }
    
    const game = new Game({
      gameName,
      userId: req.session.userId,
      bet,
      result,
      payout
    });
    await game.save();
    
    let updateData = {};
    
    if (result === 'Win') {
      updateData = { 
        $inc: { balance: payout - bet, 'stats.wins': 1 },
        $set: { 
          'stats.streaks': user.stats.streaks + 1,
          'stats.lastWin': new Date()
        }
      };
      
      if (user.stats.streaks + 1 >= 3) {
        const lockUntil = new Date();
        lockUntil.setDate(lockUntil.getDate() + 1);
        updateData.$set['stats.lockedUntil'] = lockUntil;
      }
    } else if (result === 'Lose') {
      updateData = { 
        $inc: { balance: -bet, 'stats.losses': 1 },
        $set: { 'stats.streaks': 0, 'stats.lockedUntil': null }
      };
    } else if (result === 'Draw') {
      updateData = { 
        $set: { 'stats.streaks': 0, 'stats.lockedUntil': null }
      };
    }
    
    await User.findByIdAndUpdate(req.session.userId, updateData);
    
    res.json({ success: true });
  } catch (error) {
    console.error('Game result error:', error);
    res.status(500).json({ success: false, message: 'Error saving game result' });
  }
});

app.get('/api/leaderboard', async (req, res) => {
  try {
    const leaders = await User.find().sort({ 
      'stats.wins': -1, 
      'stats.losses': 1,
      balance: -1 
    }).limit(10);
    res.json({ success: true, data: leaders });
  } catch (error) {
    console.error('Leaderboard fetch error:', error);
    res.status(500).json({ success: false, message: 'Error fetching leaderboard' });
  }
});

app.get('/api/announcements', async (req, res) => {
  try {
    const announcements = await Announcement.find().sort({ date: -1 }).limit(10);
    res.json({ success: true, data: announcements });
  } catch (error) {
    console.error('Announcements fetch error:', error);
    res.status(500).json({ success: false, message: 'Error fetching announcements' });
  }
});

app.post('/api/admin/announcements', requireAdmin, async (req, res) => {
  try {
    const { message } = req.body;
    
    if (!message) {
      return res.status(400).json({ success: false, message: 'Message is required' });
    }
    
    const announcement = new Announcement({ message });
    await announcement.save();
    
    await logAdminAction(
      req.session.userId, 
      'Created announcement', 
      announcement._id,
      { message }
    );
    
    res.json({ success: true, message: 'Announcement posted' });
  } catch (error) {
    console.error('Announcement creation error:', error);
    res.status(500).json({ success: false, message: 'Error creating announcement' });
  }
});

app.delete('/api/admin/announcements/:id', requireAdmin, async (req, res) => {
  try {
    await Announcement.findByIdAndDelete(req.params.id);
    
    await logAdminAction(
      req.session.userId, 
      'Deleted announcement', 
      req.params.id
    );
    
    res.json({ success: true, message: 'Announcement deleted' });
  } catch (error) {
    console.error('Announcement deletion error:', error);
    res.status(500).json({ success: false, message: 'Error deleting announcement' });
  }
});

app.post('/api/admin/notify', requireAdmin, async (req, res) => {
  try {
    const { userId, message } = req.body;
    
    if (!userId || !message) {
      return res.status(400).json({ success: false, message: 'User ID and message are required' });
    }
    
    await User.findByIdAndUpdate(userId, {
      $push: { notifications: { message } }
    });
    
    await logAdminAction(
      req.session.userId, 
      'Sent notification to user', 
      userId,
      { message }
    );
    
    res.json({ success: true, message: 'Notification sent' });
  } catch (error) {
    console.error('Notification send error:', error);
    res.status(500).json({ success: false, message: 'Error sending notification' });
  }
});

app.get('/api/notifications', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId);
    res.json({ success: true, data: user.notifications });
  } catch (error) {
    console.error('Notifications fetch error:', error);
    res.status(500).json({ success: false, message: 'Error fetching notifications' });
  }
});

app.post('/api/notifications/read', requireAuth, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.session.userId, {
      $set: { 'notifications.$[].read': true }
    });
    
    res.json({ success: true, message: 'All notifications marked as read' });
  } catch (error) {
    console.error('Notifications read error:', error);
    res.status(500).json({ success: false, message: 'Error updating notifications' });
  }
});

app.post('/api/gift', requireAuth, async (req, res) => {
  try {
    const { toUsername, amount } = req.body;
    
    if (!toUsername || !amount || amount <= 0) {
      return res.status(400).json({ success: false, message: 'Invalid recipient or amount' });
    }
    
    const sender = await User.findById(req.session.userId);
    const recipient = await User.findOne({ username: toUsername });
    
    if (!recipient) {
      return res.status(404).json({ success: false, message: 'Recipient not found' });
    }
    
    if (sender.balance < amount) {
      return res.status(400).json({ success: false, message: 'Insufficient balance' });
    }
    
    const giftTransaction = new Transaction({
      userId: req.session.userId,
      recipientId: recipient._id,
      type: 'gift',
      amount,
      status: 'Completed'
    });
    await giftTransaction.save();
    
    await User.findByIdAndUpdate(req.session.userId, {
      $inc: { balance: -amount }
    });
    
    await User.findByIdAndUpdate(recipient._id, {
      $inc: { balance: amount },
      $push: { notifications: { message: `You received a gift of ${amount} from ${sender.username}` } }
    });
    
    res.json({ success: true, message: 'Gift sent successfully' });
  } catch (error) {
    console.error('Gift send error:', error);
    res.status(500).json({ success: false, message: 'Error sending gift' });
  }
});

app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const users = await User.find();
    res.json({ success: true, data: users });
  } catch (error) {
    console.error('Admin users fetch error:', error);
    res.status(500).json({ success: false, message: 'Error fetching users' });
  }
});

app.post('/api/admin/users/verify', requireAdmin, async (req, res) => {
  try {
    const { userId, verified } = req.body;
    
    if (typeof verified !== 'boolean') {
      return res.status(400).json({ success: false, message: 'Invalid verification status' });
    }
    
    await User.findByIdAndUpdate(userId, { verified });
    
    await logAdminAction(
      req.session.userId, 
      `User verification ${verified ? 'granted' : 'revoked'}`,
      userId,
      { verified }
    );
    
    res.json({ success: true, message: 'Verification status updated' });
  } catch (error) {
    console.error('User verification error:', error);
    res.status(500).json({ success: false, message: 'Error updating verification' });
  }
});

app.get('/api/admin/transactions', requireAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 50 } = req.query;
    const skip = (page - 1) * limit;
    
    const transactions = await Transaction.find()
      .populate('userId', 'username')
      .populate('recipientId', 'username')
      .sort({ date: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Transaction.countDocuments();
    
    res.json({ success: true, data: transactions, total, page: parseInt(page), limit: parseInt(limit) });
  } catch (error) {
    console.error('Admin transactions fetch error:', error);
    res.status(500).json({ success: false, message: 'Error fetching transactions' });
  }
});

app.get('/api/admin/transactions/filter', requireAdmin, async (req, res) => {
  try {
    const { type, status, page = 1, limit = 50 } = req.query;
    const skip = (page - 1) * limit;
    
    let filter = {};
    if (type) filter.type = type;
    if (status) filter.status = status;
    
    const transactions = await Transaction.find(filter)
      .populate('userId', 'username')
      .populate('recipientId', 'username')
      .sort({ date: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Transaction.countDocuments(filter);
    
    res.json({ success: true, data: transactions, total, page: parseInt(page), limit: parseInt(limit) });
  } catch (error) {
    console.error('Admin transactions filter error:', error);
    res.status(500).json({ success: false, message: 'Error filtering transactions' });
  }
});

app.post('/api/admin/transactions/approve', requireAdmin, async (req, res) => {
  try {
    const { transactionId, status } = req.body;
    
    if (!['Approved', 'Declined'].includes(status)) {
      return res.status(400).json({ success: false, message: 'Invalid status' });
    }
    
    const transaction = await Transaction.findById(transactionId).populate('userId');
    
    if (!transaction) {
      return res.status(404).json({ success: false, message: 'Transaction not found' });
    }
    
    if (status === 'Approved') {
      if (transaction.type === 'deposit') {
        await User.findByIdAndUpdate(transaction.userId._id, {
          $inc: { balance: transaction.amount },
          $push: { notifications: { message: `Your deposit of ${transaction.amount} was approved` } }
        });
      } else if (transaction.type === 'withdraw') {
        await User.findByIdAndUpdate(transaction.userId._id, {
          $inc: { balance: -transaction.amount },
          $push: { notifications: { message: `Your withdrawal of ${transaction.amount} was approved` } }
        });
      }
    } else if (status === 'Declined') {
      await User.findByIdAndUpdate(transaction.userId._id, {
        $push: { notifications: { message: `Your ${transaction.type} of ${transaction.amount} was declined` } }
      });
    }
    
    transaction.status = status;
    await transaction.save();
    
    await logAdminAction(
      req.session.userId, 
      `Transaction ${status.toLowerCase()}`,
      transactionId,
      { type: transaction.type, amount: transaction.amount }
    );
    
    res.json({ success: true, message: 'Transaction updated' });
  } catch (error) {
    console.error('Transaction approval error:', error);
    res.status(500).json({ success: false, message: 'Error updating transaction' });
  }
});

app.get('/api/admin/audit-logs', requireAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 50 } = req.query;
    const skip = (page - 1) * limit;
    
    const logs = await Audit.find()
      .populate('adminId', 'username')
      .sort({ date: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Audit.countDocuments();
    
    res.json({ success: true, data: logs, total, page: parseInt(page), limit: parseInt(limit) });
  } catch (error) {
    console.error('Audit logs fetch error:', error);
    res.status(500).json({ success: false, message: 'Error fetching audit logs' });
  }
});

app.post('/api/upload-profile', requireAuth, upload.single('profilePic'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, message: 'No file uploaded' });
    }
    
    await User.findByIdAndUpdate(req.session.userId, {
      profilePic: `/uploads/${req.file.filename}`
    });
    
    res.json({ success: true, message: 'Profile picture updated', filePath: `/uploads/${req.file.filename}` });
  } catch (error) {
    console.error('Profile upload error:', error);
    res.status(500).json({ success: false, message: 'Error uploading profile picture' });
  }
});

app.get('/api/user/referral', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId);
    res.json({ success: true, referralCode: user.referralCode });
  } catch (error) {
    console.error('Referral code fetch error:', error);
    res.status(500).json({ success: false, message: 'Error fetching referral code' });
  }
});

app.get('/api/user/stats', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId);
    res.json({ success: true, data: user });
  } catch (error) {
    console.error('User stats fetch error:', error);
    res.status(500).json({ success: false, message: 'Error fetching user stats' });
  }
});

app.post('/api/daily-bonus', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId);
    const lastBonus = user.lastBonus || new Date(0);
    const now = new Date();
    
    if (now.getDate() !== lastBonus.getDate() || now.getMonth() !== lastBonus.getMonth() || now.getFullYear() !== lastBonus.getFullYear()) {
      const bonusAmount = 100;
      
      await User.findByIdAndUpdate(req.session.userId, {
        $inc: { balance: bonusAmount },
        $set: { lastBonus: now },
        $push: { notifications: { message: `You claimed your daily bonus of ${bonusAmount}` } }
      });
      
      res.json({ success: true, message: `Daily bonus of ${bonusAmount} claimed` });
    } else {
      res.status(400).json({ success: false, message: 'Daily bonus already claimed today' });
    }
  } catch (error) {
    console.error('Daily bonus error:', error);
    res.status(500).json({ success: false, message: 'Error claiming daily bonus' });
  }
});

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ success: false, message: 'File too large' });
    }
  }
  
  console.error('Unhandled error:', err);
  res.status(500).json({ success: false, message: 'Internal server error' });
});

app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Endpoint not found' });
});

app.listen(PORT, () => {
  console.log(`Cash Arena server running on port ${PORT}`);
});
