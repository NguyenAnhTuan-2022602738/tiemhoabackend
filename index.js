import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import mongoose from 'mongoose';
import cors from 'cors';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: {
    origin: process.env.CLIENT_URL || '*',
    methods: ['GET', 'POST'],
    credentials: true
  }
});
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors({
    origin: process.env.CLIENT_URL || '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true
}));
app.use(express.json({ limit: '50mb' }));

// MongoDB Connection
const MONGO_URI = process.env.MONGO_URI || "mongodb+srv://tuannguyen10112004:tuannguyencoder@cluster0.xsi5t.mongodb.net/shop_hoa";

// Only connect if not already connected
if (mongoose.connection.readyState === 0) {
    mongoose.connect(MONGO_URI)
      .then(async () => {
        console.log('✅ Connected to MongoDB');
        // Create default admin if not exists
        await createDefaultAdmin();
      })
      .catch(err => console.error('❌ MongoDB Connection Error:', err));
}

// Function to create default admin
async function createDefaultAdmin() {
  try {
    // Wait a bit for User model to be defined
    setTimeout(async () => {
      const User = mongoose.models.User;
      if (!User) return;
      
      const adminExists = await User.findOne({ role: 'admin' });
      if (!adminExists) {
        const defaultAdmin = new User({
          email: 'admin@shop.com',
          password: Buffer.from('admin123').toString('base64'), // Password: admin123
          name: 'Admin',
          phone: '0909000000',
          role: 'admin'
        });
        await defaultAdmin.save();
        console.log('👤 Default admin created: admin@shop.com / admin123');
      }
    }, 1000);
  } catch (err) {
    console.log('Admin check skipped:', err.message);
  }
}

// Schemas
const ProductSchema = new mongoose.Schema({
  id: Number, 
  name: String,
  price: Number,
  image: String,
  images: [String],
  description: String,
  category: String
});

const SettingsSchema = new mongoose.Schema({
  key: { type: String, unique: true }, 
  value: mongoose.Schema.Types.Mixed
});

const OrderSchema = new mongoose.Schema({
  customer: {
    name: String,
    phone: String,
    email: String,
    address: String,
    note: String
  },
  items: [{
    productId: Number,
    name: String,
    price: Number,
    quantity: Number,
    image: String
  }],
  totalAmount: Number,
  status: { type: String, default: 'pending' }, // pending, confirmed, shipping, delivered, cancelled
  createdAt: { type: Date, default: Date.now }
});

const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String, required: true },
  phone: { type: String },
  address: { type: String },
  role: { type: String, default: 'customer', enum: ['admin', 'customer'] },
  createdAt: { type: Date, default: Date.now }
});

// Use models if already compiled to avoid overwriting error in serverless
const Product = mongoose.models.Product || mongoose.model('Product', ProductSchema);
const Setting = mongoose.models.Setting || mongoose.model('Setting', SettingsSchema);
const Order = mongoose.models.Order || mongoose.model('Order', OrderSchema);
const User = mongoose.models.User || mongoose.model('User', UserSchema);

// --- API Routes ---
app.get('/api', (req, res) => {
    res.json({ message: "Hello from Flower Shop API 🌸" });
});

// ============ AUTH ROUTES ============

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name, phone } = req.body;
    
    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email đã được sử dụng' });
    }
    
    // Simple password hash (in production, use bcrypt)
    const hashedPassword = Buffer.from(password).toString('base64');
    
    const newUser = new User({
      email,
      password: hashedPassword,
      name,
      phone,
      role: 'customer' // Default role
    });
    
    await newUser.save();
    
    // Return user without password
    const userResponse = { 
      id: newUser._id, 
      email: newUser.email, 
      name: newUser.name, 
      phone: newUser.phone,
      role: newUser.role 
    };
    
    res.json({ message: 'Đăng ký thành công', user: userResponse });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Email hoặc mật khẩu không đúng' });
    }
    
    // Check password
    const hashedPassword = Buffer.from(password).toString('base64');
    if (user.password !== hashedPassword) {
      return res.status(401).json({ error: 'Email hoặc mật khẩu không đúng' });
    }
    
    // Return user without password
    const userResponse = { 
      id: user._id, 
      email: user.email, 
      name: user.name, 
      phone: user.phone,
      address: user.address,
      role: user.role 
    };
    
    res.json({ message: 'Đăng nhập thành công', user: userResponse });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update Profile
app.put('/api/auth/profile/:id', async (req, res) => {
  try {
    const { name, phone, address } = req.body;
    
    const updated = await User.findByIdAndUpdate(
      req.params.id,
      { name, phone, address },
      { new: true }
    );
    
    if (!updated) {
      return res.status(404).json({ error: 'Không tìm thấy người dùng' });
    }
    
    const userResponse = { 
      id: updated._id, 
      email: updated.email, 
      name: updated.name, 
      phone: updated.phone,
      address: updated.address,
      role: updated.role 
    };
    
    res.json({ message: 'Cập nhật thành công', user: userResponse });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Change Password
app.put('/api/auth/password/:id', async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'Không tìm thấy người dùng' });
    }
    
    // Verify current password
    const hashedCurrentPassword = Buffer.from(currentPassword).toString('base64');
    if (user.password !== hashedCurrentPassword) {
      return res.status(401).json({ error: 'Mật khẩu hiện tại không đúng' });
    }
    
    // Update password
    const hashedNewPassword = Buffer.from(newPassword).toString('base64');
    user.password = hashedNewPassword;
    await user.save();
    
    res.json({ message: 'Đổi mật khẩu thành công' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get User Orders (by email or phone)
app.get('/api/auth/orders/:userId', async (req, res) => {
  try {
    const user = await User.findById(req.params.userId);
    if (!user) {
      return res.status(404).json({ error: 'Không tìm thấy người dùng' });
    }
    
    // Find orders by user's phone or email
    const orders = await Order.find({
      $or: [
        { 'customer.phone': user.phone },
        { 'customer.email': user.email }
      ]
    }).sort({ createdAt: -1 });
    
    res.json(orders);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 1. Products
app.get('/api/products', async (req, res) => {
  try {
    const products = await Product.find();
    res.json(products);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/products', async (req, res) => {
  try {
    const newProduct = new Product(req.body);
    await newProduct.save();
    res.json(newProduct);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/products/:id', async (req, res) => {
  try {
    const updated = await Product.findOneAndUpdate({ id: req.params.id }, req.body, { new: true });
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/products/:id', async (req, res) => {
  try {
    await Product.findOneAndDelete({ id: req.params.id });
    res.json({ message: 'Deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 2. Settings / Layout
app.get('/api/settings/:key', async (req, res) => {
  try {
    const setting = await Setting.findOne({ key: req.params.key });
    res.json(setting ? setting.value : null);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/settings', async (req, res) => {
  try {
    const { key, value } = req.body;
    const updated = await Setting.findOneAndUpdate(
      { key }, 
      { key, value }, 
      { upsert: true, new: true }
    );
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get all settings
app.get('/api/settings', async (req, res) => {
  try {
    const allSettings = await Setting.find();
    const settingsMap = {};
    allSettings.forEach(s => {
      settingsMap[s.key] = s.value;
    });
    res.json(settingsMap);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete setting
app.delete('/api/settings/:key', async (req, res) => {
  try {
    await Setting.deleteOne({ key: req.params.key });
    res.json({ message: 'Setting deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 3. Orders
app.get('/api/orders', async (req, res) => {
  try {
    const orders = await Order.find().sort({ createdAt: -1 });
    res.json(orders);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/orders', async (req, res) => {
  try {
    const newOrder = new Order(req.body);
    await newOrder.save();
    console.log('📦 New order created:', newOrder._id);
    res.json(newOrder);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/orders/:id', async (req, res) => {
  try {
    const { status } = req.body;
    const updated = await Order.findByIdAndUpdate(
      req.params.id, 
      { status }, 
      { new: true }
    );
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/orders/:id', async (req, res) => {
  try {
    await Order.findByIdAndDelete(req.params.id);
    res.json({ message: 'Order deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Local Development Server
// Check if this module is being run directly (not imported)
// In ESM, import.meta.url is the file URL. process.argv[1] is the script path.
// Doing a loose check or simply trying to listen if PORT is defined and not serverless environment.
if (process.env.NODE_ENV !== 'production') {
    httpServer.listen(PORT, () => {
        console.log(`🚀 Server running locally on http://localhost:${PORT}`);
        console.log(`💬 Socket.IO ready for real-time chat`);
    });
}

// Socket.IO Chat Events
io.on('connection', (socket) => {
  console.log('👤 User connected:', socket.id);

  // Join specific chat session
  socket.on('join-session', (sessionId) => {
    socket.join(sessionId);
    console.log(`📥 User ${socket.id} joined session: ${sessionId}`);
  });

  // Send message
  socket.on('send-message', ({ sessionId, message }) => {
    // Broadcast to all users in this session (including sender)
    io.to(sessionId).emit('new-message', message);
    console.log(`💬 Message in session ${sessionId}:`, message.message);
  });

  // Admin typing indicator (optional)
  socket.on('typing', ({ sessionId, isTyping }) => {
    socket.to(sessionId).emit('user-typing', { isTyping });
  });

  socket.on('disconnect', () => {
    console.log('👋 User disconnected:', socket.id);
  });
});

// Start server for Railway/traditional hosting
httpServer.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});

// Export for Vercel Serverless (if needed)
export default app;
