// server.js
const express = require('express');
const path = require('path');
const { open } = require('sqlite');
const sqlite3 = require('sqlite3');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

let db;
const dbPath = path.join(__dirname, 'full.db');

const initializeDbandServer = async () => {
  try {
    db = await open({ filename: dbPath, driver: sqlite3.Database });
    await createTables();
    app.listen(3000, () => console.log('Server running at http://localhost:3000'));
  } catch (error) {
    console.log(`DB Error: ${error.message}`);
    process.exit(1);
  }
};

const createTables = async () => {
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      email TEXT UNIQUE,
      password TEXT,
      role TEXT
    );
    CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      description TEXT,
      price REAL,
      image TEXT
    );
    CREATE TABLE IF NOT EXISTS cart (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      userId INTEGER,
      productId INTEGER,
      quantity INTEGER
    );
    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      userId INTEGER,
      status TEXT,
      total REAL
    );
    CREATE TABLE IF NOT EXISTS order_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      orderId INTEGER,
      productId INTEGER,
      quantity INTEGER
    );
  `);
};

initializeDbandServer();

const JWT_SECRET = process.env.JWT_SECRET || 'mysecret';
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).send('Token missing');
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).send('Invalid token');
    req.user = user;
    next();
  });
};

// Register
app.post('/register', async (req, res) => {
  const { name, email, password, role } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    await db.run('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)', [name, email, hashedPassword, role || 'customer']);
    res.send('User registered');
  } catch (e) {
    res.status(400).send('User already exists');
  }
});

// Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await db.get('SELECT * FROM users WHERE email = ?', [email]);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).send('Invalid credentials');
  }
  const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET);
  res.json({ token });
});

// Get Profile
app.get('/profile', authenticateToken, async (req, res) => {
  const user = await db.get('SELECT id, name, email, role FROM users WHERE id = ?', [req.user.id]);
  res.json(user);
});

// Product CRUD
app.post('/products', authenticateToken, async (req, res) => {
  const { name, description, price, image } = req.body;
  if (req.user.role !== 'admin') return res.status(403).send('Forbidden');
  await db.run('INSERT INTO products (name, description, price, image) VALUES (?, ?, ?, ?)', [name, description, price, image]);
  res.send('Product added');
});

app.get('/products', async (req, res) => {
  const products = await db.all('SELECT * FROM products');
  res.json(products);
});

app.put('/products/:id', authenticateToken, async (req, res) => {
  const { name, description, price, image } = req.body;
  if (req.user.role !== 'admin') return res.status(403).send('Forbidden');
  await db.run('UPDATE products SET name=?, description=?, price=?, image=? WHERE id=?', [name, description, price, image, req.params.id]);
  res.send('Product updated');
});

app.delete('/products/:id', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).send('Forbidden');
  await db.run('DELETE FROM products WHERE id=?', [req.params.id]);
  res.send('Product deleted');
});

// Cart
app.post('/cart', authenticateToken, async (req, res) => {
  const { productId, quantity } = req.body;
  await db.run('INSERT INTO cart (userId, productId, quantity) VALUES (?, ?, ?)', [req.user.id, productId, quantity]);
  res.send('Added to cart');
});

app.get('/cart', authenticateToken, async (req, res) => {
  const items = await db.all('SELECT * FROM cart WHERE userId=?', [req.user.id]);
  res.json(items);
});

app.put('/cart/:id', authenticateToken, async (req, res) => {
  const { quantity } = req.body;
  await db.run('UPDATE cart SET quantity=? WHERE id=? AND userId=?', [quantity, req.params.id, req.user.id]);
  res.send('Cart updated');
});

app.delete('/cart/:id', authenticateToken, async (req, res) => {
  await db.run('DELETE FROM cart WHERE id=? AND userId=?', [req.params.id, req.user.id]);
  res.send('Removed from cart');
});

// Orders
app.post('/orders', authenticateToken, async (req, res) => {
  const cartItems = await db.all('SELECT * FROM cart WHERE userId=?', [req.user.id]);
  const total = cartItems.reduce((sum, item) => sum + item.quantity * 100, 0); // Assuming ₹100/product as example
  const orderRes = await db.run('INSERT INTO orders (userId, status, total) VALUES (?, ?, ?)', [req.user.id, 'Placed', total]);
  const orderId = orderRes.lastID;
  for (const item of cartItems) {
    await db.run('INSERT INTO order_items (orderId, productId, quantity) VALUES (?, ?, ?)', [orderId, item.productId, item.quantity]);
  }
  await db.run('DELETE FROM cart WHERE userId=?', [req.user.id]);
  res.send({ message: 'Order placed', orderId });
});

app.get('/orders', authenticateToken, async (req, res) => {
  const orders = await db.all('SELECT * FROM orders WHERE userId=?', [req.user.id]);
  res.json(orders);
});

app.post('/test-insert-order', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).send('Forbidden');
  
    try {
      const { userId, status, total } = req.body;
      const order = await db.run(
        'INSERT INTO orders (userId, status, total) VALUES (?, ?, ?)',
        [userId, status, total]
      );
      res.send({ message: 'Order inserted', orderId: order.lastID });
    } catch (error) {
      res.status(500).send('Error inserting order');
    }
  });
  

// Mock Payment
app.post('/payment', authenticateToken, async (req, res) => {
  res.send({ message: 'Payment successful (mock)', status: 'success' });
});

