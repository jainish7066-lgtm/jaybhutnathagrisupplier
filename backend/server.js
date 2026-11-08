// Jay Bhutnath Agri Supplier — REST API (Node.js + Express, JSON-file storage)
require('dotenv').config();
const express = require('express'), helmet = require('helmet'), cors = require('cors');
const rateLimit = require('express-rate-limit'), jwt = require('jsonwebtoken'), bcrypt = require('bcryptjs');
const crypto = require('crypto'), fs = require('fs'), path = require('path');

const PORT = process.env.PORT || 3000;
const ADMIN_USER = process.env.ADMIN_USER || 'jaybhutnathadmin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'adminbhutnath321';
const SECRET = process.env.JWT_SECRET || crypto.randomBytes(48).toString('hex');
if (!process.env.JWT_SECRET) console.warn('WARNING: JWT_SECRET not set. Logins reset on every restart.');
if (!process.env.ADMIN_PASS) console.warn('WARNING: using the default admin password. Set ADMIN_PASS in .env.');

/* ---------- storage (atomic JSON file) ---------- */
const FILE = process.env.DATA_FILE || path.join(__dirname, 'data.json');
const SEED = [
  ['Sharbati Wheat', 'Grain', 2850, 'quintal', 400], ['Castor Seed', 'Grain', 6300, 'quintal', 250],
  ['Bajra (Pearl Millet)', 'Grain', 2450, 'quintal', 300], ['Urea', 'Fertilizer', 270, '45 kg bag', 900],
  ['DAP', 'Fertilizer', 1350, '50 kg bag', 600], ['Neem-based Pesticide', 'Pesticide', 480, 'litre', 350],
  ['Chlorpyrifos', 'Pesticide', 540, 'litre', 200],
].map(([name, cat, price, unit, stock], i) => ({ id: i + 1, name, cat, price, unit, stock }));
let db;
try { db = JSON.parse(fs.readFileSync(FILE, 'utf8')); }
catch { db = { users: [], products: SEED, orders: [], seq: 1000, pid: SEED.length }; }
const save = () => { const t = FILE + '.tmp'; fs.writeFileSync(t, JSON.stringify(db)); fs.renameSync(t, FILE); };

/* ---------- helpers ---------- */
const digest = s => crypto.createHash('sha256').update(String(s)).digest();
const safeEq = (a, b) => crypto.timingSafeEqual(digest(a), digest(b));
const err = (res, code, error, extra = {}) => res.status(code).json({ error, ...extra });
const wrap = fn => (req, res, next) => { try { fn(req, res, next); } catch (e) { console.error(e); err(res, 500, 'Something went wrong'); } };
const ROLES = ['farmer', 'trader', 'partner'];
const sendSms = (phone, text) => console.log(`[SMS to ${phone}] ${text}`); // swap for Twilio / MSG91 / Fast2SMS
const newOtp = () => String(crypto.randomInt(1000, 10000));
const publicUser = u => ({ id: u.id, role: u.role, name: u.name, phone: u.phone, status: u.status, duty: !!u.duty, createdAt: u.createdAt });
// OTP is shown only to the customer who owns the order — never to admin or the delivery partner.
const orderView = (o, viewer) => {
  const { otp, otpAttempts, ...rest } = o;
  const partner = db.users.find(u => u.id === o.partnerId);
  const out = { ...rest, partner: partner ? { name: partner.name, phone: partner.phone } : null };
  if (viewer.role !== 'admin' && viewer.role !== 'partner' && viewer.id === o.userId) out.otp = otp;
  if (viewer.role === 'admin') out.otpLocked = otpAttempts >= 5;
  return out;
};

/* ---------- auth ---------- */
const sign = payload => jwt.sign(payload, SECRET, { expiresIn: '12h' });
function auth(roles = [], allowPending = false) {
  return (req, res, next) => {
    const h = req.headers.authorization || '';
    try {
      const p = jwt.verify(h.startsWith('Bearer ') ? h.slice(7) : '', SECRET);
      if (p.role === 'admin') req.user = { role: 'admin', name: 'Admin' };
      else {
        const u = db.users.find(x => x.id === p.sub);           // re-checked on every request,
        if (!u) return err(res, 401, 'Please log in again');      // so revoking access is instant
        if (u.status !== 'approved' && !allowPending)
          return err(res, 403, 'Your account has not been approved by the admin yet', { status: u.status });
        req.user = u;
      }
      if (roles.length && !roles.includes(req.user.role)) return err(res, 403, 'Not allowed for your role');
      next();
    } catch { err(res, 401, 'Please log in again'); }
  };
}

/* ---------- app ---------- */
const app = express();
app.use(helmet({ contentSecurityPolicy: { useDefaults: false, directives: {   // allows the bundled website, Google Fonts and the OpenStreetMap live map
  defaultSrc: ["'self'"], scriptSrc: ["'self'", "'unsafe-inline'"], scriptSrcAttr: ["'unsafe-inline'"],
  styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'], fontSrc: ['https://fonts.gstatic.com'],
  imgSrc: ["'self'", 'data:'], frameSrc: ['https://www.openstreetmap.org'], connectSrc: ["'self'"] } } }));
app.use(cors({ origin: process.env.CORS_ORIGIN || false }));
app.use(express.json({ limit: '50kb' }));
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false }));

app.post('/api/auth/register', wrap((req, res) => {
  const { role, name, phone, password } = req.body || {};
  if (!ROLES.includes(role)) return err(res, 400, 'Choose farmer, trader or partner');
  if (typeof name !== 'string' || name.trim().length < 2) return err(res, 400, 'Enter your full name');
  if (!/^\d{10}$/.test(phone || '')) return err(res, 400, 'Enter a 10-digit mobile number');
  if (typeof password !== 'string' || password.length < 6) return err(res, 400, 'Password needs at least 6 characters');
  if (db.users.some(u => u.phone === phone && u.role === role)) return err(res, 409, 'This number is already registered for this role');
  const u = { id: crypto.randomUUID(), role, name: name.trim().slice(0, 80), phone, hash: bcrypt.hashSync(password, 10), status: 'pending', createdAt: new Date().toISOString() };
  db.users.push(u); save();
  res.status(201).json({ message: 'Registered. You can use the site once the admin approves your account.', user: publicUser(u) });
}));

app.post('/api/auth/login', wrap((req, res) => {
  const { role, username, password } = req.body || {};
  if (role === 'admin') {
    if (safeEq(username || '', ADMIN_USER) && safeEq(password || '', ADMIN_PASS))
      return res.json({ token: sign({ role: 'admin' }), user: { role: 'admin', name: 'Admin', status: 'approved' } });
    return err(res, 401, 'Wrong admin username or password');
  }
  const u = db.users.find(x => x.phone === username && x.role === role);
  if (!u || !bcrypt.compareSync(String(password || ''), u.hash)) return err(res, 401, 'No account matches this number, password and role');
  res.json({ token: sign({ sub: u.id, role: u.role }), user: publicUser(u) }); // pending users get a token but can only call /api/me
}));

app.get('/api/me', auth([], true), (req, res) => res.json({ user: req.user.role === 'admin' ? req.user : publicUser(req.user) }));

/* ---------- products ---------- */
app.get('/api/products', auth(), (req, res) => res.json({ products: db.products }));

const readProduct = (b, partial) => {
  const o = {};
  if (!partial || b.name !== undefined) { if (typeof b.name !== 'string' || !b.name.trim()) return 'Enter a product name'; o.name = b.name.trim().slice(0, 80); }
  if (!partial || b.cat !== undefined) { if (!['Grain', 'Fertilizer', 'Pesticide', 'Other'].includes(b.cat)) return 'Invalid category'; o.cat = b.cat; }
  if (!partial || b.price !== undefined) { if (!(Number(b.price) > 0)) return 'Price must be above 0'; o.price = Number(b.price); }
  if (!partial || b.unit !== undefined) { if (typeof b.unit !== 'string' || !b.unit.trim()) return 'Enter a unit'; o.unit = b.unit.trim().slice(0, 30); }
  if (!partial || b.stock !== undefined) { if (!Number.isInteger(Number(b.stock)) || Number(b.stock) < 0) return 'Stock must be a whole number, 0 or more'; o.stock = Number(b.stock); }
  return o;
};
app.post('/api/admin/products', auth(['admin']), wrap((req, res) => {
  const o = readProduct(req.body || {}, false); if (typeof o === 'string') return err(res, 400, o);
  const p = { id: ++db.pid, ...o }; db.products.push(p); save(); res.status(201).json({ product: p });
}));
app.patch('/api/admin/products/:id', auth(['admin']), wrap((req, res) => {
  const p = db.products.find(x => x.id === +req.params.id); if (!p) return err(res, 404, 'Product not found');
  const o = readProduct(req.body || {}, true); if (typeof o === 'string') return err(res, 400, o);
  Object.assign(p, o); save(); res.json({ product: p });
}));
app.delete('/api/admin/products/:id', auth(['admin']), wrap((req, res) => {
  const n = db.products.length; db.products = db.products.filter(x => x.id !== +req.params.id);
  if (db.products.length === n) return err(res, 404, 'Product not found'); save(); res.json({ ok: true });
}));

/* ---------- admin: users, orders, stats ---------- */
app.get('/api/admin/users', auth(['admin']), (req, res) => res.json({ users: db.users.map(publicUser) }));
app.patch('/api/admin/users/:id/status', auth(['admin']), wrap((req, res) => {
  const u = db.users.find(x => x.id === req.params.id); if (!u) return err(res, 404, 'User not found');
  if (!['approved', 'rejected', 'pending'].includes(req.body?.status)) return err(res, 400, 'Invalid status');
  u.status = req.body.status; save(); res.json({ user: publicUser(u) });
}));
app.get('/api/admin/orders', auth(['admin']), (req, res) => res.json({ orders: [...db.orders].reverse().map(o => orderView(o, req.user)) }));
app.patch('/api/admin/orders/:id', auth(['admin']), wrap((req, res) => {
  const o = db.orders.find(x => x.id === +req.params.id); if (!o) return err(res, 404, 'Order not found');
  if (['Delivered', 'Cancelled', 'Out for delivery'].includes(o.status)) return err(res, 409, `A ${o.status.toLowerCase()} order cannot be changed here`);
  const { status, partnerId } = req.body || {};
  if (partnerId !== undefined) {
    const p = db.users.find(u => u.id === partnerId && u.role === 'partner' && u.status === 'approved');
    if (!p) return err(res, 400, 'Choose an approved delivery partner'); o.partnerId = p.id;
  }
  if (status !== undefined) {
    if (!['Placed', 'Confirmed', 'Packed', 'Cancelled'].includes(status)) return err(res, 400, 'Invalid status');
    if (status === 'Packed' && !o.partnerId) return err(res, 400, 'Assign a delivery partner before packing');
    if (status === 'Cancelled') o.items.forEach(i => { const p = db.products.find(x => x.id === i.productId); if (p) p.stock += i.qty; });
    o.status = status;
  }
  o.updatedAt = new Date().toISOString(); save(); res.json({ order: orderView(o, req.user) });
}));
app.post('/api/admin/orders/:id/reset-otp', auth(['admin']), wrap((req, res) => {
  const o = db.orders.find(x => x.id === +req.params.id); if (!o) return err(res, 404, 'Order not found');
  if (['Delivered', 'Cancelled'].includes(o.status)) return err(res, 409, 'This order is closed');
  o.otp = newOtp(); o.otpAttempts = 0; save(); sendSms(o.phone, `New delivery OTP for order #${o.id}: ${o.otp}`); res.json({ ok: true });
}));
app.get('/api/admin/stats', auth(['admin']), (req, res) => {
  const O = db.orders, d = O.filter(o => o.status === 'Delivered');
  res.json({ orders: O.length, inProgress: O.filter(o => !['Delivered', 'Cancelled'].includes(o.status)).length, delivered: d.length,
    deliveredValue: d.reduce((a, o) => a + o.total, 0), pendingApprovals: db.users.filter(u => u.status === 'pending').length });
});

/* ---------- customers (farmer / trader) ---------- */
app.post('/api/orders', auth(['farmer', 'trader']), wrap((req, res) => {
  const { items, address } = req.body || {};
  if (typeof address !== 'string' || address.trim().length < 8) return err(res, 400, 'Enter a full delivery address');
  if (!Array.isArray(items) || !items.length || items.length > 50) return err(res, 400, 'Your cart is empty');
  const lines = []; let total = 0;
  for (const it of items) {                                       // prices always come from the server
    const p = db.products.find(x => x.id === Number(it.productId)), q = Number(it.qty);
    if (!p || !Number.isInteger(q) || q < 1) return err(res, 400, 'Invalid item in cart');
    if (p.stock < q) return err(res, 409, `${p.name} has only ${p.stock} in stock`);
    lines.push({ productId: p.id, name: p.name, unit: p.unit, qty: q, price: p.price }); total += p.price * q;
  }
  lines.forEach(l => { db.products.find(p => p.id === l.productId).stock -= l.qty; });
  const o = { id: ++db.seq, userId: req.user.id, customer: req.user.name, phone: req.user.phone, items: lines, total, address: address.trim().slice(0, 300),
    status: 'Placed', partnerId: null, otp: newOtp(), otpAttempts: 0, createdAt: new Date().toISOString() };
  db.orders.push(o); save();
  sendSms(o.phone, `Order #${o.id} placed (Rs ${total}). Delivery OTP: ${o.otp}. Share it only with the delivery partner at your door.`);
  res.status(201).json({ order: orderView(o, req.user) });
}));
app.get('/api/orders', auth(['farmer', 'trader']), (req, res) =>
  res.json({ orders: db.orders.filter(o => o.userId === req.user.id).reverse().map(o => orderView(o, req.user)) }));

/* ---------- delivery partners ---------- */
app.get('/api/partner/orders', auth(['partner']), (req, res) =>
  res.json({ orders: db.orders.filter(o => o.partnerId === req.user.id).reverse().map(o => orderView(o, req.user)) }));
const mine = (req, res) => {
  const o = db.orders.find(x => x.id === +req.params.id && x.partnerId === req.user.id);
  if (!o) err(res, 404, 'Order not found'); return o;
};
app.post('/api/partner/orders/:id/start', auth(['partner']), wrap((req, res) => {
  const o = mine(req, res); if (!o) return;
  if (o.status !== 'Packed') return err(res, 409, 'The admin must pack this order first');
  o.status = 'Out for delivery'; o.updatedAt = new Date().toISOString(); save(); res.json({ order: orderView(o, req.user) });
}));
app.post('/api/partner/orders/:id/deliver', auth(['partner']), wrap((req, res) => {
  const o = mine(req, res); if (!o) return;
  if (o.status !== 'Out for delivery') return err(res, 409, 'This order is not out for delivery');
  if (o.otpAttempts >= 5) return err(res, 423, 'Too many wrong OTPs. Ask the admin to reset the OTP');
  if (!safeEq(String(req.body?.otp || '').trim(), o.otp)) {
    o.otpAttempts++; save();
    return err(res, 400, 'Wrong OTP', { attemptsLeft: Math.max(0, 5 - o.otpAttempts) });
  }
  o.status = 'Delivered'; o.deliveredAt = new Date().toISOString(); save(); res.json({ order: orderView(o, req.user) });
}));

/* ---------- live location & duty ---------- */
const locView = u => u.loc ? { lat: u.loc.lat, lng: u.loc.lng, accuracy: u.loc.acc, at: u.loc.at } : null;
// Partner app calls this every ~5-10 seconds while sharing (navigator.geolocation.watchPosition).
app.post('/api/partner/location', auth(['partner']), rateLimit({ windowMs: 60 * 1000, limit: 60 }), wrap((req, res) => {
  const lat = Number(req.body?.lat), lng = Number(req.body?.lng);
  if (!(lat >= -90 && lat <= 90) || !(lng >= -180 && lng <= 180)) return err(res, 400, 'Invalid location');
  req.user.loc = { lat, lng, acc: Number(req.body?.accuracy) || null, at: Date.now() };
  save(); res.json({ ok: true });
}));
app.patch('/api/partner/duty', auth(['partner']), wrap((req, res) => {
  req.user.duty = !!req.body?.duty; if (!req.user.duty) req.user.loc = null; save(); res.json({ duty: req.user.duty });
}));
// Admin: every approved partner with their last position and active orders (poll every 5 s).
app.get('/api/admin/partners', auth(['admin']), (req, res) => res.json({ partners: db.users.filter(u => u.role === 'partner' && u.status === 'approved').map(u => ({
  ...publicUser(u), duty: !!u.duty, location: locView(u),
  activeOrders: db.orders.filter(o => o.partnerId === u.id && !['Delivered', 'Cancelled'].includes(o.status)).map(o => ({ id: o.id, status: o.status, customer: o.customer, address: o.address })) })) }));
// Customer: track the partner only while their own order is out for delivery.
app.get('/api/orders/:id/track', auth(['farmer', 'trader']), wrap((req, res) => {
  const o = db.orders.find(x => x.id === +req.params.id && x.userId === req.user.id); if (!o) return err(res, 404, 'Order not found');
  if (o.status !== 'Out for delivery') return err(res, 409, 'Tracking starts when the order is out for delivery');
  const p = db.users.find(u => u.id === o.partnerId);
  res.json({ status: o.status, partner: p ? { name: p.name, phone: p.phone } : null, location: p ? locView(p) : null });
}));

/* ---------- static frontend (optional) + errors ---------- */
const PUB = path.join(__dirname, 'public');
if (fs.existsSync(PUB)) app.use(express.static(PUB));
app.use('/api', (req, res) => err(res, 404, 'Not found'));
app.use((e, req, res, next) => err(res, e.type === 'entity.parse.failed' ? 400 : 500, e.type === 'entity.parse.failed' ? 'Invalid JSON' : 'Something went wrong'));

app.listen(PORT, () => console.log(`Jay Bhutnath Agri API running on http://localhost:${PORT}`));
