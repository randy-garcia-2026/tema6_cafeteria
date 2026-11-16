const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const PORT = 3000;
// En producción define JWT_SECRET como variable de entorno
const JWT_SECRET = process.env.JWT_SECRET || 'kohi-dev-secret-cambiar';

const db = new Database(path.join(__dirname, 'kohi.db'));
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const emailValido = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);

// Registro: hashea password, asigna siguiente posición en la cola
const insertar = db.transaction((name, email, hash) => {
  const { next } = db.prepare('SELECT COALESCE(MAX(position), 0) + 1 AS next FROM waitlist').get();
  db.prepare('INSERT INTO waitlist (name, email, password_hash, position) VALUES (?, ?, ?, ?)')
    .run(name, email, hash, next);
  return next;
});

app.post('/api/register', (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Faltan campos: name, email y password son obligatorios' });
  }
  if (!emailValido(email)) return res.status(400).json({ error: 'Email no válido' });

  const emailNorm = String(email).trim().toLowerCase();
  try {
    const hash = bcrypt.hashSync(String(password), 10);
    const position = insertar(String(name).trim(), emailNorm, hash);
    res.status(201).json({ success: true, message: 'Registro exitoso', position });
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({ error: 'Este email ya está registrado' });
    }
    console.error(err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'Faltan campos: email y password son obligatorios' });
  }
  const user = db.prepare('SELECT * FROM waitlist WHERE email = ?').get(String(email).trim().toLowerCase());
  if (!user || !bcrypt.compareSync(String(password), user.password_hash)) {
    return res.status(401).json({ error: 'Credenciales inválidas' });
  }
  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ success: true, token });
});

// Middleware JWT: espera "Authorization: Bearer <token>"
function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Token requerido' });
  try {
    req.userId = jwt.verify(token, JWT_SECRET).id;
    next();
  } catch {
    res.status(401).json({ error: 'Token inválido o expirado' });
  }
}

app.get('/api/me', auth, (req, res) => {
  const user = db.prepare('SELECT id, name, email, position FROM waitlist WHERE id = ?').get(req.userId);
  if (!user) return res.status(401).json({ error: 'Usuario no encontrado' });
  const { total } = db.prepare('SELECT COUNT(*) AS total FROM waitlist').get();
  res.json({ ...user, total });
});

app.listen(PORT, () => console.log(`Kōhi escuchando en http://localhost:${PORT}`));
