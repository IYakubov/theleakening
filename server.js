const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const dbFile = './db.sqlite';
const db = new sqlite3.Database(dbFile);

// Ensure DB exists
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    title TEXT,
    duration INTEGER,
    created_at INTEGER,
    status TEXT DEFAULT 'active'
  )`);
});

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
  secret: 'leakening-secret',
  resave: false,
  saveUninitialized: true
}));
app.use(express.static(path.join(__dirname, 'public')));

// Middleware to check login
function checkAuth(req, res, next) {
  if (!req.session.user) return res.redirect('/');
  next();
}

// --- Routes ---

// Login page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Main app page
app.get('/main', checkAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'main.html'));
});

// Progress page
app.get('/progress', checkAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'progress.html'));
});
app.get('/about', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'about.html'));
});

// History page
app.get('/history', checkAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'history.html'));
});

// Auth route
app.post('/auth', (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
    if (err) return res.status(500).send('DB error');

    if (!user) {
      const hash = await bcrypt.hash(password, 10);
      db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, hash], function (err) {
        if (err) return res.status(500).send('Registration error');
        req.session.user = { id: this.lastID, username };
        return res.redirect('/main');
      });
    } else {
      const match = await bcrypt.compare(password, user.password);
      if (!match) return res.redirect('/?error=1');
      req.session.user = { id: user.id, username: user.username };
      return res.redirect('/main');
    }
  });
});

// Create task
app.post('/create-task', checkAuth, (req, res) => {
  const { title, duration } = req.body;
  const userId = req.session.user.id;

  db.all(`SELECT * FROM tasks WHERE user_id = ? AND status = 'active'`, [userId], (err, rows) => {
    if (err) return res.status(500).send('DB error');

    const currentTime = Date.now();
    const validTasks = rows.filter(task => currentTime <= (task.created_at + task.duration * 60000));

    if (validTasks.length >= 5) return res.status(400).send('You already have 5 active tasks');

    db.run(
      `INSERT INTO tasks (user_id, title, duration, created_at) VALUES (?, ?, ?, ?)`,
      [userId, title, duration, currentTime],
      function (err) {
        if (err) return res.status(500).send('Task creation failed');
        res.sendStatus(200);
      }
    );
  });
});

// Mark a single task completed
app.post('/complete-task', checkAuth, (req, res) => {
  const taskId = req.body.id;
  db.run(`UPDATE tasks SET status = 'completed' WHERE id = ?`, [taskId], err => {
    if (err) return res.status(500).send('Update failed');
    res.sendStatus(200);
  });
});

// Mark all tasks completed
app.post('/finish-tasks', checkAuth, (req, res) => {
  const userId = req.session.user.id;

  db.all(`SELECT * FROM tasks WHERE user_id = ? AND status = 'active'`, [userId], (err, rows) => {
    if (err) return res.status(500).send('DB error');

    const now = Date.now();
    const validIds = rows
      .filter(task => now <= task.created_at + task.duration * 60000)
      .map(task => task.id);

    if (validIds.length === 0) return res.sendStatus(200); // nothing valid to complete

    const placeholders = validIds.map(() => '?').join(',');
    db.run(`UPDATE tasks SET status = 'completed' WHERE id IN (${placeholders})`, validIds, err => {
      if (err) return res.status(500).send('Update failed');
      res.sendStatus(200);
    });
  });
});



// Get all tasks for logged-in user
app.get('/get-tasks', checkAuth, (req, res) => {
  const userId = req.session.user.id;
  db.all(`SELECT * FROM tasks WHERE user_id = ? ORDER BY created_at DESC`, [userId], (err, rows) => {
    if (err) return res.status(500).send('Fetch failed');
    res.json(rows);
  });
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

// Start server
const PORT = 3000;
app.listen(PORT, () => console.log(`✅ Server running at http://localhost:${PORT}`));
