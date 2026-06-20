const Database = require('better-sqlite3');
const db = new Database('users.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    stripe_customer_id TEXT,
    stripe_subscription_id TEXT,
    subscription_status TEXT DEFAULT 'inactive',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

module.exports = {
  createUser(email, passwordHash) {
    const stmt = db.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)');
    const info = stmt.run(email, passwordHash);
    return info.lastInsertRowid;
  },

  findByEmail(email) {
    return db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  },

  findById(id) {
    return db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  },

  setStripeCustomerId(userId, customerId) {
    db.prepare('UPDATE users SET stripe_customer_id = ? WHERE id = ?').run(customerId, userId);
  },

  findByStripeCustomerId(customerId) {
    return db.prepare('SELECT * FROM users WHERE stripe_customer_id = ?').get(customerId);
  },

  updateSubscription(customerId, subscriptionId, status) {
    db.prepare(
      'UPDATE users SET stripe_subscription_id = ?, subscription_status = ? WHERE stripe_customer_id = ?'
    ).run(subscriptionId, status, customerId);
  },

  hasActiveSubscription(user) {
    return user && (user.subscription_status === 'active' || user.subscription_status === 'trialing');
  }
};
