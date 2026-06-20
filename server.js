require('dotenv').config();
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcryptjs');
const Stripe = require('stripe');
const path = require('path');
const db = require('./db');

const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;
const DOMAIN = process.env.DOMAIN || `http://localhost:${PORT}`;

// --- IMPORTANT : le webhook Stripe a besoin du corps brut (raw body),
// donc on le déclare AVANT express.json() et seulement sur sa propre route.
app.post('/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Échec de vérification du webhook :', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  switch (event.type) {
    case 'checkout.session.completed': {
      const session = event.data.object;
      const userId = session.client_reference_id;
      const customerId = session.customer;
      const user = db.findById(userId);
      if (user) {
        db.setStripeCustomerId(user.id, customerId);
      }
      break;
    }
    case 'customer.subscription.created':
    case 'customer.subscription.updated': {
      const subscription = event.data.object;
      db.updateSubscription(subscription.customer, subscription.id, subscription.status);
      break;
    }
    case 'customer.subscription.deleted': {
      const subscription = event.data.object;
      db.updateSubscription(subscription.customer, subscription.id, 'canceled');
      break;
    }
  }

  res.json({ received: true });
});

// --- Middlewares standards (après le webhook)
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  store: new SQLiteStore({ db: 'sessions.db' }),
  secret: process.env.SESSION_SECRET || 'change-moi-en-prod',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 jours
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production'
  }
}));

function requireLogin(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  next();
}

function sendView(res, file) {
  res.sendFile(path.join(__dirname, 'views', file));
}

// --- Pages publiques
app.get('/', (req, res) => {
  if (req.session.userId) return res.redirect('/app');
  sendView(res, 'login.html');
});

app.get('/login', (req, res) => sendView(res, 'login.html'));

// --- Inscription
app.post('/api/signup', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password || password.length < 6) {
    return res.status(400).json({ error: 'Email invalide ou mot de passe trop court (min. 6 caractères).' });
  }
  const existing = db.findByEmail(email);
  if (existing) {
    return res.status(400).json({ error: 'Un compte existe déjà avec cet email.' });
  }
  const hash = await bcrypt.hash(password, 10);
  const userId = db.createUser(email, hash);
  req.session.userId = userId;
  res.json({ ok: true });
});

// --- Connexion
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = db.findByEmail(email);
  if (!user) return res.status(400).json({ error: 'Email ou mot de passe incorrect.' });

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(400).json({ error: 'Email ou mot de passe incorrect.' });

  req.session.userId = user.id;
  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// --- Créer une session de paiement Stripe Checkout
app.post('/api/create-checkout-session', requireLogin, async (req, res) => {
  const user = db.findById(req.session.userId);

  try {
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      payment_method_types: ['card'],
      line_items: [{ price: process.env.STRIPE_PRICE_ID, quantity: 1 }],
      client_reference_id: String(user.id),
      customer_email: user.email,
      success_url: `${DOMAIN}/app?success=true`,
      cancel_url: `${DOMAIN}/pricing?canceled=true`,
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Impossible de créer la session de paiement.' });
  }
});

// --- Portail client Stripe (gérer/annuler l'abonnement)
app.post('/api/create-portal-session', requireLogin, async (req, res) => {
  const user = db.findById(req.session.userId);
  if (!user.stripe_customer_id) {
    return res.status(400).json({ error: 'Aucun abonnement trouvé.' });
  }
  const portalSession = await stripe.billingPortal.sessions.create({
    customer: user.stripe_customer_id,
    return_url: `${DOMAIN}/app`,
  });
  res.json({ url: portalSession.url });
});

// --- Page d'abonnement (après inscription, avant paiement)
app.get('/pricing', requireLogin, (req, res) => sendView(res, 'pricing.html'));

// --- L'application elle-même : mur payant
app.get('/app', requireLogin, (req, res) => {
  const user = db.findById(req.session.userId);
  if (!db.hasActiveSubscription(user)) {
    return res.redirect('/pricing');
  }
  sendView(res, 'tracker.html');
});

// --- Infos utilisateur pour le frontend
app.get('/api/me', requireLogin, (req, res) => {
  const user = db.findById(req.session.userId);
  res.json({
    email: user.email,
    active: db.hasActiveSubscription(user)
  });
});

app.listen(PORT, () => {
  console.log(`✅ Serveur lancé sur ${DOMAIN}`);
});
