import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import csrf from 'csurf';
import bcrypt from 'bcryptjs';
import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const port = Number(process.env.PORT || 3000);
const dbPath = path.join(__dirname, 'data', 'aviara-auth.db');
fs.mkdirSync(path.dirname(dbPath), { recursive: true });

const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fullName TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    passwordHash TEXT NOT NULL,
    createdAt TEXT NOT NULL,
    updatedAt TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER NOT NULL,
    token TEXT NOT NULL UNIQUE,
    expiresAt TEXT NOT NULL,
    createdAt TEXT NOT NULL,
    FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
  CREATE INDEX IF NOT EXISTS idx_reset_tokens_userId ON password_reset_tokens(userId);

  CREATE TABLE IF NOT EXISTS new_joiner_invites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    tokenHash TEXT NOT NULL UNIQUE,
    expiresAt TEXT NOT NULL,
    usedAt TEXT,
    createdAt TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS new_joiners (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER NOT NULL UNIQUE,
    fullName TEXT NOT NULL DEFAULT '',
    personalEmail TEXT NOT NULL DEFAULT '',
    assignedCompany TEXT NOT NULL DEFAULT '',
    department TEXT NOT NULL DEFAULT '',
    designation TEXT NOT NULL DEFAULT '',
    expectedJoiningDate TEXT NOT NULL DEFAULT '',
    hrContact TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'IN_PROGRESS',
    submittedAt TEXT,
    createdAt TEXT NOT NULL,
    updatedAt TEXT NOT NULL,
    FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS onboarding_documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    documentKey TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    version TEXT NOT NULL,
    effectiveDate TEXT NOT NULL,
    lastUpdated TEXT NOT NULL,
    description TEXT NOT NULL,
    required INTEGER NOT NULL DEFAULT 1,
    active INTEGER NOT NULL DEFAULT 1
  );

  CREATE TABLE IF NOT EXISTS onboarding_acknowledgements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    joinerId INTEGER NOT NULL,
    documentId INTEGER NOT NULL,
    documentVersion TEXT NOT NULL,
    status TEXT NOT NULL,
    acknowledgedAt TEXT NOT NULL,
    UNIQUE(joinerId, documentId),
    FOREIGN KEY (joinerId) REFERENCES new_joiners(id) ON DELETE CASCADE,
    FOREIGN KEY (documentId) REFERENCES onboarding_documents(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS onboarding_audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    joinerId INTEGER NOT NULL,
    eventType TEXT NOT NULL,
    documentId INTEGER,
    documentVersion TEXT,
    createdAt TEXT NOT NULL,
    FOREIGN KEY (joinerId) REFERENCES new_joiners(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS logo_feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL DEFAULT '',
    rating INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
    feedback TEXT NOT NULL,
    createdAt TEXT NOT NULL,
    notificationStatus TEXT NOT NULL DEFAULT 'PENDING'
  );

  CREATE INDEX IF NOT EXISTS idx_logo_feedback_notificationStatus ON logo_feedback(notificationStatus);
`);

const onboardingDocuments = [
  ['employment-terms', 'Employment Terms', 'Terms & Conditions', 'CONFIGURE-1.0', 'Pending HR publication', 'Pending official Aviara HR document. Replace this configuration record before launch.'],
  ['confidentiality', 'Confidentiality', 'Terms & Conditions', 'CONFIGURE-1.0', 'Pending HR publication', 'Pending official Aviara confidentiality document. Replace this configuration record before launch.'],
  ['intellectual-property', 'Intellectual Property', 'Terms & Conditions', 'CONFIGURE-1.0', 'Pending HR publication', 'Pending official Aviara intellectual property document. Replace this configuration record before launch.'],
  ['code-of-conduct', 'Code of Conduct', 'Company Policies', 'CONFIGURE-1.0', 'Pending HR publication', 'Professional expectations covering respect, integrity, confidentiality and reporting concerns.'],
  ['privacy-data', 'Data Protection & Privacy', 'Company Policies', 'CONFIGURE-1.0', 'Pending HR publication', 'Pending official Aviara privacy and data protection policy. Replace this configuration record before launch.'],
  ['information-security', 'Information Security', 'Technology & Security', 'CONFIGURE-1.0', 'Pending HR publication', 'General security expectations: protect accounts, devices, data and access permissions.'],
  ['company-assets', 'Company Assets', 'Company Policies', 'CONFIGURE-1.0', 'Pending HR publication', 'Pending official Aviara company assets policy. Replace this configuration record before launch.']
];
const insertOnboardingDocument = db.prepare(`INSERT OR IGNORE INTO onboarding_documents (documentKey, name, category, version, effectiveDate, lastUpdated, description, required, active) VALUES (?, ?, ?, ?, ?, ?, ?, 1, 1)`);
onboardingDocuments.forEach(([key, name, category, version, date, description]) => insertOnboardingDocument.run(key, name, category, version, date, date, description));

const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const passwordPattern = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,72}$/;
const allowedTypes = new Set([
  'General Enquiry', 'Business Enquiry', 'Partnership', 'Careers',
  'Technology', 'Aviara Air', 'Aviara Aviation', 'Other'
]);
const fields = ['fullName', 'email', 'enquiryType', 'subject', 'message'];
const predictionFields = ['flightNumber', 'departureAirport', 'arrivalAirport', 'travelDate', 'scheduledDeparture'];
const airportBaselines = { BOM: 16, DEL: 21, LHR: 18, JFK: 20, DXB: 14, SIN: 11, DOH: 13, CDG: 19, FRA: 17, AMS: 15 };
const emailProviderConfigured = Boolean(process.env.EMAIL_API_KEY && process.env.EMAIL_FROM_ADDRESS && process.env.ENQUIRY_RECEIVER_EMAIL);

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '12kb' }));
app.use(express.urlencoded({ extended: false, limit: '12kb' }));
app.get('/', (_req, res) => res.redirect('/aviaratechmain.html'));
app.get('/aviaralogin.html', (_req, res) => res.redirect('/login'));
app.get('/aviarafeedback.html', (_req, res) => res.redirect('/logo-feedback'));
app.get('/aviara-newjoiners.html', (_req, res) => res.redirect('/new-joiners'));
app.use(express.static(__dirname, { index: false }));
app.use(session({
  name: 'aviara.sid',
  secret: process.env.SESSION_SECRET || 'aviara-super-secret-session-key-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 24 * 7,
    path: '/'
  }
}));
app.use(csrf());
app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  res.locals.csrfToken = req.csrfToken();
  next();
});

app.get('/logo-feedback', (req, res) => {
  const html = renderPage('aviara-logo-feedback.html', { csrfToken: req.csrfToken(), user: req.session.user || null });
  res.type('html').send(html);
});

const enquiryLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Unable to send enquiry.' }
});

const predictionLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Unable to generate prediction.' }
});

const signupLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many sign-up attempts. Please try again later.' }
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 12,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Please try again later.' }
});

const resetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 8,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many password reset attempts. Please try again later.' }
});

const logoFeedbackLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { success: false, message: 'Too many feedback submissions. Please try again later.' }
});

function clean(value, maxLength) {
  return String(value ?? '')
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/<[^>]*>/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, maxLength);
}

function validateLogoFeedback(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return { error: 'Enter a rating and feedback.' };

  const rating = Number(body.rating);
  const feedback = clean(body.feedback, 2000);
  const name = clean(body.name, 120);
  const submissionTimestamp = clean(body.submissionTimestamp, 40);

  if (!Number.isInteger(rating) || rating < 1 || rating > 5) return { error: 'Choose a rating from 1 to 5 stars.' };
  if (!feedback || feedback.length < 3) return { error: 'Share a little feedback about the logo.' };
  if (String(body.website ?? '').trim()) return { error: 'Invalid submission.' };
  if (submissionTimestamp) {
    const parsedTimestamp = new Date(submissionTimestamp);
    if (Number.isNaN(parsedTimestamp.getTime())) return { error: 'Invalid submission time.' };
  }

  return { rating, feedback, name };
}

async function sendLogoFeedbackWhatsApp(feedbackRecord) {
  const accessToken = process.env.WHATSAPP_ACCESS_TOKEN;
  const phoneNumberId = process.env.WHATSAPP_PHONE_NUMBER_ID;
  const adminPhone = process.env.WHATSAPP_ADMIN_PHONE;
  if (!accessToken || !phoneNumberId || !adminPhone) {
    console.error('Logo feedback notification skipped: WhatsApp configuration is incomplete.');
    return false;
  }

  const message = [
    '🔔 NEW AVIARA.TECH LOGO FEEDBACK',
    '',
    `⭐ Rating: ${feedbackRecord.rating}/5`,
    '',
    '💬 Feedback:',
    feedbackRecord.feedback,
    '',
    '👤 Name:',
    feedbackRecord.name || 'Anonymous',
    '',
    '🕒 Submitted:',
    new Date(feedbackRecord.createdAt).toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short', timeZone: 'Asia/Kolkata' })
  ].join('\n');

  try {
    const response = await fetch(`https://graph.facebook.com/v21.0/${encodeURIComponent(phoneNumberId)}/messages`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        messaging_product: 'whatsapp',
        recipient_type: 'individual',
        to: adminPhone,
        type: 'text',
        text: { preview_url: false, body: message }
      }),
      signal: AbortSignal.timeout(10000)
    });
    if (!response.ok) throw new Error(`WhatsApp API returned HTTP ${response.status}`);
    return true;
  } catch (error) {
    console.error('Logo feedback WhatsApp notification failed:', error.message);
    return false;
  }
}

function getSafeUser(user) {
  if (!user) return null;
  return {
    id: user.id,
    fullName: user.fullName,
    email: user.email
  };
}

function validatePayload(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return null;
  const values = Object.fromEntries(fields.map(field => [field, clean(body[field], field === 'message' ? 5000 : 160)]));
  const missing = fields.some(field => !values[field]);
  const validEmail = emailPattern.test(values.email) && values.email.length <= 254;
  const validType = allowedTypes.has(values.enquiryType);
  if (missing || !validEmail || !validType || String(body.website ?? '').trim()) return null;
  return values;
}

function validatePredictionPayload(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return { errors: { form: 'Enter valid flight details.' } };
  const values = Object.fromEntries(predictionFields.map(field => [field, clean(body[field], 80)]));
  const errors = {};
  const labels = { flightNumber: 'Flight number', departureAirport: 'Departure airport', arrivalAirport: 'Arrival airport', travelDate: 'Travel date', scheduledDeparture: 'Scheduled departure' };
  predictionFields.forEach(field => { if (!values[field]) errors[field] = `${labels[field]} is required.`; });
  values.departureAirport = values.departureAirport.toUpperCase();
  values.arrivalAirport = values.arrivalAirport.toUpperCase();
  const airportCode = /^[A-Z]{3}$/;
  if (values.departureAirport && !airportCode.test(values.departureAirport)) errors.departureAirport = 'Use a three-letter airport code.';
  if (values.arrivalAirport && !airportCode.test(values.arrivalAirport)) errors.arrivalAirport = 'Use a three-letter airport code.';
  const parsedDate = new Date(`${values.travelDate}T00:00:00Z`);
  if (values.travelDate && (!/^\d{4}-\d{2}-\d{2}$/.test(values.travelDate) || Number.isNaN(parsedDate.getTime()) || parsedDate.toISOString().slice(0, 10) !== values.travelDate)) errors.travelDate = 'Use a valid travel date.';
  const [hours, minutes] = values.scheduledDeparture.split(':').map(Number);
  if (values.scheduledDeparture && (!/^\d{2}:\d{2}$/.test(values.scheduledDeparture) || hours > 23 || minutes > 59)) errors.scheduledDeparture = 'Use a valid departure time.';
  if (Object.keys(errors).length) return { errors };
  return { values };
}

function hashText(value) {
  return [...value].reduce((total, character) => total + character.charCodeAt(0), 0);
}

function createPrototypePrediction(flight) {
  const [hour] = flight.scheduledDeparture.split(':').map(Number);
  const date = new Date(`${flight.travelDate}T00:00:00Z`);
  const weekday = date.getUTCDay();
  const flightDigits = Number((flight.flightNumber.match(/\d+/) || ['0'])[0]);
  const departureBaseline = airportBaselines[flight.departureAirport] || 12 + hashText(flight.departureAirport) % 11;
  const arrivalBaseline = airportBaselines[flight.arrivalAirport] || 12 + hashText(flight.arrivalAirport) % 11;
  const routeSignal = Math.abs(hashText(flight.departureAirport) - hashText(flight.arrivalAirport)) % 10;
  const peakHour = (hour >= 6 && hour <= 10) || (hour >= 16 && hour <= 20);
  const lateNight = hour >= 22 || hour < 5;
  const timeImpact = peakHour ? 15 : lateNight ? 4 : 8;
  const dayImpact = weekday === 1 || weekday === 5 ? 10 : weekday === 0 || weekday === 6 ? 3 : 6;
  const flightSignal = flightDigits % 13;
  const probability = Math.min(91, Math.max(8, Math.round((departureBaseline + arrivalBaseline) / 2 + timeImpact + dayImpact + routeSignal + flightSignal)));
  const riskLevel = probability >= 66 ? 'HIGH' : probability >= 38 ? 'MODERATE' : 'LOW';
  const estimatedDelayMin = Math.max(5, Math.round(probability / 4));
  const estimatedDelayMax = estimatedDelayMin + 10 + (routeSignal % 9);
  const confidence = Math.min(86, 56 + (airportBaselines[flight.departureAirport] ? 8 : 2) + (airportBaselines[flight.arrivalAirport] ? 6 : 2) + (flightDigits % 8));
  const impact = value => value >= 13 ? 'High' : value >= 8 ? 'Medium' : 'Low';
  return {
    success: true,
    modelStatus: 'prototype',
    riskLevel,
    delayProbability: probability,
    estimatedDelayMin,
    estimatedDelayMax,
    confidence,
    factors: [
      { name: 'Scheduled Departure Time', impact: impact(timeImpact) },
      { name: 'Departure Airport Baseline', impact: impact(departureBaseline) },
      { name: 'Arrival Airport Baseline', impact: impact(arrivalBaseline) },
      { name: 'Travel Day Pattern', impact: impact(dayImpact) },
      { name: 'Flight Number Signal', impact: impact(flightSignal) },
      { name: 'Route Signal', impact: impact(routeSignal) }
    ],
    summary: `Prototype model estimates a ${riskLevel.toLowerCase()} delay risk from the submitted flight profile.`,
    timestamp: new Date().toISOString()
  };
}

function renderPage(fileName, { csrfToken, user } = {}) {
  const templatePath = path.join(__dirname, fileName);
  const html = fs.readFileSync(templatePath, 'utf8');
  const page = html
    .replace(/__CSRF_TOKEN__/g, csrfToken || '')
    .replace(/__CURRENT_USER_NAME__/g, user?.fullName || 'Aviara Member')
    .replace(/__CURRENT_USER_EMAIL__/g, user?.email || '');
  return page;
}

function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  return next();
}

function validateSignupRequest(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return { error: 'Complete all required details.' };

  const fullName = clean(body.fullName, 120);
  const email = clean(body.email, 254).toLowerCase();
  const password = String(body.password ?? '');
  const confirmPassword = String(body.confirmPassword ?? '');

  if (!fullName || fullName.length < 2) return { error: 'Enter your full name.' };
  if (!emailPattern.test(email)) return { error: 'Enter a valid email address.' };
  if (!passwordPattern.test(password)) return { error: 'Use at least 8 characters, including uppercase, lowercase, a number and a symbol.' };
  if (password !== confirmPassword) return { error: 'Passwords do not match.' };
  if (String(body.website ?? '').trim()) return { error: 'Invalid submission.' };

  return { fullName, email, password };
}

function validateLoginRequest(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return { error: 'Enter your email and password.' };
  const email = clean(body.email, 254).toLowerCase();
  const password = String(body.password ?? '');
  if (!emailPattern.test(email)) return { error: 'Enter a valid email address.' };
  if (!password || password.length > 128) return { error: 'Enter a valid password.' };
  if (String(body.website ?? '').trim()) return { error: 'Invalid submission.' };
  return { email, password };
}

function setSessionUser(req, user) {
  req.session.user = getSafeUser(user);
}

function getJoinerForUser(userId) {
  return db.prepare('SELECT * FROM new_joiners WHERE userId = ?').get(userId);
}

function requireNewJoiner(req, res, next) {
  if (!req.session.user) return res.redirect('/login?returnTo=%2Fnew-joiners');
  if (!getJoinerForUser(req.session.user.id)) return res.status(403).send('New joiner access must be issued by Aviara HR.');
  return next();
}

function validateNewJoinerProfile(body) {
  const profile = {
    fullName: clean(body?.fullName, 120),
    personalEmail: clean(body?.personalEmail, 254).toLowerCase(),
    assignedCompany: clean(body?.assignedCompany, 80),
    department: clean(body?.department, 100),
    designation: clean(body?.designation, 100),
    expectedJoiningDate: clean(body?.expectedJoiningDate, 10),
    hrContact: clean(body?.hrContact, 160)
  };
  if (!profile.fullName || profile.fullName.length < 2) return { error: 'Enter your full name.' };
  if (!emailPattern.test(profile.personalEmail)) return { error: 'Enter a valid personal email address.' };
  if (!['Aviara Tech', 'Aviara Air', 'Aviara Intelligence', 'Aviara Aviation', 'Aviara Tourism'].includes(profile.assignedCompany)) return { error: 'Select your assigned company.' };
  if (!profile.department || !profile.designation || !/^\d{4}-\d{2}-\d{2}$/.test(profile.expectedJoiningDate) || !profile.hrContact) return { error: 'Complete all required joiner information.' };
  return profile;
}

app.get('/login', (req, res) => {
  const html = renderPage('login.html', { csrfToken: req.csrfToken(), user: req.session.user || null });
  res.type('html').send(html);
});

app.get('/signup', (req, res) => {
  const html = renderPage('signup.html', { csrfToken: req.csrfToken(), user: req.session.user || null });
  res.type('html').send(html);
});

app.get('/forgot-password', (req, res) => {
  const html = renderPage('forgot-password.html', { csrfToken: req.csrfToken(), user: req.session.user || null });
  res.type('html').send(html);
});

app.get('/reset-password', (req, res) => {
  const html = renderPage('reset-password.html', { csrfToken: req.csrfToken(), user: req.session.user || null });
  res.type('html').send(html);
});

app.get('/new-joiners', requireNewJoiner, (req, res) => {
  const html = renderPage('aviara-newjoiners.html', { csrfToken: req.csrfToken(), user: req.session.user || null });
  res.type('html').send(html);
});

app.get('/new-joiners/invite/:token', (req, res) => {
  if (!req.session.user) return res.redirect(`/login?returnTo=${encodeURIComponent(`/new-joiners/invite/${req.params.token}`)}`);
  const tokenHash = crypto.createHash('sha256').update(String(req.params.token)).digest('hex');
  const invite = db.prepare('SELECT * FROM new_joiner_invites WHERE tokenHash = ? AND usedAt IS NULL').get(tokenHash);
  if (!invite || new Date(invite.expiresAt).getTime() < Date.now() || invite.email !== req.session.user.email) {
    return res.status(403).send('This Aviara new joiner invitation is invalid, expired or assigned to another email.');
  }
  const existing = getJoinerForUser(req.session.user.id);
  if (!existing) {
    const now = new Date().toISOString();
    db.prepare('INSERT INTO new_joiners (userId, fullName, personalEmail, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?)').run(req.session.user.id, req.session.user.fullName, req.session.user.email, now, now);
  }
  db.prepare('UPDATE new_joiner_invites SET usedAt = ? WHERE id = ?').run(new Date().toISOString(), invite.id);
  return res.redirect('/new-joiners');
});

app.get('/my-aviara', requireAuth, (req, res) => {
  const html = renderPage('my-aviara.html', { csrfToken: req.csrfToken(), user: req.session.user || null });
  res.type('html').send(html);
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.get('/api/auth/session', (req, res) => {
  res.json({
    authenticated: Boolean(req.session.user),
    user: req.session.user || null
  });
});

app.post('/api/auth/signup', signupLimiter, async (req, res) => {
  const validation = validateSignupRequest(req.body);
  if (validation.error) {
    return res.status(400).json({ success: false, message: validation.error });
  }

  const existingUser = db.prepare('SELECT id FROM users WHERE email = ?').get(validation.email);
  if (existingUser) {
    return res.status(409).json({ success: false, message: 'An account with this email already exists.' });
  }

  const passwordHash = await bcrypt.hash(validation.password, 12);
  const now = new Date().toISOString();
  try {
    const statement = db.prepare(`
      INSERT INTO users (fullName, email, passwordHash, createdAt, updatedAt)
      VALUES (?, ?, ?, ?, ?)
    `);
    const user = statement.run(validation.fullName, validation.email, passwordHash, now, now);
    const createdUser = db.prepare('SELECT id, fullName, email FROM users WHERE id = ?').get(user.lastInsertRowid);
    setSessionUser(req, createdUser);

    return res.status(201).json({
      success: true,
      message: 'Account created successfully.',
      redirectUrl: '/my-aviara'
    });
  } catch (error) {
    console.error('Sign up failed:', error);
    return res.status(500).json({ success: false, message: 'Unable to create account.' });
  }
});

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const validation = validateLoginRequest(req.body);
  if (validation.error) {
    return res.status(400).json({ success: false, message: validation.error });
  }

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(validation.email);
  if (!user) {
    return res.status(401).json({ success: false, message: 'Invalid email or password.' });
  }

  const passwordMatches = await bcrypt.compare(validation.password, user.passwordHash);
  if (!passwordMatches) {
    return res.status(401).json({ success: false, message: 'Invalid email or password.' });
  }

  setSessionUser(req, user);
  return res.json({
    success: true,
    message: 'Signed in successfully.',
    redirectUrl: '/my-aviara'
  });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('aviara.sid');
    return res.json({ success: true, redirectUrl: '/login' });
  });
});

async function sendPasswordResetEmail(email, token) {
  if (!emailProviderConfigured) {
    return { enabled: false, message: 'Email delivery is pending configuration. Add your provider settings to enable password reset emails securely.' };
  }

  const resetUrl = `${process.env.APP_URL || 'http://localhost:3000'}/reset-password?token=${encodeURIComponent(token)}`;
  const emailText = [
    'Aviara Account Password Reset',
    '',
    `We received a request to reset the password for ${email}.`,
    '',
    `Reset your password here: ${resetUrl}`,
    '',
    'This link expires in 60 minutes.'
  ].join('\n');

  try {
    const providerResponse = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${process.env.EMAIL_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        from: process.env.EMAIL_FROM_ADDRESS,
        to: [email],
        subject: 'Aviara Account Password Reset',
        text: emailText
      })
    });

    if (!providerResponse.ok) {
      throw new Error('Email provider rejected the request');
    }

    return { enabled: true, message: 'If an account exists, a secure reset link has been prepared.' };
  } catch (error) {
    console.error('Password reset email failed:', error.message);
    return { enabled: false, message: 'Password reset is installed but email delivery is still pending configuration.' };
  }
}

app.post('/api/auth/forgot-password', resetLimiter, async (req, res) => {
  const body = req.body || {};
  const email = clean(body.email, 254).toLowerCase();
  if (!emailPattern.test(email)) {
    return res.status(400).json({ success: false, message: 'Enter a valid email address.' });
  }

  const user = db.prepare('SELECT id, email FROM users WHERE email = ?').get(email);
  if (!user) {
    return res.status(200).json({
      success: true,
      message: 'If an account exists, a password reset link will be available once email delivery is configured.'
    });
  }

  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();
  db.prepare('DELETE FROM password_reset_tokens WHERE userId = ?').run(user.id);
  db.prepare('INSERT INTO password_reset_tokens (userId, token, expiresAt, createdAt) VALUES (?, ?, ?, ?)').run(user.id, token, expiresAt, new Date().toISOString());

  const emailResult = await sendPasswordResetEmail(user.email, token);
  return res.status(200).json({
    success: true,
    message: emailResult.message
  });
});

app.post('/api/auth/reset-password', resetLimiter, async (req, res) => {
  const token = clean(req.body?.token, 128);
  const password = String(req.body?.password ?? '');
  const confirmPassword = String(req.body?.confirmPassword ?? '');

  if (!token) {
    return res.status(400).json({ success: false, message: 'Reset token is required.' });
  }
  if (!passwordPattern.test(password)) {
    return res.status(400).json({ success: false, message: 'Use at least 8 characters, including uppercase, lowercase, a number and a symbol.' });
  }
  if (password !== confirmPassword) {
    return res.status(400).json({ success: false, message: 'Passwords do not match.' });
  }

  const resetRecord = db.prepare('SELECT * FROM password_reset_tokens WHERE token = ?').get(token);
  if (!resetRecord) {
    return res.status(400).json({ success: false, message: 'The reset link is invalid or has expired.' });
  }

  const expiresAt = new Date(resetRecord.expiresAt).getTime();
  if (Number.isNaN(expiresAt) || expiresAt < Date.now()) {
    db.prepare('DELETE FROM password_reset_tokens WHERE token = ?').run(token);
    return res.status(400).json({ success: false, message: 'The reset link is invalid or has expired.' });
  }

  const passwordHash = await bcrypt.hash(password, 12);
  db.prepare('UPDATE users SET passwordHash = ?, updatedAt = ? WHERE id = ?').run(passwordHash, new Date().toISOString(), resetRecord.userId);
  db.prepare('DELETE FROM password_reset_tokens WHERE token = ?').run(token);

  return res.json({
    success: true,
    message: 'Password updated successfully.',
    redirectUrl: '/login'
  });
});

app.post('/api/admin/new-joiner-invites', (req, res) => {
  const configuredKey = process.env.NEW_JOINER_ADMIN_KEY;
  const suppliedKey = String(req.get('x-aviara-admin-key') || '');
  if (!configuredKey || suppliedKey.length !== configuredKey.length || !crypto.timingSafeEqual(Buffer.from(suppliedKey), Buffer.from(configuredKey))) {
    return res.status(403).json({ success: false, message: 'Admin authorization required.' });
  }
  const email = clean(req.body?.email, 254).toLowerCase();
  if (!emailPattern.test(email)) return res.status(400).json({ success: false, message: 'Enter a valid joiner email.' });
  const token = crypto.randomBytes(32).toString('hex');
  const now = new Date().toISOString();
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
  db.prepare('INSERT INTO new_joiner_invites (email, tokenHash, expiresAt, createdAt) VALUES (?, ?, ?, ?)').run(email, crypto.createHash('sha256').update(token).digest('hex'), expiresAt, now);
  return res.status(201).json({ success: true, inviteUrl: `${process.env.APP_URL || `http://localhost:${port}`}/new-joiners/invite/${token}`, expiresAt });
});

app.get('/api/new-joiners/me', requireNewJoiner, (req, res) => {
  const joiner = getJoinerForUser(req.session.user.id);
  const documents = db.prepare(`
    SELECT d.id, d.documentKey, d.name, d.category, d.version, d.effectiveDate, d.lastUpdated, d.description, d.required,
      a.status AS acknowledgementStatus, a.acknowledgedAt
    FROM onboarding_documents d
    LEFT JOIN onboarding_acknowledgements a ON a.documentId = d.id AND a.joinerId = ?
    WHERE d.active = 1 ORDER BY d.id
  `).all(joiner.id);
  return res.json({ success: true, joiner, documents });
});

app.put('/api/new-joiners/profile', requireNewJoiner, (req, res) => {
  const profile = validateNewJoinerProfile(req.body);
  if (profile.error) return res.status(400).json({ success: false, message: profile.error });
  const joiner = getJoinerForUser(req.session.user.id);
  if (joiner.status === 'SUBMITTED') return res.status(409).json({ success: false, message: 'Submitted onboarding details cannot be changed.' });
  db.prepare(`UPDATE new_joiners SET fullName = ?, personalEmail = ?, assignedCompany = ?, department = ?, designation = ?, expectedJoiningDate = ?, hrContact = ?, updatedAt = ? WHERE id = ?`).run(profile.fullName, profile.personalEmail, profile.assignedCompany, profile.department, profile.designation, profile.expectedJoiningDate, profile.hrContact, new Date().toISOString(), joiner.id);
  return res.json({ success: true, message: 'Information saved.' });
});

app.post('/api/new-joiners/acknowledgements', requireNewJoiner, (req, res) => {
  const documentId = Number(req.body?.documentId);
  const version = clean(req.body?.version, 80);
  const joiner = getJoinerForUser(req.session.user.id);
  const document = db.prepare('SELECT * FROM onboarding_documents WHERE id = ? AND active = 1').get(documentId);
  if (!document || document.version !== version) return res.status(400).json({ success: false, message: 'The document version is no longer current. Refresh and review the latest version.' });
  if (joiner.status === 'SUBMITTED') return res.status(409).json({ success: false, message: 'Submitted onboarding cannot be changed.' });
  const now = new Date().toISOString();
  db.prepare(`INSERT INTO onboarding_acknowledgements (joinerId, documentId, documentVersion, status, acknowledgedAt) VALUES (?, ?, ?, 'ACKNOWLEDGED', ?) ON CONFLICT(joinerId, documentId) DO UPDATE SET documentVersion = excluded.documentVersion, status = excluded.status, acknowledgedAt = excluded.acknowledgedAt`).run(joiner.id, document.id, document.version, now);
  db.prepare('INSERT INTO onboarding_audit_log (joinerId, eventType, documentId, documentVersion, createdAt) VALUES (?, ?, ?, ?, ?)').run(joiner.id, 'DOCUMENT_ACKNOWLEDGED', document.id, document.version, now);
  return res.json({ success: true, message: 'Acknowledgement recorded.' });
});

app.post('/api/new-joiners/submit', requireNewJoiner, (req, res) => {
  const joiner = getJoinerForUser(req.session.user.id);
  const requiredDocuments = db.prepare('SELECT id FROM onboarding_documents WHERE active = 1 AND required = 1').all();
  const acknowledged = db.prepare(`SELECT documentId FROM onboarding_acknowledgements WHERE joinerId = ? AND status = 'ACKNOWLEDGED'`).all(joiner.id).map(record => record.documentId);
  const completeProfile = validateNewJoinerProfile(joiner);
  if (completeProfile.error || requiredDocuments.some(document => !acknowledged.includes(document.id))) return res.status(400).json({ success: false, message: 'Complete your information and acknowledge every required document before submitting.' });
  const now = new Date().toISOString();
  db.prepare('UPDATE new_joiners SET status = ?, submittedAt = ?, updatedAt = ? WHERE id = ?').run('SUBMITTED', now, now, joiner.id);
  db.prepare('INSERT INTO onboarding_audit_log (joinerId, eventType, createdAt) VALUES (?, ?, ?)').run(joiner.id, 'ONBOARDING_SUBMITTED', now);
  return res.json({ success: true, message: 'Your pre-joining process has been submitted for review.' });
});

app.post('/api/predict-delay', predictionLimiter, (req, res) => {
  const validation = validatePredictionPayload(req.body);
  if (validation.errors) return res.status(400).json({ success: false, errors: validation.errors });
  return res.status(200).json(createPrototypePrediction(validation.values));
});

app.post('/api/logo-feedback', logoFeedbackLimiter, async (req, res) => {
  const validation = validateLogoFeedback(req.body);
  if (validation.error) return res.status(400).json({ success: false, message: validation.error });

  const createdAt = new Date().toISOString();
  let feedbackId;
  try {
    const result = db.prepare(`
      INSERT INTO logo_feedback (name, rating, feedback, createdAt, notificationStatus)
      VALUES (?, ?, ?, ?, 'PENDING')
    `).run(validation.name, validation.rating, validation.feedback, createdAt);
    feedbackId = result.lastInsertRowid;
  } catch (error) {
    console.error('Logo feedback storage failed:', error.message);
    return res.status(500).json({ success: false, message: 'Unable to save your feedback right now.' });
  }

  const notificationSent = await sendLogoFeedbackWhatsApp({
    name: validation.name,
    rating: validation.rating,
    feedback: validation.feedback,
    createdAt
  });
  const notificationStatus = notificationSent ? 'SENT' : 'FAILED';
  db.prepare('UPDATE logo_feedback SET notificationStatus = ? WHERE id = ?').run(notificationStatus, feedbackId);

  return res.status(201).json({
    success: true,
    message: 'Thank you for your feedback.',
    notificationConfigured: Boolean(process.env.WHATSAPP_ACCESS_TOKEN && process.env.WHATSAPP_PHONE_NUMBER_ID && process.env.WHATSAPP_ADMIN_PHONE)
  });
});

app.post('/api/enquiry', enquiryLimiter, async (req, res) => {
  const enquiry = validatePayload(req.body);
  if (!enquiry || !process.env.ENQUIRY_RECEIVER_EMAIL || !process.env.EMAIL_API_KEY || !process.env.EMAIL_FROM_ADDRESS) {
    return res.status(400).json({ error: 'Unable to send enquiry.' });
  }

  const submittedAt = new Date().toISOString();
  const emailText = [
    'New Aviara Tech Enquiry', '',
    `Name: ${enquiry.fullName}`, '',
    `Email: ${enquiry.email}`, '',
    `Enquiry Type: ${enquiry.enquiryType}`, '',
    `Subject: ${enquiry.subject}`, '',
    `Message: ${enquiry.message}`, '',
    `Submission Time: ${submittedAt}`
  ].join('\n');

  try {
    const providerResponse = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: `Bearer ${process.env.EMAIL_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: process.env.EMAIL_FROM_ADDRESS,
        to: [process.env.ENQUIRY_RECEIVER_EMAIL],
        reply_to: enquiry.email,
        subject: `[AVIARA TECH] New Enquiry — ${enquiry.enquiryType}`,
        text: emailText
      })
    });
    if (!providerResponse.ok) throw new Error('Email provider rejected the request');
    return res.status(200).json({ ok: true });
  } catch (error) {
    console.error('Enquiry delivery failed:', error.message);
    return res.status(502).json({ error: 'Unable to send enquiry.' });
  }
});

app.use((error, _req, res, _next) => {
  if (error && error.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ success: false, message: 'Security validation failed. Please refresh and try again.' });
  }
  if (error.type === 'entity.too.large' || error instanceof SyntaxError) {
    return res.status(400).json({ error: 'Unable to process this request.' });
  }
  return res.status(500).json({ error: 'Something went wrong.' });
});

app.listen(port, () => {
  console.log(`Aviara Tech server listening on port ${port}`);
  console.log(`Auth database: ${dbPath}`);
});
