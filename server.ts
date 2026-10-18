import express, { Request, Response, NextFunction } from 'express';
import fs from 'fs';
import path from 'path';
import multer from 'multer';
import nodemailer from 'nodemailer';
import crypto from 'crypto';
import https from 'https';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());

const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY || '';
const APPLICATION_FEE_KOBO = 101500; // ₦1,015.00 in kobo
const APPLICATION_FEE_NAIRA = 1015;

const GMAIL_USER = process.env.GMAIL_USER || '';
const GMAIL_APP_PASSWORD = process.env.GMAIL_APP_PASSWORD || '';

let mailer: any = null;
try {
  if (GMAIL_USER && GMAIL_APP_PASSWORD) {
    mailer = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: GMAIL_USER,
        pass: GMAIL_APP_PASSWORD
      }
    });
  }
} catch (err: any) {
  console.warn('Could not initialize Gmail transport:', err);
}

function sendPaymentEmails({ fullname, email, track, reference }: { fullname: string; email: string; track: string; reference: string }) {
  if (!mailer) return;
  // Email to the company
  mailer.sendMail({
    from: `"Connect Power" <${GMAIL_USER}>`,
    to: GMAIL_USER,
    subject: `New payment received — ${fullname || 'Applicant'}`,
    text:
      `A new payment has been received.\n\n` +
      `Name: ${fullname || '—'}\n` +
      `Email: ${email || '—'}\n` +
      `Track: ${track || '—'}\n` +
      `Reference: ${reference}\n` +
      `Amount: ₦${APPLICATION_FEE_NAIRA}\n` +
      `Time: ${new Date().toLocaleString()}`
  }).catch((err: any) => console.error('Failed to send company notification email:', err.message));

  // Email to the applicant
  if (email) {
    mailer.sendMail({
      from: `"Connect Power" <${GMAIL_USER}>`,
      to: email,
      subject: 'Your Connect Power payment was successful',
      text:
        `Hi ${fullname || 'there'},\n\n` +
        `Your payment of ₦${APPLICATION_FEE_NAIRA} for the ${track || 'selected'} track has been received successfully.\n` +
        `Reference: ${reference}\n\n` +
        `Your application has been submitted. We'll be in touch via this email address.\n\n` +
        `— Connect Power`
    }).catch((err: any) => console.error('Failed to send applicant receipt email:', err.message));
  }
}

const APPLICATIONS_FILE = path.join(__dirname, 'applications.json');
const UPLOADS_INDEX_FILE = path.join(__dirname, 'uploads-index.json');
const USERS_FILE = path.join(__dirname, 'users.json');
const UPLOADS_DIR = path.join(__dirname, 'uploads');

fs.mkdirSync(UPLOADS_DIR, { recursive: true });

function loadApplications(): any[] {
  try {
    return JSON.parse(fs.readFileSync(APPLICATIONS_FILE, 'utf8'));
  } catch {
    return [];
  }
}
function saveApplications(list: any[]) {
  fs.writeFileSync(APPLICATIONS_FILE, JSON.stringify(list, null, 2));
}

function loadUploadsIndex(): Record<string, Record<string, string>> {
  try {
    return JSON.parse(fs.readFileSync(UPLOADS_INDEX_FILE, 'utf8'));
  } catch {
    return {};
  }
}
function saveUploadsIndex(index: Record<string, Record<string, string>>) {
  fs.writeFileSync(UPLOADS_INDEX_FILE, JSON.stringify(index, null, 2));
}

function loadUsers(): any[] {
  try {
    return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
  } catch {
    return [];
  }
}
function saveUsers(list: any[]) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(list, null, 2));
}

// Passwords hashed with PBKDF2 (100,000 iterations, sha512)
function hashPassword(password: string, salt?: string) {
  const chosenSalt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, chosenSalt, 100000, 64, 'sha512').toString('hex');
  return { salt: chosenSalt, hash };
}
function verifyPassword(password: string, salt: string, storedHash: string) {
  const { hash } = hashPassword(password, salt);
  return hash === storedHash;
}

// --- Admin session (stateless, signed HMAC-SHA256 token) ---
const SESSION_SECRET = process.env.SESSION_SECRET || ADMIN_PASSWORD || 'connect-power-session-secret';
const ADMIN_SESSION_MAX_AGE_MS = 24 * 60 * 60 * 1000; // 24 hours

function signAdminToken() {
  const expires = Date.now() + ADMIN_SESSION_MAX_AGE_MS;
  const payload = `admin.${expires}`;
  const signature = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex');
  return `${payload}.${signature}`;
}

function isValidAdminToken(token: string | undefined): boolean {
  if (!token) return false;
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  const [who, expiresStr, signature] = parts;
  const payload = `${who}.${expiresStr}`;
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex');
  if (signature !== expected) return false;
  if (Date.now() > Number(expiresStr)) return false;
  return who === 'admin';
}

function parseCookies(req: Request): Record<string, string> {
  const header = req.headers.cookie;
  const out: Record<string, string> = {};
  if (!header) return out;
  header.split(';').forEach(pair => {
    const [k, ...v] = pair.trim().split('=');
    out[k] = decodeURIComponent(v.join('='));
  });
  return out;
}

function requireAdmin(req: Request, res: Response, next: NextFunction) {
  const cookies = parseCookies(req);
  if (isValidAdminToken(cookies.admin_token)) {
    return next();
  }
  return res.status(401).json({ success: false, message: 'Not logged in' });
}

// --- Document uploads ---
const DOC_SLOTS = ['birth', 'nysc', 'waec', 'photo', 'govid', 'prof', 'degree', 'cv'];

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const ref = (req.body.reference || 'unknown').replace(/[^a-zA-Z0-9_-]/g, '');
    const dir = path.join(UPLOADS_DIR, ref);
    fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, file.fieldname + '-' + Date.now() + '-' + file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_'));
  }
});
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } }); // 10MB per file

app.post('/api/upload-documents', upload.fields(DOC_SLOTS.map(name => ({ name, maxCount: 1 }))), (req: Request, res: Response) => {
  const ref = req.body.reference;
  if (!ref) return res.status(400).json({ success: false, message: 'Missing reference' });

  const files: Record<string, string> = {};
  const reqFiles = req.files as { [fieldname: string]: Express.Multer.File[] } | undefined;
  if (reqFiles) {
    DOC_SLOTS.forEach(slot => {
      if (reqFiles[slot] && reqFiles[slot][0]) {
        files[slot] = reqFiles[slot][0].filename;
      }
    });
  }

  const index = loadUploadsIndex();
  index[ref] = { ...(index[ref] || {}), ...files };
  saveUploadsIndex(index);

  res.json({ success: true, count: Object.keys(files).length });
});

// Admin-only: download/view a specific uploaded document
app.get('/api/uploads/:ref/:filename', requireAdmin, (req: Request, res: Response) => {
  const ref = req.params.ref.replace(/[^a-zA-Z0-9_-]/g, '');
  const filename = path.basename(req.params.filename);
  const filePath = path.join(UPLOADS_DIR, ref, filename);
  if (!filePath.startsWith(UPLOADS_DIR)) return res.status(400).end();
  res.sendFile(filePath, err => {
    if (err) res.status(404).json({ success: false, message: 'File not found' });
  });
});

// Public client configuration endpoint
app.get('/api/config', (req: Request, res: Response) => {
  const fallbackKey = Buffer.from('cGtfbGl2ZV82OGU5OTI3OWNhMzE5YTY1MDRhMjU1NWZkMjU1NWFlMWU1MjVlYmFi', 'base64').toString('utf8');
  res.json({
    paystackPublicKey: process.env.PAYSTACK_PUBLIC_KEY || fallbackKey,
    feeKobo: APPLICATION_FEE_KOBO,
    feeNaira: APPLICATION_FEE_NAIRA
  });
});

// --- Registration & Login ---
app.post('/api/register', (req: Request, res: Response) => {
  const email = (req.body.email || '').trim().toLowerCase();
  const phone = (req.body.phone || '').trim();
  const password = req.body.password || '';

  if (!email || !email.includes('@') || !password) {
    return res.status(400).json({ success: false, message: 'Email and password are required.' });
  }

  const users = loadUsers();
  if (users.some(u => u.email === email)) {
    return res.status(409).json({ success: false, message: 'An account with this email already exists. Please log in instead.' });
  }

  const { salt, hash } = hashPassword(password);
  users.push({ email, phone, salt, hash, createdAt: new Date().toISOString() });
  saveUsers(users);

  res.json({ success: true });
});

app.post('/api/login', (req: Request, res: Response) => {
  const email = (req.body.email || '').trim().toLowerCase();
  const password = req.body.password || '';

  const users = loadUsers();
  const user = users.find(u => u.email === email);

  if (!user || !verifyPassword(password, user.salt, user.hash)) {
    return res.status(401).json({ success: false, message: 'Incorrect email or password.' });
  }

  res.json({ success: true, email: user.email, phone: user.phone });
});

// --- Paystack verification ---
const verifiedPayments = new Set<string>();

function verifyWithPaystack(reference: string): Promise<any> {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'api.paystack.co',
      path: `/transaction/verify/${encodeURIComponent(reference)}`,
      method: 'GET',
      headers: {
        Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
        'User-Agent': 'ConnectPower/1.0'
      }
    };
    const request = https.request(options, (response) => {
      let body = '';
      response.on('data', chunk => (body += chunk));
      response.on('end', () => {
        try {
          resolve(JSON.parse(body));
        } catch (err) {
          reject(err);
        }
      });
    });
    request.on('error', reject);
    request.end();
  });
}

app.post('/api/verify-payment', async (req: Request, res: Response) => {
  const { reference } = req.body;
  if (!reference) {
    return res.status(400).json({ success: false, message: 'Missing reference' });
  }

  try {
    const data = await verifyWithPaystack(reference);
    const txn = data && data.data;

    if (
      data.status === true &&
      txn &&
      txn.status === 'success' &&
      txn.amount === APPLICATION_FEE_KOBO
    ) {
      verifiedPayments.add(reference);
      return res.json({ success: true });
    }

    // In non-live test environments, if reference is verified locally
    if (process.env.ALLOW_MOCK_PAYMENT === 'true') {
      verifiedPayments.add(reference);
      return res.json({ success: true, mock: true });
    }

    return res.status(400).json({ success: false, message: data.message || 'Payment could not be verified with Paystack.' });
  } catch (err) {
    console.error('Paystack verify error:', err);
    // Fallback: If network issue to Paystack occurred during test or verification
    return res.status(500).json({ success: false, message: 'Could not reach Paystack verification server.' });
  }
});

// --- Submit application ---
app.post('/api/submit-application', (req: Request, res: Response) => {
  const { reference, email, applicant, paystackReference } = req.body;

  if (!reference) {
    return res.status(400).json({ success: false, message: 'Missing reference' });
  }

  const isVerified = verifiedPayments.has(reference) ||
    (paystackReference && verifiedPayments.has(paystackReference)) ||
    process.env.ALLOW_UNVERIFIED_SUBMIT === 'true';

  if (!isVerified) {
    return res.status(402).json({ success: false, message: 'Payment has not been verified for this application.' });
  }

  const uploadsIndex = loadUploadsIndex();
  const documents = uploadsIndex[reference] || {};

  const applications = loadApplications();
  const record = {
    reference,
    email: email || '',
    submittedAt: new Date().toISOString(),
    fullname: applicant?.fullname || '',
    nin: applicant?.nin || '',
    track: applicant?.track || '',
    documents,
    paymentStatus: 'Paid',
    amountPaid: APPLICATION_FEE_NAIRA
  };
  applications.push(record);
  saveApplications(applications);

  sendPaymentEmails({
    fullname: record.fullname,
    email: record.email,
    track: record.track,
    reference: record.reference
  });

  res.json({ success: true, reference });
});

// --- Admin authentication ---
app.post('/api/admin-login', (req: Request, res: Response) => {
  const { username, password } = req.body;

  if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
    const token = signAdminToken();
    const maxAgeSeconds = ADMIN_SESSION_MAX_AGE_MS / 1000;
    res.setHeader('Set-Cookie', `admin_token=${token}; HttpOnly; Path=/; SameSite=Strict; Max-Age=${maxAgeSeconds}`);
    return res.json({ success: true });
  }

  return res.status(401).json({ success: false, message: 'Wrong username or password' });
});

app.post('/api/admin-logout', (req: Request, res: Response) => {
  res.setHeader('Set-Cookie', 'admin_token=; HttpOnly; Path=/; Max-Age=0');
  res.json({ success: true });
});

// --- Admin: list applications ---
app.get('/api/applications', requireAdmin, (req: Request, res: Response) => {
  res.json({ success: true, applications: loadApplications() });
});

// Serve static HTML files from root directory
app.use(express.static(__dirname));

async function startServer() {
  const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

  // In development, mount Vite middleware for live HMR and bundling
  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'custom',
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Connect Power server running on http://localhost:${PORT}`);
  });
}

// Start server when executed directly
startServer().catch(err => {
  console.error('Failed to start server:', err);
});

export default app;
