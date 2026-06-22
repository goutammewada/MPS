/**
 * MP Online Services — Unified Backend Server & Frontend Gateway
 * Stack: Node.js + Express 4 + MySQL2 + Multer
 */

'use strict';

require('dotenv').config();
const express   = require('express');
const mysql     = require('mysql2/promise');   // Promise API — eliminates callback nesting
const cors      = require('cors');
const multer    = require('multer');
const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');
const path      = require('path');
const fs        = require('fs');

/* ──────────────────────────────────────────
   APPLICATION INITIALIZATION
────────────────────────────────────────── */
const app  = express();
const PORT = process.env.PORT || 3000;

/* ──────────────────────────────────────────
   SECURITY & POLICY MIDDLEWARE
────────────────────────────────────────── */

// Enforces secure HTTP headers (XSS, clickjacking, etc.)
// Content Security Policy adjusted to allow external CDNs utilized by your templates
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net", "www.gstatic.com", "cdnjs.cloudflare.com"],
            styleSrc: ["'self'", "'unsafe-inline'", "fonts.googleapis.com", "cdnjs.cloudflare.com"],
            fontSrc: ["'self'", "fonts.gstatic.com", "cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "*"],
            connectSrc: ["'self'", "*"]
        }
    }
}));

// Cross-Origin Resource Sharing configuration mapping from environment variables
const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'http://localhost')
    .split(',')
    .map(o => o.trim());

app.use(cors({
    origin: (origin, callback) => {
        if (!origin && process.env.NODE_ENV !== 'production') return callback(null, true);
        if (allowedOrigins.includes(origin) || allowedOrigins.includes('*') || !origin) return callback(null, true);
        callback(new Error(`CORS blocked: origin ${origin} not allowed`));
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'x-admin-key'],
}));

// Global anti-DDOS rate limiter — 150 requests per 15 minutes per IP segment
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 150,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests originating from this endpoint. Please retry later.' },
});
app.use(globalLimiter);

// Stricter limiter for public document submittals to insulate against bot spams
const submitLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour window
    max: 15,
    message: { error: 'Form submission limit hit for this IP. Please try again after one hour.' },
});

app.use(express.json({ limit: '1mb' }));

/* ──────────────────────────────────────────
   NATIVE FRONTEND & STATIC DELIVERY ENGINE
────────────────────────────────────────── */
// Serve static frontend HTML assets (index, login, track, etc.) right from the root directory
app.use(express.static(__dirname));

// Persistent upload volume setup for user attachments
const UPLOADS_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

app.use('/uploads', express.static(UPLOADS_DIR));

/* ──────────────────────────────────────────
   RELATIONAL DATABASE CONNECTION POOL
────────────────────────────────────────── */
const db = mysql.createPool({
    host:               process.env.DB_HOST     || 'localhost',
    port:               parseInt(process.env.DB_PORT) || 3307,
    user:               process.env.DB_USER     || 'root',
    password:           process.env.DB_PASSWORD || '',
    database:           process.env.DB_NAME     || 'mp_online',
    waitForConnections: true,
    connectionLimit:    10,       // Maximum concurrent database channels
    queueLimit:         0,        // Unlimited request fallback queue
    enableKeepAlive:    true,
    keepAliveInitialDelay: 10000,
});

// Structural initialization checkpoint
(async () => {
    try {
        const conn = await db.getConnection();
        console.log('✅ MySQL production pool connected successfully');
        
        // Auto-create target structural query tables if they are missing
        await conn.query(`
            CREATE TABLE IF NOT EXISTS applications (
                id INT AUTO_INCREMENT PRIMARY KEY,
                applicant_name VARCHAR(255) NOT NULL,
                phone VARCHAR(15) NOT NULL,
                service_type VARCHAR(100) NOT NULL,
                status ENUM('Pending', 'In Progress', 'Completed', 'Rejected') DEFAULT 'Pending',
                photo_path VARCHAR(500) NULL,
                aadhaar_path VARCHAR(500) NULL,
                signature_path VARCHAR(500) NULL,
                marksheet_path VARCHAR(500) NULL,
                address_path VARCHAR(500) NULL,
                property_path VARCHAR(500) NULL,
                shopphoto_path VARCHAR(500) NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        conn.release();
    } catch (err) {
        console.error('❌ Database handshake drop failure:', err.message);
        console.error('   Please confirm environmental parameters or active cluster bindings.');
    }
})();

/* ──────────────────────────────────────────
   MULTER MULTIPART FILE UPLOAD LOGIC
────────────────────────────────────────── */
const ALLOWED_MIME_TYPES = [
    'image/jpeg',
    'image/png',
    'image/webp',
    'application/pdf',
];
const MAX_FILE_SIZE_MB = 5;

const storage = multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, UPLOADS_DIR),
    filename: (_req, file, cb) => {
        const ext  = path.extname(file.originalname).toLowerCase();
        const name = `${Date.now()}-${Math.round(Math.random() * 1e6)}${ext}`;
        cb(null, name);
    },
});

const fileFilter = (_req, file, cb) => {
    if (ALLOWED_MIME_TYPES.includes(file.mimetype)) {
        cb(null, true);
    } else {
        cb(new multer.MulterError('LIMIT_UNEXPECTED_FILE', `File format rejection: ${file.mimetype}`));
    }
};

const upload = multer({
    storage,
    fileFilter,
    limits: { fileSize: MAX_FILE_SIZE_MB * 1024 * 1024 },
});

/* ──────────────────────────────────────────
   ADMINISTRATIVE SESSION CONTROL MIDDLEWARE
────────────────────────────────────────── */
function requireAdmin(req, res, next) {
    const key = req.headers['x-admin-key'];
    if (!key || key !== process.env.ADMIN_SECRET) {
        return res.status(401).json({ error: 'Unauthorised: Cryptographic master verification token mismatch.' });
    }
    next();
}

/* ──────────────────────────────────────────
   SCHEMA COMPLIANCE WHITE-LIST CHECKS
────────────────────────────────────────── */
const VALID_STATUSES = ['Pending', 'In Progress', 'Completed', 'Rejected'];

function isValidPhone(phone) {
    return /^\d{10}$/.test(phone);
}

function isValidService(service) {
    const allowed = [
        'PAN Card',
        'Gumasta Registration',
        'Domicile Certificate',
        'Caste Certificate',
        'Udyam Certificate',
        'PMEGP Loan',
        'Marriage Registration',
        'Firm Registration',
        'Clinic Registration',
        'Character Certificate',
        'Food License (FSSAI)',
        'Swarojgar Yojana',
        'Yuva Udyami',
    ];
    return allowed.includes(service);
}

/* ──────────────────────────────────────────
   ROUTING NODES & API ENDPOINTS
────────────────────────────────────────── */

// Node 01: Deploy Form Data Ingestion Payload (Public)
app.post(
    '/apply',
    submitLimiter,
    upload.fields([
        { name: 'photo',      maxCount: 1 },
        { name: 'aadhaar',    maxCount: 1 },
        { name: 'signature',  maxCount: 1 },
        { name: 'marksheet',  maxCount: 1 },
        { name: 'address',    maxCount: 1 },
        { name: 'property',   maxCount: 1 },
        { name: 'shopphoto',  maxCount: 1 },
    ]),
    async (req, res) => {
        try {
            const { name, phone, service } = req.body;

            if (!name || name.trim().length < 2) {
                return res.status(400).json({ error: 'Applicant validation exception: name required.' });
            }
            if (!isValidPhone(phone)) {
                return res.status(400).json({ error: 'Applicant validation exception: 10-digit phone schema required.' });
            }
            if (!isValidService(service)) {
                return res.status(400).json({ error: 'System whitelist drop: Target service module non-existent.' });
            }

            const filePath = (fieldName) =>
                req.files?.[fieldName]?.[0]
                    ? `/uploads/${req.files[fieldName][0].filename}`
                    : null;

            const sql = `
                INSERT INTO applications
                    (applicant_name, phone, service_type,
                     photo_path, aadhaar_path, signature_path,
                     marksheet_path, address_path, property_path, shopphoto_path,
                     status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending')
            `;
            const values = [
                name.trim(),
                phone.trim(),
                service,
                filePath('photo'),
                filePath('aadhaar'),
                filePath('signature'),
                filePath('marksheet'),
                filePath('address'),
                filePath('property'),
                filePath('shopphoto'),
            ];

            const [result] = await db.execute(sql, values);

            return res.status(201).json({
                message:     'Application record generated successfully.',
                id:          result.insertId,
                tracking_id: `APP-${result.insertId}`,
            });

        } catch (err) {
            console.error('[POST /apply Error Context]', err);
            return res.status(500).json({ error: 'Transactional writing failed down-funnel.' });
        }
    }
);

// Node 02: Pull Database Records Matrix (Protected Admin Interface)
app.get('/admin/applications', requireAdmin, async (req, res) => {
    try {
        const { status } = req.query;
        let sql    = 'SELECT * FROM applications ORDER BY created_at DESC';
        let params = [];

        if (status && VALID_STATUSES.includes(status)) {
            sql    = 'SELECT * FROM applications WHERE status = ? ORDER BY created_at DESC';
            params = [status];
        }

        const [rows] = await db.execute(sql, params);
        return res.json(rows);

    } catch (err) {
        console.error('[GET /admin/applications Error Context]', err);
        return res.status(500).json({ error: 'Failed to access structural record states.' });
    }
});

// Node 03: Modify Transaction Workflow Status Nodes (Protected Admin Interface)
app.put('/admin/applications/:id/status', requireAdmin, async (req, res) => {
    try {
        const id     = parseInt(req.params.id);
        const { status } = req.body;

        if (!Number.isInteger(id) || id < 1) {
            return res.status(400).json({ error: 'Malformed payload: target key index missing numeric casting.' });
        }
        if (!VALID_STATUSES.includes(status)) {
            return res.status(400).json({ error: `State transition rejected. Scope target must evaluate to whitelist.` });
        }

        const [result] = await db.execute(
            'UPDATE applications SET status = ? WHERE id = ?',
            [status, id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Operational execution dropped: record not found.' });
        }

        return res.json({ message: 'State step modified successfully.' });

    } catch (err) {
        console.error('[PUT /admin/applications/:id/status Error Context]', err);
        return res.status(500).json({ error: 'Downstream state write sequence crashed.' });
    }
});

// Node 04: Drop Entity Record & Purge Associated Binaries (Protected Admin Interface)
app.delete('/admin/applications/:id', requireAdmin, async (req, res) => {
    try {
        const id = parseInt(req.params.id);

        if (!Number.isInteger(id) || id < 1) {
            return res.status(400).json({ error: 'Malformed parameters.' });
        }

        const [rows] = await db.execute(
            'SELECT photo_path, aadhaar_path, signature_path, marksheet_path, address_path, property_path, shopphoto_path FROM applications WHERE id = ?',
            [id]
        );

        if (rows.length === 0) {
            return res.status(404).json({ error: 'Target record index isolated: blank status.' });
        }

        await db.execute('DELETE FROM applications WHERE id = ?', [id]);

        const filePaths = Object.values(rows[0]).filter(Boolean);
        filePaths.forEach(relativePath => {
            const abs = path.join(__dirname, relativePath);
            fs.unlink(abs, err => {
                if (err && err.code !== 'ENOENT') {
                    console.warn(`[Disk Purge Warning] Asset link broken, skipped clean execution for: ${abs}`);
                }
            });
        });

        return res.json({ message: 'Target database block cleanly evacuated, assets purged.' });

    } catch (err) {
        console.error('[DELETE /admin/applications/:id Error Context]', err);
        return res.status(500).json({ error: 'Cluster database record dropping sequence aborted.' });
    }
});

// Node 05: Public Metric Audit Journey Pipeline Tracer (Public Endpoint)
app.get('/api/track/:id', async (req, res) => {
    try {
        const id = parseInt(req.params.id);

        if (!Number.isInteger(id) || id < 1) {
            return res.status(400).json({ error: 'Parameter formatting error.' });
        }

        const [rows] = await db.execute(
            `SELECT id, applicant_name, service_type, status, created_at
             FROM applications WHERE id = ?`,
            [id]
        );

        if (rows.length === 0) {
            return res.status(404).json({ message: 'No registered tracking records match the query signature.' });
        }

        return res.json(rows[0]);

    } catch (err) {
        console.error('[GET /api/track/:id Error Context]', err);
        return res.status(500).json({ error: 'Query processing trace thread disrupted.' });
    }
});

// Node 06: Infrastructure Health Monitor Check
app.get('/api/health', async (_req, res) => {
    try {
        await db.execute('SELECT 1');
        res.json({ status: 'ok', pool: 'connected', instanceUptime: process.uptime() });
    } catch {
        res.status(503).json({ status: 'unhealthy', pool: 'disconnected' });
    }
});

/* ──────────────────────────────────────────
   ERROR PIPELINE HANDLING SYSTEMS
────────────────────────────────────────── */
app.use((err, _req, res, next) => {
    if (err instanceof multer.MulterError || err.message?.startsWith('File format rejection')) {
        return res.status(400).json({ error: err.message });
    }
    next(err);
});

// Handle custom 404 falling past API checks to serve frontend fallback links smoothly
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.use((err, _req, res, _next) => {
    console.error('[Global Runtime Panic Trap]', err);
    res.status(500).json({ error: 'An unexpected application processing exception occurred.' });
});

/* ──────────────────────────────────────────
   SERVER PORT PROVISIONING & STANDUP
────────────────────────────────────────── */
const server = app.listen(PORT, () => {
    console.log(`🚀 Unified portal running via port mapping: http://localhost:${PORT}`);
    console.log(`   Cluster Running Context Profile: ${process.env.NODE_ENV || 'production'}`);
});

/* ──────────────────────────────────────────
   CLEAN COLD CLOSURE PROCESS SEQUENCES
────────────────────────────────────────── */
async function shutdown(signal) {
    console.log(`\n${signal} execution command received. Terminating instances...`);
    server.close(async () => {
        try {
            await db.end();
            console.log('✅ Connection pool safely released. Operations closed.');
        } catch (err) {
            console.error('Failure releasing connections on exit loop:', err.message);
        }
        process.exit(0);
    });
}

process.on('SIGINT',  () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
/* ──────────────────────────────────────────
   STATIC FILES
────────────────────────────────────────── */
// ADD THIS LINE: This forces Express to serve your static HTML files
app.use(express.static(__dirname));

const UPLOADS_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

app.use('/uploads', express.static(UPLOADS_DIR));