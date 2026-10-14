/* =====================================================
   SMARTQ BACKEND
   Pure Node.js (no npm install needed) + built-in SQLite.
   Run:  node server.js     Open:  http://localhost:3000
   ===================================================== */

"use strict";

const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { DatabaseSync } = require("node:sqlite");

const PORT = process.env.PORT || 3000;
const FRONTEND = path.join(__dirname, "..", "frontend");

// MULTI-ADMIN MODE
//  - Anyone can register as an Admin (e.g. a doctor / clinic / office). Each admin
//    owns their own services, queue and staff, completely separate from other admins.
//  - Staff register using the personal STAFF CODE of the admin they work for
//    (shown on that admin's dashboard). A staff member only ever sees that admin's data.
//  - Optional: set an ADMIN_CODE environment variable if you want to restrict
//    who can create admin accounts (people must then enter it when registering).
const ADMIN_CODE = process.env.ADMIN_CODE || "";


/* ---------- DATABASE ---------- */

const db = new DatabaseSync(process.env.DB_PATH || path.join(__dirname, "smartq.db"));

db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'customer'
    );
    CREATE TABLE IF NOT EXISTS services (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        duration INTEGER NOT NULL,
        description TEXT DEFAULT 'SmartQ service',
        start_time TEXT NOT NULL DEFAULT '09:00',
        end_time TEXT NOT NULL DEFAULT '18:00',
        capacity INTEGER NOT NULL DEFAULT 50
    );
    CREATE TABLE IF NOT EXISTS appointments (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        service_id TEXT NOT NULL,
        service_name TEXT NOT NULL,
        duration INTEGER NOT NULL,
        date TEXT NOT NULL,
        time TEXT NOT NULL,
        token TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'Waiting',
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS resets (
        email TEXT PRIMARY KEY,
        code_hash TEXT NOT NULL,
        expires INTEGER NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    );
`);

// Migration: add the new service-window/capacity columns if this is an
// existing database created before this feature existed.
const serviceColumns = db.prepare("PRAGMA table_info(services)").all().map(c => c.name);
if (!serviceColumns.includes("start_time")) {
    db.exec("ALTER TABLE services ADD COLUMN start_time TEXT NOT NULL DEFAULT '09:00'");
}
if (!serviceColumns.includes("end_time")) {
    db.exec("ALTER TABLE services ADD COLUMN end_time TEXT NOT NULL DEFAULT '18:00'");
}
if (!serviceColumns.includes("capacity")) {
    db.exec("ALTER TABLE services ADD COLUMN capacity INTEGER NOT NULL DEFAULT 50");
}

// Multi-admin columns (safe to run on old databases)
function addColumn(table, column, ddl) {
    const cols = db.prepare("PRAGMA table_info(" + table + ")").all().map(c => c.name);
    if (!cols.includes(column)) db.exec("ALTER TABLE " + table + " ADD COLUMN " + column + " " + ddl);
}
addColumn("users", "admin_id", "TEXT");        // staff -> which admin they work for
addColumn("users", "org_name", "TEXT");        // admin -> clinic / business name
addColumn("users", "staff_code", "TEXT");      // admin -> code staff use to join
addColumn("services", "owner_id", "TEXT");     // which admin owns the service
addColumn("appointments", "admin_id", "TEXT"); // which admin the booking is with

function getSetting(key) {
    const row = db.prepare("SELECT value FROM settings WHERE key = ?").get(key);
    return row ? row.value : null;
}

function setSetting(key, value) {
    db.prepare(
        "INSERT INTO settings (key, value) VALUES (?, ?) " +
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value"
    ).run(key, value);
}

let SECRET = getSetting("secret");
if (!SECRET) {
    SECRET = crypto.randomBytes(32).toString("hex");
    setSetting("secret", SECRET);
}
if (getSetting("current_token") === null) setSetting("current_token", "Q000");


/* ---------- PASSWORDS + LOGIN TOKENS ---------- */

function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString("hex");
    return salt + ":" + crypto.scryptSync(password, salt, 64).toString("hex");
}

function checkPassword(password, stored) {
    const [salt, hash] = stored.split(":");
    const test = crypto.scryptSync(password, salt, 64);
    return crypto.timingSafeEqual(test, Buffer.from(hash, "hex"));
}

function sign(body) {
    return crypto.createHmac("sha256", SECRET).update(body).digest("base64url");
}

function makeToken(user) {
    const body = Buffer.from(JSON.stringify({
        id: user.id,
        exp: Date.now() + 7 * 24 * 60 * 60 * 1000
    })).toString("base64url");
    return body + "." + sign(body);
}

function userFromRequest(req) {
    const header = req.headers.authorization || "";
    const [body, sig] = header.replace("Bearer ", "").split(".");

    if (!body || !sig) return null;

    const good = sign(body);
    if (sig.length !== good.length ||
        !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good))) return null;

    try {
        const payload = JSON.parse(Buffer.from(body, "base64url").toString());
        if (payload.exp < Date.now()) return null;
        return db.prepare(
            "SELECT id, name, email, role, admin_id, org_name FROM users WHERE id = ?"
        ).get(payload.id) || null;
    } catch (e) {
        return null;
    }
}


/* ---------- DEMO DATA (only on first run) ---------- */

const insertUser = db.prepare(
    "INSERT INTO users (id, name, email, password, role) VALUES (?, ?, ?, ?, ?)"
);

if (!db.prepare("SELECT 1 FROM users LIMIT 1").get()) {
    insertUser.run("admin001", "SmartQ Admin", "admin@smartq.com", hashPassword("admin123"), "admin");
    insertUser.run("staff001", "SmartQ Staff", "staff@smartq.com", hashPassword("staff123"), "staff");
}

if (!db.prepare("SELECT 1 FROM services LIMIT 1").get()) {
    const ins = db.prepare(
        `INSERT INTO services (id, name, duration, description, start_time, end_time, capacity)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
    );
    ins.run("S001", "General Consultation", 15, "General consultation and assistance", "09:00", "18:00", 50);
    ins.run("S002", "Document Verification", 10, "Document checking and verification", "09:00", "18:00", 50);
    ins.run("S003", "Customer Support", 15, "Customer support and help", "09:00", "18:00", 50);
    ins.run("S004", "Account Services", 20, "Account related services", "09:00", "18:00", 50);
}


/* ---------- MULTI-ADMIN MIGRATION (old data goes to the first admin) ---------- */

function makeStaffCode() {
    return "ST-" + crypto.randomBytes(4).toString("hex").toUpperCase();
}

{
    const firstAdmin = db.prepare(
        "SELECT id FROM users WHERE role = 'admin' ORDER BY rowid LIMIT 1"
    ).get();

    if (firstAdmin) {
        db.prepare("UPDATE services SET owner_id = ? WHERE owner_id IS NULL").run(firstAdmin.id);
        db.prepare("UPDATE users SET admin_id = ? WHERE role = 'staff' AND admin_id IS NULL").run(firstAdmin.id);
        db.prepare(
            `UPDATE appointments SET admin_id = COALESCE(
                 (SELECT owner_id FROM services WHERE services.id = appointments.service_id), ?)
             WHERE admin_id IS NULL`
        ).run(firstAdmin.id);

        const oldToken = getSetting("current_token");
        if (oldToken !== null && getSetting("current_token:" + firstAdmin.id) === null) {
            setSetting("current_token:" + firstAdmin.id, oldToken);
        }
    }

    db.prepare("SELECT id, name, org_name, staff_code FROM users WHERE role = 'admin'").all().forEach(a => {
        if (!a.org_name) db.prepare("UPDATE users SET org_name = ? WHERE id = ?").run(a.name, a.id);
        if (!a.staff_code) db.prepare("UPDATE users SET staff_code = ? WHERE id = ?").run(makeStaffCode(), a.id);
    });
}


/* ---------- HELPERS ---------- */

class HttpError extends Error {
    constructor(status, message) {
        super(message);
        this.status = status;
    }
}

const sha = s => crypto.createHash("sha256").update(s).digest("hex");

const clean = s => String(s || "").replace(/[<>]/g, "").trim();

function todayString() {
    const d = new Date();
    const pad = n => String(n).padStart(2, "0");
    return d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate());
}

// The admin whose data this user may see: an admin sees their own, staff see their boss's.
function tenantOf(user) {
    if (user.role === "admin") return user.id;
    if (user.role === "staff") return user.admin_id;
    return null;
}

function publicUser(row) {
    let orgName = row.org_name || null;

    if (row.role === "staff" && row.admin_id) {
        const boss = db.prepare("SELECT name, org_name FROM users WHERE id = ?").get(row.admin_id);
        orgName = boss ? (boss.org_name || boss.name) : null;
    }

    return { id: row.id, name: row.name, email: row.email, role: row.role, orgName };
}

function requireLogin(user, roles) {
    if (!user) throw new HttpError(401, "Please login again");
    if (roles && !roles.includes(user.role)) throw new HttpError(403, "Not allowed");
}

function readBody(req) {
    return new Promise((resolve, reject) => {
        let data = "";
        req.on("data", chunk => {
            data += chunk;
            if (data.length > 1e6) reject(new HttpError(413, "Request too large"));
        });
        req.on("end", () => {
            try { resolve(data ? JSON.parse(data) : {}); }
            catch (e) { reject(new HttpError(400, "Invalid JSON")); }
        });
    });
}

const APPT_SQL = `
    SELECT rowid AS rid,
           id,
           user_id AS userId,
           (SELECT name FROM users WHERE id = user_id) AS userName,
           service_id AS serviceId,
           service_name AS serviceName,
           admin_id AS adminId,
           (SELECT COALESCE(org_name, name) FROM users WHERE id = appointments.admin_id) AS providerName,
           duration, date, time, token, status,
           created_at AS createdAt
    FROM appointments
`;

const SERVICE_SQL = `
    SELECT s.id, s.name, s.duration, s.description,
           s.start_time AS startTime, s.end_time AS endTime, s.capacity,
           s.owner_id AS ownerId,
           COALESCE(u.org_name, u.name, 'SmartQ') AS providerName
    FROM services s
    LEFT JOIN users u ON u.id = s.owner_id
`;

function currentTokenFor(adminId) {
    return (adminId && getSetting("current_token:" + adminId)) || "Q000";
}

function buildState(user) {

    const tenant = tenantOf(user);
    const state = {};

    /* ----- services: customers see every admin's services; admin/staff only their own ----- */

    let services;

    if (user.role === "customer") {
        services = db.prepare(
            SERVICE_SQL + " ORDER BY providerName COLLATE NOCASE, s.rowid"
        ).all();
    } else {
        services = db.prepare(
            SERVICE_SQL + " WHERE s.owner_id = ? ORDER BY s.rowid"
        ).all(tenant);
    }

    if (user.role === "admin") {
        services.forEach(s => {
            s.bookedToday = db.prepare(
                "SELECT COUNT(*) AS c FROM appointments WHERE service_id = ? AND date = ? AND status != 'Cancelled'"
            ).get(s.id, todayString()).c;
        });
    }

    state.services = services;

    /* ----- appointments ----- */

    if (user.role === "customer") {

        const mine = db.prepare(
            APPT_SQL + " WHERE user_id = ? ORDER BY created_at, rowid"
        ).all(user.id);

        const aheadStmt = db.prepare(
            `SELECT duration FROM appointments
             WHERE admin_id = ? AND date = ? AND status = 'Waiting' AND rowid < ?`
        );

        const tokens = {};

        state.appointments = mine.map(a => {

            const item = { ...a, peopleAhead: 0, estimatedWait: 0 };
            delete item.rid;

            if (a.status === "Waiting") {
                // only people waiting for the SAME admin on the SAME day count
                const ahead = aheadStmt.all(a.adminId, a.date, a.rid);
                item.peopleAhead = ahead.length;
                item.estimatedWait = ahead.reduce((sum, b) => sum + (b.duration || 15), 0);
            }

            if (a.status === "Waiting" || a.status === "Called") {
                tokens[a.adminId] = currentTokenFor(a.adminId);
            }

            return item;
        });

        state.currentTokens = tokens;
        state.currentToken = "Q000";

    } else {

        state.appointments = db.prepare(
            APPT_SQL + " WHERE admin_id = ? ORDER BY created_at, rowid"
        ).all(tenant).map(a => { delete a.rid; return a; });

        state.currentToken = currentTokenFor(tenant);
    }

    /* ----- admin extras ----- */

    if (user.role === "admin") {

        state.customerCount = db.prepare(
            "SELECT COUNT(DISTINCT user_id) AS c FROM appointments WHERE admin_id = ?"
        ).get(user.id).c;

        state.staff = db.prepare(
            "SELECT id, name, email FROM users WHERE role = 'staff' AND admin_id = ? ORDER BY rowid"
        ).all(user.id);

        state.staffCode = db.prepare(
            "SELECT staff_code FROM users WHERE id = ?"
        ).get(user.id).staff_code;
    }

    return state;
}

function findAppointment(id) {
    const row = db.prepare("SELECT * FROM appointments WHERE id = ?").get(id);
    if (!row) throw new HttpError(404, "Appointment not found");
    return row;
}


/* ---------- API ROUTES ---------- */

async function handleApi(req, res, url) {

    const method = req.method;
    const p = url.pathname;
    const body = (method === "POST" || method === "PUT") ? await readBody(req) : {};

    /* ----- auth ----- */

    if (method === "POST" && p === "/api/register") {

        const name = clean(body.name);
        const email = clean(body.email).toLowerCase();
        const password = String(body.password || "");
        const role = ["staff", "admin"].includes(body.role) ? body.role : "customer";
        const accessCode = String(body.accessCode || "").trim();

        if (!name || !email || !password) throw new HttpError(400, "Please fill all fields");
        if (!/^\S+@\S+\.\S+$/.test(email)) throw new HttpError(400, "Enter a valid email");
        if (password.length < 6) throw new HttpError(400, "Password must be at least 6 characters");

        if (db.prepare("SELECT 1 FROM users WHERE email = ?").get(email)) {
            throw new HttpError(400, "Email already registered");
        }

        let adminId = null;
        let orgName = null;
        let staffCode = null;

        if (role === "admin") {

            if (ADMIN_CODE && accessCode !== ADMIN_CODE) {
                throw new HttpError(403, "Invalid admin invite code");
            }

            orgName = clean(body.orgName) || name;
            staffCode = makeStaffCode();
        }

        if (role === "staff") {

            const boss = db.prepare(
                "SELECT id FROM users WHERE role = 'admin' AND staff_code = ?"
            ).get(accessCode.toUpperCase());

            if (!boss) {
                throw new HttpError(403, "Invalid staff code. Ask your admin for their staff code");
            }

            adminId = boss.id;
        }

        db.prepare(
            `INSERT INTO users (id, name, email, password, role, admin_id, org_name, staff_code)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
        ).run(
            "U" + Date.now() + crypto.randomBytes(2).toString("hex"),
            name, email, hashPassword(password), role, adminId, orgName, staffCode
        );

        return { ok: true };
    }

    if (method === "POST" && p === "/api/login") {

        const email = clean(body.email).toLowerCase();
        const row = db.prepare("SELECT * FROM users WHERE email = ?").get(email);

        if (!row || !checkPassword(String(body.password || ""), row.password)) {
            throw new HttpError(401, "Invalid email or password");
        }

        const user = publicUser(row);

        return { token: makeToken(user), user };
    }

    if (method === "PUT" && p === "/api/profile") {

        const user = userFromRequest(req);
        requireLogin(user);

        const name = clean(body.name);
        const email = clean(body.email).toLowerCase();

        if (!name || !/^\S+@\S+\.\S+$/.test(email)) throw new HttpError(400, "Enter a valid name and email");

        const taken = db.prepare("SELECT id FROM users WHERE email = ? AND id != ?").get(email, user.id);
        if (taken) throw new HttpError(400, "Email already used by another account");

        db.prepare("UPDATE users SET name = ?, email = ? WHERE id = ?").run(name, email, user.id);

        return { user: publicUser(db.prepare("SELECT * FROM users WHERE id = ?").get(user.id)) };
    }

    /* ----- forgot / reset password ----- */

    if (method === "POST" && p === "/api/forgot-password") {

        const email = clean(body.email).toLowerCase();

        if (db.prepare("SELECT 1 FROM users WHERE email = ?").get(email)) {

            const code = String(crypto.randomInt(100000, 1000000));

            db.prepare(
                `INSERT INTO resets (email, code_hash, expires, attempts) VALUES (?, ?, ?, 0)
                 ON CONFLICT(email) DO UPDATE SET code_hash = excluded.code_hash,
                 expires = excluded.expires, attempts = 0`
            ).run(email, sha(code), Date.now() + 10 * 60 * 1000);

            // No email service is connected, so the code is shown here in the server terminal.
            console.log("\n[PASSWORD RESET]  " + email + "  ->  code: " + code + "  (valid 10 minutes)\n");
        }

        return { ok: true };
    }

    if (method === "POST" && p === "/api/reset-password") {

        const email = clean(body.email).toLowerCase();
        const code = String(body.code || "").trim();
        const password = String(body.password || "");

        if (password.length < 6) throw new HttpError(400, "Password must be at least 6 characters");

        const row = db.prepare("SELECT * FROM resets WHERE email = ?").get(email);

        if (!row || row.expires < Date.now() || row.attempts >= 5) {
            throw new HttpError(400, "Reset code expired. Please request a new one");
        }

        if (!crypto.timingSafeEqual(Buffer.from(sha(code)), Buffer.from(row.code_hash))) {
            db.prepare("UPDATE resets SET attempts = attempts + 1 WHERE email = ?").run(email);
            throw new HttpError(400, "Incorrect reset code");
        }

        db.prepare("UPDATE users SET password = ? WHERE email = ?").run(hashPassword(password), email);
        db.prepare("DELETE FROM resets WHERE email = ?").run(email);

        return { ok: true };
    }

    /* ----- everything below needs login ----- */

    const user = userFromRequest(req);
    requireLogin(user);

    if (method === "GET" && p === "/api/state") {
        return buildState(user);
    }

    /* ----- services (admin) ----- */

    if (method === "POST" && p === "/api/services") {

        requireLogin(user, ["admin"]);

        const name = clean(body.name);
        const duration = parseInt(body.duration, 10);
        const startTime = String(body.startTime || "09:00");
        const endTime = String(body.endTime || "18:00");
        const capacity = parseInt(body.capacity, 10);

        if (!name || !(duration > 0 && duration <= 600)) {
            throw new HttpError(400, "Enter service name and duration (1-600 minutes)");
        }
        if (!/^\d{2}:\d{2}$/.test(startTime) || !/^\d{2}:\d{2}$/.test(endTime)) {
            throw new HttpError(400, "Enter a valid start and end time");
        }
        if (startTime >= endTime) {
            throw new HttpError(400, "Start time must be earlier than end time");
        }
        if (!(capacity > 0 && capacity <= 1000)) {
            throw new HttpError(400, "Enter a valid number of appointments allowed (1-1000)");
        }

        db.prepare(
            `INSERT INTO services (id, name, duration, description, start_time, end_time, capacity, owner_id)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
        ).run("S" + Date.now() + crypto.randomBytes(2).toString("hex"), name, duration, "SmartQ service", startTime, endTime, capacity, user.id);

        return { ok: true };
    }

    let match = p.match(/^\/api\/services\/([\w-]+)$/);

    if (method === "DELETE" && match) {
        requireLogin(user, ["admin"]);

        // an admin can only delete their OWN services
        const r = db.prepare("DELETE FROM services WHERE id = ? AND owner_id = ?").run(match[1], user.id);
        if (!r.changes) throw new HttpError(404, "Service not found");

        return { ok: true };
    }

    /* ----- business name (admin only) ----- */

    if (method === "PUT" && p === "/api/org") {

        requireLogin(user, ["admin"]);

        const orgName = clean(body.orgName);
        if (!orgName) throw new HttpError(400, "Enter your business / clinic name");

        db.prepare("UPDATE users SET org_name = ? WHERE id = ?").run(orgName, user.id);

        return { user: publicUser(db.prepare("SELECT * FROM users WHERE id = ?").get(user.id)) };
    }

    /* ----- staff management (admin only, own staff only) ----- */

    if (method === "POST" && p === "/api/staff-code") {

        requireLogin(user, ["admin"]);

        const staffCode = makeStaffCode();
        db.prepare("UPDATE users SET staff_code = ? WHERE id = ?").run(staffCode, user.id);

        return { staffCode };
    }

    match = p.match(/^\/api\/staff\/([\w-]+)$/);

    if (method === "DELETE" && match) {

        requireLogin(user, ["admin"]);

        const r = db.prepare(
            "DELETE FROM users WHERE id = ? AND role = 'staff' AND admin_id = ?"
        ).run(match[1], user.id);

        if (!r.changes) throw new HttpError(404, "Staff member not found");

        return { ok: true };
    }

    /* ----- appointments ----- */

    if (method === "POST" && p === "/api/appointments") {

        requireLogin(user, ["customer"]);

        const service = db.prepare("SELECT * FROM services WHERE id = ?").get(String(body.serviceId || ""));
        const date = String(body.date || "");
        const time = String(body.time || "");

        if (!service) throw new HttpError(400, "Please select a valid service");
        if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || !/^\d{2}:\d{2}$/.test(time)) {
            throw new HttpError(400, "Please select a valid date and time");
        }
        if (date < todayString()) throw new HttpError(400, "Please choose today or a future date");

        if (time < service.start_time || time >= service.end_time) {
            throw new HttpError(
                400,
                `${service.name} is only available between ${service.start_time} and ${service.end_time}`
            );
        }

        const bookedForService = db.prepare(
            "SELECT COUNT(*) AS c FROM appointments WHERE service_id = ? AND date = ? AND status != 'Cancelled'"
        ).get(service.id, date).c;

        if (bookedForService >= service.capacity) {
            throw new HttpError(400, `${service.name} is fully booked for ${date}. Please choose another date.`);
        }

        // token numbers restart every day, separately for each admin
        const count = db.prepare(
            "SELECT COUNT(*) AS c FROM appointments WHERE date = ? AND admin_id = ?"
        ).get(date, service.owner_id).c;
        const token = "Q" + String(count + 1).padStart(3, "0");
        const id = "A" + Date.now() + crypto.randomBytes(2).toString("hex");

        db.prepare(
            `INSERT INTO appointments
             (id, user_id, service_id, service_name, duration, date, time, token, status, created_at, admin_id)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Waiting', ?, ?)`
        ).run(id, user.id, service.id, service.name, service.duration, date, time, token, new Date().toISOString(), service.owner_id);

        return { id, token };
    }

    match = p.match(/^\/api\/appointments\/([\w-]+)\/(call|complete|cancel)$/);

    if (method === "PUT" && match) {

        const appt = findAppointment(match[1]);
        const action = match[2];

        if (action === "cancel") {

            const owner = user.role === "customer" && appt.user_id === user.id;
            const staff = (user.role === "staff" || user.role === "admin") && appt.admin_id === tenantOf(user);

            if (!owner && !staff) throw new HttpError(403, "Not allowed");
            if (appt.status !== "Waiting" && appt.status !== "Called") {
                throw new HttpError(400, "Appointment is already closed");
            }

            db.prepare("UPDATE appointments SET status = 'Cancelled' WHERE id = ?").run(appt.id);
            return { ok: true };
        }

        requireLogin(user, ["staff", "admin"]);

        // staff/admin can only act on their own admin's appointments
        if (appt.admin_id !== tenantOf(user)) throw new HttpError(403, "Not allowed");

        if (action === "call") {
            db.prepare("UPDATE appointments SET status = 'Called' WHERE id = ?").run(appt.id);
            setSetting("current_token:" + appt.admin_id, appt.token);
        } else {
            db.prepare("UPDATE appointments SET status = 'Completed' WHERE id = ?").run(appt.id);
        }

        return { ok: true };
    }

    throw new HttpError(404, "Not found");
}


/* ---------- STATIC FILES (serves your frontend folder) ---------- */

const MIME = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon"
};

function serveStatic(res, url) {

    let file = decodeURIComponent(url.pathname);
    if (file === "/") file = "/index.html";

    const full = path.join(FRONTEND, file);

    if (!full.startsWith(FRONTEND) || !fs.existsSync(full) || !fs.statSync(full).isFile()) {
        res.writeHead(404, { "Content-Type": "text/plain" });
        return res.end("Not found");
    }

    res.writeHead(200, {
        "Content-Type": MIME[path.extname(full)] || "application/octet-stream",
        "Cache-Control": "no-cache"
    });

    fs.createReadStream(full).pipe(res);
}


/* ---------- SERVER ---------- */

const server = http.createServer(async (req, res) => {

    const url = new URL(req.url, "http://localhost");

    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");

    if (req.method === "OPTIONS") {
        res.writeHead(204);
        return res.end();
    }

    if (!url.pathname.startsWith("/api/")) {
        return serveStatic(res, url);
    }

    try {
        const result = await handleApi(req, res, url);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(result));
    } catch (e) {
        const status = e.status || 500;
        if (status === 500) console.error(e);
        res.writeHead(status, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: status === 500 ? "Server error" : e.message }));
    }
});

server.listen(PORT, () => {
    console.log("SmartQ is running  ->  http://localhost:" + PORT);
});