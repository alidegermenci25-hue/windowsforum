import { kv } from "@vercel/kv";
import crypto from 'crypto';

export default async function handler(req, res) {
    const { method, query, body, headers } = req;

    // CORS
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");

    if (method === 'OPTIONS') return res.status(204).end();

    const action = query.action;
    const clientIp = headers['x-forwarded-for'] || req.socket.remoteAddress || '';

    function hashPassword(password, salt) {
        return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
    }

    try {
        // ─── SIGNUP ────────────────────────────────────────────────────────────────
        if (action === 'signup') {
            const { username, password } = body;
            if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
            if (username.length < 3 || username.length > 20) return res.status(400).json({ error: 'Username must be 3–20 characters' });
            if (!/^[a-zA-Z0-9_]+$/.test(username)) return res.status(400).json({ error: 'Username: letters, numbers, underscores only' });
            if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

            const existing = await kv.get(`users:${username.toLowerCase()}`);
            if (existing) return res.status(409).json({ error: 'Username already taken' });

            const salt = crypto.randomBytes(16).toString('hex');
            const passwordHash = hashPassword(password, salt);
            await kv.set(`users:${username.toLowerCase()}`, { username, passwordHash, salt, createdAt: new Date().toISOString() });

            const sessionToken = crypto.randomBytes(32).toString('hex');
            await kv.set(`sessions:${sessionToken}`, { username, createdAt: new Date().toISOString() });

            return res.status(200).json({ ok: true, token: sessionToken, username });
        }

        // ─── LOGIN ─────────────────────────────────────────────────────────────────
        if (action === 'login') {
            const { username, password } = body;
            if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

            const user = await kv.get(`users:${username.toLowerCase()}`);
            if (!user) return res.status(401).json({ error: 'Invalid username or password' });

            const hash = hashPassword(password, user.salt);
            if (hash !== user.passwordHash) return res.status(401).json({ error: 'Invalid username or password' });

            const sessionToken = crypto.randomBytes(32).toString('hex');
            await kv.set(`sessions:${sessionToken}`, { username: user.username, createdAt: new Date().toISOString() });

            return res.status(200).json({ ok: true, token: sessionToken, username: user.username });
        }

        // ─── VERIFY SESSION ────────────────────────────────────────────────────────
        if (action === 'verify') {
            const { token } = query;
            if (!token) return res.status(400).json({ error: 'Token required' });

            const session = await kv.get(`sessions:${token}`);
            if (!session) return res.status(401).json({ error: 'Invalid or expired session' });

            const age = Date.now() - new Date(session.createdAt).getTime();
            if (age > 7 * 24 * 60 * 60 * 1000) {
                await kv.del(`sessions:${token}`);
                return res.status(401).json({ error: 'Session expired, please log in again' });
            }

            return res.status(200).json({ ok: true, username: session.username });
        }

        // ─── LOGOUT ────────────────────────────────────────────────────────────────
        if (action === 'logout') {
            const { token } = body;
            if (token) await kv.del(`sessions:${token}`);
            return res.status(200).json({ ok: true });
        }

        return res.status(400).json({ error: 'Unknown action' });
    } catch (err) {
        console.error("Auth error:", err);
        return res.status(500).json({ error: "Server error: " + err.message });
    }
}
