import { createClient } from 'redis';
import crypto from 'crypto';

const client = createClient({ url: process.env.REDIS_URL });
client.on('error', (err) => console.log('Redis Client Error', err));
let connected = false;

async function getClient() {
    if (!connected) {
        await client.connect();
        connected = true;
    }
    return client;
}

export default async function handler(req, res) {
    const { method, query, body, headers } = req;
    const redis = await getClient();

    // CORS
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");

    if (method === 'OPTIONS') return res.status(204).end();

    const action = query.action;

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

            const userJson = await redis.get(`users:${username.toLowerCase()}`);
            if (userJson) return res.status(409).json({ error: 'Username already taken' });

            const salt = crypto.randomBytes(16).toString('hex');
            const passwordHash = hashPassword(password, salt);
            await redis.set(`users:${username.toLowerCase()}`, JSON.stringify({ username, passwordHash, salt, createdAt: new Date().toISOString() }));

            const sessionToken = crypto.randomBytes(32).toString('hex');
            await redis.set(`sessions:${sessionToken}`, JSON.stringify({ username, createdAt: new Date().toISOString() }));

            return res.status(200).json({ ok: true, token: sessionToken, username });
        }

        // ─── LOGIN ─────────────────────────────────────────────────────────────────
        if (action === 'login') {
            const { username, password } = body;
            if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

            const userJson = await redis.get(`users:${username.toLowerCase()}`);
            if (!userJson) return res.status(401).json({ error: 'Invalid username or password' });

            const user = JSON.parse(userJson);
            const hash = hashPassword(password, user.salt);
            if (hash !== user.passwordHash) return res.status(401).json({ error: 'Invalid username or password' });

            const sessionToken = crypto.randomBytes(32).toString('hex');
            await redis.set(`sessions:${sessionToken}`, JSON.stringify({ username: user.username, createdAt: new Date().toISOString() }));

            return res.status(200).json({ ok: true, token: sessionToken, username: user.username });
        }

        // ─── VERIFY SESSION ────────────────────────────────────────────────────────
        if (action === 'verify') {
            const { token } = query;
            if (!token) return res.status(400).json({ error: 'Token required' });

            const sessionJson = await redis.get(`sessions:${token}`);
            if (!sessionJson) return res.status(401).json({ error: 'Invalid or expired session' });

            const session = JSON.parse(sessionJson);
            const age = Date.now() - new Date(session.createdAt).getTime();
            if (age > 7 * 24 * 60 * 60 * 1000) {
                await redis.del(`sessions:${token}`);
                return res.status(401).json({ error: 'Session expired, please log in again' });
            }

            return res.status(200).json({ ok: true, username: session.username });
        }

        // ─── LOGOUT ────────────────────────────────────────────────────────────────
        if (action === 'logout') {
            const { token } = body;
            if (token) await redis.del(`sessions:${token}`);
            return res.status(200).json({ ok: true });
        }

        return res.status(400).json({ error: 'Unknown action' });
    } catch (err) {
        console.error("Auth error:", err);
        return res.status(500).json({ error: "Server error: " + err.message });
    }
}
