import { kv } from "@vercel/kv";

const ROOT_CODE = process.env.ROOT_CODE || "admin123";

export default async function handler(req, res) {
    const { method, query, body } = req;

    // CORS
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");

    if (method === "OPTIONS") return res.status(204).end();

    let code = query.code || (body && body.code);
    const action = query.action;

    if (code !== ROOT_CODE) {
        return res.status(401).json({ error: "Invalid account code" });
    }

    try {
        // --- LIST ALL PASTES ---
        if (action === "list") {
            const keys = await kv.keys("pastes:*");
            const pastes = keys.map(k => ({ key: k.replace("pastes:", "") }));
            return res.status(200).json({ pastes });
        }

        // --- VIEW SINGLE PASTE ---
        if (action === "view") {
            const id = query.id;
            if (!id) return res.status(400).json({ error: "Missing id" });
            const content = await kv.get(`pastes:${id}`);
            if (!content) return res.status(404).json({ error: "Paste not found" });
            return res.status(200).json({ id, content });
        }

        // --- DELETE A PASTE ---
        if (action === "delete") {
            const id = query.id;
            if (!id) return res.status(400).json({ error: "Missing id" });
            await kv.del(`pastes:${id}`);
            return res.status(200).json({ ok: true, deleted: id });
        }

        // --- EDIT A PASTE ---
        if (action === "edit") {
            const id = query.id;
            const newContent = body && body.content;
            if (!id || !newContent) return res.status(400).json({ error: "Missing id or content" });
            await kv.set(`pastes:${id}`, newContent);
            return res.status(200).json({ ok: true, id });
        }

        // --- USER MANAGEMENT ---
        if (action === "listUsers") {
            const keys = await kv.keys("users:*");
            const users = await Promise.all(keys.map(k => kv.get(k)));
            return res.status(200).json({ users: users.filter(Boolean) });
        }

        if (action === "addUser" || action === "updateUser") {
            const { username, password, plainPassword } = body;
            const targetUser = query.username || username;
            if (!targetUser) return res.status(400).json({ error: "Username required" });

            let userData = (await kv.get(`users:${targetUser.toLowerCase()}`)) || {};

            if (password) {
                const crypto = await import('crypto');
                const salt = crypto.randomBytes(16).toString('hex');
                const passwordHash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
                userData.passwordHash = passwordHash;
                userData.salt = salt;
                userData.plainPassword = plainPassword || password;
            }

            if (username && action === "addUser") userData.username = username;
            if (!userData.createdAt) userData.createdAt = new Date().toISOString();

            await kv.set(`users:${targetUser.toLowerCase()}`, userData);
            return res.status(200).json({ ok: true });
        }

        if (action === "removeUser") {
            const username = query.username;
            if (!username) return res.status(400).json({ error: "Username required" });
            await kv.del(`users:${username.toLowerCase()}`);
            return res.status(200).json({ ok: true });
        }

        if (action === "renameUser") {
            const { oldUsername, newUsername } = body;
            if (!oldUsername || !newUsername) return res.status(400).json({ error: "Both old and new usernames required" });

            const userData = await kv.get(`users:${oldUsername.toLowerCase()}`);
            if (!userData) return res.status(404).json({ error: "User not found" });

            userData.username = newUsername;
            await kv.set(`users:${newUsername.toLowerCase()}`, userData);
            await kv.del(`users:${oldUsername.toLowerCase()}`);

            return res.status(200).json({ ok: true });
        }

        // --- VERIFY CODE (login check) ---
        if (action === "login" || !action) {
            return res.status(200).json({ ok: true, role: "root" });
        }

        return res.status(400).json({ error: "Unknown action" });
    } catch (err) {
        console.error("Admin error:", err);
        return res.status(500).json({ error: "Server error: " + err.message });
    }
}
