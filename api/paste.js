import { kv } from "@vercel/kv";
import { nanoid } from "nanoid";

export default async function handler(req, res) {
  const { method, headers, query, body } = req;

  // --- CORS ---
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (method === "OPTIONS") {
    return res.status(204).end();
  }

  // --- CREATE PASTE (POST) ---
  if (method === "POST") {
    try {
      const { content, sessionToken } = body;

      // Verify session token
      if (!sessionToken) {
        return res.status(401).json({ error: "You must be logged in to create a paste" });
      }

      const session = await kv.get(`sessions:${sessionToken}`);
      if (!session) {
        return res.status(401).json({ error: "Invalid or expired session. Please log in again." });
      }

      if (!content || typeof content !== "string") {
        return res.status(400).json({ error: "Content is required" });
      }

      if (content.length > 500000) {
        return res.status(413).json({ error: "Content too large (max 500KB)" });
      }

      const id = nanoid(12);
      await kv.set(`pastes:${id}`, content);

      const siteUrl = process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : `https://${headers.host}`;
      const rawUrl = `${siteUrl}/raw/${id}`;

      return res.status(201).json({ id, rawUrl });
    } catch (err) {
      console.error("POST error:", err);
      return res.status(500).json({ error: "Failed to create paste", detail: err.message });
    }
  }

  // --- GET PASTE ---
  if (method === "GET") {
    const id = query.id || req.url.split("/").pop();
    const userAgent = headers["user-agent"] || "";

    if (!id || id === "paste") {
      return res.status(400).send("Missing paste ID");
    }

    try {
      const content = await kv.get(`pastes:${id}`);

      if (!content) {
        return res.status(404).send("Paste not found");
      }

      // Return raw text for CLI/PowerShell
      const isCli = /PowerShell|curl|Wget|PostmanRuntime/i.test(userAgent);
      if (isCli) {
        res.setHeader("Content-Type", "text/plain; charset=utf-8");
        res.setHeader("Cache-Control", "public, max-age=300");
        return res.status(200).send(content);
      }

      // Browser gets the Protection View
      const siteUrl = process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : `https://${headers.host}`;
      const rawUrl = `${siteUrl}/raw/${id}`;
      const psCommand = `irm '${rawUrl}' | iex`;

      const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>WindowsForum JS Shield Protection</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&family=JetBrains+Mono&display=swap" rel="stylesheet">
  <style>
    :root { --bg:#0b0c10; --card:#15181f; --accent:#00e5ff; --text:#fff; --dim:#a0a5b1; --border:rgba(255,255,255,0.05); }
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:'Inter',sans-serif;background:var(--bg);color:var(--text);display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;padding:20px}
    .orb{position:absolute;width:400px;height:400px;background:radial-gradient(circle,rgba(0,229,255,0.1),transparent 70%);filter:blur(80px);z-index:0;top:-100px}
    .logo{position:relative;z-index:10;width:80px;height:80px;margin-bottom:2rem;color:var(--accent);filter:drop-shadow(0 0 15px rgba(0,229,255,0.4))}
    .title{font-size:2.5rem;font-weight:800;margin-bottom:0.5rem;position:relative;z-index:10}
    .title span{color:var(--accent)}
    .subtitle{color:var(--dim);font-size:1rem;margin-bottom:3rem;position:relative;z-index:10}
    .card{background:var(--card);border:1px solid var(--border);border-radius:20px;width:100%;max-width:520px;padding:2.5rem;position:relative;z-index:10;box-shadow:0 30px 60px rgba(0,0,0,0.5)}
    .status{display:flex;align-items:center;gap:.75rem;margin-bottom:1.5rem;font-size:1.25rem;font-weight:700}
    .status svg{color:#ffa500}
    .desc{color:var(--dim);line-height:1.6;margin-bottom:2rem;font-size:.95rem}
    .warning{background:rgba(255,165,0,0.1);border-left:3px solid #ffa500;padding:1rem;color:#ffa500;font-size:.85rem;font-weight:600;margin-bottom:2rem;border-radius:4px}
    .stats{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;margin-bottom:2.5rem}
    .stat-item{text-align:center;padding:1rem 0;background:rgba(255,255,255,.02);border-radius:12px;border:1px solid var(--border)}
    .stat-val{font-weight:800;font-size:1.1rem;color:var(--accent);margin-bottom:.2rem}
    .stat-lbl{font-size:.65rem;color:var(--dim);text-transform:uppercase;letter-spacing:1px}
    .exec-label{font-size:.7rem;color:var(--dim);text-transform:uppercase;letter-spacing:1px;margin-bottom:.75rem;font-weight:600}
    .cmd-box{background:#000;border:1px solid var(--border);border-radius:10px;padding:1rem;display:flex;align-items:center;justify-content:space-between;gap:1rem}
    .cmd-text{font-family:'JetBrains Mono',monospace;font-size:.8rem;color:var(--accent);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .copy-btn{background:var(--accent);color:#000;border:none;padding:.4rem .8rem;border-radius:6px;font-size:.75rem;font-weight:700;cursor:pointer;transition:opacity .2s}
    .copy-btn:hover{opacity:.8}
    .footer{margin-top:3rem;font-size:.75rem;color:var(--dim);position:relative;z-index:10}
    .footer span{color:var(--accent);opacity:.8}
  </style>
</head>
<body>
  <div class="orb"></div>
  <svg class="logo" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
    <path d="M12 2L3 7v10l9 5 9-5V7l-9-5z" stroke-linejoin="round"/>
    <path d="M12 22V12M12 12l9-5M12 12L3 7" stroke-linecap="round"/>
  </svg>
  <h1 class="title">WindowsForum<span> JS</span> Protection</h1>
  <p class="subtitle">Advanced Script Protection &amp; Verification System</p>
  <div class="card">
    <div class="status">
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
      Script Protected
    </div>
    <p class="desc">This script is protected by <strong>WindowsForum JS</strong> — The most advanced PowerShell script protection system. Direct browser access is blocked to prevent unauthorized copying.</p>
    <div class="warning">⚠ This endpoint can only be accessed through PowerShell</div>
    <div class="stats">
      <div class="stat-item"><div class="stat-val">24/7</div><div class="stat-lbl">Protection</div></div>
      <div class="stat-item"><div class="stat-val">AES-256</div><div class="stat-lbl">Encryption</div></div>
      <div class="stat-item"><div class="stat-val">Verified</div><div class="stat-lbl">Safe</div></div>
    </div>
    <p class="exec-label">How to Execute:</p>
    <div class="cmd-box">
      <div class="cmd-text" id="cmd">${psCommand}</div>
      <button class="copy-btn" onclick="copyCmd()">Copy</button>
    </div>
  </div>
  <p class="footer">"Your script is safe with <span>WindowsForum JS</span>"</p>
  <script>
    function copyCmd(){const t=document.getElementById('cmd').innerText;navigator.clipboard.writeText(t).then(()=>{const b=document.querySelector('.copy-btn');b.innerText='Copied!';setTimeout(()=>b.innerText='Copy',2000)})}
  </script>
</body>
</html>`;
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      return res.status(200).send(html);
    } catch (err) {
      console.error("GET error:", err);
      return res.status(500).send("Internal error: " + err.message);
    }
  }

  return res.status(405).send("Method not allowed");
}
