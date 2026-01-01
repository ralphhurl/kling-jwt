// kling-jwt-service.js
// Minimal JWT signer for Kling API (because n8n blocks crypto)
// Deploy to: Railway, Fly.io, or any Node.js host

const express = require('express');
const crypto = require('crypto');

const app = express();
app.use(express.json());

function base64url(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input);
  return buf.toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

app.post('/kling', (req, res) => {
  try {
    const { access_key, secret_key, timestamp } = req.body;
    
    if (!access_key || !secret_key) {
      return res.status(400).json({ error: 'Missing access_key or secret_key' });
    }

    const now = timestamp || Math.floor(Date.now() / 1000);
    const header = { alg: 'HS256', typ: 'JWT' };
    const payload = {
      iss: access_key,
      exp: now + 1800,
      nbf: now - 5
    };

    const encodedHeader = base64url(JSON.stringify(header));
    const encodedPayload = base64url(JSON.stringify(payload));
    const signingInput = `${encodedHeader}.${encodedPayload}`;

    const signature = crypto
      .createHmac('sha256', secret_key)
      .update(signingInput)
      .digest();

    const token = `${signingInput}.${base64url(signature)}`;

    res.json({ token });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Kling JWT service: http://localhost:${PORT}`);
});

// DEPLOY INSTRUCTIONS:
// 1. npm init -y
// 2. npm install express cors
// 3. Deploy to Railway/Fly.io/Render
// 4. Update n8n workflow URL to your deployed endpoint
