// kling-jwt-service.js
// Run this on a server you control, then call from n8n

const express = require('express');
const crypto = require('crypto');

const app = express();
app.use(express.json());

const KLING_ACCESS_KEY = process.env.KLING_ACCESS_KEY;
const KLING_SECRET_KEY = process.env.KLING_SECRET_KEY;

if (!KLING_ACCESS_KEY || !KLING_SECRET_KEY) {
  throw new Error('Missing KLING_ACCESS_KEY or KLING_SECRET_KEY env vars');
}

function base64url(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input);
  return buf.toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function generateKlingJWT() {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'HS256', typ: 'JWT' };
  const payload = {
    iss: KLING_ACCESS_KEY,
    exp: now + 1800, // 30 min
    nbf: now - 5
  };

  const encodedHeader = base64url(JSON.stringify(header));
  const encodedPayload = base64url(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const signature = crypto
    .createHmac('sha256', KLING_SECRET_KEY)
    .update(signingInput)
    .digest();

  return `${signingInput}.${base64url(signature)}`;
}

app.post('/token', (req, res) => {
  try {
    const token = generateKlingJWT();
    res.json({ token });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.listen(3000, () => {
  console.log('Kling JWT service running on port 3000');
});

// Usage from n8n:
// POST http://your-server:3000/token
// Response: { "token": "eyJhbG..." }
