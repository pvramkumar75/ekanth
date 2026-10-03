// Ekanth 189 key card: stores the encrypted gate/door codes and lets the admin change them.
// The codes are encrypted in the browser with the card password (PBKDF2-SHA256 250k + AES-GCM);
// this function only ever stores ciphertext. Saving needs the admin PIN (env ADMIN_PIN) and the
// current card password, which is checked by decrypting the stored vault.
import { get, put } from '@vercel/blob';
import crypto from 'node:crypto';

// The vault the site shipped with; used until the first change is saved.
const SEED = { s: 'XvurYdycBW8A7wb+1ooleA==', i: '3j13LCnq6e4FJ2xr', c: 'wHY+nKF2ZcugyOcOb85Vmn94ly0YPRsLcjQBacV/OseVJIDUjE3q2NTbgOWj5nJb' };
const VAULT_PATH = 'vault.json';
const ATTEMPTS_PATH = 'attempts.json';
const MAX_FAILS = 5;
const LOCK_MS = 15 * 60 * 1000;

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};
const json = (body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...CORS } });

const hasStore = () => !!process.env.BLOB_READ_WRITE_TOKEN;

async function readJSON(path) {
  if (!hasStore()) return null;
  const r = await get(path, { access: 'private', useCache: false });
  if (!r || r.statusCode !== 200) return null;
  return JSON.parse(await new Response(r.stream).text());
}
async function writeJSON(path, obj) {
  await put(path, JSON.stringify(obj), { access: 'private', allowOverwrite: true, addRandomSuffix: false, contentType: 'application/json' });
}

// Mirrors the browser's openVault: WebCrypto AES-GCM appends the 16-byte tag to the ciphertext.
function openVault(vault, password) {
  try {
    const key = crypto.pbkdf2Sync(String(password), Buffer.from(vault.s, 'base64'), 250000, 32, 'sha256');
    const buf = Buffer.from(vault.c, 'base64');
    const d = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(vault.i, 'base64'));
    d.setAuthTag(buf.subarray(buf.length - 16));
    return JSON.parse(Buffer.concat([d.update(buf.subarray(0, buf.length - 16)), d.final()]).toString('utf8'));
  } catch {
    return null;
  }
}

const isVault = v =>
  v && typeof v === 'object' &&
  ['s', 'i', 'c'].every(k => typeof v[k] === 'string' && v[k].length > 0 && v[k].length < 2000 && /^[A-Za-z0-9+/=]+$/.test(v[k]));
const isCodes = c => c && /^\d{3,8}$/.test(c.gate) && /^\d{3,8}$/.test(c.door);

function pinMatches(pin) {
  const a = crypto.createHash('sha256').update(String(pin ?? '')).digest();
  const b = crypto.createHash('sha256').update(String(process.env.ADMIN_PIN)).digest();
  return crypto.timingSafeEqual(a, b);
}

export function OPTIONS() {
  return new Response(null, { status: 204, headers: CORS });
}

export async function GET() {
  const vault = (await readJSON(VAULT_PATH)) || SEED;
  return json({ vault, canSave: hasStore() && !!process.env.ADMIN_PIN });
}

// Body: { pin }                                   -> checks the PIN
//       { pin, password }                         -> also checks the current card password
//       { pin, password, newPassword, vault }     -> saves the new vault
export async function POST(request) {
  if (!hasStore() || !process.env.ADMIN_PIN) return json({ error: 'not_setup' }, 503);
  let body;
  try { body = await request.json(); } catch { return json({ error: 'bad_request' }, 400); }

  const now = Date.now();
  const attempts = (await readJSON(ATTEMPTS_PATH)) || { fails: 0, until: 0 };
  if (attempts.until > now) return json({ error: 'locked', retryAfter: Math.ceil((attempts.until - now) / 1000) }, 429);

  if (!pinMatches(body.pin)) {
    const fails = attempts.fails + 1;
    const locked = fails >= MAX_FAILS;
    await writeJSON(ATTEMPTS_PATH, locked ? { fails: 0, until: now + LOCK_MS } : { fails, until: 0 });
    return locked ? json({ error: 'locked', retryAfter: LOCK_MS / 1000 }, 429) : json({ error: 'pin', triesLeft: MAX_FAILS - fails }, 401);
  }
  if (attempts.fails) await writeJSON(ATTEMPTS_PATH, { fails: 0, until: 0 });
  if (body.password === undefined) return json({ ok: true });

  const current = (await readJSON(VAULT_PATH)) || SEED;
  if (!openVault(current, body.password)) return json({ error: 'password' }, 401);
  if (body.vault === undefined) return json({ ok: true });

  if (!isVault(body.vault) || typeof body.newPassword !== 'string' || body.newPassword.trim().length < 4) return json({ error: 'bad_request' }, 400);
  if (!isCodes(openVault(body.vault, body.newPassword))) return json({ error: 'bad_vault' }, 400);

  await writeJSON(VAULT_PATH, { s: body.vault.s, i: body.vault.i, c: body.vault.c });
  return json({ ok: true });
}
