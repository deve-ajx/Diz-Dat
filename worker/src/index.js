// sVn Pro: Paystack -> Cloudflare Worker (free plan) -> verify with Paystack -> Firestore -> Pro.
// Secrets (Cloudflare only): PAYSTACK_SECRET_KEY, FIREBASE_SERVICE_ACCOUNT. Nothing from the browser is trusted except the reference.
const AMOUNT_KOBO = 100000, DURATION_DAYS = 30, CURRENCY = 'NGN';   // fixed server-side values

const enc = new TextEncoder();
const b64u = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = s => { s = s.replace(/-/g, '+').replace(/_/g, '/'); return Uint8Array.from(atob(s.padEnd(Math.ceil(s.length / 4) * 4, '=')), c => c.charCodeAt(0)); };
class Unauth extends Error {}

/* Firebase ID token verification (RS256 against Google's public keys) */
let jwks = { keys: [], exp: 0 };
async function verifyIdToken(env, token) {
  const [h, p, s] = String(token).split('.');
  if (!s) throw new Unauth('malformed');
  const head = JSON.parse(new TextDecoder().decode(unb64u(h))), pl = JSON.parse(new TextDecoder().decode(unb64u(p)));
  if (head.alg !== 'RS256') throw new Unauth('alg');
  if (Date.now() > jwks.exp || !jwks.keys.find(k => k.kid === head.kid)) {
    const r = await fetch('https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com');
    jwks = { keys: (await r.json()).keys || [], exp: Date.now() + 36e5 };
  }
  const jwk = jwks.keys.find(k => k.kid === head.kid);
  if (!jwk) throw new Unauth('kid');
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  if (!(await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, unb64u(s), enc.encode(h + '.' + p)))) throw new Unauth('sig');
  const now = Date.now() / 1000, pid = env.FIREBASE_PROJECT_ID;
  if (pl.exp <= now || pl.iat > now + 60 || pl.aud !== pid || pl.iss !== 'https://securetoken.google.com/' + pid || !pl.sub) throw new Unauth('claims');
  return pl;   // pl.sub is the real UID
}

/* Firestore REST via service account (bypasses rules; credentials stay in a Worker secret) */
let gtok = { v: null, exp: 0 };
async function gToken(env) {
  if (gtok.v && Date.now() < gtok.exp) return gtok.v;
  const sa = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT), now = Math.floor(Date.now() / 1000);
  const head = b64u(enc.encode(JSON.stringify({ alg: 'RS256', typ: 'JWT' })));
  const claim = b64u(enc.encode(JSON.stringify({ iss: sa.client_email, scope: 'https://www.googleapis.com/auth/datastore', aud: 'https://oauth2.googleapis.com/token', iat: now, exp: now + 3600 })));
  const der = Uint8Array.from(atob(sa.private_key.replace(/-----[^-]+-----/g, '').replace(/\s/g, '')), c => c.charCodeAt(0));
  const key = await crypto.subtle.importKey('pkcs8', der, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, enc.encode(head + '.' + claim));
  const r = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: head + '.' + claim + '.' + b64u(sig) }) });
  const j = await r.json();
  if (!j.access_token) throw new Error('google token failed');
  gtok = { v: j.access_token, exp: Date.now() + (j.expires_in - 120) * 1000 };
  return gtok.v;
}
const root = env => `projects/${env.FIREBASE_PROJECT_ID}/databases/(default)/documents`;
async function fs(env, method, path, body) {
  const r = await fetch(`https://firestore.googleapis.com/v1/${root(env)}${path}`, { method, headers: { Authorization: 'Bearer ' + await gToken(env), 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
  if (r.status === 404) return null;
  const j = await r.json();
  if (!r.ok) { const e = new Error('firestore ' + r.status); e.status = r.status; throw e; }
  return j;
}
const S = v => ({ stringValue: String(v) }), I = v => ({ integerValue: String(v) }), TS = ms => ({ timestampValue: new Date(ms).toISOString() });
const g = (d, k) => { const f = d && d.fields && d.fields[k]; if (!f) return undefined; if (f.timestampValue) return Date.parse(f.timestampValue); if (f.integerValue !== undefined) return Number(f.integerValue); return f.stringValue ?? f.booleanValue; };
const commit = (env, writes) => fs(env, 'POST', ':commit', { writes });
const iso = ms => ms ? new Date(ms).toISOString() : null;

/* The ONE processing path used by both /verify-payment and /webhook. claim = verified {uid} or null (webhook). */
async function processPayment(env, ref, claim) {
  const done = ex => ({ success: true, status: 'approved', reference: ref, proExpiresAt: iso(g(ex, 'proExpiresAt')) });
  const existing = await fs(env, 'GET', '/proPayments/' + encodeURIComponent(ref));
  if (existing && g(existing, 'status') === 'approved') return done(existing);          // already processed: never credit twice

  const r = await fetch('https://api.paystack.co/transaction/verify/' + encodeURIComponent(ref), { headers: { Authorization: 'Bearer ' + env.PAYSTACK_SECRET_KEY } });
  const v = await r.json().catch(() => null), d = v && v.data;
  if (!v) return { success: false, status: 'pending', message: 'Payment is still being verified.' };
  if (!v.status || !d) return r.status === 404 ? { success: false, status: 'failed', message: 'Payment could not be verified.' } : { success: false, status: 'pending', message: 'Payment is still being verified.' };
  if (d.status !== 'success') return ['failed', 'abandoned', 'reversed'].includes(d.status) ? { success: false, status: 'failed', message: 'Payment could not be verified.' } : { success: false, status: 'pending', message: 'Payment is still being verified.' };
  const bad = { success: false, status: 'failed', message: 'Payment could not be verified.' };
  if (d.reference !== ref || d.amount !== AMOUNT_KOBO || d.currency !== CURRENCY) return bad;
  const uid = d.metadata && d.metadata.uid;
  if (!uid || (claim && claim.uid !== uid)) return bad;                                  // must belong to the authenticated user
  const email = (d.customer && d.customer.email || '').toLowerCase();

  for (let attempt = 0; attempt < 3; attempt++) {
    const ud = await fs(env, 'GET', '/users/' + encodeURIComponent(uid));
    if (!ud || String(g(ud, 'email') || '').toLowerCase() !== email) return bad;
    const now = Date.now(), cur = g(ud, 'premiumExpiresAt') || 0, live = g(ud, 'premium') === true && cur > now;
    const start = live ? cur : now, exp = start + DURATION_DAYS * 864e5, began = live && g(ud, 'premiumStartedAt') ? g(ud, 'premiumStartedAt') : now;
    const payName = `${root(env)}/proPayments/${ref}`;
    try {
      // One atomic commit: the payment record must NOT exist yet, and the user must be unchanged since we read it.
      await commit(env, [
        { update: { name: payName, fields: { uid: S(uid), userId: S(uid), email: S(email), amount: I(AMOUNT_KOBO), amountNaira: I(AMOUNT_KOBO / 100), currency: S(CURRENCY), reference: S(ref), status: S('approved'), provider: S('paystack'), plan: S('pro'), durationDays: I(DURATION_DAYS), source: S('automatic'), paystackTransactionId: S(d.id), paystackStatus: S(d.status), verifiedAt: TS(now), proStartsAt: TS(start), proExpiresAt: TS(exp) } }, currentDocument: { exists: false } },
        { update: { name: `${root(env)}/users/${uid}`, fields: { premium: { booleanValue: true }, premiumSource: S('paystack'), premiumPlan: S('pro_monthly'), premiumStartedAt: TS(began), premiumExpiresAt: TS(exp), lastPaymentReference: S(ref), updatedAt: TS(now) } }, updateMask: { fieldPaths: ['premium', 'premiumSource', 'premiumPlan', 'premiumStartedAt', 'premiumExpiresAt', 'lastPaymentReference', 'updatedAt'] }, currentDocument: { updateTime: ud.updateTime } },
      ]);
      return { success: true, status: 'approved', reference: ref, proExpiresAt: iso(exp) };
    } catch (e) {
      const again = await fs(env, 'GET', '/proPayments/' + encodeURIComponent(ref));
      if (again && g(again, 'status') === 'approved') return done(again);               // a concurrent request won: report, don't credit again
      if (attempt === 2) throw e;                                                       // else the user changed mid-flight: retry
    }
  }
}

/* HTTP */
const same = (a, b) => { if (a.length !== b.length) return false; let x = 0; for (let i = 0; i < a.length; i++) x |= a.charCodeAt(i) ^ b.charCodeAt(i); return x === 0; };
async function validSig(env, raw, sig) {
  const k = await crypto.subtle.importKey('raw', enc.encode(env.PAYSTACK_SECRET_KEY), { name: 'HMAC', hash: 'SHA-512' }, false, ['sign']);
  const hex = [...new Uint8Array(await crypto.subtle.sign('HMAC', k, enc.encode(raw)))].map(x => x.toString(16).padStart(2, '0')).join('');
  return same(hex, sig || '');
}
const out = (o, status, h) => new Response(JSON.stringify(o), { status, headers: { ...h, 'Content-Type': 'application/json' } });
const REF = /^[A-Za-z0-9_.=-]{6,100}$/;

export default {
  async fetch(req, env) {
    const u = new URL(req.url), origin = req.headers.get('Origin');
    const h = origin && origin === env.ALLOWED_ORIGIN ? { 'Access-Control-Allow-Origin': origin, 'Access-Control-Allow-Headers': 'Authorization, Content-Type', 'Access-Control-Allow-Methods': 'POST, OPTIONS', Vary: 'Origin' } : {};
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: h });
    try {
      if (req.method === 'POST' && u.pathname === '/verify-payment') {
        const c = await verifyIdToken(env, (req.headers.get('Authorization') || '').replace(/^Bearer /, ''));
        const ref = String(((await req.json().catch(() => ({}))).reference) || '');
        if (!REF.test(ref)) return out({ success: false, message: 'Payment could not be verified.' }, 400, h);
        return out(await processPayment(env, ref, { uid: c.sub }), 200, h);
      }
      if (req.method === 'POST' && u.pathname === '/webhook') {
        const raw = await req.text();
        if (!(await validSig(env, raw, req.headers.get('x-paystack-signature')))) return out({ success: false, message: 'invalid signature' }, 401, {});
        const ev = JSON.parse(raw);
        if (ev.event === 'charge.success' && ev.data && REF.test(String(ev.data.reference || ''))) await processPayment(env, ev.data.reference, null);
        return out({ success: true }, 200, {});
      }
      if (req.method === 'GET' && u.pathname === '/health') return out({ ok: true }, 200, h);
      return out({ success: false, message: 'Not found.' }, 404, h);
    } catch (e) {
      if (e instanceof Unauth) return out({ success: false, message: 'Please sign in again.' }, 401, h);
      console.error(e.message);
      return out({ success: false, status: 'pending', message: 'Payment is still being verified.' }, 500, h);
    }
  },
};
