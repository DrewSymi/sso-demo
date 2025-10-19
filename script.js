// Interactive SSO Demo — White theme + Vendor switcher + Policy Simulator
// Flow: Credentials → TOTP (RFC 6238) → HS256 JWT → Redirect
// Extras: claim table, policy checks, simulator controls, audit log, copy/verify/download

// ---------- Utilities ----------
const qs  = (s)=>document.querySelector(s);
const qsa = (s)=>Array.from(document.querySelectorAll(s));
const enc = new TextEncoder();

const b64url = (bytesOrStr) => {
  const str = bytesOrStr instanceof Uint8Array ? String.fromCharCode(...bytesOrStr) : bytesOrStr;
  return btoa(str).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
};
const fromB64url = (b64u) => {
  const pad = (s)=> s + "===".slice((s.length+3)%4);
  return Uint8Array.from(atob(pad(b64u.replace(/-/g,'+').replace(/_/g,'/'))), c=>c.charCodeAt(0));
};

function go(n){
  qsa('.panel').forEach((p,i)=>p.classList.toggle('active', i===n-1));
  qsa('.stepper .step').forEach((s,i)=>s.classList.toggle('active', i<=n-1));
  window.scrollTo({top:0,behavior:'smooth'});
}

function downloadFile(name, text, type='application/json'){
  const blob = new Blob([text], {type});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.click();
  URL.revokeObjectURL(a.href);
}

// ---------- TOTP (RFC 6238) ----------
const BASE32_ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32Decode(str){
  const clean = str.replace(/=+$/,'').toUpperCase().replace(/[^A-Z2-7]/g,'');
  let bits = "", out = [];
  for(const c of clean){
    const val = BASE32_ALPH.indexOf(c);
    if(val < 0) continue;
    bits += val.toString(2).padStart(5,'0');
  }
  for(let i=0;i+8<=bits.length;i+=8){
    out.push(parseInt(bits.slice(i,i+8),2));
  }
  return new Uint8Array(out);
}

async function hmacSha1(keyBytes, msgBytes){
  const key = await crypto.subtle.importKey("raw", keyBytes, {name:"HMAC", hash:"SHA-1"}, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, msgBytes);
  return new Uint8Array(sig);
}

function intToBytes(num){
  const arr = new Uint8Array(8);
  new DataView(arr.buffer).setBigUint64(0, BigInt(num));
  return arr;
}

async function totp(secretB32, time = Date.now(), step = 30, digits = 6){
  const keyBytes = base32Decode(secretB32);
  const counter = Math.floor(time/1000/step);
  const msg = intToBytes(counter);
  const hmac = await hmacSha1(keyBytes, msg);
  const offset = hmac[hmac.length-1] & 0x0f;
  const bin = ((hmac[offset] & 0x7f) << 24) |
              ((hmac[offset+1] & 0xff) << 16) |
              ((hmac[offset+2] & 0xff) << 8)  |
              (hmac[offset+3] & 0xff);
  const otp = (bin % (10 ** digits)).toString().padStart(digits,'0');
  return otp;
}

// ---------- JWT (HS256) ----------
async function hmacSha256(keyBytes, msgBytes){
  const key = await crypto.subtle.importKey("raw", keyBytes, {name:"HMAC", hash:"SHA-256"}, false, ["sign","verify"]);
  const sig = await crypto.subtle.sign("HMAC", key, msgBytes);
  return new Uint8Array(sig);
}
async function hmacSha256Verify(keyBytes, msgBytes, signature){
  const key = await crypto.subtle.importKey("raw", keyBytes, {name:"HMAC", hash:"SHA-256"}, false, ["verify"]);
  return crypto.subtle.verify("HMAC", key, signature, msgBytes);
}
function uuidv4(){
  const a = new Uint8Array(16);
  crypto.getRandomValues(a);
  a[6] = (a[6] & 0x0f) | 0x40;
  a[8] = (a[8] & 0x3f) | 0x80;
  const hex = [...a].map(b=>b.toString(16).padStart(2,'0'));
  return `${hex[0]}${hex[1]}${hex[2]}${hex[3]}-${hex[4]}${hex[5]}-${hex[6]}${hex[7]}-${hex[8]}${hex[9]}-${hex[10]}${hex[11]}${hex[12]}${hex[13]}${hex[14]}${hex[15]}`;
}

// ---------- State & Policy Simulator ----------
const state = {
  email: null,
  totpSecret: "JBSWY3DPEHPK3PXP",           // Base32 demo secret
  jwtSecret:  "andrew-iam-portfolio-demo-key", // HS256 demo key
  interval: null,
  audit: [],
  latestPayload: null,
  latestToken: null,
};

const policy = {
  expectedAud: "https://app.example.com",
  requireMFA: true,
  minRoles: 1,
  expLeeway
