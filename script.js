// Interactive SSO Demo — White theme, enterprise polish
// Features: Credentials → TOTP (RFC 6238) → HS256 JWT → Redirect, claim highlights, policy checks, audit trail, theme toggle

// ---- Utilities ----
const qs = (s)=>document.querySelector(s);
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

function downloadFile(name, text){
  const blob = new Blob([text], {type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.click();
  URL.revokeObjectURL(a.href);
}

// ---- TOTP (RFC 6238) ----
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

// ---- JWT (HS256) ----
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
  return `${hex[0]}${hex[1]}${hex[2]}${hex[3]}-${hex[4]}${hex[5]}-${hex[6]}${hex[7]}-${hex[8]}${hex[9]}-${hex[10]}${hex[11]}${hex[12]}${hex[13]}-${hex[14]}${hex[15]}`;
}

// ---- State & Theme ----
const state = {
  email: null,
  totpSecret: "JBSWY3DPEHPK3PXP",
  jwtSecret: "andrew-iam-portfolio-demo-key",
  interval: null,
  audit: []
};

function logAudit(event, details={}){
  const ts = new Date().toISOString();
  state.audit.push({ ts, event, ...details });
  qs('#audit').textContent = JSON.stringify(state.audit, null, 2);
}

function drawMockQR(canvas, text){
  const ctx = canvas.getContext('2d');
  const {width:w, height:h} = canvas;
  ctx.clearRect(0,0,w,h);
  ctx.fillStyle = "#f0f6ff";
  ctx.fillRect(0,0,w,h);
  ctx.strokeStyle = "#d9e4f2";
  ctx.strokeRect(4,4,w-8,h-8);
  ctx.fillStyle = "#2d7bff";
  for(let y=12; y<h-12; y+=16){
    for(let x=12; x<w-12; x+=16){
      if(((x+y)/16) % 2 === 0) ctx.fillRect(x,y,6,6);
    }
  }
  ctx.fillStyle = "#274266";
  ctx.font = "10px ui-sans-serif";
  ctx.fillText("TOTP DEMO", 36, h-12);
}

function renderClaims(payload){
  const table = qs('#claims');
  table.innerHTML = "";
  const rows = Object.entries(payload);
  const mk = (k,v)=>`<tr><th>${k}</th><td>${Array.isArray(v)? v.map(x=>`<span class="badge">${x}</span>`).join(' ') : (typeof v==='object'? `<code>${JSON.stringify(v)}</code>` : String(v))}</td></tr>`;
  table.innerHTML = rows.map(([k,v])=>mk(k,v)).join("");

  const ul = qs('#checks');
  ul.innerHTML = "";
  const now = Math.floor(Date.now()/1000);
  const checks = [
    {label:"Token not expired", ok: payload.exp && payload.exp > now},
    {label:"Audience accepted (app.example.com)", ok: payload.aud === "https://app.example.com"},
    {label:"AMR includes MFA", ok: Array.isArray(payload.amr) && payload.amr.includes("mfa")},
    {label:"Has IAM roles", ok: Array.isArray(payload.roles) && payload.roles.length > 0},
    {label:"Has security groups", ok: Array.isArray(payload.groups) && payload.groups.length > 0},
  ];
  checks.forEach(c=>{
    const li = document.createElement('li');
    li.innerHTML = c.ok ? `<span class="badge good">PASS</span> ${c.label}` : `<span class="badge warn">CHECK</span> ${c.label}`;
    ul.appendChild(li);
  });
}

// ---- App wiring ----
function setup(){
  // Theme toggle
  qs('#btn-theme').addEventListener('click', (e)=>{
    const on = !document.body.classList.contains('dark');
    document.body.classList.toggle('dark', on);
    e.currentTarget.setAttribute('aria-pressed', String(on));
    logAudit('theme_toggle', {dark:on});
  });

  // Step 1
  qs('#form-credentials').addEventListener('submit', e=>{
    e.preventDefault();
    const email = qs('#email').value.trim();
    const pass = qs('#password').value.trim();
    if(!email || !email.includes('@')) return alert('Enter a valid email.');
    if(!pass || pass.length < 8) return alert('Password must be at least 8 characters (demo rule).');
    state.email = email;
    logAudit('signin_submit', {email});

    const secret = state.totpSecret;
    qs('#mfa-secret').textContent = secret;
    drawMockQR(qs('#qr'), `otpauth://totp/ACS:${email}?secret=${secret}&issuer=AccessControlSecure`);

    const ttlEl = qs('#mfa-ttl');
    const codeEl = qs('#mfa-code');
    const tick = async () => {
      const now = Date.now();
      const remain = 30 - Math.floor((now/1000) % 30);
      ttlEl.textContent = remain + "s";
      codeEl.textContent = await totp(secret, now, 30);
    };
    clearInterval(state.interval);
    tick();
    state.interval = setInterval(tick, 1000);
    go(2);
  });

  qs('#btn-back-1').addEventListener('click', ()=>{
    clearInterval(state.interval);
    logAudit('back_to_credentials');
    go(1);
  });

  // Step 2
  qs('#form-mfa').addEventListener('submit', async e=>{
    e.preventDefault();
    const input = qs('#mfa-input').value.trim();
    const current = qs('#mfa-code').textContent.trim();
    if(input !== current){
      logAudit('mfa_failed', {input});
      return alert('Invalid code. Try again in this or the next window.');
    }
    logAudit('mfa_ok');

    // Build HS256 JWT
    const now = Math.floor(Date.now()/1000);
    const header = { alg: "HS256", typ: "JWT" };
    const payload = {
      iss: "https://idp.example.com",
      aud: "https://app.example.com",
      sub: state.email || "user@example.com",
      name: "Andrew Symister (Demo)",
      roles: ["User","PAM-Viewer","Access-Reviewer"],
      groups: ["iam-lab","security","audit-readers"],
      amr: ["pwd","mfa"],
      scope: "openid profile email",
      iat: now, exp: now + 60*10, jti: uuidv4()
    };
    const encodedHeader = b64url(JSON.stringify(header));
    const encodedPayload = b64url(JSON.stringify(payload));
    const signingInput = enc.encode(`${encodedHeader}.${encodedPayload}`);
    const sig = await hmacSha256(enc.encode(state.jwtSecret), signingInput);
    const signature = b64url(sig);
    const token = `${encodedHeader}.${encodedPayload}.${signature}`;

    qs('#jwt').textContent = token;
    renderClaims(payload);
    logAudit('jwt_issued', {sub: payload.sub, exp: payload.exp});
    go(3);
  });

  // Step 3
  qs('#btn-copy').addEventListener('click', async ()=>{
    try{
      await navigator.clipboard.writeText(qs('#jwt').textContent);
      logAudit('token_copied');
      alert('Token copied to clipboard.');
    }catch(e){ alert('Copy failed.'); }
  });

  qs('#btn-verify').addEventListener('click', async ()=>{
    const token = qs('#jwt').textContent.trim();
    const [h,p,s] = token.split('.');
    if(!h||!p||!s){ qs('#verify-result').textContent = "Invalid token format."; return; }
    const ok = await hmacSha256Verify(
      enc.encode(state.jwtSecret),
      enc.encode(`${h}.${p}`),
      fromB64url(s).buffer
    );
    qs('#verify-result').textContent = ok ? "Signature valid ✅" : "Signature invalid ❌";
    logAudit('token_verify', {ok});
  });

  qs('#btn-download').addEventListener('click', ()=>{
    const token = qs('#jwt').textContent.trim();
    const [h,p,s] = token.split('.');
    const header = JSON.parse(atob(h.replace(/-/g,'+').replace(/_/g,'/')));
    const payload = JSON.parse(atob(p.replace(/-/g,'+').replace(/_/g,'/')));
    const out = { token, header, payload, signature:s };
    downloadFile('token.json', JSON.stringify(out, null, 2));
    logAudit('token_download');
  });

  qs('#btn-back-2').addEventListener('click', ()=>{ logAudit('back_to_mfa'); go(2); });
  qs('#btn-continue').addEventListener('click', ()=>{ logAudit('continue_to_redirect'); go(4); });

  // Step 4
  qs('#btn-restart').addEventListener('click', ()=>{
    clearInterval(state.interval);
    state.email = null;
    state.audit = [];
    qs('#audit').textContent = "[]";
    qsa('form').forEach(f=>f.reset());
    qs('#jwt').textContent = "";
    qs('#claims').innerHTML = "";
    qs('#checks').innerHTML = "";
    qs('#verify-result').textContent = "";
    logAudit('restart');
    go(1);
  });

  // Audit download
  qs('#btn-audit').addEventListener('click', ()=>{
    downloadFile('audit.json', JSON.stringify(state.audit, null, 2));
  });

  // Start
  logAudit('loaded');
  go(1);
}

document.addEventListener('DOMContentLoaded', setup);
