// Interactive SSO Demo — White theme + Policy Simulator
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
  // Demo secrets (change these if you want to rotate the demo):
  totpSecret: "JBSWY3DPEHPK3PXP",           // Base32 (e.g., "Hello!")
  jwtSecret:  "andrew-iam-portfolio-demo-key", // HS256 signing key (demo)
  interval: null,
  audit: [],
  latestPayload: null,
  latestToken: null,
};

const policy = {
  expectedAud: "https://app.example.com",
  requireMFA: true,
  minRoles: 1,
  expLeewaySec: 0 // allow small clock skew if you want (>0)
};

function logAudit(event, details={}){
  const ts = new Date().toISOString();
  state.audit.push({ ts, event, ...details });
  const el = qs('#audit');
  if(el) el.textContent = JSON.stringify(state.audit, null, 2);
}

// Build small “What-if Policy Simulator” controls in the Policy column
function buildPolicySimulatorUI(){
  const col = document.querySelector('#checks')?.parentElement;
  if(!col) return;

  // Avoid double-build
  if(col.querySelector('.sim-wrap')) return;

  const wrap = document.createElement('div');
  wrap.className = 'sim-wrap';
  wrap.style.marginBottom = '10px';
  wrap.innerHTML = `
    <h4 style="margin:4px 0 6px">What-if Policy Simulator</h4>
    <div class="row" style="gap:8px;flex-wrap:wrap">
      <label style="font-size:13px">Expected aud:
        <input id="sim-aud" type="text" value="${policy.expectedAud}" style="margin-left:6px;min-width:220px">
      </label>
      <label style="font-size:13px">
        <input id="sim-mfa" type="checkbox" ${policy.requireMFA ? 'checked':''}> Require MFA
      </label>
      <label style="font-size:13px">Min roles:
        <input id="sim-roles" type="number" min="0" value="${policy.minRoles}" style="width:64px;margin-left:6px">
      </label>
      <label style="font-size:13px">Exp leeway (s):
        <input id="sim-leeway" type="number" min="0" value="${policy.expLeewaySec}" style="width:80px;margin-left:6px">
      </label>
      <button id="sim-apply" class="btn ghost">Apply</button>
    </div>
  `;
  col.prepend(wrap);

  // Wire up simulator apply
  wrap.querySelector('#sim-apply').addEventListener('click', ()=>{
    policy.expectedAud   = wrap.querySelector('#sim-aud').value.trim() || policy.expectedAud;
    policy.requireMFA    = wrap.querySelector('#sim-mfa').checked;
    policy.minRoles      = Math.max(0, parseInt(wrap.querySelector('#sim-roles').value || "0", 10));
    policy.expLeewaySec  = Math.max(0, parseInt(wrap.querySelector('#sim-leeway').value || "0", 10));
    logAudit('policy_updated', {...policy});
    // Re-run checks if we have a payload already
    if(state.latestPayload) renderClaims(state.latestPayload);
  });
}

// ---------- QR (visual placeholder) ----------
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

// ---------- Claims & Checks ----------
function renderClaims(payload){
  const table = qs('#claims');
  if(!table) return;
  table.innerHTML = "";
  const rows = Object.entries(payload);
  const mk = (k,v)=>`<tr><th>${k}</th><td>${Array.isArray(v)? v.map(x=>`<span class="badge">${x}</span>`).join(' ') : (typeof v==='object'? `<code>${JSON.stringify(v)}</code>` : String(v))}</td></tr>`;
  table.innerHTML = rows.map(([k,v])=>mk(k,v)).join("");

  // Policy checks
  const ul = qs('#checks');
  if(!ul) return;
  ul.innerHTML = "";
  const now = Math.floor(Date.now()/1000);
  const checks = [
    {label:`Token not expired (≤ ${policy.expLeewaySec}s leeway)`, ok: payload.exp && (payload.exp + policy.expLeewaySec) > now},
    {label:`Audience accepted (${policy.expectedAud})`, ok: payload.aud === policy.expectedAud},
    {label:`AMR ${policy.requireMFA ? 'includes MFA' : 'checked (MFA not required)'}`, ok: policy.requireMFA ? (Array.isArray(payload.amr) && payload.amr.includes("mfa")) : true},
    {label:`Has ≥ ${policy.minRoles} role(s)`, ok: Array.isArray(payload.roles) && payload.roles.length >= policy.minRoles},
    {label:"Has security groups", ok: Array.isArray(payload.groups) && payload.groups.length > 0},
  ];
  checks.forEach(c=>{
    const li = document.createElement('li');
    li.innerHTML = c.ok ? `<span class="badge good">PASS</span> ${c.label}` : `<span class="badge warn">CHECK</span> ${c.label}`;
    ul.appendChild(li);
  });
}

// ---------- App wiring ----------
function setup(){
  // Theme toggle
  const themeBtn = qs('#btn-theme');
  if(themeBtn){
    themeBtn.addEventListener('click', (e)=>{
      const on = !document.body.classList.contains('dark');
      document.body.classList.toggle('dark', on);
      e.currentTarget.setAttribute('aria-pressed', String(on));
      logAudit('theme_toggle', {dark:on});
    });
  }

  // Build Policy Simulator UI
  buildPolicySimulatorUI();

  // Step 1
  qs('#form-credentials').addEventListener('submit', e=>{
    e.preventDefault();
    const email = qs('#email').value.trim();
    const pass  = qs('#password').value.trim();
    if(!email || !email.includes('@')) return alert('Enter a valid email.');
    if(!pass || pass.length < 8)      return alert('Password must be at least 8 characters (demo rule).');
    state.email = email;
    logAudit('signin_submit', {email});

    const secret = state.totpSecret;
    qs('#mfa-secret').textContent = secret;
    const canvas = qs('#qr');
    if(canvas) drawMockQR(canvas, `otpauth://totp/ACS:${email}?secret=${secret}&issuer=AccessControlSecure`);

    const ttlEl  = qs('#mfa-ttl');
    const codeEl = qs('#mfa-code');
    const tick = async () => {
      const now = Date.now();
      const remain = 30 - Math.floor((now/1000) % 30);
      if(ttlEl)  ttlEl.textContent  = remain + "s";
      if(codeEl) codeEl.textContent = await totp(secret, now, 30);
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
    const input   = qs('#mfa-input').value.trim();
    const current = (qs('#mfa-code')?.textContent || "").trim();
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
      amr: ["pwd","mfa"],           // password + MFA
      scope: "openid profile email",
      iat: now,
      exp: now + 60*10,            // 10 minutes
      jti: uuidv4()
    };
    const encodedHeader  = b64url(JSON.stringify(header));
    const encodedPayload = b64url(JSON.stringify(payload));
    const signingInput   = enc.encode(`${encodedHeader}.${encodedPayload}`);
    const sig            = await hmacSha256(enc.encode(state.jwtSecret), signingInput);
    const signature      = b64url(sig);
    const token          = `${encodedHeader}.${encodedPayload}.${signature}`;

    state.latestPayload = payload;
    state.latestToken   = token;

    const jwtPre = qs('#jwt');
    if(jwtPre) jwtPre.textContent = token;
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
    const token = (qs('#jwt')?.textContent || "").trim();
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
    const token = (qs('#jwt')?.textContent || "").trim();
    if(!token) return;
    const [h,p,s] = token.split('.');
    try{
      const header  = JSON.parse(atob(h.replace(/-/g,'+').replace(/_/g,'/')));
      const payload = JSON.parse(atob(p.replace(/-/g,'+').replace(/_/g,'/')));
      const out = { token, header, payload, signature:s };
      downloadFile('token.json', JSON.stringify(out, null, 2));
      logAudit('token_download');
    }catch(e){
      alert('Could not parse token.');
    }
  });

  qs('#btn-back-2').addEventListener('click', ()=>{ logAudit('back_to_mfa'); go(2); });
  qs('#btn-continue').addEventListener('click', ()=>{ logAudit('continue_to_redirect'); go(4); });

  // Step 4
  qs('#btn-restart').addEventListener('click', ()=>{
    clearInterval(state.interval);
    state.email = null;
    state.audit = [];
    state.latestPayload = null;
    state.latestToken = null;
    const auditEl = qs('#audit'); if(auditEl) auditEl.textContent = "[]";
    qsa('form').forEach(f=>f.reset());
    const jwtPre = qs('#jwt');    if(jwtPre) jwtPre.textContent = "";
    const claims = qs('#claims'); if(claims) claims.innerHTML = "";
    const checks = qs('#checks'); if(checks) checks.innerHTML = "";
    const res = qs('#verify-result'); if(res) res.textContent = "";
    logAudit('restart');
    go(1);
  });

  // Start
  logAudit('loaded');
  go(1);
}

document.addEventListener('DOMContentLoaded', setup);

