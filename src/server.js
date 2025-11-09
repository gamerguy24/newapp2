import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { getWeather as getOpenMeteoWeather } from './providers/openmeteo.js';
import { getAirQuality } from './providers/openmeteo-air.js'; // NEW
import fs from 'node:fs';
import crypto from 'node:crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// NEW: User storage and auth settings
const DATA_DIR = path.join(__dirname, '..', 'data');
const USERS_DB = path.join(DATA_DIR, 'users.json');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(USERS_DB)) fs.writeFileSync(USERS_DB, '[]');

const APP_SECRET = process.env.APP_SECRET || 'dev-' + crypto.randomBytes(32).toString('hex');
const TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

function readUsers() {
  try { return JSON.parse(fs.readFileSync(USERS_DB, 'utf8')); } catch { return []; }
}
function writeUsers(users) {
  fs.writeFileSync(USERS_DB, JSON.stringify(users, null, 2));
}
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.pbkdf2Sync(password, salt, 120000, 32, 'sha256').toString('hex');
  return { salt, hash };
}
function verifyPassword(password, user) {
  if (!user?.salt || !user?.passwordHash) return false;
  const { hash } = hashPassword(password, user.salt);
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(user.passwordHash, 'hex'));
}
function b64url(buf) {
  return Buffer.from(typeof buf === 'string' ? buf : JSON.stringify(buf))
    .toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function signToken(payload) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const body = { ...payload, exp: Date.now() + TOKEN_TTL_MS };
  const part1 = b64url(header);
  const part2 = b64url(body);
  const sig = crypto.createHmac('sha256', APP_SECRET).update(`${part1}.${part2}`).digest('base64')
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  return `${part1}.${part2}.${sig}`;
}
function verifyToken(token) {
  try {
    const [p1, p2, sig] = String(token).split('.');
    const expected = crypto.createHmac('sha256', APP_SECRET).update(`${p1}.${p2}`).digest('base64')
      .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    if (!crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig))) return null;
    const payload = JSON.parse(Buffer.from(p2.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
    if (!payload?.exp || Date.now() > payload.exp) return null;
    return payload;
  } catch { return null; }
}
function parseCookies(req) {
  const raw = req.headers.cookie || '';
  return raw.split(';').map(v => v.trim()).filter(Boolean).reduce((acc, cur) => {
    const i = cur.indexOf('=');
    if (i > -1) acc[cur.slice(0, i)] = decodeURIComponent(cur.slice(i + 1));
    return acc;
  }, {});
}
function setAuthCookie(res, token) {
  const isProd = process.env.NODE_ENV === 'production';
  const cookie = [
    `auth=${encodeURIComponent(token)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    isProd ? 'Secure' : '',
    `Max-Age=${Math.floor(TOKEN_TTL_MS / 1000)}`
  ].filter(Boolean).join('; ');
  res.setHeader('Set-Cookie', cookie);
}
function clearAuthCookie(res) {
  const cookie = `auth=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`;
  res.setHeader('Set-Cookie', cookie);
}

// Attach req.user if cookie present
app.use((req, _res, next) => {
  try {
    const cookies = parseCookies(req);
    const tok = cookies.auth;
    const payload = tok ? verifyToken(tok) : null;
    if (payload?.sub) req.user = { username: payload.sub };
  } catch {}
  next();
});

// Simple in-memory cache: key -> { data, expiresAt }
const cache = new Map();
const DEFAULT_TTL_MS = 60 * 1000; // 1 minute to keep UI snappy without rate issues
const AIR_TTL_MS = 10 * 60 * 1000; // cache air quality longer
const ALERTS_TTL_MS = 2 * 60 * 1000; // alerts refresh every 2 minutes

// Defaults for United States, Atlanta, GA
const DEFAULT_COORDS = { lat: 33.7490, lon: -84.3880 };
const DEFAULT_UNITS = 'us';

// MapTiler (weather layers) API key (fallback placeholder)
const MAPTILER_KEY = process.env.MAPTILER_KEY || 'y9ll4swt9c9AYv0zu5O6';

// ADD BACK: Alert feed URLs (were removed, caused ReferenceError)
const ALERT_ATOM_URLS = [
  'https://api.weather.gov/alerts/active.atom?event=Tornado+Warning',
  'https://api.weather.gov/alerts/active.atom?event=Severe+Thunderstorm+Warning',
  'https://api.weather.gov/alerts/active.atom?event=Flash+Flood+Warning'
];

// Helpers to resolve coords/units with sensible fallbacks
function cacheKey({ lat, lon, units }) {
  return `${lat}:${lon}:${units || 'auto'}`;
}
function resolveCoords(req) {
  const qLat = parseFloat(req.query.lat);
  const qLon = parseFloat(req.query.lon);
  return {
    lat: Number.isFinite(qLat) ? qLat : DEFAULT_COORDS.lat,
    lon: Number.isFinite(qLon) ? qLon : DEFAULT_COORDS.lon
  };
}
function resolveUnits(req) {
  const u = (req.query.units || DEFAULT_UNITS).toLowerCase();
  return u === 'imperial' ? 'us' : u;
}

app.use(express.json());

// --- SpotterNetwork proxy helpers ---
const SPOTTER_BASE = 'https://www.spotternetwork.org';
// NEW: default SpotterNetwork Application ID (can be overridden via env)
const DEFAULT_SPOTTER_ID = process.env.SPOTTER_ID || '55f78b6ed31f5';

async function spotterPost(endpoint, body) {
  const r = await fetch(`${SPOTTER_BASE}${endpoint}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {})
  });
  const text = await r.text();
  let data = null;
  try { data = JSON.parse(text); } catch { data = { raw: text }; }
  return { ok: r.ok, status: r.status, data };
}

// Proxy: fetch positions (POST /positions). Accept both GET (query) and POST (body).
app.get('/api/spotter/positions', async (req, res) => {
  try {
    const id = String(req.query.id || '').trim();
    if (!id) return res.status(400).json({ error: 'Missing id' });
    const markers = req.query.markers ? String(req.query.markers).split(',').map(s => parseInt(s, 10)).filter(n => Number.isFinite(n)) : undefined;
    const payload = markers && markers.length ? { id, markers } : { id };
    const { ok, status, data } = await spotterPost('/positions', payload);
    return res.status(status).json(data);
  } catch (e) {
    console.error('Spotter positions error', e);
    return res.status(500).json({ error: 'Failed to fetch positions' });
  }
});

app.post('/api/spotter/positions', async (req, res) => {
  try {
    const { id, markers } = req.body || {};
    if (!id) return res.status(400).json({ error: 'Missing id' });
    const payload = Array.isArray(markers) && markers.length ? { id, markers } : { id };
    const { ok, status, data } = await spotterPost('/positions', payload);
    return res.status(status).json(data);
  } catch (e) {
    console.error('Spotter positions error', e);
    return res.status(500).json({ error: 'Failed to fetch positions' });
  }
});

// Optional: update position proxy
app.post('/api/spotter/positions/update', async (req, res) => {
  try {
    const { id, report_at, lat, lon, elev, mph, dir, active, gps } = req.body || {};
    if (!id) return res.status(400).json({ error: 'Missing id' });
    const payload = { id, report_at, lat, lon, elev, mph, dir, active, gps };
    const { status, data } = await spotterPost('/positions/update', payload);
    return res.status(status).json(data);
  } catch (e) {
    console.error('Spotter update error', e);
    return res.status(500).json({ error: 'Failed to update position' });
  }
});

// Helper to disable caching for inline pages
function noStore(res) {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
}

// --- HTML helpers (reuse for /, /tv, /map) ---
function tvHtml() {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <!-- updated for mobile PWA friendliness -->
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover" />
  <meta name="theme-color" content="#0b1020" />
  <meta name="apple-mobile-web-app-capable" content="yes" />
  <meta name="format-detection" content="telephone=no,email=no,address=no" />
  <title>Twistcasterlive Media • TV</title>
  <style>
    :root{--bg0:#0b1020;--bg1:#111a34;--glass:rgba(255,255,255,.06);--glass-b:rgba(255,255,255,.08);--fg:#e6eef8;--muted:#a8b3c7;--accent:#4fb3ff}
    *{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
    html,body{height:100%;margin:0;background:radial-gradient(1000px 600px at 10% 0%,#17243f,#0b1020);color:var(--fg);font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;overflow:auto;overflow-x:hidden}
    .topbar{display:flex;gap:1rem;align-items:center;justify-content:space-between;flex-wrap:wrap;padding:calc(.5rem + env(safe-area-inset-top)) 1rem .5rem 1rem;background:linear-gradient(180deg,rgba(255,255,255,.06),rgba(255,255,255,.02));border-bottom:1px solid var(--glass-b)}
    .brand{font-weight:800;letter-spacing:.1em;color:var(--accent)}
    .nav{display:flex;gap:.6rem;flex-wrap:wrap}
    .nav a{font-size:.75rem;letter-spacing:.05em;text-transform:uppercase;background:rgba(255,255,255,.06);color:var(--muted);padding:.45rem .7rem;border-radius:8px;text-decoration:none;font-weight:600;transition:.2s}
    .nav a:hover,.nav a:focus{background:rgba(255,255,255,.12);color:var(--fg)}
    .nav a.active{background:var(--accent);color:#051627}
    .now{display:flex;gap:1rem;color:var(--muted);font-weight:600}
    /* NEW: 2-row grid with scrollable days sidebar */
    .grid{height:calc(100dvh - 110px);display:grid;grid-template-columns:360px 1fr;grid-template-rows:1fr 1fr;gap:12px;padding:12px 12px calc(12px + env(safe-area-inset-bottom))}
    .panel{background:var(--glass);border:1px solid var(--glass-b);border-radius:14px;padding:12px;overflow:hidden}
    .panel-title{font-size:.9rem;color:var(--muted);margin-bottom:10px;letter-spacing:.06em;text-transform:uppercase}
    /* Days now scrollable, spans both rows */
    .days{grid-row:1 / span 2;display:flex;flex-direction:column;gap:12px;overflow-y:auto;padding-right:6px}
    .days::-webkit-scrollbar{width:6px}
    .days::-webkit-scrollbar-track{background:rgba(255,255,255,.05);border-radius:8px}
    .days::-webkit-scrollbar-thumb{background:rgba(255,255,255,.15);border-radius:8px}
    .days::-webkit-scrollbar-thumb:hover{background:rgba(255,255,255,.25)}
    .day{background:rgba(255,255,255,.04);border:1px solid var(--glass-b);border-radius:10px;padding:12px;display:grid;grid-template-columns:1fr auto;align-items:center;min-height:90px}
    .day .left{display:grid;gap:8px}.day .name{font-weight:700;font-size:1rem}.day .sub{color:var(--muted);font-size:.95rem}
    .day .right{text-align:right}.day .icon{font-size:2rem}.day .hilo{font-weight:700;font-size:1.1rem}
    /* Current bigger: increase icon/temp size */
    .current .current-row{display:grid;grid-template-columns:auto 1fr;gap:20px}
    .bigtemp{display:flex;align-items:baseline;gap:14px;font-weight:800;padding:12px 14px;background:rgba(255,255,255,.04);border-radius:12px}
    #cur-icon{font-size:4rem}#cur-temp{font-size:6rem;line-height:.9}#cur-unit{color:var(--muted);font-size:1.6rem}
    .cur-meta{display:grid;gap:8px;font-size:1rem}.cur-meta .sub{color:var(--muted)}
    /* Tomorrow bigger */
    .tomorrow{grid-column:2;grid-row:2}
    .tom-row{display:grid;grid-template-columns:auto 1fr;gap:16px;align-items:center}
    .tom-icon{font-size:4rem}.tom-meta{display:grid;gap:6px}.tom-meta .t{font-weight:700;fontsize:1.1rem}.tom-meta .sub{color:var(--muted);font-size:.95rem}
    /* Air bigger */
    .air{grid-column:1;grid-row:2}
    .air .aq-row{display:grid;grid-template-columns:140px 1fr;gap:16px}
    .aq-badge{display:grid;place-items:center;font-weight:800;border-radius:14px;background:rgba(255,255,255,.08);height:120px;font-size:1.2rem}
    .aq-meta{display:grid;gap:6px}.aq-meta .t{font-weight:700;font-size:1.05rem}.aq-meta .sub{color:var(--muted);font-size:.9rem}
    /* Alerts now in alerts panel (if needed, adjust) - keep as-is for now */
    .alerts{display:grid;grid-template-rows:auto 1fr}
    .alerts-list{height:100%;overflow:auto;display:grid;gap:8px;padding-right:4px}
    .alert{background:rgba(255,255,255,.04);border:1px solid var(--glass-b);border-left:6px solid #f39c12;border-radius:10px;padding:8px}
    .alert .h{font-weight:800} .alert .sub{color:var(--muted);font-size:.9rem}
    .ticker{height:50px;border-top:1px solid var(--glass-b);background:linear-gradient(180deg,rgba(255,255,255,.02),rgba(255,255,255,.06));overflow:hidden}
    .track{display:inline-flex;gap:28px;align-items:center;white-space:nowrap;padding-left:100%;animation:scroll 40s linear infinite}
    .tag{background:var(--accent);color:#06121f;font-weight:800;padding:6px 10px;border-radius:8px}.tick{color:var(--fg);opacity:.95}
    @keyframes scroll{from{transform:translateX(0)}to{transform:translateX(-50%)}}
    @media (prefers-reduced-motion: reduce){.track{animation:none}}
    @media (max-width: 900px){
      html,body{overflow:auto}
      .grid{grid-template-columns:1fr;grid-template-rows:auto;gap:10px;height:auto;min-height:100dvh;padding:8px 8px calc(8px + env(safe-area-inset-bottom))}
      .now{gap:.5rem;font-size:.9rem}
      .days{grid-row:auto;flex-direction:row;overflow-x:auto;overflow-y:hidden;padding-bottom:8px;padding-right:0}
      .day{min-width:140px}
      #cur-icon{font-size:2.5rem}#cur-temp{font-size:4rem}#cur-unit{font-size:1.2rem}
      .tom-icon{font-size:2.5rem}
      .aq-badge{height:90px;font-size:1rem}
      .ticker{height:36px}
      .tag{padding:4px 8px}
    }
    @media (max-width: 420px){
      .nav{width:100%}
      .ticker{display:none}
      .day{min-width:130px}
    }
  </style>
</head>
<body>
  <header class="topbar">
    <div style="display:flex;align-items:center;gap:1rem;flex-wrap:wrap">
      <div class="brand">TWISTCASTERLIVE MEDIA</div>
      <nav class="nav">
        <a href="/tv" class="active">Dashboard</a>
        <a href="/map">Map</a>
        <a href="/team">Team</a>
        <a href="/stream">Stream</a>
      </nav>
    </div>
    <div class="now">
      <span id="city">Atlanta, GA</span>
      <span id="clock">--:--</span>
      <span id="tz"></span>
    </div>
  </header>
  <main class="grid">
    <aside class="panel days" id="days"></aside>
    <section class="panel current">
      <div class="panel-title">Current Conditions</div>
      <div class="current-row">
        <div class="bigtemp"><span id="cur-icon">⛅</span><span id="cur-temp">--</span><span id="cur-unit">°F</span></div>
        <div class="cur-meta">
          <div id="cur-desc">Loading...</div>
          <div id="cur-hilo">H -- / L --</div>
          <div>Wind: <span id="cur-wind">--</span></div>
          <div>Sunrise: <span id="cur-sunrise">--</span> • Sunset: <span id="cur-sunset">--</span></div>
        </div>
      </div>
    </section>
    <section class="panel air">
      <div class="panel-title">Air Quality (US AQI)</div>
      <div class="aq-row">
        <div class="aq-badge" id="aq-badge">--</div>
        <div class="aq-meta">
          <div class="t">Index: <span id="aq-index">--</span></div>
          <div class="sub">PM2.5: <span id="aq-pm25">--</span> μg/m³ • PM10: <span id="aq-pm10">--</span> μg/m³</div>
          <div class="sub" id="aq-time">--</div>
        </div>
      </div>
    </section>
    <section class="panel tomorrow">
      <div class="panel-title">Tomorrow</div>
      <div class="tom-row">
        <div class="tom-icon" id="tom-icon">⛅</div>
        <div class="tom-meta">
          <div class="t">High: <span id="tom-high">--</span></div>
          <div class="t">Low: <span id="tom-low">--</span></div>
          <div class="sub" id="tom-desc"></div>
        </div>
      </div>
    </section>
    <section class="panel alerts">
      <div class="panel-title">Weather Alerts (NWS)</div>
      <div class="alerts-list" id="alerts"></div>
    </section>
  </main>
  <footer class="ticker"><div class="track" id="ticker-track"></div></footer>
  <script type="module">
    // REMOVED: all MapTiler map code (no radar on dashboard)
    const qs=(n,d)=>{const v=new URLSearchParams(location.search).get(n); return v??d;};
    const coords={ lat: parseFloat(qs('lat','${DEFAULT_COORDS.lat}'))||${DEFAULT_COORDS.lat},
                   lon: parseFloat(qs('lon','${DEFAULT_COORDS.lon}'))||${DEFAULT_COORDS.lon} };
    const units=(qs('units','${DEFAULT_UNITS}')||'${DEFAULT_UNITS}').toLowerCase();
    const state=(qs('state','GA')||'GA').toUpperCase();
    document.getElementById('city').textContent=\`\${coords.lat.toFixed(2)}, \${coords.lon.toFixed(2)}\`;

    const dayName = s => new Date(s).toLocaleDateString([], { weekday:'short' });
    const hm = s => s ? new Date(s).toLocaleTimeString([], { hour:'2-digit', minute:'2-digit' }) : '--';
    const iconFor = c => ({0:'☀️',1:'🌤️',2:'⛅',3:'☁️',45:'🌫️',48:'🌫️',51:'🌦️',53:'🌦️',55:'🌧️',56:'🌧️',57:'🌧️',61:'🌧️',63:'🌧️',65:'🌧️',66:'🌧️',67:'🌧️',71:'🌨️',73:'🌨️',75:'❄️',77:'❄️',80:'🌦️',81:'🌦️',82:'⛈️',85:'🌨️',86:'❄️',95:'⛈️',96:'⛈️',99:'⛈️'}[c]||'❓');

    // Render 7 days (scrollable)
    function renderDays(daily, unit){
      const el=document.getElementById('days'); el.innerHTML='';
      const times=daily.time||[];
      const max=Math.min(7,times.length);
      for(let i=0;i<max;i++){
        const icon=iconFor(daily.weathercode?.[i]??0);
        const hi=Math.round(daily.temperature_2m_max?.[i]??0);
        const lo=Math.round(daily.temperature_2m_min?.[i]??0);
        const div=document.createElement('div'); div.className='day';
        div.innerHTML=\`<div class="left"><div class="name">\${dayName(times[i])}</div><div class="sub">\${icon}</div></div>
                        <div class="right"><div class="icon">\${icon}</div><div class="hilo">\${hi}\${unit} / \${lo}\${unit}</div></div>\`;
        el.appendChild(div);
      }
    }
    function renderCurrent(data){
      document.getElementById('cur-icon').textContent=data.current.icon;
      document.getElementById('cur-temp').textContent=Math.round(data.current.temperature);
      document.getElementById('cur-unit').textContent=data.current.units.temperature;
      document.getElementById('cur-desc').textContent=data.current.description;
      document.getElementById('cur-hilo').textContent=\`H \${Math.round(data.today.high)} / L \${Math.round(data.today.low)}\`;
      document.getElementById('cur-wind').textContent=\`\${Math.round(data.current.windspeed)} \${data.current.units.windspeed}\`;
      document.getElementById('cur-sunrise').textContent=hm(data.today.sunrise);
      document.getElementById('cur-sunset').textContent=hm(data.today.sunset);
      document.getElementById('tz').textContent=data.location?.timezone||'';
    }
    function renderTomorrow(data){
      const d=data.raw?.daily||{};
      const i=(d.time?.length||0)>1?1:0;
      const hi=Math.round(d.temperature_2m_max?.[i]??data.today.high??0);
      const lo=Math.round(d.temperature_2m_min?.[i]??data.today.low??0);
      document.getElementById('tom-icon').textContent=iconFor(d.weathercode?.[i]??0);
      document.getElementById('tom-high').textContent=\`\${hi}\${data.current.units.temperature}\`;
      document.getElementById('tom-low').textContent=\`\${lo}\${data.current.units.temperature}\`;
    }
    function severityColor(sev){
      const s=(sev||'').toLowerCase();
      if(s.includes('extreme')) return '#7f1d1d';
      if(/severe|high|warning/.test(s)) return '#e74c3c';
      if(/moderate|watch/.test(s)) return '#f39c12';
      return '#2ecc71';
    }
    function renderAlerts(feed){
      const list=document.getElementById('alerts'); list.innerHTML='';
      if(!feed?.items?.length){
        list.innerHTML='<div class="alert" style="border-left-color:#2ecc71"><div class="h">No active alerts</div><div class="sub">NWS</div></div>';
        return;
      }
      feed.items.forEach(it=>{
        const when=it.updated?new Date(it.updated).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'}):'';
        const div=document.createElement('div'); div.className='alert';
        div.style.borderLeftColor=severityColor(it.severity||it.title||'');
        div.innerHTML=\`<div class="h">\${it.event||it.title||'Alert'}</div><div class="sub">\${it.areaDesc||''}</div><div class="sub">\${when}</div>\`;
        list.appendChild(div);
      });
    }
    function buildTicker(data, air, alerts){
      const items=[
        {tag:'Temp',text:\`\${Math.round(data.current.temperature)}\${data.current.units.temperature}\`},
        {tag:'Wind',text:\`\${Math.round(data.current.windspeed)} \${data.current.units.windspeed}\`},
        {tag:'Sunrise',text:hm(data.today.sunrise)},
        {tag:'Sunset',text:hm(data.today.sunset)}
      ];
      if(air?.current?.aqi!=null) items.push({tag:'AQI',text:\`\${air.current.aqi} \${air.current.category}\`});
      if(alerts?.items?.length) items.push({tag:'ALERT',text:alerts.items.slice(0,3).map(a=>a.event||a.title).join(' • ')});
      const html=items.map(i=>\`<span class="tag">\${i.tag}</span><span class="tick">\${i.text}</span>\`).join('<span>•</span>');
      document.getElementById('ticker-track').innerHTML='<div>'+html+'</div><div style="margin-left:48px">'+html+'</div>';
    }
    (function clock(){
      const el=document.getElementById('clock');
      setInterval(()=>{ el.textContent=new Date().toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',second:'2-digit'}); },500);
    })();

    async function load(){
      const wurl=\`/api/weather?lat=\${coords.lat}&lon=\${coords.lon}&units=\${encodeURIComponent(units)}\`;
      const aurl=\`/api/air?lat=\${coords.lat}&lon=\${coords.lon}\`;
      const alurl=\`/api/alerts?state=\${encodeURIComponent(state)}&lat=\${coords.lat}&lon=\${coords.lon}\`;
      const [wr,ar,alr]=await Promise.all([fetch(wurl),fetch(aurl).catch(()=>null),fetch(alurl).catch(()=>null)]);
      if(!wr.ok) return;
      const weather=await wr.json();
      const air=ar?.ok?await ar.json():null;
      const alerts=alr?.ok?await alr.json():null;
      renderCurrent(weather);
      renderDays(weather.raw?.daily||{}, weather.current.units.temperature);
      renderTomorrow(weather);
      if(air?.current){
        const b=document.getElementById('aq-badge'); b.textContent=air.current.category; b.style.background=air.current.color;
        document.getElementById('aq-index').textContent=air.current.aqi??'--';
        document.getElementById('aq-pm25').textContent=air.current.pm25?.toFixed(1)??'--';
        document.getElementById('aq-pm10').textContent=air.current.pm10?.toFixed(1)??'--';
        document.getElementById('aq-time').textContent=air.current.time?'Updated '+hm(air.current.time):'';
      }
      renderAlerts(alerts);
      buildTicker(weather, air, alerts);
    }

    load().catch(console.error);
    const refreshDefault=/Mobi|Android|iPhone|iPad/i.test(navigator.userAgent)?90000:60000;
    const refreshMs=Math.max(15000, parseInt(qs('refresh', String(refreshDefault)),10)||refreshDefault);
    setInterval(()=>load().catch(()=>{}), refreshMs);
  </script>
</body>
</html>`;
}

// FIX: mapHtml now becomes the full radar view (no leftover Leaflet code)
function mapHtml() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Maptiler weather layers</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous"/>
  <script src="https://cdn.maptiler.com/maptiler-sdk-js/v3.8.0/maptiler-sdk.umd.min.js"></script>
  <link href="https://cdn.maptiler.com/maptiler-sdk-js/v3.8.0/maptiler-sdk.css" rel="stylesheet"/>
  <script src="https://cdn.maptiler.com/maptiler-weather/v3.1.1/maptiler-weather.umd.min.js"></script>
  <style>
    body{margin:0;padding:0;font-family:sans-serif}
    #map{position:absolute;top:0;bottom:0;width:100%;background-color:#3E4048}
    #pointer-data{z-index:1;position:fixed;font-size:20px;font-weight:900;margin:27px 0 0 10px;color:#fff;text-shadow:0 0 10px #0007}
    #variable-name{z-index:1;position:fixed;font-size:20px;font-weight:500;margin:5px 0 0 10px;color:#fff;text-shadow:0 0 10px #0007;text-transform:capitalize}
    #time-info{position:fixed;width:60vw;bottom:0;z-index:1;margin:10px;text-shadow:0 0 5px black;color:white;font-size:18px;font-weight:500;text-align:center;left:0;right:0;margin:auto;padding:20px}
    #time-text{font-size:12px;font-weight:600}
    #time-slider{width:100%;height:fit-content;left:0;right:0;z-index:1;filter:drop-shadow(0 0 7px #000a);margin-top:10px}
    #buttons{width:auto;margin:0 10px;padding:0;position:absolute;top:50px;left:0;z-index:99}
    .button{display:block;position:relative;margin:10px 0 0 0;font-size:0.9em}
    #back-btn{position:fixed;bottom:20px;right:20px;z-index:100;padding:10px 20px;font-size:14px;font-weight:600;border:none;border-radius:8px;background:#4fb3ff;color:#051627;cursor:pointer;box-shadow:0 2px 8px rgba(0,0,0,0.3);transition:all 0.2s}
    #back-btn:hover{background:#3a9de8;transform:translateY(-2px);box-shadow:0 4px 12px rgba(0,0,0,0.4)}
    .spotter-popup{font-size:12px;font-weight:600}
    .spotter-popup .name{font-size:14px;font-weight:700;margin-bottom:4px}
    .spotter-popup .detail{margin:2px 0;color:#555}
  </style>
</head>
<body>
  <button id="back-btn" onclick="window.location.href='/tv'">← Back to Dashboard</button>
  <div id="time-info">
    <span id="time-text"></span>
    <button id="play-pause-bt" class="btn btn-primary btn-sm time-button">Play 3600x</button>
    <input type="range" id="time-slider" min="0" max="11" step="1">
  </div>
  <div id="variable-name">Wind</div>
  <div id="pointer-data"></div>
  <div id="map">
    <ul id="buttons">
      <li id="precipitation" class="btn btn-primary button">Precipitation</li>
      <li id="pressure" class="btn btn-primary button">Pressure</li>
      <li id="radar" class="btn btn-primary button">Radar</li>
      <li id="temperature" class="btn btn-primary button">Temperature</li>
      <li id="wind" class="btn btn-primary button">Wind</li>
    </ul>
  </div>
  <script>
    maptilersdk.config.apiKey = '${MAPTILER_KEY}';
    const SPOTTER_ID = '${DEFAULT_SPOTTER_ID}';
    const weatherLayers = {
      "precipitation": { "layer": null, "value": "value", "units": " mm" },
      "pressure": { "layer": null, "value": "value", "units": " hPa" },
      "radar": { "layer": null, "value": "value", "units": " dBZ" },
      "temperature": { "layer": null, "value": "value", "units": "°" },
      "wind": { "layer": null, "value": "speedMetersPerSecond", "units": " m/s" }
    };
    const map = (window.map = new maptilersdk.Map({
      container: 'map',
      style: maptilersdk.MapStyle.BACKDROP,
      zoom: 2,
      center: [-42.66, 37.63],
      hash: true,
      projectionControl: true,
      projection: 'globe'
    }));
    const initWeatherLayer = "wind";
    const timeInfoContainer = document.getElementById("time-info");
    const timeTextDiv = document.getElementById("time-text");
    const timeSlider = document.getElementById("time-slider");
    const playPauseButton = document.getElementById("play-pause-bt");
    const pointerDataDiv = document.getElementById("pointer-data");
    let pointerLngLat = null, activeLayer = null, isPlaying = false, currentTime = null;

    // SpotterNetwork markers
    let spotterMarkers = [];
    
    async function loadSpotters() {
      try {
        const res = await fetch(\`/api/spotter/positions?id=\${SPOTTER_ID}\`);
        if (!res.ok) return;
        const data = await res.json();
        
        // Clear old markers
        spotterMarkers.forEach(m => m.remove());
        spotterMarkers = [];
        
        if (!data?.positions) return;
        
        data.positions.forEach(pos => {
          const lat = parseFloat(pos.lat);
          const lon = parseFloat(pos.lon);
          if (!Number.isFinite(lat) || !Number.isFinite(lon)) return;
          
          // Create marker element
          const el = document.createElement('div');
          el.style.width = '12px';
          el.style.height = '12px';
          el.style.borderRadius = '50%';
          el.style.backgroundColor = pos.active ? '#ff4444' : '#4fb3ff';
          el.style.border = '2px solid white';
          el.style.boxShadow = '0 2px 4px rgba(0,0,0,0.3)';
          el.style.cursor = 'pointer';
          
          const marker = new maptilersdk.Marker({ element: el })
            .setLngLat([lon, lat])
            .addTo(map);
          
          // Build name from API fields: first, last, callsign
          const first = pos.first || '';
          const last = pos.last || '';
          const callsign = pos.callsign || '';
          const name = [first, last].filter(Boolean).join(' ') || callsign || 'Spotter';
          
          const mph = parseFloat(pos.mph) || 0;
          const dir = parseFloat(pos.dir) || 0;
          const reportAt = pos.report_at || pos.unix ? new Date(pos.unix * 1000).toLocaleString() : '';
          
          const popupHtml = \`
            <div class="spotter-popup">
              <div class="name">\${name}</div>
              \${callsign ? \`<div class="detail">Callsign: \${callsign}</div>\` : ''}
              <div class="detail">Speed: \${Math.round(mph)} mph</div>
              <div class="detail">Heading: \${Math.round(dir)}°</div>
              \${reportAt ? \`<div class="detail">Updated: \${reportAt}</div>\` : ''}
            </div>
          \`;
          const popup = new maptilersdk.Popup({ offset: 15 }).setHTML(popupHtml);
          marker.setPopup(popup);
          
          spotterMarkers.push(marker);
        });
      } catch (e) {
        console.warn('Failed to load spotters', e);
      }
    }
    timeSlider.addEventListener("input", (evt) => {
      const weatherLayer = weatherLayers[activeLayer]?.layer;
      if (weatherLayer) weatherLayer.setAnimationTime(parseInt(timeSlider.value / 1000));
    });
    playPauseButton.addEventListener("click", () => {
      const weatherLayer = weatherLayers[activeLayer]?.layer;
      if (weatherLayer) {
        if (isPlaying) pauseAnimation(weatherLayer);
        else playAnimation(weatherLayer);
      }
    });
    function pauseAnimation(weatherLayer) {
      weatherLayer.animateByFactor(0);
      playPauseButton.innerText = "Play 3600x";
      isPlaying = false;
    }
    function playAnimation(weatherLayer) {
      weatherLayer.animateByFactor(3600);
      playPauseButton.innerText = "Pause";
      isPlaying = true;
    }
    map.on('load', function () {
      map.setPaintProperty("Water", 'fill-color', "rgba(0, 0, 0, 0.4)");
      initWeatherMap(initWeatherLayer);
      loadSpotters();
    });
    map.on('mouseout', function(evt) {
      if (!evt.originalEvent.relatedTarget) {
        pointerDataDiv.innerText = "";
        pointerLngLat = null;
      }
    });
    function updatePointerValue(lngLat) {
      if (!lngLat) return;
      pointerLngLat = lngLat;
      const weatherLayer = weatherLayers[activeLayer]?.layer;
      const weatherLayerValue = weatherLayers[activeLayer]?.value;
      const weatherLayerUnits = weatherLayers[activeLayer]?.units;
      if (weatherLayer) {
        const value = weatherLayer.pickAt(lngLat.lng, lngLat.lat);
        if (!value) { pointerDataDiv.innerText = ""; return; }
        pointerDataDiv.innerText = \`\${value[weatherLayerValue].toFixed(1)}\${weatherLayerUnits}\`
      }
    }
    map.on('mousemove', (e) => { updatePointerValue(e.lngLat); });
    document.getElementById('buttons').addEventListener('click', function (event) {
      changeWeatherLayer(event.target.id);
    });
    function changeWeatherLayer(type) {
      if (type !== activeLayer) {
        if (map.getLayer(activeLayer)) {
          const activeWeatherLayer = weatherLayers[activeLayer]?.layer;
          if (activeWeatherLayer) {
            currentTime = activeWeatherLayer.getAnimationTime();
            map.setLayoutProperty(activeLayer, 'visibility', 'none');
          }
        }
        activeLayer = type;
        const weatherLayer = weatherLayers[activeLayer].layer || createWeatherLayer(activeLayer);
        if (map.getLayer(activeLayer)) map.setLayoutProperty(activeLayer, 'visibility', 'visible');
        else map.addLayer(weatherLayer, 'Water');
        changeLayerLabel(activeLayer);
        activateButton(activeLayer);
        changeLayerAnimation(weatherLayer);
        return weatherLayer;
      }
    }
    function activateButton(activeLayer) {
      const buttons = document.getElementsByClassName('button');
      for (let i = 0; i < buttons.length; i++) {
        const btn = buttons[i];
        if (btn.id === activeLayer) btn.classList.add('active');
        else btn.classList.remove('active');
      }
    }
    function changeLayerAnimation(weatherLayer) {
      weatherLayer.setAnimationTime(parseInt(timeSlider.value / 1000));
      if (isPlaying) playAnimation(weatherLayer);
      else pauseAnimation(weatherLayer);
    }
    function createWeatherLayer(type){
      let weatherLayer = null;
      switch (type) {
        case 'precipitation': weatherLayer = new maptilerweather.PrecipitationLayer({id: 'precipitation'}); break;
        case 'pressure': weatherLayer = new maptilerweather.PressureLayer({ opacity: 0.8, id: 'pressure' }); break;
        case 'radar': weatherLayer = new maptilerweather.RadarLayer({ opacity: 0.8, id: 'radar' }); break;
        case 'temperature': weatherLayer = new maptilerweather.TemperatureLayer({ colorramp: maptilerweather.ColorRamp.builtin.TEMPERATURE_3, id: 'temperature' }); break;
        case 'wind': weatherLayer = new maptilerweather.WindLayer({id: 'wind'}); break;
      }
      weatherLayer.on("tick", event => { refreshTime(); updatePointerValue(pointerLngLat); });
      weatherLayer.on("animationTimeSet", event => { refreshTime(); });
      weatherLayer.on("sourceReady", event => {
        const startDate = weatherLayer.getAnimationStartDate();
        const endDate = weatherLayer.getAnimationEndDate();
        if (timeSlider.min > 0){ weatherLayer.setAnimationTime(currentTime); changeLayerAnimation(weatherLayer); }
        else {
          const currentDate = weatherLayer.getAnimationTimeDate();
          timeSlider.min = +startDate;
          timeSlider.max = +endDate;
          timeSlider.value = +currentDate;
        }
      });
      weatherLayers[type].layer = weatherLayer;
      return weatherLayer;
    }
    function refreshTime() {
      const weatherLayer = weatherLayers[activeLayer]?.layer;
      if (weatherLayer) {
        const d = weatherLayer.getAnimationTimeDate();
        timeTextDiv.innerText = d.toString();
        timeSlider.value = +d;
      }
    }
    function changeLayerLabel(type) { document.getElementById("variable-name").innerText = type; }
    function initWeatherMap(type) { const weatherLayer = changeWeatherLayer(type); }
    
    // Refresh spotters every 60 seconds
    setInterval(loadSpotters, 60000);
  </script>
</body>
</html>`;
}

// ADD BACK: minimal team and stream pages so tabs work
function streamHtml() {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
  <meta name="theme-color" content="#0b1020">
  <title>Stream • Twistcasterlive Media</title>
  <style>
    :root{--bg0:#0b1020;--bg1:#111a34;--glass:rgba(255,255,255,.06);--glass-b:rgba(255,255,255,.08);--fg:#e6eef8;--muted:#a8b3c7;--accent:#4fb3ff}
    *{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
    html,body{height:100%;margin:0;background:radial-gradient(1000px 600px at 10% 0%,#17243f,#0b1020);color:var(--fg);font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
    .topbar{display:flex;gap:1rem;align-items:center;justify-content:space-between;flex-wrap:wrap;padding:calc(.5rem + env(safe-area-inset-top)) 1rem .5rem 1rem;background:linear-gradient(180deg,rgba(255,255,255,.06),rgba(255,255,255,.02));border-bottom:1px solid var(--glass-b)}
    .brand{font-weight:800;letter-spacing:.1em;color:var(--accent)}
    .nav{display:flex;gap:.6rem;flex-wrap:wrap}
    .nav a{font-size:.75rem;letter-spacing:.05em;text-transform:uppercase;background:rgba(255,255,255,.06);color:var(--muted);padding:.45rem .7rem;border-radius:8px;text-decoration:none;font-weight:600;transition:.2s}
    .nav a:hover,.nav a:focus{background:rgba(255,255,255,.12);color:var(--fg)}
    .nav a.active{background:var(--accent);color:#051627}
    .content{max-width:1400px;margin:40px auto;padding:0 16px calc(16px + env(safe-area-inset-bottom))}
    .panel{background:var(--glass);border:1px solid var(--glass-b);border-radius:14px;padding:24px;margin-bottom:20px}
    h1{font-size:2rem;margin:0 0 16px;color:var(--accent)}
    p{line-height:1.6;color:var(--muted)}
    .embed{width:100%;aspect-ratio:16/9;border-radius:12px;overflow:hidden;background:#000;border:1px solid var(--glass-b)}
    .embed iframe{width:100%;height:100%;border:none}
  </style>
</head>
<body>
  <header class="topbar">
    <div style="display:flex;align-items:center;gap:1rem;flex-wrap:wrap">
      <div class="brand">TWISTCASTERLIVE MEDIA</div>
      <nav class="nav">
        <a href="/tv">Dashboard</a>
        <a href="/map">Map</a>
        <a href="/team">Team</a>
        <a href="/stream" class="active">Stream</a>
      </nav>
    </div>
  </header>
  <main class="content">
    <div class="panel">
      <h1>Live Stream</h1>
      <div class="embed">
        <iframe src="https://www.youtube.com/embed/live_stream?channel=UCQvEZ1q0pS4YoaPWGS8DHeg" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>
      </div>
    </div>
  </main>
</body>
</html>`;
}

function teamHtml() {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
  <meta name="theme-color" content="#0b1020">
  <title>Team • Twistcasterlive Media</title>
  <style>
    :root{--bg0:#0b1020;--bg1:#111a34;--glass:rgba(255,255,255,.06);--glass-b:rgba(255,255,255,.08);--fg:#e6eef8;--muted:#a8b3c7;--accent:#4fb3ff}
    *{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
    html,body{min-height:100%;margin:0;background:radial-gradient(1000px 600px at 10% 0%,#17243f,#0b1020);color:var(--fg);font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
    .topbar{display:flex;gap:1rem;align-items:center;justify-content:space-between;flex-wrap:wrap;padding:calc(.5rem + env(safe-area-inset-top)) 1rem .5rem 1rem;background:linear-gradient(180deg,rgba(255,255,255,.06),rgba(255,255,255,.02));border-bottom:1px solid var(--glass-b)}
    .brand{font-weight:800;letter-spacing:.1em;color:var(--accent)}
    .nav{display:flex;gap:.6rem;flex-wrap:wrap}
    .nav a{font-size:.75rem;letter-spacing:.05em;text-transform:uppercase;background:rgba(255,255,255,.06);color:var(--muted);padding:.45rem .7rem;border-radius:8px;text-decoration:none;font-weight:600;transition:.2s}
    .nav a:hover,.nav a:focus{background:rgba(255,255,255,.12);color:var(--fg)}
    .nav a.active{background:var(--accent);color:#051627}
    .content{max-width:1200px;margin:40px auto;padding:0 16px calc(16px + env(safe-area-inset-bottom))}
    .panel{background:var(--glass);border:1px solid var(--glass-b);border-radius:14px;padding:24px;margin-bottom:20px}
    h1{font-size:2rem;margin:0 0 16px;color:var(--accent)}
    h2{font-size:1.3rem;margin:24px 0 12px;color:var(--fg)}
    p{line-height:1.6;color:var(--muted)}
    .team-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:16px;margin-top:24px}
    .member{background:rgba(255,255,255,.04);border:1px solid var(--glass-b);border-radius:10px;padding:16px;text-align:center}
    .member .name{font-weight:700;font-size:1.1rem;color:var(--fg);margin-bottom:4px}
    .member .role{color:var(--accent);font-size:.9rem;margin-bottom:8px}
    .member .bio{color:var(--muted);font-size:.85rem;line-height:1.5}
  </style>
</head>
<body>
  <header class="topbar">
    <div style="display:flex;align-items:center;gap:1rem;flex-wrap:wrap">
      <div class="brand">TWISTCASTERLIVE MEDIA</div>
      <nav class="nav">
        <a href="/tv">Dashboard</a>
        <a href="/map">Map</a>
        <a href="/team" class="active">Team</a>
        <a href="/stream">Stream</a>
      </nav>
    </div>
  </header>
  <main class="content">
    <div class="panel">
      <h1>Our Team</h1>
      <p>Meet the storm chasers, meteorologists, and media professionals behind Twistcasterlive Media.</p>
      
      <h2>Leadership</h2>
      <div class="team-grid">
        <div class="member">
          <div class="name">Nathan Bradley</div>
          <div class="role">Founder</div>
          <div class="bio">Founder / Storm Tracker, Meteorologist</div>
        </div>
        <div class="member">
          <div class="name">David Wallis</div>
          <div class="role">President</div>
          <div class="bio">Social Media Manager / Coding Specialist</div>
        </div>
      </div>
      
      <h2>Meteorology Team</h2>
      <div class="team-grid">
        <div class="member">
          <div class="name">Joey Pisani</div>
          <div class="role">Lead Meteorologist</div>
          <div class="bio">Weather Forecasting / Analysis</div>
        </div>
      </div>
      
      <h2>Storm Chasers</h2>
      <div class="team-grid">
        <div class="member">
          <div class="name">Nick Carter</div>
          <div class="role">Lead Storm Chaser</div>
          <div class="bio">Field Operations</div>
        </div>
        <div class="member">
          <div class="name">Mandy Jenes</div>
          <div class="role">Storm Chaser</div>
          <div class="bio">TCL Media</div>
        </div>
        <div class="member">
          <div class="name">Jesse Perkins</div>
          <div class="role">Storm Chaser</div>
          <div class="bio">TCL Media</div>
        </div>
        <div class="member">
          <div class="name">Michael Lynn</div>
          <div class="role">Storm Chaser</div>
          <div class="bio">TCL Media</div>
        </div>
        <div class="member">
          <div class="name">Cody Knox</div>
          <div class="role">Storm Chaser</div>
          <div class="bio">TCL Media</div>
        </div>
      </div>
      
      <h2>SpotterNetwork Integration</h2>
      <p>Our team uses SpotterNetwork to share real-time position data during active weather events. All spotters are registered with unique callsigns and follow NWS reporting protocols.</p>
      
      <h2>Contact</h2>
      <p>For media inquiries, collaboration opportunities, or SpotterNetwork coordination, reach out via your preferred contact method.</p>
    </div>
  </main>
</body>
</html>`;
}

// --- Routes ---
// Serve TV at root and index.html explicitly (bypass any static index)
app.get(['/', '/index.html'], (req, res) => {
  noStore(res);
  res.type('html').send(tvHtml());
});

// Keep static after the root handler so it doesn't shadow the custom pages
app.use(express.static(path.join(__dirname, '..', 'public'), { index: false, maxAge: '1h' }));

// NEW: Auth API
app.post('/api/auth/register', (req, res) => {
  try {
    const { username, password, displayName } = req.body || {};
    const uname = String(username || '').trim().toLowerCase();
    if (!/^[a-z0-9_]{3,20}$/.test(uname)) return res.status(400).json({ error: 'Invalid username' });
    if (String(password || '').length < 6) return res.status(400).json({ error: 'Password too short' });

    const users = readUsers();
    if (users.find(u => u.username === uname)) return res.status(409).json({ error: 'Username taken' });

    const { salt, hash } = hashPassword(password);
    const user = {
      username: uname,
      displayName: String(displayName || uname),
      passwordHash: hash,
      salt,
      createdAt: new Date().toISOString()
    };
    users.push(user);
    writeUsers(users);

    const token = signToken({ sub: uname });
    setAuthCookie(res, token);
    return res.json({ username: user.username, displayName: user.displayName, createdAt: user.createdAt });
  } catch (e) {
    console.error('Register error', e);
    return res.status(500).json({ error: 'Failed to register' });
  }
});

app.post('/api/auth/login', (req, res) => {
  try {
    const { username, password } = req.body || {};
    const uname = String(username || '').trim().toLowerCase();
    const users = readUsers();
    const user = users.find(u => u.username === uname);
    if (!user || !verifyPassword(String(password || ''), user)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = signToken({ sub: user.username });
    setAuthCookie(res, token);
    return res.json({ username: user.username, displayName: user.displayName, createdAt: user.createdAt });
  } catch (e) {
    console.error('Login error', e);
    return res.status(500).json({ error: 'Failed to login' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  clearAuthCookie(res);
  return res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  try {
    if (!req.user?.username) return res.status(401).json({ error: 'Unauthorized' });
    const users = readUsers();
    const user = users.find(u => u.username === req.user.username);
    if (!user) return res.status(401).json({ error: 'Unauthorized' });
    return res.json({ username: user.username, displayName: user.displayName, createdAt: user.createdAt });
  } catch (e) {
    console.error('Me error', e);
    return res.status(500).json({ error: 'Failed to load profile' });
  }
});

app.get('/api/weather', async (req, res) => {
  try {
    const { lat, lon } = resolveCoords(req);
    const units = resolveUnits(req);

    const key = cacheKey({ lat, lon, units });
    const now = Date.now();
    const entry = cache.get(key);
    if (entry && entry.expiresAt > now) {
      return res.json(entry.data);
    }

    // Provider selection (extensible)
    const data = await getOpenMeteoWeather({ lat, lon, units });

    cache.set(key, { data, expiresAt: now + DEFAULT_TTL_MS });
    res.json(data);
  } catch (err) {
    console.error('Weather API error:', err);
    res.status(500).json({ error: 'Failed to retrieve weather data' });
  }
});

app.get('/api/air', async (req, res) => {
  try {
    const { lat, lon } = resolveCoords(req);
    const key = `air:${lat}:${lon}`;
    const now = Date.now();
    const entry = cache.get(key);
    if (entry && entry.expiresAt > now) return res.json(entry.data);

    const data = await getAirQuality({ lat, lon });
    cache.set(key, { data, expiresAt: now + AIR_TTL_MS });
    res.json(data);
  } catch (err) {
    console.error('Air API error:', err);
    res.status(500).json({ error: 'Failed to retrieve air quality' });
  }
});

// NEW helpers for polygon parsing and point-in-polygon
function parsePolygon(str) {
  if (!str) return null;
  const pts = String(str)
    .trim()
    .split(/\s+/)
    .map(p => {
      const [la, lo] = p.split(',');
      const lat = parseFloat(la), lon = parseFloat(lo);
      return Number.isFinite(lat) && Number.isFinite(lon) ? [lat, lon] : null;
    })
    .filter(Boolean);
  return pts.length >= 3 ? pts : null;
}
function pointInPolygon(lat, lon, poly) {
  if (!Array.isArray(poly) || poly.length < 3) return false;
  let inside = false;
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
    const xi = poly[i][1], yi = poly[i][0];
    const xj = poly[j][1], yj = poly[j][0];
    const intersect = (yi > lat) !== (yj > lat) && lon < ((xj - xi) * (lat - yi)) / ((yj - yi) || 1e-12) + xi;
    if (intersect) inside = !inside;
  }
  return inside;
}

// UPDATE: Parse NWS Atom feed with UGC + polygon extraction (capture ALL UGC values)
function parseAtom(xml) {
  const entries = [];
  const blocks = xml.match(/<entry[\s\S]*?<\/entry>/gi) || [];
  for (const b of blocks) {
    const get = (tag) => {
      const re = new RegExp(`<(?:[a-zA-Z0-9_]+:)?${tag}[^>]*>([\\s\\S]*?)<\\/(?:[a-zA-Z0-9_]+:)?${tag}>`, 'i');
      const m = b.match(re);
      return m ? m[1].replace(/<!\\[CDATA\\[(.*?)\\]\\]>/g, '$1').trim() : null;
    };
    const linkMatch = b.match(/<link[^>]+href="([^"]+)"/i);

    // Collect all <geocode> blocks (with or without namespace)
    const geocodes = b.match(/<(?:[a-zA-Z0-9_]+:)?geocode[\s\S]*?<\/(?:[a-zA-Z0-9_]+:)?geocode>/gi) || [];
    const ugc = [];
    const fips6 = [];

    for (const g of geocodes) {
      // Capture values under UGC
      const ugcIdx = g.search(/<valueName>\s*UGC\s*<\/valueName>/i);
      if (ugcIdx >= 0) {
        const after = g.slice(ugcIdx);
        const stop = after.search(/<valueName>/i);
        const seg = stop > 0 ? after.slice(0, stop) : after;
        const vals = [...seg.matchAll(/<value>([\s\S]*?)<\/value>/gi)].map(m => m[1]);
        for (const v of vals) {
          v.split(/[\s,;]+/g).forEach(code => {
            const c = code.trim().toUpperCase();
            if (c) ugc.push(c);
          });
        }
      }
      // Capture values under FIPS6 (optional)
      const fipsIdx = g.search(/<valueName>\s*FIPS6\s*<\/valueName>/i);
      if (fipsIdx >= 0) {
        const after = g.slice(fipsIdx);
        const stop = after.search(/<valueName>/i);
        const seg = stop > 0 ? after.slice(0, stop) : after;
        const vals = [...seg.matchAll(/<value>([\s\S]*?)<\/value>/gi)].map(m => m[1]);
        for (const v of vals) {
          v.split(/[\s,;]+/g).forEach(code => {
            const c = code.trim();
            if (c) fips6.push(c);
          });
        }
      }
    }

    const polygon = parsePolygon(get('polygon'));

    entries.push({
      id: get('id'),
      title: get('title'),
      summary: get('summary'),
      updated: get('updated') || get('sent') || null,
      effective: get('effective'),
      expires: get('expires'),
      areaDesc: get('areaDesc'),
      severity: get('severity'),
      event: get('event'),
      link: linkMatch ? linkMatch[1] : null,
      ugc,
      fips6,
      polygon
    });
  }
  return entries;
}

// REPLACE: Alerts API -> fetch three event-specific Atom feeds, merge, filter by state and point
app.get('/api/alerts', async (req, res) => {
  try {
    const state = String(req.query.state || 'GA').toUpperCase(); // default GA
    const qLat = parseFloat(req.query.lat);
    const qLon = parseFloat(req.query.lon);
    const lat = Number.isFinite(qLat) ? qLat : DEFAULT_COORDS.lat;
    const lon = Number.isFinite(qLon) ? qLon : DEFAULT_COORDS.lon;
    const nocache = String(req.query.nocache || '').toLowerCase() === '1' || String(req.query.nocache || '').toLowerCase() === 'true';

    // Use fixed URLs list for cache key
    const evKey = ALERT_ATOM_URLS.join('|');
    const key = `alerts:${state}:${lat.toFixed(2)}:${lon.toFixed(2)}:${evKey}`;
    const now = Date.now();

    if (!nocache) {
      const entry = cache.get(key);
      if (entry && entry.expiresAt > now) return res.json(entry.data);
    }

    const headers = {
      'User-Agent': 'Twistcasterlive Media (contact: you@example.com)',
      'Accept': 'application/atom+xml'
    };

    // Fetch all event-specific feeds concurrently (exact links)
    const urls = ALERT_ATOM_URLS;
    const xmls = await Promise.all(
      urls.map(async (u) => {
        const r = await fetch(u, { headers, redirect: 'follow' });
        if (!r.ok) throw new Error(`NWS alerts error: ${r.status}`);
        return r.text();
      })
    );

    // Merge and dedupe by id
    const merged = [];
    for (const xml of xmls) merged.push(...parseAtom(xml));
    const byId = new Map();
    for (const it of merged) {
      if (it?.id && !byId.has(it.id)) byId.set(it.id, it);
    }
    let items = Array.from(byId.values());
    const fetchedCount = items.length;

    // State filter: UGC prefix or text fallback; include full state name for GA and neighbors
    const fullName = state === 'GA' ? 'GEORGIA'
                   : state === 'AL' ? 'ALABAMA'
                   : state === 'FL' ? 'FLORIDA'
                   : state === 'SC' ? 'SOUTH CAROLINA'
                   : state === 'NC' ? 'NORTH CAROLINA'
                   : null;

    let afterState = items.length;
    if (state && state !== 'ALL') {
      items = items.filter(i => {
        if (Array.isArray(i.ugc) && i.ugc.some(code => code.startsWith(state))) return true;
        const hay = `${i.areaDesc || ''} ${i.summary || ''} ${i.title || ''}`.toUpperCase();
        if (hay.includes(` ${state}`) || hay.includes(`(${state})`) || hay.includes(`${state}-`) || hay.includes(`${state},`)) return true;
        if (fullName && hay.includes(fullName)) return true;
        return false;
      });
      afterState = items.length;
      // IMPORTANT: If state filter yields nothing, fall back to the unfiltered list
      if (afterState === 0) {
        items = Array.from(byId.values());
      }
    }

    // If polygons exist, prefer alerts whose polygons contain the point
    const polyHits = items.filter(i => Array.isArray(i.polygon) && pointInPolygon(lat, lon, i.polygon));
    const afterPoly = polyHits.length;
    if (afterPoly > 0) items = polyHits;

    items = items.slice(0, 50);
    const data = {
      state,
      point: { lat, lon },
      count: items.length,
      items,
      fetchedAt: new Date().toISOString(),
      debug: { fetched: fetchedCount, afterState, afterPoly, feeds: urls.length }
    };
    if (!nocache) cache.set(key, { data, expiresAt: now + ALERTS_TTL_MS });
    res.json(data);
  } catch (err) {
    console.error('Alerts API error:', err);
    res.status(500).json({ error: 'Failed to retrieve alerts' });
  }
});

// NEW: TV Layout with radar, forecasts, AQI, Alerts and ticker (inline page)
app.get(['/tv', '/tv.html'], (req, res) => {
  noStore(res);
  res.type('html').send(tvHtml());
});

// NEW: Full-screen Map (radar-first) layout (inline page)
app.get(['/map', '/map.html'], (req, res) => {
  noStore(res);
  res.type('html').send(mapHtml());
});

// ADD: stream route (before catch-all)
app.get(['/stream', '/stream.html'], (req, res) => {
  noStore(res);
  res.type('html').send(streamHtml());
});

// ADD: team route (before catch-all)
app.get(['/team', '/team.html'], (req, res) => {
  noStore(res);
  res.type('html').send(teamHtml());
});

// catch-all must remain LAST so API routes above still work
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'Not found' });
  noStore(res);
  return res.type('html').send(tvHtml());
});

app.listen(PORT, () => {
  console.log(
    `Twistcasterlive Media running at http://localhost:${PORT} | Default: Atlanta, GA (${DEFAULT_COORDS.lat}, ${DEFAULT_COORDS.lon}) • Units: US`
  );
});