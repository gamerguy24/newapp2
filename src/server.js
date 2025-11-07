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

// NEW: fixed NWS Atom URLs for specific events (use exact links)
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
    /* NEW nav styles */
    .nav{display:flex;gap:.6rem;flex-wrap:wrap}
    .nav a{font-size:.75rem;letter-spacing:.05em;text-transform:uppercase;background:rgba(255,255,255,.06);color:var(--muted);padding:.45rem .7rem;border-radius:8px;text-decoration:none;font-weight:600;transition:.2s}
    .nav a:hover,.nav a:focus{background:rgba(255,255,255,.12);color:var(--fg)}
    .nav a.active{background:var(--accent);color:#051627}
    .now{display:flex;gap:1rem;color:var(--muted);font-weight:600}
    .grid{height:calc(100dvh - 110px);display:grid;grid-template-columns:320px 1fr 420px;grid-template-rows:46% 32% 22%;gap:12px;padding:12px 12px calc(12px + env(safe-area-inset-bottom))}
    .panel{background:var(--glass);border:1px solid var(--glass-b);border-radius:14px;padding:10px;overflow:hidden}
    .panel-title{font-size:.9rem;color:var(--muted);margin-bottom:8px;letter-spacing:.06em;text-transform:uppercase}
    .days{grid-row:1 / span 3;display:grid;grid-auto-rows:1fr;gap:10px}
    .day{background:rgba(255,255,255,.04);border:1px solid var(--glass-b);border-radius:10px;padding:10px;display:grid;grid-template-columns:1fr auto;align-items:center;min-width:140px}
    .day .left{display:grid;gap:6px}.day .name{font-weight:700}.day .sub{color:var(--muted);font-size:.9rem}
    .day .right{text-align:right}.day .icon{font-size:1.6rem}.day .hilo{font-weight:700}
    .radar iframe{width:100%;height:calc(100% - 22px);border:0;border-radius:10px}
    .current .current-row{display:grid;grid-template-columns:auto 1fr;gap:16px}
    .bigtemp{display:flex;align-items:baseline;gap:12px;font-weight:800;padding:8px 10px;background:rgba(255,255,255,.04);border-radius:10px}
    #cur-icon{font-size:3rem}#cur-temp{font-size:5rem;line-height:.9}#cur-unit{color:var(--muted);font-size:1.4rem}
    .cur-meta{display:grid;gap:6px}.cur-meta .sub{color:var(--muted)}
    .tom-row{display:grid;grid-template-columns:auto 1fr;gap:12px}.tom-icon{font-size:3rem}.tom-meta .t{font-weight:700}.tom-meta .sub{color:var(--muted)}
    .air .aq-row{display:grid;grid-template-columns:120px 1fr;gap:12px}
    .aq-badge{display:grid;place-items:center;font-weight:800;border-radius:12px;background:rgba(255,255,255,.08);height:100px}
    .aq-meta .t{font-weight:700}.aq-meta .sub{color:var(--muted)}
    .alerts{display:grid;grid-template-rows:auto 1fr}
    .alerts-list{height:100%;overflow:auto;display:grid;gap:8px;padding-right:4px}
    .alert{background:rgba(255,255,255,.04);border:1px solid var(--glass-b);border-left:6px solid #f39c12;border-radius:10px;padding:8px}
    .alert .h{font-weight:800} .alert .sub{color:var(--muted);font-size:.9rem}
    .ticker{height:50px;border-top:1px solid var(--glass-b);background:linear-gradient(180deg,rgba(255,255,255,.02),rgba(255,255,255,.06));overflow:hidden}
    .track{display:inline-flex;gap:28px;align-items:center;white-space:nowrap;padding-left:100%;animation:scroll 40s linear infinite}
    .tag{background:var(--accent);color:#06121f;font-weight:800;padding:6px 10px;border-radius:8px}.tick{color:var(--fg);opacity:.95}
    @keyframes scroll{from{transform:translateX(0)}to{transform:translateX(-50%)}}
    /* reduce motion if requested */
    @media (prefers-reduced-motion: reduce){.track{animation:none}}
    /* Mobile layout */
    @media (max-width: 900px){
      html,body{overflow:auto}
      .grid{grid-template-columns:1fr;grid-template-rows:auto;gap:10px;height:auto;min-height:100dvh;padding:8px 8px calc(8px + env(safe-area-inset-bottom))}
      .now{gap:.5rem;font-size:.9rem}
      .days{grid-row:auto;grid-auto-flow:column;grid-auto-columns:minmax(120px,1fr);grid-auto-rows:unset;overflow-x:auto;padding-bottom:8px}
      .radar iframe{height:52vh}
      #cur-icon{font-size:2.2rem}#cur-temp{font-size:3.6rem}#cur-unit{font-size:1.1rem}
      .ticker{height:36px}
      .tag{padding:4px 8px}
    }
    @media (max-width: 420px){
      .nav{width:100%}
      .ticker{display:none}
      .day{min-width:120px}
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
    <section class="panel radar">
      <div class="panel-title">Radar</div>
      <iframe id="radar" title="Radar" loading="lazy"></iframe>
    </section>
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
    <!-- NEW Alerts panel -->
    <section class="panel alerts">
      <div class="panel-title">Weather Alerts (NWS)</div>
      <div class="alerts-list" id="alerts"></div>
    </section>
  </main>
  <footer class="ticker"><div class="track" id="ticker-track"></div></footer>
  <script>
    const DEF = { lat: ${DEFAULT_COORDS.lat}, lon: ${DEFAULT_COORDS.lon} };
    const qs = (n,f)=>{const v=new URLSearchParams(location.search).get(n);return v??f};
    const dayName = s => new Date(s).toLocaleDateString([], { weekday:'short' });
    const hm = s => s ? new Date(s).toLocaleTimeString([], { hour:'2-digit', minute:'2-digit' }) : '--';
    const iconFor = c => ({0:'☀️',1:'🌤️',2:'⛅',3:'☁️',45:'🌫️',48:'🌫️',51:'🌦️',53:'🌦️',55:'🌧️',56:'🌧️',57:'🌧️',61:'🌧️',63:'🌧️',65:'🌧️',66:'🌧️',67:'🌧️',71:'🌨️',73:'🌨️',75:'❄️',77:'❄️',80:'🌦️',81:'🌦️',82:'⛈️',85:'🌨️',86:'❄️',95:'⛈️',96:'⛈️',99:'⛈️'}[c]||'❓');
    const coords = { lat: parseFloat(qs('lat', DEF.lat))||DEF.lat, lon: parseFloat(qs('lon', DEF.lon))||DEF.lon };
    const units = (qs('units','${DEFAULT_UNITS}')||'${DEFAULT_UNITS}').toLowerCase();
    const state = (qs('state','GA')||'GA').toUpperCase();
    document.getElementById('city').textContent = \`\${coords.lat.toFixed(2)}, \${coords.lon.toFixed(2)}\`;
    const zoom = parseInt(qs('zoom','6'),10)||6;
    const radarSrc = \`https://www.rainviewer.com/map.html?loc=\${coords.lat},\${coords.lon},\${zoom}&oFa=1&oC=1&sm=1&sn=1&layer=radar\`;
    document.getElementById('radar').src = radarSrc;

    function renderDays(daily, unit) {
      const el = document.getElementById('days'); el.innerHTML='';
      for (let i=0;i<Math.min(5,(daily.time||[]).length);i++){
        const icon = iconFor(daily.weathercode?.[i]??0);
        const hi = Math.round(daily.temperature_2m_max?.[i]??0);
        const lo = Math.round(daily.temperature_2m_min?.[i]??0);
        const name = dayName(daily.time[i]);
        const div = document.createElement('div'); div.className='day';
        div.innerHTML = \`
          <div class="left"><div class="name">\${name}</div><div class="sub">\${icon}</div></div>
          <div class="right"><div class="icon">\${icon}</div><div class="hilo">\${hi}\${unit} / \${lo}\${unit}</div></div>\`;
        el.appendChild(div);
      }
    }
    function renderCurrent(data){
      document.getElementById('cur-icon').textContent = data.current.icon;
      document.getElementById('cur-temp').textContent = Math.round(data.current.temperature);
      document.getElementById('cur-unit').textContent = data.current.units.temperature;
      document.getElementById('cur-desc').textContent = data.current.description;
      document.getElementById('cur-hilo').textContent = \`H \${Math.round(data.today.high)} / L \${Math.round(data.today.low)}\`;
      document.getElementById('cur-wind').textContent = \`\${Math.round(data.current.windspeed)} \${data.current.units.windspeed}\`;
      document.getElementById('cur-sunrise').textContent = hm(data.today.sunrise);
      document.getElementById('cur-sunset').textContent = hm(data.today.sunset);
      document.getElementById('tz').textContent = data.location?.timezone || '';
    }
    function renderTomorrow(data){
      const i = (data.raw?.daily?.time?.length||0)>1?1:0;
      const d = data.raw?.daily || {};
      const hi = Math.round(d.temperature_2m_max?.[i] ?? data.today.high ?? 0);
      const lo = Math.round(d.temperature_2m_min?.[i] ?? data.today.low ?? 0);
      const code = d.weathercode?.[i] ?? 0;
      document.getElementById('tom-icon').textContent = iconFor(code);
      document.getElementById('tom-high').textContent = \`\${hi}\${data.current.units.temperature}\`;
      document.getElementById('tom-low').textContent = \`\${lo}\${data.current.units.temperature}\`;
    }
    function severityColor(sev){
      const s=(sev||'').toLowerCase();
      if(s.includes('extreme')) return '#7f1d1d';
      if(s.includes('severe')||s.includes('high')||s.includes('warning')) return '#e74c3c';
      if(s.includes('moderate')||s.includes('watch')) return '#f39c12';
      return '#2ecc71';
    }
    function renderAlerts(feed){
      const list=document.getElementById('alerts'); list.innerHTML='';
      if(!feed || !feed.items || feed.items.length === 0){
        const div=document.createElement('div'); div.className='alert';
        div.style.borderLeftColor = '#2ecc71';
        div.innerHTML = '<div class="h">No active alerts</div><div class="sub">NWS</div>';
        list.appendChild(div);
        return;
      }
      (feed.items||[]).forEach(it=>{
        const div=document.createElement('div'); div.className='alert';
        div.style.borderLeftColor = severityColor(it.severity || it.title || '');
        const when = it.updated ? new Date(it.updated).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'}) : '';
        div.innerHTML=\`<div class="h">\${it.event || it.title || 'Alert'}</div>
                        <div class="sub">\${it.areaDesc || ''}</div>
                        <div class="sub">\${when}</div>\`;
        list.appendChild(div);
      });
    }
    function buildTicker(data, air, alerts){
      const items=[];
      items.push({tag:'Temp',text:\`\${Math.round(data.current.temperature)}\${data.current.units.temperature}\`});
      items.push({tag:'Wind',text:\`\${Math.round(data.current.windspeed)} \${data.current.units.windspeed}\`});
      items.push({tag:'Sunrise',text:hm(data.today.sunrise)});
      items.push({tag:'Sunset',text:hm(data.today.sunset)});
      if(air?.current?.aqi!=null) items.push({tag:'AQI',text:\`\${air.current.aqi} \${air.current.category}\`});
      if(alerts?.items?.length){ const top=alerts.items.slice(0,3).map(a=>a.event||a.title); items.push({tag:'ALERT',text:top.join(' • ')}); }
      const once = items.map(i=>\`<span class="tag">\${i.tag}</span><span class="tick">\${i.text}</span>\`).join('<span>•</span>');
      document.getElementById('ticker-track').innerHTML = '<div>'+once+'</div><div style="margin-left:48px">'+once+'</div>';
    }
    (function tickClock(){
      const el=document.getElementById('clock');
      setInterval(()=>{ el.textContent = new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'}); }, 500);
    })();
    async function load(){
      const wurl=\`/api/weather?lat=\${coords.lat}&lon=\${coords.lon}&units=\${encodeURIComponent(units)}\`;
      const aurl=\`/api/air?lat=\${coords.lat}&lon=\${coords.lon}\`;
      // Pass lat/lon and force nocache during testing to avoid stale empty results
      const alurl=\`/api/alerts?state=\${encodeURIComponent(state)}&lat=\${coords.lat}&lon=\${coords.lon}&nocache=1\`;
      const [wr,ar,alr]=await Promise.all([fetch(wurl),fetch(aurl).catch(()=>null),fetch(alurl).catch(()=>null)]);
      if(!wr.ok) return;
      const weather=await wr.json();
      const air = ar&&ar.ok ? await ar.json() : null;
      const alerts = alr&&alr.ok ? await alr.json() : null;
      renderCurrent(weather); renderDays(weather.raw?.daily||{}, weather.current.units.temperature); renderTomorrow(weather);
      if(air?.current){
        const b=document.getElementById('aq-badge'); b.textContent=air.current.category; b.style.background=air.current.color;
        document.getElementById('aq-index').textContent = air.current.aqi ?? '--';
        document.getElementById('aq-pm25').textContent = air.current.pm25?.toFixed(1) ?? '--';
        document.getElementById('aq-pm10').textContent = air.current.pm10?.toFixed(1) ?? '--';
        document.getElementById('aq-time').textContent = air.current.time ? 'Updated '+hm(air.current.time) : '';
      }
      renderAlerts(alerts);
      buildTicker(weather, air, alerts);
    }
    load().catch(console.error);
    // mobile-aware refresh default to save battery
    const refreshDefault = /Mobi|Android|iPhone|iPad/i.test(navigator.userAgent) ? 90000 : 60000;
    const refreshMs = Math.max(15000, parseInt(qs('refresh', String(refreshDefault)),10)||refreshDefault);
    setInterval(()=>load().catch(()=>{}), refreshMs);
  </script>
</body>
</html>`;
}

// ADD: mapHtml helper (enhanced with Spotters HUD)
function mapHtml() {
  return `<!doctype html><html lang="en"><head>
  <meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"/>
  <title>Map</title>
  <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" integrity="sha256-p4NxAoJBhIIN+hmNHrzRCf9tD/miZyoHS5obTRR9BMY=" crossorigin="anonymous">
  <style>
    html,body{height:100%;margin:0;background:#0b1020;color:#e6eef8;font-family:system-ui,Segoe UI,Roboto,sans-serif}
    #map{position:fixed;inset:0}
    .hud{position:fixed;left:12px;bottom:12px;right:auto;display:flex;flex-direction:column;gap:10px;z-index:1000}
    .panel{background:rgba(0,0,0,.45);backdrop-filter:blur(6px);border:1px solid rgba(255,255,255,.12);border-radius:12px;padding:8px 10px;max-width:min(92vw,520px)}
    .title{font-size:.8rem;letter-spacing:.06em;text-transform:uppercase;color:#9fb0c5}
    .pill{display:inline-block;padding:.2rem .5rem;border-radius:999px;background:#4fb3ff1a;color:#9fd8ff;font-weight:700;font-size:.72rem;margin-left:.4rem}
    /* NEW: top-right weather HUD */
    .hudR{position:fixed;right:12px;top:12px;display:flex;flex-direction:column;gap:10px;z-index:1000}
    .wx .row{display:flex;align-items:baseline;gap:.4rem;font-weight:800}
    .wx .temp{font-size:1.4rem}
    .wx .unit{color:#9fb0c5}
    .wx .sub{font-size:.8rem;color:#cfd9ea;opacity:.95}
  </style></head><body>
  <div id="map" aria-label="Map"></div>
  <div class="hud">
    <div class="panel"><span class="title">Spotters</span> <span id="spotter-count" class="pill">0</span></div>
  </div>
  <div class="hudR">
    <div class="panel">
      <div class="title">Weather</div>
      <div id="wx" class="wx">
        <div class="row"><span id="wx-icon">⛅</span><span id="wx-temp" class="temp">--</span><span id="wx-unit" class="unit">°F</span></div>
        <div class="sub" id="wx-desc">Loading...</div>
        <div class="sub" id="wx-hilo">H -- / L --</div>
        <div class="sub" id="wx-wind">Wind --</div>
        <div class="sub" id="wx-aqi">AQI --</div>
        <div class="sub" id="wx-alerts">Alerts --</div>
      </div>
    </div>
  </div>
  <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js" integrity="sha256-20nQCchB9co0qIjJZRGuk2/Z9VM+kNiyxNV1lvTlZBo=" crossorigin="anonymous"></script>
  <script>
    const DEF={ lat: ${DEFAULT_COORDS.lat}, lon: ${DEFAULT_COORDS.lon} };
    const qs=(n)=>new URLSearchParams(location.search).get(n);
    const zoom=parseInt(qs('zoom')||'6',10)||6;
    const lat=parseFloat(qs('lat')||DEF.lat)||DEF.lat;
    const lon=parseFloat(qs('lon')||DEF.lon)||DEF.lon;
    const state=(qs('state')||'GA').toUpperCase();
    const units=(qs('units')||'us').toLowerCase();

    const map=L.map('map',{zoomControl:true}).setView([lat,lon], zoom);
    // Base map
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',{ maxZoom: 19, attribution: '&copy; OpenStreetMap' }).addTo(map);

    // NEW: Rainviewer radar overlay (latest frame)
    let radarLayer=null;
    function setRadar(time){
      if (radarLayer) { map.removeLayer(radarLayer); radarLayer=null; }
      const url = \`https://tilecache.rainviewer.com/v2/radar/\${time}/256/{z}/{x}/{y}/2/1_1.png\`;
      radarLayer = L.tileLayer(url, { opacity: 0.7, zIndex: 500 });
      radarLayer.addTo(map);
    }
    fetch('https://api.rainviewer.com/public/weather-maps.json')
      .then(r=>r.json())
      .then(j=>{
        const frames = (j?.radar?.nowcast?.length ? j.radar.nowcast : j?.radar?.past) || [];
        if (frames.length) setRadar(frames[frames.length-1].time);
      })
      .catch(()=>{});

    // Spotters layer + count
    const spotLayer=L.layerGroup().addTo(map);
    const countEl=document.getElementById('spotter-count');
    function addSpotterMarker(p){
      const la=parseFloat(p.lat), lo=parseFloat(p.lon);
      if(!Number.isFinite(la)||!Number.isFinite(lo)) return;
      const marker=L.circleMarker([la,lo],{ radius:6, weight:1, color:'#4fb3ff', fillColor:'#4fb3ff', fillOpacity:0.85 });
      const name = p.callsign || p.ham || [p.first,p.last].filter(Boolean).join(' ') || 'Spotter';
      const when = p.unix ? new Date(parseInt(p.unix,10)*1000).toLocaleString() : (p.report_at||'');
      marker.bindPopup(\`<b>\${name}</b><br/>\${la.toFixed(3)}, \${lo.toFixed(3)}<br/>\${when}\`);
      marker.addTo(spotLayer);
    }
    async function loadSpotters(){
      const id = qs('snid') || '${DEFAULT_SPOTTER_ID}';
      try{
        const r=await fetch(\`/api/spotter/positions?id=\${encodeURIComponent(id)}\`);
        if(!r.ok) throw new Error('spotter http '+r.status);
        const data=await r.json();
        const items=Array.isArray(data.positions)?data.positions:[];
        spotLayer.clearLayers();
        items.forEach(addSpotterMarker);
        countEl.textContent=String(items.length);
      }catch(e){ console.error('spotter load failed', e); }
    }

    // Weather HUD
    const iconFor=c=>({0:'☀️',1:'🌤️',2:'⛅',3:'☁️',45:'🌫️',48:'🌫️',51:'🌦️',53:'🌦️',55:'🌧️',56:'🌧️',57:'🌧️',61:'🌧️',63:'🌧️',65:'🌧️',66:'🌧️',67:'🌧️',71:'🌨️',73:'🌨️',75:'❄️',77:'❄️',80:'🌦️',81:'🌦️',82:'⛈️',85:'🌨️',86:'❄️',95:'⛈️',96:'⛈️',99:'⛈️'}[c]||'❓');
    async function loadWeather(lat, lon){
      try{
        const [wr, ar, al] = await Promise.all([
          fetch(\`/api/weather?lat=\${lat}&lon=\${lon}&units=\${encodeURIComponent(units)}\`),
          fetch(\`/api/air?lat=\${lat}&lon=\${lon}\`).catch(()=>null),
          fetch(\`/api/alerts?state=\${encodeURIComponent(state)}&lat=\${lat}&lon=\${lon}\`).catch(()=>null)
        ]);
        if(!wr?.ok) return;
        const weather = await wr.json();
        const air = ar && ar.ok ? await ar.json() : null;
        const alerts = al && al.ok ? await al.json() : null;

        document.getElementById('wx-icon').textContent = weather.current.icon || iconFor(weather.raw?.current_weather?.weathercode||0);
        document.getElementById('wx-temp').textContent = Math.round(weather.current.temperature||0);
        document.getElementById('wx-unit').textContent = weather.current?.units?.temperature || '°F';
        document.getElementById('wx-desc').textContent = weather.current.description || '';
        document.getElementById('wx-hilo').textContent = \`H \${Math.round(weather.today?.high||0)} / L \${Math.round(weather.today?.low||0)}\`;
        document.getElementById('wx-wind').textContent = \`Wind \${Math.round(weather.current?.windspeed||0)} \${weather.current?.units?.windspeed||''}\`;
        if(air?.current){
          const aqi = air.current.aqi != null ? \`\${air.current.aqi} \${air.current.category||''}\` : '--';
          document.getElementById('wx-aqi').textContent = \`AQI \${aqi}\`;
        } else {
          document.getElementById('wx-aqi').textContent = 'AQI --';
        }
        const alertStr = alerts?.items?.length ? \`\${alerts.items.length} active\` : 'None';
        document.getElementById('wx-alerts').textContent = \`Alerts \${alertStr}\`;
      }catch(e){ console.error('weather load failed', e); }
    }

    function debounce(fn, ms){ let t; return (...a)=>{ clearTimeout(t); t=setTimeout(()=>fn(...a), ms); }; }

    loadSpotters();
    setInterval(loadSpotters, 60000);
    loadWeather(lat, lon);
    map.on('moveend', debounce(()=>{
      const c = map.getCenter();
      loadWeather(c.lat, c.lng);
    }, 800));
  </script>
  </body></html>`;
}

// ADD: streamHtml helper (minimal + graceful RTMP fallback)
function streamHtml() {
  return `<!doctype html><html lang="en"><head>
  <meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"/>
  <title>Stream</title><style>
    html,body{height:100%;margin:0;background:#000}
    iframe{position:fixed;inset:0;width:100%;height:100%;border:0;background:#000}
  </style></head><body>
    <iframe src="rtmp://a.rtmp.youtube.com/live2" allow="autoplay; fullscreen; picture-in-picture"></iframe>
  </body></html>`;
}

// ADD: teamHtml helper (Meet the Team page)
function teamHtml() {
  return `<!doctype html><html lang="en"><head>
  <meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"/>
  <title>Team</title><style>
    :root{--bg:#0b1020;--accent:#4fb3ff;--fg:#e6eef8;--muted:#9fb0c5;--glass:rgba(255,255,255,.07);--glass-b:rgba(255,255,255,.12)}
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:linear-gradient(140deg,#0b1020,#17243f);color:var(--fg);min-height:100vh;display:flex;flex-direction:column}
    header{padding:1rem 1.2rem;border-bottom:1px solid var(--glass-b);display:flex;flex-wrap:wrap;align-items:center;gap:1rem;background:linear-gradient(180deg,rgba(255,255,255,.07),rgba(255,255,255,.02))}
    .brand{font-weight:800;letter-spacing:.1em;color:var(--accent)}
    nav{display:flex;gap:.6rem;flex-wrap:wrap}
    nav a{font-size:.65rem;text-transform:uppercase;letter-spacing:.06em;text-decoration:none;padding:.45rem .7rem;border-radius:8px;font-weight:600;background:rgba(255,255,255,.1);color:var(--muted)}
    nav a.active,nav a:hover{background:var(--accent);color:#051b2e}
    main{width:100%;max-width:1100px;margin:0 auto;padding:1.4rem 1.2rem 2.8rem;display:flex;flex-direction:column;gap:1.8rem}
    h1{font-size:clamp(1.6rem,3vw,2.3rem);letter-spacing:.05em}
    .grid{display:grid;gap:18px;grid-template-columns:repeat(auto-fill,minmax(240px,1fr))}
    .card{background:var(--glass);border:1px solid var(--glass-b);border-radius:16px;padding:16px;display:flex;flex-direction:column;gap:.6rem}
    .nm{font-weight:700;letter-spacing:.03em}
    .role{font-size:.75rem;font-weight:600;letter-spacing:.08em;color:var(--accent);text-transform:uppercase}
    .desc{font-size:.8rem;color:var(--muted);line-height:1.35}
    footer{margin-top:auto;padding:1rem .8rem;text-align:center;font-size:.65rem;color:var(--muted);border-top:1px solid var(--glass-b)}
    @media (max-width:640px){.grid{gap:14px}.card{padding:14px}}
  </style></head><body>
  <header>
    <div class="brand">TWISTCASTERLIVE MEDIA</div>
    <nav>
      <a href="/tv">Dashboard</a>
      <a href="/map">Map</a>
      <a href="/team" class="active">Team</a>
      <a href="/stream">Stream</a>
    </nav>
  </header>
  <main>
    <h1>Meet the Team</h1>
    <div class="grid">
      <div class="card"><div class="nm">Nathan Bradley</div><div class="role">Founder</div><div class="desc">Founder / Storm Tracker, Meteorologist</div></div>
      <div class="card"><div class="nm">David Wallis</div><div class="role">President</div><div class="desc">Social Media Manager / Coding Specialist</div></div>
      <div class="card"><div class="nm">Joey Pisani</div><div class="role">Lead Meteorologist</div><div class="desc">Weather Forecasting / Analysis</div></div>
      <div class="card"><div class="nm">Nick Carter</div><div class="role">Lead Storm Chaser</div><div class="desc">Field Operations</div></div>
      <div class="card"><div class="nm">Mandy Jenes</div><div class="role">Storm Chaser</div><div class="desc">TCL Media Field Team</div></div>
      <div class="card"><div class="nm">Jesse Perkins</div><div class="role">Storm Chaser</div><div class="desc">TCL Media Field Team</div></div>
      <div class="card"><div class="nm">Michael Lynn</div><div class="role">Storm Chaser</div><div class="desc">TCL Media Field Team</div></div>
      <div class="card"><div class="nm">Cody Knox</div><div class="role">Storm Chaser</div><div class="desc">TCL Media Field Team</div></div>
    </div>
  </main>
  <footer>&copy; ${new Date().getFullYear()} Twistcasterlive Media</footer>
  </body></html>`;
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
    const key = `alerts:${state}:${lat.toFixed(2)},${lon.toFixed(2)}:${evKey}`;
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

// NEW: catch-all route to serve TV for non-API paths (helps hosting setups)
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'Not found' });
  noStore(res);
  return res.type('html').send(tvHtml());
});

app.listen(PORT, () => {
  console.log(
    `Twistcasterlive Media running at http://localhost:${PORT} | Default: Atlanta, GA (${DEFAULT_COORDS.lat}, ${DEFAULT_COORDS.lon}) • Units: US`
  );
});
