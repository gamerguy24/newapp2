function qs(name, fallback) {
  const v = new URLSearchParams(location.search).get(name);
  return v ?? fallback;
}

function dayName(s) {
  const d = new Date(s);
  return d.toLocaleDateString([], { weekday: 'short' });
}
function timeHM(s) {
  if (!s) return '--';
  return new Date(s).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function pickIcon(code) {
  const m = {
    0:'☀️',1:'🌤️',2:'⛅',3:'☁️',45:'🌫️',48:'🌫️',51:'🌦️',53:'🌦️',55:'🌧️',56:'🌧️',57:'🌧️',
    61:'🌧️',63:'🌧️',65:'🌧️',66:'🌧️',67:'🌧️',71:'🌨️',73:'🌨️',75:'❄️',77:'❄️',80:'🌦️',81:'🌦️',82:'⛈️',
    85:'🌨️',86:'❄️',95:'⛈️',96:'⛈️',99:'⛈️'
  };
  return m[code] || '❓';
}

async function getCoords() {
  const lat = parseFloat(qs('lat', 'NaN'));
  const lon = parseFloat(qs('lon', 'NaN'));
  if (Number.isFinite(lat) && Number.isFinite(lon)) return { lat, lon };
  return new Promise((resolve) => {
    if (!navigator.geolocation) return resolve({ lat: 40.7128, lon: -74.0060 });
    navigator.geolocation.getCurrentPosition(
      (pos) => resolve({ lat: pos.coords.latitude, lon: pos.coords.longitude }),
      () => resolve({ lat: 40.7128, lon: -74.0060 }),
      { enableHighAccuracy: true, timeout: 4000 }
    );
  });
}

function mountRadar({ lat, lon }) {
  const zoom = parseInt(qs('zoom', '6'), 10) || 6;
  const opts = 'oFa=1&oC=1&sm=1&sn=1&layer=radar';
  const src = `https://www.rainviewer.com/map.html?loc=${lat},${lon},${zoom}&${opts}`;
  document.getElementById('radar').src = src;
}

function renderDays(daily, unit) {
  const el = document.getElementById('days');
  el.innerHTML = '';
  for (let i = 0; i < Math.min(5, daily.time?.length || 0); i++) {
    const icon = pickIcon(daily.weathercode?.[i] ?? 0);
    const hi = Math.round(daily.temperature_2m_max?.[i] ?? 0);
    const lo = Math.round(daily.temperature_2m_min?.[i] ?? 0);
    const name = dayName(daily.time[i]);
    const div = document.createElement('div');
    div.className = 'day';
    div.innerHTML = `
      <div class="left">
        <div class="name">${name}</div>
        <div class="sub">${icon}</div>
      </div>
      <div class="right">
        <div class="icon">${icon}</div>
        <div class="hilo">${hi}${unit} / ${lo}${unit}</div>
      </div>
    `;
    el.appendChild(div);
  }
}

function renderCurrent(data) {
  document.getElementById('cur-icon').textContent = data.current.icon;
  document.getElementById('cur-temp').textContent = Math.round(data.current.temperature);
  document.getElementById('cur-unit').textContent = data.current.units.temperature;
  document.getElementById('cur-desc').textContent = data.current.description;
  document.getElementById('cur-hilo').textContent = `H ${Math.round(data.today.high)} / L ${Math.round(data.today.low)}`;
  document.getElementById('cur-wind').textContent = `${Math.round(data.current.windspeed)} ${data.current.units.windspeed}`;
  document.getElementById('cur-sunrise').textContent = timeHM(data.today.sunrise);
  document.getElementById('cur-sunset').textContent = timeHM(data.today.sunset);

  document.getElementById('tz').textContent = data.location.timezone || '';
}

function renderTomorrow(data) {
  // Use daily index 1 for tomorrow (if available), else repeat today
  const i = (data.raw?.daily?.time?.length || 0) > 1 ? 1 : 0;
  const d = data.raw?.daily || {};
  const hi = Math.round(d.temperature_2m_max?.[i] ?? data.today.high ?? 0);
  const lo = Math.round(d.temperature_2m_min?.[i] ?? data.today.low ?? 0);
  const code = d.weathercode?.[i] ?? 0;
  const icon = pickIcon(code);
  document.getElementById('tom-icon').textContent = icon;
  document.getElementById('tom-high').textContent = `${hi}${data.current.units.temperature}`;
  document.getElementById('tom-low').textContent = `${lo}${data.current.units.temperature}`;
  document.getElementById('tom-desc').textContent = '';
}

function buildTicker(data, air) {
  const items = [];
  items.push({ tag: 'Temp', text: `${Math.round(data.current.temperature)}${data.current.units.temperature}` });
  items.push({ tag: 'Wind', text: `${Math.round(data.current.windspeed)} ${data.current.units.windspeed}` });
  items.push({ tag: 'Sunrise', text: timeHM(data.today.sunrise) });
  items.push({ tag: 'Sunset', text: timeHM(data.today.sunset) });
  if (air?.current?.aqi != null) items.push({ tag: 'AQI', text: `${air.current.aqi} ${air.current.category}` });
  const h = data.hourly || {};
  if (h.precipitation?.length) items.push({ tag: 'Precip (hr)', text: `${(h.precipitation[0] ?? 0).toFixed(1)}` });

  const track = document.getElementById('ticker-track');
  const once = items.map(i => `<span class="tag">${i.tag}</span><span class="tick">${i.text}</span>`).join('<span>•</span>');
  // Duplicate for seamless loop (50% translate in CSS)
  track.innerHTML = `<div>${once}</div><div style="margin-left:48px">${once}</div>`;
}

function tickClock(tz) {
  const el = document.getElementById('clock');
  setInterval(() => {
    const opts = { hour: '2-digit', minute: '2-digit', second: '2-digit', timeZone: tz || undefined };
    el.textContent = new Date().toLocaleTimeString([], opts);
  }, 500);
}

async function main() {
  const units = qs('units', 'auto');
  const coords = await getCoords();
  const { lat, lon } = coords;

  // City label hint (coords text if no reverse geocode)
  document.getElementById('city').textContent = `${lat.toFixed(2)}, ${lon.toFixed(2)}`;
  mountRadar(coords);

  const wurl = `/api/weather?lat=${lat}&lon=${lon}&units=${encodeURIComponent(units)}`;
  const aurl = `/api/air?lat=${lat}&lon=${lon}`;

  const [wRes, aRes] = await Promise.all([fetch(wurl), fetch(aurl).catch(() => null)]);
  if (!wRes.ok) return;
  const weather = await wRes.json();
  const air = aRes && aRes.ok ? await aRes.json() : null;

  renderCurrent(weather);
  renderDays(weather.raw?.daily || {}, weather.current.units.temperature);
  renderTomorrow(weather);

  if (air?.current) {
    const badge = document.getElementById('aq-badge');
    badge.textContent = air.current.category;
    badge.style.background = air.current.color;
    document.getElementById('aq-index').textContent = air.current.aqi ?? '--';
    document.getElementById('aq-pm25').textContent = air.current.pm25?.toFixed(1) ?? '--';
    document.getElementById('aq-pm10').textContent = air.current.pm10?.toFixed(1) ?? '--';
    document.getElementById('aq-time').textContent = air.current.time ? `Updated ${timeHM(air.current.time)}` : '';
  }

  buildTicker(weather, air);
  tickClock(weather.location?.timezone);

  const refreshMs = Math.max(15000, parseInt(qs('refresh', '60000'), 10) || 60000);
  setInterval(async () => {
    const [wr, ar] = await Promise.all([fetch(wurl), fetch(aurl).catch(() => null)]);
    if (wr.ok) {
      const w = await wr.json();
      renderCurrent(w);
      renderDays(w.raw?.daily || {}, w.current.units.temperature);
      renderTomorrow(w);
      buildTicker(w, air); // air refresh less frequently is fine
    }
  }, refreshMs);
}

main().catch(console.error);
