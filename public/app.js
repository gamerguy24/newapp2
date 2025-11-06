function qs(name, fallback) {
  const v = new URLSearchParams(location.search).get(name);
  return v ?? fallback;
}

function formatTime(s) {
  if (!s) return '--';
  const d = new Date(s);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

async function getCoords() {
  const lat = parseFloat(qs('lat', 'NaN'));
  const lon = parseFloat(qs('lon', 'NaN'));
  if (Number.isFinite(lat) && Number.isFinite(lon)) return { lat, lon };

  return new Promise((resolve) => {
    if (!navigator.geolocation) return resolve({ lat: 40.7128, lon: -74.0060 }); // NYC fallback
    navigator.geolocation.getCurrentPosition(
      (pos) => resolve({ lat: pos.coords.latitude, lon: pos.coords.longitude }),
      () => resolve({ lat: 40.7128, lon: -74.0060 }),
      { enableHighAccuracy: true, timeout: 4000 }
    );
  });
}

function render(data) {
  const t = document.getElementById('temperature');
  const u = document.getElementById('temp-unit');
  const d = document.getElementById('description');
  const ic = document.getElementById('icon');
  const hilo = document.getElementById('hi-lo');
  const sun = document.getElementById('sun');
  const wind = document.getElementById('wind');
  const precip = document.getElementById('precip');
  const updated = document.getElementById('updated');
  const hourly = document.getElementById('hourly');

  t.textContent = Math.round(data.current.temperature);
  u.textContent = data.current.units.temperature;
  d.textContent = data.current.description;
  ic.textContent = data.current.icon;
  hilo.textContent = `H: ${Math.round(data.today.high)} L: ${Math.round(data.today.low)}`;
  sun.textContent = `Sunrise: ${formatTime(data.today.sunrise)} • Sunset: ${formatTime(data.today.sunset)}`;
  wind.textContent = `${Math.round(data.current.windspeed)} ${data.current.units.windspeed}`;
  precip.textContent = `${(data.today.precipitation_sum ?? 0).toFixed(1)} total`;
  updated.textContent = new Date(data.current.time || Date.now()).toLocaleTimeString();

  hourly.innerHTML = '';
  const times = data.hourly.time || [];
  const temps = data.hourly.temperature || [];
  const codes = data.hourly.weathercode || [];

  for (let i = 0; i < Math.min(times.length, 24); i++) {
    const card = document.createElement('div');
    card.className = 'card';
    const time = new Date(times[i]).toLocaleTimeString([], { hour: '2-digit' });
    const temp = Math.round(temps[i]);
    const code = codes[i] ?? 0;
    const icon = pickIcon(code);
    card.innerHTML = `
      <div class="t">${icon} ${temp}${data.current.units.temperature}</div>
      <div class="sub">${time}</div>
    `;
    hourly.appendChild(card);
  }
}

function pickIcon(code) {
  const m = {
    0:'☀️',1:'🌤️',2:'⛅',3:'☁️',45:'🌫️',48:'🌫️',51:'🌦️',53:'🌦️',55:'🌧️',56:'🌧️',57:'🌧️',
    61:'🌧️',63:'🌧️',65:'🌧️',66:'🌧️',67:'🌧️',71:'🌨️',73:'🌨️',75:'❄️',77:'❄️',80:'🌦️',81:'🌦️',82:'⛈️',
    85:'🌨️',86:'❄️',95:'⛈️',96:'⛈️',99:'⛈️'
  };
  return m[code] || '❓';
}

async function main() {
  const units = qs('units', 'auto'); // auto | metric | us/imperial
  const coords = await getCoords();
  const url = `/api/weather?lat=${coords.lat}&lon=${coords.lon}&units=${encodeURIComponent(units)}`;
  const res = await fetch(url);
  if (!res.ok) {
    console.error('Failed to load weather');
    return;
  }
  const data = await res.json();
  render(data);

  const refreshMs = Math.max(15000, parseInt(qs('refresh', '60000'), 10) || 60000);
  setInterval(async () => {
    const r = await fetch(url);
    if (r.ok) render(await r.json());
  }, refreshMs);
}

main().catch(console.error);
