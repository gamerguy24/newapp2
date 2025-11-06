function aqiCategory(aqi) {
  if (aqi == null) return { label: 'Unknown', color: '#8a8f98' };
  if (aqi <= 50) return { label: 'Good', color: '#2ecc71' };
  if (aqi <= 100) return { label: 'Moderate', color: '#f1c40f' };
  if (aqi <= 150) return { label: 'USG', color: '#e67e22' }; // Unhealthy for Sensitive Groups
  if (aqi <= 200) return { label: 'Unhealthy', color: '#e74c3c' };
  if (aqi <= 300) return { label: 'Very Unhealthy', color: '#8e44ad' };
  return { label: 'Hazardous', color: '#7f1d1d' };
}

export async function getAirQuality({ lat, lon }) {
  const url = new URL('https://air-quality-api.open-meteo.com/v1/air-quality');
  url.searchParams.set('latitude', lat);
  url.searchParams.set('longitude', lon);
  url.searchParams.set('hourly', 'pm2_5,pm10,us_aqi');
  url.searchParams.set('timezone', 'auto');
  url.searchParams.set('forecast_days', '3');

  const resp = await fetch(url.href, { headers: { 'User-Agent': 'WeatherHD/0.1 (+https://example.local)' } });
  if (!resp.ok) throw new Error(`Open-Meteo AQ error: ${resp.status}`);
  const json = await resp.json();

  const h = json.hourly || {};
  const times = h.time || [];
  const idx = 0; // current/next hour (API is time-ordered)
  const aqi = h.us_aqi?.[idx] ?? null;
  const cat = aqiCategory(aqi);

  return {
    provider: 'open-meteo-air',
    location: { lat, lon, timezone: json.timezone },
    current: {
      aqi,
      category: cat.label,
      color: cat.color,
      pm25: h.pm2_5?.[idx] ?? null,
      pm10: h.pm10?.[idx] ?? null,
      time: times[idx] ?? null
    },
    hourly: {
      time: times,
      us_aqi: h.us_aqi || [],
      pm2_5: h.pm2_5 || [],
      pm10: h.pm10 || []
    },
    raw: { ...json }
  };
}
