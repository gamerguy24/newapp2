const WEATHER_CODE_MAP = {
  0: { label: 'Clear sky', icon: '☀️' },
  1: { label: 'Mainly clear', icon: '🌤️' },
  2: { label: 'Partly cloudy', icon: '⛅' },
  3: { label: 'Overcast', icon: '☁️' },
  45: { label: 'Fog', icon: '🌫️' },
  48: { label: 'Depositing rime fog', icon: '🌫️' },
  51: { label: 'Light drizzle', icon: '🌦️' },
  53: { label: 'Moderate drizzle', icon: '🌦️' },
  55: { label: 'Dense drizzle', icon: '🌧️' },
  56: { label: 'Freezing light drizzle', icon: '🌧️' },
  57: { label: 'Freezing dense drizzle', icon: '🌧️' },
  61: { label: 'Slight rain', icon: '🌧️' },
  63: { label: 'Moderate rain', icon: '🌧️' },
  65: { label: 'Heavy rain', icon: '🌧️' },
  66: { label: 'Light freezing rain', icon: '🌧️' },
  67: { label: 'Heavy freezing rain', icon: '🌧️' },
  71: { label: 'Slight snow', icon: '🌨️' },
  73: { label: 'Moderate snow', icon: '🌨️' },
  75: { label: 'Heavy snow', icon: '❄️' },
  77: { label: 'Snow grains', icon: '❄️' },
  80: { label: 'Slight rain showers', icon: '🌦️' },
  81: { label: 'Moderate rain showers', icon: '🌦️' },
  82: { label: 'Violent rain showers', icon: '⛈️' },
  85: { label: 'Slight snow showers', icon: '🌨️' },
  86: { label: 'Heavy snow showers', icon: '❄️' },
  95: { label: 'Thunderstorm', icon: '⛈️' },
  96: { label: 'Thunderstorm with slight hail', icon: '⛈️' },
  99: { label: 'Thunderstorm with heavy hail', icon: '⛈️' }
};

function unitsFor(units) {
  if (units === 'us' || units === 'imperial') return { temp: '°F', speed: 'mph' };
  if (units === 'metric') return { temp: '°C', speed: 'km/h' };
  return { temp: '°C', speed: 'km/h' }; // auto default
}

export async function getWeather({ lat, lon, units = 'auto' }) {
  const url = new URL('https://api.open-meteo.com/v1/forecast');
  url.searchParams.set('latitude', lat);
  url.searchParams.set('longitude', lon);
  url.searchParams.set('current_weather', 'true');
  url.searchParams.set('hourly', 'temperature_2m,apparent_temperature,relativehumidity_2m,precipitation,weathercode');
  url.searchParams.set('daily', 'temperature_2m_max,temperature_2m_min,sunrise,sunset,precipitation_sum,weathercode');
  url.searchParams.set('timezone', 'auto');

  // For US/Imperial override
  if (units === 'us' || units === 'imperial') {
    url.searchParams.set('temperature_unit', 'fahrenheit');
    url.searchParams.set('windspeed_unit', 'mph');
    url.searchParams.set('precipitation_unit', 'inch');
  }

  const resp = await fetch(url.href, { headers: { 'User-Agent': 'WeatherHD/0.1 (+https://example.local)' } });
  if (!resp.ok) throw new Error(`Open-Meteo error: ${resp.status}`);
  const json = await resp.json();

  const cw = json.current_weather || {};
  const daily = json.daily || {};
  const idx0 = 0;

  const code = cw.weathercode ?? daily.weathercode?.[idx0] ?? 0;
  const look = WEATHER_CODE_MAP[code] || { label: 'Unknown', icon: '❓' };
  const u = unitsFor(units);

  return {
    provider: 'open-meteo',
    location: {
      lat,
      lon,
      timezone: json.timezone
    },
    current: {
      temperature: cw.temperature,
      windspeed: cw.windspeed,
      winddirection: cw.winddirection,
      code,
      description: look.label,
      icon: look.icon,
      time: cw.time,
      units: { temperature: u.temp, windspeed: u.speed }
    },
    today: {
      high: daily.temperature_2m_max?.[idx0],
      low: daily.temperature_2m_min?.[idx0],
      sunrise: daily.sunrise?.[idx0],
      sunset: daily.sunset?.[idx0],
      precipitation_sum: daily.precipitation_sum?.[idx0]
    },
    hourly: {
      time: json.hourly?.time || [],
      temperature: json.hourly?.temperature_2m || [],
      apparent_temperature: json.hourly?.apparent_temperature || [],
      relative_humidity: json.hourly?.relativehumidity_2m || [],
      precipitation: json.hourly?.precipitation || [],
      weathercode: json.hourly?.weathercode || []
    },
    raw: { // allows advanced custom layouts to use more detail
      ...json
    }
  };
}
