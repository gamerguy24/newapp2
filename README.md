# WeatherHD

Modern weather graphics for displays and broadcasts. Built with Node.js and standard web tech.

## Quick start
- Requires Node.js 18+
- Install: `npm i`
- Run: `npm start`
- Open: http://localhost:3000

## Customize
- URL params:
  - lat, lon: `?lat=40.7&lon=-74.0`
  - units: `auto` | `metric` | `us`/`imperial`
  - refresh (ms): `?refresh=45000`
- Frontend: edit files in `public/`
- Providers: add modules in `src/providers/` and wire them in `src/server.js`

## TV/Broadcast layout
Open the TV layout:
- http://localhost:3000/tv.html
- Optional params:
  - lat, lon: `?lat=49.90&lon=-97.14`
  - units: `auto` | `metric` | `us`
  - zoom: radar zoom level (default 6)
  - refresh: milliseconds between updates

The page shows a 5‑day outlook, radar (RainViewer embed), current conditions, tomorrow highlights, air quality, and a bottom ticker.

## Notes
- Uses Open-Meteo (no API key). Add caching and more providers as needed.
