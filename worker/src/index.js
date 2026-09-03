import { routeRadar } from './radar.js';

const allowedOrigins = new Set([
  'https://radarfico.github.io',
  'http://localhost:8788',
  'http://127.0.0.1:8788',
]);

function cors(request) {
  const origin = request.headers.get('origin');
  const allowed = !origin || allowedOrigins.has(origin);
  return {
    'access-control-allow-origin': allowed && origin ? origin : 'https://radarfico.github.io',
    'access-control-allow-methods': 'GET,POST,OPTIONS',
    'access-control-allow-headers': 'authorization,content-type',
    'access-control-max-age': '86400',
    vary: 'Origin',
  };
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors(request) });
    const response = await routeRadar(request, env);
    if (response) return response;
    return new Response(JSON.stringify({ ok: false, error: 'Rota não encontrada.' }), {
      status: 404,
      headers: { 'content-type': 'application/json; charset=utf-8', ...cors(request) },
    });
  },
};
