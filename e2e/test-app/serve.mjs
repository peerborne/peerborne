import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const files = new Map([
  ['/', ['index.html', 'text/html; charset=utf-8']],
  ['/index.html', ['index.html', 'text/html; charset=utf-8']],
  ['/app.js', ['app.js', 'text/javascript; charset=utf-8']],
  ['/app.js.map', ['app.js.map', 'application/json']],
  ['/config.json', ['config.json', 'application/json']],
]);

export function createTestAppServer(directory) {
  return createServer(async (request, response) => {
    response.setHeader('Access-Control-Allow-Origin', '*');
    response.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    if (request.method === 'OPTIONS') {
      response.writeHead(204).end();
      return;
    }
    if (!['GET', 'HEAD'].includes(request.method)) {
      response.setHeader('Allow', 'GET, HEAD, OPTIONS');
      response.writeHead(405).end();
      return;
    }
    const file = files.get(request.url?.split('?')[0]);
    if (!file) {
      response.writeHead(404).end();
      return;
    }
    try {
      const body = await readFile(join(directory, file[0]));
      response.writeHead(200, {
        'Content-Type': file[1],
        'Content-Length': body.length,
      });
      response.end(request.method === 'HEAD' ? undefined : body);
    } catch (error) {
      response.writeHead(error.code === 'ENOENT' ? 404 : 500).end();
    }
  });
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  const directory = join(dirname(fileURLToPath(import.meta.url)), 'dist');
  createTestAppServer(directory).listen(3000, '0.0.0.0');
}
