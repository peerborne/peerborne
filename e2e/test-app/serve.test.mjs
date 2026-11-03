import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { request } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { createTestAppServer } from './serve.mjs';

test('the network fixture serves only its public assets with CORS', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'peerborne-static-test-'));
  const server = createTestAppServer(directory);
  try {
    for (const file of ['index.html', 'app.js', 'app.js.map', 'config.json']) {
      await writeFile(join(directory, file), `fixture ${file}`);
    }
    await writeFile(join(directory, 'private.txt'), 'must not be served');
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const origin = `http://127.0.0.1:${server.address().port}`;
    for (const path of [
      '/',
      '/index.html',
      '/app.js',
      '/app.js.map',
      '/config.json?fresh=1',
    ]) {
      const response = await fetch(origin + path);
      assert.equal(response.status, 200);
      assert.equal(response.headers.get('access-control-allow-origin'), '*');
      assert.equal(response.headers.get('cache-control'), 'no-store');
      assert.match(await response.text(), /^fixture /u);
    }
    const head = await fetch(origin + '/app.js', { method: 'HEAD' });
    assert.equal(head.status, 200);
    assert.equal(
      head.headers.get('content-type'),
      'text/javascript; charset=utf-8',
    );
    assert.equal(
      Number(head.headers.get('content-length')),
      'fixture app.js'.length,
    );
    assert.equal(await head.text(), '');
    const options = await fetch(origin + '/', { method: 'OPTIONS' });
    assert.equal(options.status, 204);
    assert.equal(
      options.headers.get('access-control-allow-methods'),
      'GET, HEAD, OPTIONS',
    );
    const post = await fetch(origin + '/', { method: 'POST' });
    assert.equal(post.status, 405);
    assert.equal(post.headers.get('allow'), 'GET, HEAD, OPTIONS');
    for (const path of [
      '/private.txt',
      '/%2e%2e/private.txt',
      '/../private.txt',
      '/missing',
      '/%zz',
    ]) {
      const status = await new Promise((resolve, reject) => {
        const child = request(origin, { path }, (response) => {
          response.resume();
          response.once('end', () => resolve(response.statusCode));
        });
        child.once('error', reject);
        child.end();
      });
      assert.equal(status, 404);
    }
    await rm(join(directory, 'app.js'));
    assert.equal((await fetch(origin + '/app.js')).status, 404);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    await rm(directory, { recursive: true, force: true });
  }
});
