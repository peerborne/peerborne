import { serve } from '@hono/node-server';
import { serveStatic } from '@hono/node-server/serve-static';
import { Hono } from 'hono';
import handler from './dist/server/server.js';

const app = new Hono();
app.use('/assets/*', serveStatic({ root: './dist/client' }));
app.all('*', (context) => handler.fetch(context.req.raw));
serve({
  fetch: app.fetch,
  hostname: '127.0.0.1',
  port: Number(process.env.PORT ?? 4192),
});
