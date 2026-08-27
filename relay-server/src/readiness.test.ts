import { startReadinessServer } from './readiness.js'

describe('readiness server', () => {
  it('stays unready until startup completes and returns to unready on shutdown', async () => {
    const readiness = await startReadinessServer(0, '127.0.0.1')
    const baseUrl = `http://127.0.0.1:${readiness.port}`
    try {
      const live = await fetch(`${baseUrl}/livez`)
      expect(live.status).toBe(200)
      await expect(live.json()).resolves.toEqual({ status: 'alive' })

      const starting = await fetch(`${baseUrl}/readyz`)
      expect(starting.status).toBe(503)
      await expect(starting.json()).resolves.toEqual({ status: 'not-ready' })

      readiness.markReady('12D3KooWStableRelay')
      const ready = await fetch(`${baseUrl}/readyz`)
      expect(ready.status).toBe(200)
      expect(ready.headers.get('cache-control')).toBe('no-store')
      await expect(ready.json()).resolves.toEqual({
        status: 'ready',
        peerId: '12D3KooWStableRelay',
      })

      readiness.markNotReady()
      expect((await fetch(`${baseUrl}/readyz`)).status).toBe(503)
    } finally {
      await readiness.close()
    }
  })

  it('does not expose readiness on unrelated paths', async () => {
    const readiness = await startReadinessServer(0, '127.0.0.1')
    try {
      expect(
        (await fetch(`http://127.0.0.1:${readiness.port}/relay.key`)).status,
      ).toBe(404)
    } finally {
      await readiness.close()
    }
  })

  it('rejects deterministically when the readiness port cannot bind', async () => {
    const occupied = await startReadinessServer(0, '127.0.0.1')
    try {
      await expect(
        startReadinessServer(occupied.port, '127.0.0.1'),
      ).rejects.toMatchObject({ code: 'EADDRINUSE' })
    } finally {
      await occupied.close()
    }
  })
})
