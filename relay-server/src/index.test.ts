import { jest } from '@jest/globals'

it('reports invalid relay configuration without logging its value', async () => {
  jest.replaceProperty(process, 'env', {
    ...process.env,
    TRUSTED_PROXY_IPS: 'synthetic-proxy-setting',
  })
  const stdout = jest.spyOn(console, 'log').mockImplementation(() => {})
  const stderr = jest.spyOn(console, 'error').mockImplementation(() => {})
  const exit = jest.spyOn(process, 'exit').mockImplementation(() => undefined as never)

  try {
    await import('./index.js')

    expect(exit.mock.calls).toEqual([[1]])
    expect(stdout).not.toHaveBeenCalled()
    expect(stderr.mock.calls).toEqual([
      [
        'Failed to start relay server. Check relay configuration, listener ports, and identity file permissions.',
      ],
    ])
  } finally {
    jest.restoreAllMocks()
  }
})
