import { describe, expect, test } from '@jest/globals';
import { hasBootstrapPeers } from './bootstrap-config.js';

describe('bootstrap configuration', () => {
  test.each<{ name: string; list: string[]; expected: boolean }>([
    {
      name: 'omits bootstrap discovery for a valid standalone swarm',
      list: [],
      expected: false,
    },
    {
      name: 'enables bootstrap discovery when an address is configured',
      list: ['/ip4/127.0.0.1/tcp/9001/ws'],
      expected: true,
    },
  ])('$name', ({ list, expected }) => {
    expect(hasBootstrapPeers({ list })).toBe(expected);
  });
});
