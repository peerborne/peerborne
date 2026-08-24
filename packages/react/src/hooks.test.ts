import { describe, expect, test, jest, beforeEach } from '@jest/globals';
import React from 'react';
import { render, act, waitFor } from '@testing-library/react';
import { PeerborneContext, usePeerborne } from './hooks.js';

// ---------------------------------------------------------------------------
// PeerborneContext defaults
// ---------------------------------------------------------------------------
describe('PeerborneContext defaults', () => {
  test('has expected default shape with empty caches and no-op setters', () => {
    // Render a consumer that reads the context without a provider wrapper so
    // we get the default value passed to createContext().
    let ctxValue: any;
    function Reader() {
      ctxValue = React.useContext(PeerborneContext);
      return null;
    }
    render(React.createElement(Reader));

    expect(ctxValue).toBeDefined();
    expect(ctxValue.docCache).toEqual({});
    expect(ctxValue.docDataCache).toEqual({});
    expect(ctxValue.docReadersCache).toEqual({});
    expect(ctxValue.docWritersCache).toEqual({});
    // Setters should be functions (no-ops by default).
    expect(typeof ctxValue.setDocCache).toBe('function');
    expect(typeof ctxValue.setDocDataCache).toBe('function');
    expect(typeof ctxValue.setDocReadersCache).toBe('function');
    expect(typeof ctxValue.setDocWritersCache).toBe('function');
  });

  test('default setters do not throw when called', () => {
    let ctxValue: any;
    function Reader() {
      ctxValue = React.useContext(PeerborneContext);
      return null;
    }
    render(React.createElement(Reader));

    expect(() => ctxValue.setDocCache({ foo: 'bar' })).not.toThrow();
    expect(() => ctxValue.setDocDataCache({ foo: 'bar' })).not.toThrow();
    expect(() => ctxValue.setDocReadersCache({ foo: [] })).not.toThrow();
    expect(() => ctxValue.setDocWritersCache({ foo: [] })).not.toThrow();
  });

  test('provider overrides default values', () => {
    let ctxValue: any;
    function Reader() {
      ctxValue = React.useContext(PeerborneContext);
      return null;
    }

    const custom = {
      docCache: { '/doc': {} as any },
      docDataCache: { '/doc': 'hello' },
      docReadersCache: { '/doc': ['reader1'] },
      docWritersCache: { '/doc': ['writer1'] },
      setDocCache: jest.fn(),
      setDocDataCache: jest.fn(),
      setDocReadersCache: jest.fn(),
      setDocWritersCache: jest.fn(),
    };

    render(
      React.createElement(
        PeerborneContext.Provider,
        { value: custom },
        React.createElement(Reader),
      ),
    );

    expect(ctxValue.docCache).toBe(custom.docCache);
    expect(ctxValue.docDataCache).toBe(custom.docDataCache);
    expect(ctxValue.docReadersCache).toBe(custom.docReadersCache);
    expect(ctxValue.docWritersCache).toBe(custom.docWritersCache);
  });
});

// ---------------------------------------------------------------------------
// usePeerborne hook
// ---------------------------------------------------------------------------

// We need to mock the @peerborne/core module so that `new Peerborne(...)`
// doesn't try to actually set up libp2p etc.
jest.mock('@peerborne/core', () => {
  const mockInitialize = jest.fn(() => Promise.resolve());
  class MockPeerborne {
    initialize = mockInitialize;
    constructor(..._args: any[]) {}
  }
  return {
    __esModule: true,
    Peerborne: MockPeerborne,
    _mockInitialize: mockInitialize,
  };
});

describe('usePeerborne hook', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });
  // Helper to capture the hook return value.
  function HookConsumer(props: {
    privateKey: any;
    publicKey: any;
    captureRef: { current: any };
  }) {
    const result = usePeerborne(
      props.privateKey,
      props.publicKey,
      // Provide stubs for all required provider arguments.
      {} as any, // provider
      {} as any, // changesSerializer
      {} as any, // syncMessageSerializer
      {} as any, // loadMessageSerializer
      {} as any, // authProvider
      {} as any, // aclProvider
      {} as any, // keychainProvider
    );
    props.captureRef.current = result;
    return null;
  }

  test('returns undefined when keys are not provided', () => {
    const captureRef = { current: undefined as any };
    render(
      React.createElement(HookConsumer, {
        privateKey: undefined,
        publicKey: undefined,
        captureRef,
      }),
    );
    expect(captureRef.current).toBeUndefined();
  });

  test('creates a Peerborne instance after initialization when keys are provided', async () => {
    const captureRef = { current: undefined as any };

    await act(async () => {
      render(
        React.createElement(HookConsumer, {
          privateKey: 'priv-key',
          publicKey: 'pub-key',
          captureRef,
        }),
      );
    });

    // Wait for the async useEffect IIFE to complete and update state.
    await waitFor(() => {
      expect(captureRef.current).toBeDefined();
      expect(captureRef.current.initialize).toBeDefined();
    });

    expect(captureRef.current.initialize).toHaveBeenCalled();
  });

  test('returns undefined initially then resolves after effect', async () => {
    const captureRef = { current: 'SENTINEL' as any };

    await act(async () => {
      render(
        React.createElement(HookConsumer, {
          privateKey: 'priv-key',
          publicKey: 'pub-key',
          captureRef,
        }),
      );
    });

    // Wait for the async useEffect IIFE to complete and update state.
    await waitFor(() => {
      expect(captureRef.current).toBeDefined();
      expect(captureRef.current).not.toBe('SENTINEL');
    });
  });
});
