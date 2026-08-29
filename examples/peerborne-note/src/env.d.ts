/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_PEERBORNE_RELAY_MULTIADDR?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
