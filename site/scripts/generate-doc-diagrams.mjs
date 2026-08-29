#!/usr/bin/env node

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptPath = fileURLToPath(import.meta.url);
const root = resolve(dirname(scriptPath), '../..');
const outputDirectory = resolve(root, 'site/src/assets/diagrams');

function escapeXml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;');
}

function text(x, y, value, className = 'body', options = {}) {
  const attributes = [
    `x="${x}"`,
    `y="${y}"`,
    `class="${className}"`,
    options.anchor ? `text-anchor="${options.anchor}"` : '',
    options.fill ? `fill="${options.fill}"` : '',
  ]
    .filter(Boolean)
    .join(' ');
  return `<text ${attributes}>${escapeXml(value)}</text>`;
}

function lines(x, y, values, options = {}) {
  const lineHeight = options.lineHeight ?? 24;
  return values
    .map((value, index) =>
      text(x, y + index * lineHeight, value, options.className ?? 'body', options),
    )
    .join('\n');
}

function card(x, y, width, height, options = {}) {
  return `<rect x="${x}" y="${y}" width="${width}" height="${height}" rx="${options.radius ?? 18}" fill="${options.fill ?? '#142033'}" stroke="${options.stroke ?? '#475569'}" stroke-width="${options.strokeWidth ?? 1.5}"${options.dash ? ` stroke-dasharray="${options.dash}"` : ''}/>`;
}

function pill(x, y, width, label, options = {}) {
  const background = card(x, y, width, 34, {
    radius: 17,
    fill: options.fill ?? '#172554',
    stroke: options.stroke ?? '#6366f1',
  });
  const badgeText = text(x + width / 2, y + 23, label, 'badge', {
    anchor: 'middle',
    fill: options.text ?? '#c7d2fe',
  });
  return [background, badgeText].join('\n    ');
}

function arrow(path, options = {}) {
  return `<path d="${path}" fill="none" stroke="${options.stroke ?? '#818cf8'}" stroke-width="${options.width ?? 3}"${options.dash ? ` stroke-dasharray="${options.dash}"` : ''} marker-end="url(#${options.marker ?? 'arrowIndigo'})"/>`;
}

function diagramFrame({ id, width = 1200, height, title, subtitle, description, body }) {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" role="img" aria-labelledby="${id}-title ${id}-description">
  <title id="${id}-title">${escapeXml(title)}</title>
  <desc id="${id}-description">${escapeXml(description)}</desc>
  <defs>
    <linearGradient id="background" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#0b1220"/>
      <stop offset="0.55" stop-color="#111827"/>
      <stop offset="1" stop-color="#172554"/>
    </linearGradient>
    <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
      <path d="M40 0H0V40" fill="none" stroke="#c7d2fe" stroke-opacity="0.035"/>
    </pattern>
    <filter id="shadow" x="-20%" y="-20%" width="140%" height="150%">
      <feDropShadow dx="0" dy="6" stdDeviation="8" flood-color="#020617" flood-opacity="0.38"/>
    </filter>
    <marker id="arrowIndigo" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">
      <path d="M0 0L10 5L0 10Z" fill="#818cf8"/>
    </marker>
    <marker id="arrowTeal" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">
      <path d="M0 0L10 5L0 10Z" fill="#2dd4bf"/>
    </marker>
    <style>
      text { font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
      .title { fill: #f8fafc; font-size: 30px; font-weight: 760; }
      .subtitle { fill: #94a3b8; font-size: 17px; }
      .eyebrow { font-size: 15px; font-weight: 760; letter-spacing: 1.25px; }
      .section { fill: #e2e8f0; font-size: 16px; font-weight: 740; letter-spacing: .5px; }
      .card-title { fill: #f8fafc; font-size: 19px; font-weight: 740; }
      .body { fill: #cbd5e1; font-size: 15px; }
      .body-strong { fill: #e2e8f0; font-size: 15px; font-weight: 700; }
      .badge { font-size: 15px; font-weight: 760; letter-spacing: .35px; }
      .node { fill: #f8fafc; font-size: 18px; font-weight: 760; }
      .node-detail { fill: #cbd5e1; font-size: 15px; }
      .number { fill: #0f172a; font-size: 15px; font-weight: 800; text-anchor: middle; dominant-baseline: middle; }
    </style>
  </defs>
  <rect width="${width}" height="${height}" rx="28" fill="url(#background)"/>
  <rect width="${width}" height="${height}" rx="28" fill="url(#grid)"/>
  <path d="M0 28A28 28 0 0 1 28 0H${width - 28}A28 28 0 0 1 ${width} 28V34H0Z" fill="#2dd4bf"/>
  <g>
    ${text(50, 69, title, 'title')}
    ${text(50, 99, subtitle, 'subtitle')}
${body}
  </g>
</svg>
`;
}

function packageDependencies() {
  const body = `
    ${pill(934, 51, 216, 'ARROW = DEPENDS ON', {
      fill: '#0f2b2e',
      stroke: '#2dd4bf',
      text: '#99f6e4',
    })}

    ${text(50, 151, 'CRDT ADAPTER WORKSPACES', 'eyebrow', { fill: '#a5b4fc' })}
    ${card(50, 170, 270, 76, { stroke: '#6366f1' })}
    ${text(72, 202, '@peerborne/yjs', 'card-title')}
    ${text(72, 228, 'Yjs CRDTProvider adapter', 'body')}
    ${card(50, 264, 270, 76, { stroke: '#6366f1' })}
    ${text(72, 296, '@peerborne/automerge', 'card-title')}
    ${text(72, 322, 'Automerge CRDTProvider adapter', 'body')}

    ${text(880, 151, 'INTEGRATION WORKSPACES', 'eyebrow', { fill: '#5eead4' })}
    ${card(880, 170, 270, 68, { stroke: '#14b8a6' })}
    ${text(902, 200, '@peerborne/react', 'card-title')}
    ${text(902, 223, 'React lifecycle bindings', 'body')}
    ${card(880, 252, 270, 68, { stroke: '#14b8a6' })}
    ${text(902, 282, '@peerborne/redux', 'card-title')}
    ${text(902, 305, 'Redux bindings', 'body')}
    ${card(880, 334, 270, 68, { stroke: '#14b8a6' })}
    ${text(902, 364, '@peerborne/index', 'card-title')}
    ${text(902, 387, 'Indexing and query layer', 'body')}

    <g filter="url(#shadow)">
      ${card(368, 164, 464, 242, {
        radius: 24,
        fill: '#18213c',
        stroke: '#818cf8',
        strokeWidth: 2.5,
      })}
    </g>
    ${text(600, 211, '@peerborne/core', 'card-title', { anchor: 'middle', fill: '#eef2ff' })}
    ${text(600, 239, 'Document lifecycle and synchronization', 'body', { anchor: 'middle' })}
    <line x1="402" y1="258" x2="798" y2="258" stroke="#334155"/>
    ${lines(408, 291, ['CRDTProvider boundary', 'Encryption + authorization', 'Shadow graph + storage'], {
      className: 'body-strong',
      lineHeight: 31,
    })}
    ${lines(640, 291, ['libp2p orchestration', 'Membership + invitations', 'Document API'], {
      className: 'body-strong',
      lineHeight: 31,
    })}
    ${arrow('M320 208H360', { stroke: '#a5b4fc' })}
    ${arrow('M320 302H360', { stroke: '#a5b4fc' })}
    ${arrow('M880 204H840', { stroke: '#5eead4', marker: 'arrowTeal' })}
    ${arrow('M880 286H840', { stroke: '#5eead4', marker: 'arrowTeal' })}
    ${arrow('M880 368H840', { stroke: '#5eead4', marker: 'arrowTeal' })}

    ${text(50, 448, 'CORE RUNTIME AND INTERNAL PRIMITIVES', 'eyebrow', { fill: '#fbbf24' })}
    ${card(50, 490, 260, 126, { stroke: '#475569' })}
    ${text(72, 523, 'libp2p', 'card-title')}
    ${lines(72, 550, ['Networking, discovery,', 'GossipSub, NAT traversal'], { lineHeight: 22 })}
    ${card(330, 490, 260, 126, { stroke: '#475569' })}
    ${text(352, 523, 'Helia + Bitswap', 'card-title')}
    ${lines(352, 550, ['Content-addressed blocks', 'and block exchange'], { lineHeight: 22 })}
    ${card(610, 490, 260, 126, { stroke: '#475569' })}
    ${text(632, 523, 'IPNS support (limited)', 'card-title')}
    ${lines(632, 550, ['DHT record validator', 'and selector only'], { lineHeight: 22 })}
    ${card(890, 490, 260, 126, { stroke: '#475569' })}
    ${text(912, 523, 'Core security modules', 'card-title')}
    ${lines(912, 550, ['BeeKEM membership', 'Optional UCAN ACL provider', 'selected by the application'], { lineHeight: 22 })}
    ${arrow('M470 406V457H180V482', { stroke: '#fbbf24' })}
    ${arrow('M550 406V458H460V482', { stroke: '#fbbf24' })}
    ${arrow('M650 406V458H740V482', { stroke: '#fbbf24' })}
    ${arrow('M730 406V457H1020V482', { stroke: '#fbbf24' })}

    ${card(50, 647, 1100, 67, { fill: '#101c2d', stroke: '#334155' })}
    ${text(74, 675, 'Dependency direction matters:', 'body-strong')}
    ${text(310, 675, 'Yjs and Automerge adapters depend on core; core does not import either adapter.', 'body')}
    ${text(74, 699, 'Applications choose and inject a CRDTProvider implementation at the package boundary.', 'body')}`;

  return diagramFrame({
    id: 'package-dependencies',
    height: 750,
    title: 'Package and runtime dependencies',
    subtitle: 'Adapters and integrations depend on core; core composes networking, storage, and security primitives.',
    description:
      'Dependency diagram with Peerborne core at the center. The Yjs and Automerge adapter packages, and the React, Redux, and index integration packages, depend on core. Core composes libp2p and Helia, has limited IPNS DHT validator and selector support, and contains BeeKEM membership code. An optional UCAN ACL provider can participate in authorization when selected by the application; it is not enabled automatically. Core does not depend on the CRDT adapter packages.',
    body,
  });
}

function networkingStack() {
  const body = `
    ${pill(664, 51, 154, 'VERIFIED PATH', {
      fill: '#0f2b2e',
      stroke: '#14b8a6',
      text: '#99f6e4',
    })}
    ${pill(830, 51, 158, 'PARTIAL EVIDENCE', {
      fill: '#3b2b13',
      stroke: '#f59e0b',
      text: '#fde68a',
    })}
    ${pill(1000, 51, 150, 'CONFIGURED ONLY', {
      fill: '#271b42',
      stroke: '#8b5cf6',
      text: '#ddd6fe',
    })}

    ${card(50, 136, 1100, 70, { fill: '#132e35', stroke: '#14b8a6', strokeWidth: 2 })}
    ${text(76, 166, 'APPLICATION', 'eyebrow', { fill: '#5eead4' })}
    ${text(250, 169, 'Calls the document API; owns user identity and key persistence.', 'body')}

    ${card(50, 226, 1100, 88, { fill: '#17213a', stroke: '#6366f1', strokeWidth: 2 })}
    ${text(76, 258, 'PEERBORNE CORE', 'eyebrow', { fill: '#a5b4fc' })}
    ${text(250, 257, 'Document lifecycle · ACL · encryption · shadow sync graph', 'body-strong')}
    ${text(250, 284, 'Coordinates configured Helia and libp2p services; does not replace their protocols.', 'body')}
    ${arrow('M600 206V218', { stroke: '#2dd4bf', marker: 'arrowTeal' })}

    ${card(50, 334, 1100, 384, { fill: '#101a2c', stroke: '#475569', strokeWidth: 2 })}
    ${text(76, 369, 'LIBP2P NETWORKING', 'eyebrow', { fill: '#c7d2fe' })}
    ${text(1030, 369, 'Noise + yamux', 'body-strong', { anchor: 'end' })}

    ${text(76, 410, 'TRANSPORTS', 'section')}
    ${card(76, 426, 326, 104, { fill: '#0f2b2e', stroke: '#14b8a6' })}
    ${text(98, 458, 'WebSocket + Circuit Relay v2', 'card-title')}
    ${text(98, 484, 'Cross-NAT live sync path', 'body')}
    ${pill(98, 495, 144, 'VERIFIED PATH', {
      fill: '#123a3d',
      stroke: '#2dd4bf',
      text: '#99f6e4',
    })}
    ${card(437, 426, 326, 104, { fill: '#2d2518', stroke: '#f59e0b' })}
    ${text(459, 458, 'WebRTC + WebRTC Direct', 'card-title')}
    ${text(459, 484, 'ICE uses configured STUN / TURN', 'body')}
    ${pill(459, 495, 158, 'PARTIAL EVIDENCE', {
      fill: '#3b2b13',
      stroke: '#f59e0b',
      text: '#fde68a',
    })}
    ${card(798, 426, 326, 104, { fill: '#251b3b', stroke: '#8b5cf6' })}
    ${text(820, 458, 'WebTransport', 'card-title')}
    ${text(820, 484, 'Present in default transport config', 'body')}
    ${pill(820, 495, 150, 'CONFIGURED ONLY', {
      fill: '#32224e',
      stroke: '#8b5cf6',
      text: '#ddd6fe',
    })}

    ${text(76, 572, 'DISCOVERY, ROUTING, AND SERVICES', 'section')}
    ${card(76, 588, 326, 102, { fill: '#2d2518', stroke: '#f59e0b' })}
    ${text(98, 619, 'Discovery + client DHT', 'card-title')}
    ${lines(98, 644, ['Bootstrap when set + PubSub discovery', 'Node default adds LAN-broadcast mDNS', 'DHT client: IPNS validator / selector only'], { lineHeight: 21 })}
    ${card(437, 588, 326, 102, { fill: '#0f2b2e', stroke: '#14b8a6' })}
    ${text(459, 619, 'GossipSub document topics', 'card-title')}
    ${lines(459, 645, ['Fresh mutations are exercised across the', 'dedicated relay-backed browser topology.'], { lineHeight: 22 })}
    ${card(798, 588, 326, 102, { fill: '#2d2518', stroke: '#f59e0b' })}
    ${text(820, 619, 'DCUtR + AutoNAT + ICE', 'card-title')}
    ${lines(820, 645, ['Configured and component-tested; direct-path', 'and authenticated TURN coverage is incomplete.'], { lineHeight: 22 })}
    ${arrow('M600 314V326', { stroke: '#818cf8' })}

    ${card(50, 738, 1100, 91, { fill: '#121f31', stroke: '#475569', strokeWidth: 2 })}
    ${text(76, 770, 'HELIA / CONTENT-ADDRESSED STORAGE', 'eyebrow', { fill: '#93c5fd' })}
    ${text(76, 796, 'Browser default', 'body-strong')}
    ${text(430, 796, 'Node default', 'body-strong')}
    ${text(870, 796, 'Both', 'body-strong')}
    ${text(76, 819, 'IndexedDB blockstore + datastore', 'body')}
    ${text(430, 819, 'Process-local in-memory stores; custom stores supported', 'body')}
    ${text(870, 819, 'Bitswap + CID validation', 'body')}
    ${arrow('M600 718V730', { stroke: '#818cf8' })}

    ${card(50, 849, 1100, 54, { fill: '#111d2e', stroke: '#334155' })}
    ${text(600, 882, 'Evidence labels describe current automated coverage—not every capability of the configured protocols.', 'body', { anchor: 'middle' })}`;

  return diagramFrame({
    id: 'networking-stack',
    height: 930,
    title: 'Peer-to-peer networking stack',
    subtitle: 'Configured components and current automated evidence are shown separately.',
    description:
      'Layer diagram from application through Peerborne core, libp2p, and Helia. WebSocket through Circuit Relay and GossipSub live mutations are verified in the dedicated cross-NAT browser path. WebRTC, WebRTC Direct, ICE, DCUtR, AutoNAT, bootstrap, and Kademlia have partial evidence. WebTransport is configured but lacks a successful synchronization assertion. Bootstrap and PubSub peer discovery are configured, and the Node default additionally uses LAN-broadcast mDNS. IPNS support is limited to DHT record validators and selectors. Browser defaults use IndexedDB stores; Node defaults use process-local in-memory stores and allow custom stores.',
    body,
  });
}

function encryptionIdentity() {
  const body = `
    ${text(50, 143, 'THREE SEPARATE KEY OR IDENTITY ROLES', 'eyebrow', { fill: '#5eead4' })}
    ${card(50, 163, 340, 138, { fill: '#16213a', stroke: '#6366f1', strokeWidth: 2 })}
    ${text(74, 198, 'Writer signing identity', 'card-title')}
    ${text(74, 225, 'ECDSA P-384 key pair', 'body-strong')}
    ${lines(74, 251, ['Application supplied and stored', 'Authenticates signed document messages'], { lineHeight: 23 })}
    ${card(430, 163, 340, 138, { fill: '#123038', stroke: '#14b8a6', strokeWidth: 2 })}
    ${text(454, 198, 'Reader onboarding identity', 'card-title')}
    ${text(454, 225, 'ECDH P-256 KEM key pair', 'body-strong')}
    ${lines(454, 251, ['Application supplied and stored', 'Opens recipient-sealed Welcome data'], { lineHeight: 23 })}
    ${card(810, 163, 340, 138, { fill: '#302441', stroke: '#8b5cf6', strokeWidth: 2 })}
    ${text(834, 198, 'Transport identity', 'card-title')}
    ${text(834, 225, 'libp2p Peer ID', 'body-strong')}
    ${lines(834, 251, ['Owned by the libp2p transport', 'Separate from application signing keys'], { lineHeight: 23 })}

    ${card(50, 329, 1100, 132, { fill: '#111f34', stroke: '#475569', strokeWidth: 2 })}
    ${text(74, 363, 'DOCUMENT-SCOPED STATE', 'eyebrow', { fill: '#93c5fd' })}
    ${text(74, 397, 'Document encryption keys', 'card-title')}
    ${text(333, 397, 'AES-GCM by default', 'body')}
    ${text(590, 397, 'Reader / writer ACL', 'card-title')}
    ${text(806, 397, 'Bound to signing public keys', 'body')}
    ${pill(74, 414, 442, 'NO SIGNING-KEY → PEER-ID MAP', {
      fill: '#301f2c',
      stroke: '#f472b6',
      text: '#fbcfe8',
    })}
    ${text(540, 438, 'Applications own enrollment, private-key persistence, backup, and recovery.', 'body')}
    ${arrow('M220 301V321', { stroke: '#818cf8' })}
    ${arrow('M600 301V321', { stroke: '#2dd4bf', marker: 'arrowTeal' })}
    ${arrow('M980 301V321', { stroke: '#8b5cf6' })}

    ${text(50, 508, 'PER-CHANGE ARTIFACTS', 'eyebrow', { fill: '#fbbf24' })}
    ${card(50, 530, 520, 222, { fill: '#1b2140', stroke: '#6366f1', strokeWidth: 2 })}
    ${text(76, 565, 'CID-addressed stored payload', 'card-title')}
    ${lines(76, 595, ['Serialized CRDT change', '→ encrypted with the document key', '→ stored as opaque bytes in Helia', '→ CID addresses the complete byte frame'], {
      lineHeight: 26,
    })}
    ${pill(76, 696, 412, 'NO BLOCK SIGNATURE OR ACL DECISION', {
      fill: '#301f2c',
      stroke: '#f472b6',
      text: '#fbcfe8',
    })}

    ${card(630, 530, 520, 222, { fill: '#123038', stroke: '#14b8a6', strokeWidth: 2 })}
    ${text(656, 565, 'Separate GossipSub envelope', 'card-title')}
    ${lines(656, 595, ['CRDTSyncMessage names the new CID', '→ signed with P-384 when signing is enabled', '→ serialized and encrypted with document key', '→ full encrypted envelope is published'], {
      lineHeight: 26,
    })}
    ${pill(656, 696, 362, 'SIGNATURE COVERS WIRE MESSAGE', {
      fill: '#0f3b3b',
      stroke: '#2dd4bf',
      text: '#99f6e4',
    })}

    ${card(50, 781, 1100, 89, { fill: '#111d2e', stroke: '#475569', strokeWidth: 2 })}
    ${text(74, 815, 'RECEIVER ORDER', 'eyebrow', { fill: '#93c5fd' })}
    ${text(240, 815, 'decrypt + deserialize envelope', 'body-strong')}
    ${text(475, 815, '→', 'body-strong')}
    ${text(507, 815, 'verify known writer when applicable', 'body-strong')}
    ${text(787, 815, '→', 'body-strong')}
    ${text(819, 815, 'apply inline / fetch CIDs', 'body-strong')}
    ${text(240, 842, 'Fetched stored blocks: CID validation → decrypt → deserialize; no per-block writer authentication.', 'body')}`;

  return diagramFrame({
    id: 'encryption-identity',
    height: 900,
    title: 'Encryption and identity roles',
    subtitle: 'Signing identity, KEM identity, and libp2p transport identity are separate concerns.',
    description:
      'Diagram separating an application-supplied ECDSA P-384 writer signing key, an application-supplied ECDH P-256 onboarding KEM key, and the libp2p Peer ID transport identity. Peerborne does not map signing keys to Peer IDs. Document state includes encryption keys and an ACL bound to signing public keys. Each change produces a CID-addressed encrypted stored payload without a block signature and a separate signed-when-enabled encrypted GossipSub message.',
    body,
  });
}

function changeLifecycle() {
  const step = (number, x, y, width, titleValue, details, color = 'indigo') => {
    const accent = color === 'teal' ? '#2dd4bf' : '#818cf8';
    const fill = color === 'teal' ? '#123038' : '#18213c';
    return `<g filter="url(#shadow)">
      ${card(x, y, width, 116, { fill, stroke: accent, strokeWidth: 2 })}
    </g>
    <circle cx="${x + 27}" cy="${y + 29}" r="16" fill="${accent}"/>
    ${text(x + 27, y + 30, number, 'number')}
    ${text(x + 52, y + 34, titleValue, 'card-title')}
    ${lines(x + 22, y + 69, details, { lineHeight: 23 })}`;
  };

  const body = `
    ${pill(916, 51, 234, 'LOCAL MUTATION FIRST', {
      fill: '#301f2c',
      stroke: '#f472b6',
      text: '#fbcfe8',
    })}
    ${step('1', 50, 145, 300, 'document.change(fn)', ['Application supplies a change callback.'])}
    ${step('2', 450, 145, 300, 'Authorize the write', ['Current writer access is checked.'])}
    ${step('3', 850, 145, 300, 'CRDTProvider', ['localChange(document, message, fn)', 'runs the callback at the adapter boundary.'], 'teal')}
    ${arrow('M350 203H442')}
    ${arrow('M750 203H842')}

    ${step('4', 850, 320, 300, 'Local replica changes', ['Provider returns the updated document', 'and a provider-specific CRDT delta.'], 'teal')}
    ${step('5', 450, 320, 300, 'Serialize + encrypt', ['Serialize the provider delta, then', 'encrypt with the document key.'])}
    ${step('6', 50, 320, 300, 'Store bytes in Helia', ['Content addressing returns a CID.'])}
    ${arrow('M1000 261V312', { stroke: '#2dd4bf', marker: 'arrowTeal' })}
    ${arrow('M850 378H758')}
    ${arrow('M450 378H358')}

    ${step('7', 50, 495, 300, 'Build CRDTSyncMessage', ['Name the CID; include inline history', 'and deferred CID references.'])}
    ${step('8', 450, 495, 300, 'Protect wire message', ['Sign when enabled, serialize, then', 'encrypt with the document key.'], 'teal')}
    ${step('9', 850, 495, 300, 'Publish full envelope', ['Send to the document GossipSub topic;', 'this is not a CID-only announcement.'], 'teal')}
    ${arrow('M200 436V487')}
    ${arrow('M350 553H442')}
    ${arrow('M750 553H842', { stroke: '#2dd4bf', marker: 'arrowTeal' })}

    ${card(50, 670, 1100, 107, { fill: '#301f2c', stroke: '#f472b6', strokeWidth: 2 })}
    ${text(76, 705, 'FAILURE BOUNDARY', 'eyebrow', { fill: '#f9a8d4' })}
    ${text(270, 705, 'The local replica changes during CRDTProvider.localChange, before storage and publication finish.', 'body-strong')}
    ${text(76, 737, 'A later storage or publication error can reject change() while the mutation remains visible locally.', 'body')}
    ${text(76, 762, 'There is no automatic rollback, durable outbox, or remote delivery receipt.', 'body')}`;

  return diagramFrame({
    id: 'change-lifecycle',
    height: 810,
    title: 'The document.change() lifecycle',
    subtitle: 'Core delegates the local mutation to CRDTProvider.localChange before creating storage and wire artifacts.',
    description:
      'Nine-step flow. An application calls document.change, write access is checked, and core calls CRDTProvider.localChange with the document and callback. The local replica changes and a provider-specific CRDT delta is returned. Peerborne serializes and encrypts that delta, stores the payload in Helia to obtain a CID, builds a CRDT sync message, signs it when enabled, encrypts it, and publishes the full envelope through GossipSub. A later failure does not automatically roll back the local mutation.',
    body,
  });
}

function shadowSyncGraph() {
  const node = (x, y, label, detail, options = {}) => {
    const fill = options.deferred ? '#302441' : '#123038';
    const stroke = options.deferred ? '#a78bfa' : '#2dd4bf';
    return `<g filter="url(#shadow)">
      ${card(x, y, 242, 94, {
        fill,
        stroke,
        strokeWidth: 2,
        dash: options.deferred ? '8 6' : undefined,
      })}
    </g>
    ${text(x + 121, y + 38, label, 'node', { anchor: 'middle' })}
    ${text(x + 121, y + 67, detail, 'node-detail', { anchor: 'middle' })}`;
  };

  const body = `
    ${text(50, 145, 'ENCRYPTED CRDTSyncMessage SHADOW TREE', 'eyebrow', { fill: '#5eead4' })}
    ${node(270, 174, 'CID C', 'root · inline change')}
    ${node(95, 346, 'CID B', 'inline prior change')}
    ${node(445, 346, 'CID B′', 'deferred concurrent cross-link', { deferred: true })}
    ${node(95, 518, 'CID A', 'inline ancestor')}
    ${arrow('M391 268V301H216V338', { stroke: '#2dd4bf', marker: 'arrowTeal' })}
    ${arrow('M391 268V301H566V338', {
      stroke: '#a78bfa',
      dash: '9 7',
    })}
    ${arrow('M216 440V510', { stroke: '#2dd4bf', marker: 'arrowTeal' })}
    ${pill(197, 289, 388, 'B AND B′ ARE SIBLINGS UNDER C', {
      fill: '#0f2b2e',
      stroke: '#2dd4bf',
      text: '#99f6e4',
    })}

    ${card(735, 145, 415, 516, { fill: '#121d30', stroke: '#475569', strokeWidth: 2 })}
    ${text(761, 180, 'SEPARATE HELIA BLOCKS', 'eyebrow', { fill: '#93c5fd' })}
    ${text(761, 212, 'Each CID addresses encrypted change bytes.', 'body')}
    ${card(761, 240, 165, 70, { fill: '#1b2140', stroke: '#6366f1' })}
    ${text(843.5, 271, 'block C', 'card-title', { anchor: 'middle' })}
    ${text(843.5, 294, 'encrypted change', 'body', { anchor: 'middle' })}
    ${card(959, 240, 165, 70, { fill: '#1b2140', stroke: '#6366f1' })}
    ${text(1041.5, 271, 'block B', 'card-title', { anchor: 'middle' })}
    ${text(1041.5, 294, 'encrypted change', 'body', { anchor: 'middle' })}
    ${card(761, 331, 165, 70, { fill: '#1b2140', stroke: '#6366f1' })}
    ${text(843.5, 362, 'block B′', 'card-title', { anchor: 'middle' })}
    ${text(843.5, 385, 'fetched if missing', 'body', { anchor: 'middle' })}
    ${card(959, 331, 165, 70, { fill: '#1b2140', stroke: '#6366f1' })}
    ${text(1041.5, 362, 'block A', 'card-title', { anchor: 'middle' })}
    ${text(1041.5, 385, 'encrypted change', 'body', { anchor: 'middle' })}
    <line x1="761" y1="434" x2="1124" y2="434" stroke="#334155"/>
    ${text(761, 469, 'Stored payloads do not contain:', 'body-strong')}
    ${lines(781, 500, ['• parent or cross-link edges', '• a separate writer signature', '• a per-block ACL decision'], { lineHeight: 28 })}
    ${pill(761, 594, 363, 'GRAPH LIVES IN THE WIRE MESSAGE', {
      fill: '#172554',
      stroke: '#6366f1',
      text: '#c7d2fe',
    })}

    ${card(50, 684, 1100, 67, { fill: '#111d2e', stroke: '#334155' })}
    ${text(74, 712, 'Merge semantics:', 'body-strong')}
    ${text(212, 712, 'the CRDT layer merges B and B′ when both payloads arrive; the shadow graph guides discovery.', 'body')}
    ${text(74, 736, 'Inline nodes can be applied immediately; an omitted payload is fetched by its CID only when needed.', 'body')}`;

  return diagramFrame({
    id: 'shadow-sync-graph',
    height: 785,
    title: 'Shadow sync graph',
    subtitle: 'Graph edges travel in the encrypted wire message, while stored change payloads remain link-free.',
    description:
      'A CRDT sync message contains inline root C. C has two sibling child-map entries: inline prior change B and deferred concurrent cross-link B prime. B has inline ancestor A. The CRDT layer merges B and B prime when both arrive. Separate Helia blocks are addressed by CIDs and contain encrypted changes but no graph links, separate writer signatures, or per-block ACL decisions.',
    body,
  });
}

function storedPayload() {
  const body = `
    ${text(50, 148, 'OPAQUE BYTES STORED IN HELIA', 'eyebrow', { fill: '#a5b4fc' })}
    <g filter="url(#shadow)">
      ${card(70, 174, 720, 372, { fill: '#151d35', stroke: '#818cf8', strokeWidth: 2.5, radius: 24 })}
    </g>
    ${text(100, 211, 'Complete stored byte frame', 'card-title')}
    <line x1="100" y1="230" x2="760" y2="230" stroke="#475569"/>

    ${card(100, 254, 660, 63, { fill: '#1e293b', stroke: '#475569' })}
    ${text(126, 292, 'document-key ID', 'body-strong')}
    ${text(620, 292, 'framing field', 'body', { anchor: 'end' })}
    ${card(100, 334, 660, 74, { fill: '#1e293b', stroke: '#475569' })}
    ${text(126, 365, 'mode-specific encryption parameters', 'body-strong')}
    ${text(126, 390, 'nonce / IV / counter, according to the configured provider', 'body')}
    ${card(100, 425, 660, 91, { fill: '#123038', stroke: '#14b8a6' })}
    ${text(126, 458, 'encrypted change bytes', 'body-strong')}
    ${text(126, 486, 'ciphertext of the serialized CRDT change', 'body')}

    ${arrow('M790 360H854', { stroke: '#2dd4bf', marker: 'arrowTeal', width: 4 })}
    ${card(862, 276, 288, 168, { fill: '#0f2b2e', stroke: '#2dd4bf', strokeWidth: 2.5, radius: 24 })}
    ${text(1006, 316, 'CID', 'card-title', { anchor: 'middle', fill: '#99f6e4' })}
    ${text(1006, 347, 'content address of the', 'body', { anchor: 'middle' })}
    ${text(1006, 371, 'complete byte frame', 'body', { anchor: 'middle' })}
    ${pill(894, 390, 224, 'OUTSIDE THE FRAME', {
      fill: '#123a3d',
      stroke: '#2dd4bf',
      text: '#99f6e4',
    })}

    ${card(50, 582, 1100, 86, { fill: '#301f2c', stroke: '#f472b6', strokeWidth: 2 })}
    ${text(76, 615, 'NOT STORED IN THIS FRAME', 'eyebrow', { fill: '#f9a8d4' })}
    ${text(76, 646, 'parent links · shadow-tree topology · separate writer signature · per-block ACL decision', 'body-strong')}

    ${text(600, 709, 'Helia validates fetched ciphertext against the requested CID before Peerborne decrypts and deserializes it.', 'body', { anchor: 'middle' })}`;

  return diagramFrame({
    id: 'stored-payload',
    height: 745,
    title: 'CID-addressed stored change payload',
    subtitle: 'The CID addresses the complete encrypted byte frame; it is not a field inside that frame.',
    description:
      'A stored Helia byte frame contains a document-key ID, mode-specific encryption parameters such as a nonce, IV, or counter, and encrypted serialized CRDT change bytes. The CID is shown outside the frame as its content address. Parent links, shadow-tree topology, a separate writer signature, and a per-block ACL decision are not stored in the payload.',
    body,
  });
}

function localIndexPipeline() {
  const body = `
    ${pill(886, 51, 264, 'LOCAL PROJECTION ONLY', {
      fill: '#0f2b2e',
      stroke: '#2dd4bf',
      text: '#99f6e4',
    })}

    ${card(180, 137, 840, 72, { fill: '#123038', stroke: '#14b8a6', strokeWidth: 2 })}
    ${text(600, 168, 'Authorized, decrypted CRDT snapshot', 'card-title', { anchor: 'middle' })}
    ${text(600, 193, 'Source state already available to the local application', 'body', { anchor: 'middle' })}
    ${arrow('M600 209V239', { stroke: '#2dd4bf', marker: 'arrowTeal' })}

    ${card(180, 247, 840, 94, { fill: '#18213c', stroke: '#818cf8', strokeWidth: 2 })}
    ${text(600, 280, 'IndexManager validation and normalization', 'card-title', { anchor: 'middle' })}
    ${text(600, 308, 'Schema generation · field types · invalid-value policy · storage policy', 'body', { anchor: 'middle' })}
    ${text(600, 330, 'Malformed values fail or skip according to the index definition; values stay out of diagnostics.', 'body', { anchor: 'middle' })}

    ${arrow('M600 341V374H280V392')}
    ${arrow('M600 341V374H920V392')}
    ${card(80, 400, 400, 112, { fill: '#151f35', stroke: '#6366f1', strokeWidth: 2 })}
    ${text(280, 436, 'Named compound physical keys', 'card-title', { anchor: 'middle' })}
    ${lines(280, 464, ['Leading equality fields, then one range or prefix', 'Required fields only for physical keys'], {
      anchor: 'middle',
      lineHeight: 23,
    })}
    ${card(720, 400, 400, 112, { fill: '#151f35', stroke: '#6366f1', strokeWidth: 2 })}
    ${text(920, 436, 'Stored indexed fields', 'card-title', { anchor: 'middle' })}
    ${lines(920, 464, ['Local projection for predicate rechecks and output', 'Memory by default; cleartext persistence is explicit'], {
      anchor: 'middle',
      lineHeight: 23,
    })}

    ${arrow('M280 512V550H455V568')}
    ${arrow('M920 512V550H745V568')}
    ${card(220, 576, 760, 86, { fill: '#111f34', stroke: '#475569', strokeWidth: 2 })}
    ${text(600, 610, 'Query planner', 'card-title', { anchor: 'middle' })}
    ${text(600, 638, 'Select a physical key or require an explicit full scan; record residual predicates.', 'body', { anchor: 'middle' })}
    ${arrow('M600 662V694')}

    ${card(220, 702, 760, 72, { fill: '#123038', stroke: '#14b8a6', strokeWidth: 2 })}
    ${text(600, 733, 'Candidate range, union, or approved full scan', 'card-title', { anchor: 'middle' })}
    ${text(600, 758, 'Physical lookup narrows work; it never decides the final result by itself.', 'body', { anchor: 'middle' })}
    ${arrow('M600 774V806', { stroke: '#2dd4bf', marker: 'arrowTeal' })}

    ${card(80, 814, 1040, 84, { fill: '#0f2b2e', stroke: '#2dd4bf', strokeWidth: 2 })}
    ${text(600, 847, 'Full predicate recheck', 'card-title', { anchor: 'middle' })}
    ${text(600, 875, 'Then deterministic sort, cursor validation, count, and projection for the bounded local result.', 'body', { anchor: 'middle' })}`;

  return diagramFrame({
    id: 'local-index-pipeline',
    height: 930,
    title: 'Local indexing pipeline',
    subtitle: 'Indexes are rebuildable materialized projections of authorized, decrypted local document state.',
    description:
      'A local authorized and decrypted CRDT snapshot enters IndexManager validation and normalization. The manager derives named compound physical keys and stored indexed fields. The query planner chooses a physical key or an explicitly approved full scan, reads a candidate range or union, rechecks the complete predicate, and then performs deterministic sorting, cursor handling, counting, and projection. Physical lookup narrows local work but does not independently decide results. Memory storage is the default and cleartext local persistence requires an explicit choice.',
    body,
  });
}

function distributedIndexFlow() {
  const body = `
    ${pill(796, 51, 354, 'PROTOCOL + ORCHESTRATION PRIMITIVES', {
      fill: '#3b2b13',
      stroke: '#f59e0b',
      text: '#fde68a',
    })}

    ${card(150, 137, 900, 92, { fill: '#18213c', stroke: '#818cf8', strokeWidth: 2 })}
    ${text(600, 172, 'Signed collection manifest', 'card-title', { anchor: 'middle' })}
    ${text(600, 199, 'Schema hash · generation · search-key epoch · discovery mode · TTL · response budget', 'body', { anchor: 'middle' })}
    ${text(600, 221, 'Manager signature and monotonic sequence are validated.', 'body', { anchor: 'middle' })}

    ${arrow('M600 229V262H300V280')}
    ${arrow('M600 229V262H900V280')}
    ${card(70, 288, 460, 138, { fill: '#123038', stroke: '#14b8a6', strokeWidth: 2 })}
    ${text(300, 325, 'Signed, expiring Bloom snapshot', 'card-title', { anchor: 'middle' })}
    ${lines(300, 354, ['Blind equality-routing tokens only', 'A positive match nominates a peer; it proves nothing', 'about a document or the completeness of the result set.'], {
      anchor: 'middle',
      lineHeight: 24,
    })}
    ${card(670, 288, 460, 138, { fill: '#151f35', stroke: '#6366f1', strokeWidth: 2 })}
    ${text(900, 325, 'Signed, bounded direct request', 'card-title', { anchor: 'middle' })}
    ${lines(900, 354, ['Blind tokens or an explicitly disclosed query AST', 'Responses remain size-, time-, and count-bounded', 'and can omit, fabricate, or reorder candidates.'], {
      anchor: 'middle',
      lineHeight: 24,
    })}

    ${arrow('M300 426V461H455V479', { stroke: '#2dd4bf', marker: 'arrowTeal' })}
    ${arrow('M900 426V461H745V479')}
    ${card(190, 487, 820, 86, { fill: '#2d2518', stroke: '#f59e0b', strokeWidth: 2 })}
    ${text(600, 520, 'Untrusted candidate peer / document-path claims', 'card-title', { anchor: 'middle' })}
    ${text(600, 548, 'Signatures attribute the claimant; they do not make a claim true or complete.', 'body', { anchor: 'middle' })}
    ${arrow('M600 573V605')}

    ${card(190, 613, 820, 92, { fill: '#111f34', stroke: '#475569', strokeWidth: 2 })}
    ${text(600, 647, 'Normal secure document load', 'card-title', { anchor: 'middle' })}
    ${text(600, 675, 'Apply configured quorum/CID gates, authorization, signatures, decryption, and history validation.', 'body', { anchor: 'middle' })}
    ${text(600, 697, 'A collection search key never grants document read access.', 'body', { anchor: 'middle' })}
    ${arrow('M600 705V737')}

    ${card(190, 745, 820, 74, { fill: '#123038', stroke: '#14b8a6', strokeWidth: 2 })}
    ${text(600, 777, 'Complete predicate recheck on authorized local state', 'card-title', { anchor: 'middle' })}
    ${text(600, 802, 'Only this local evaluation can admit the loaded document to the result page.', 'body', { anchor: 'middle' })}
    ${arrow('M600 819V851', { stroke: '#2dd4bf', marker: 'arrowTeal' })}

    ${card(190, 859, 820, 70, { fill: '#151f35', stroke: '#6366f1', strokeWidth: 2 })}
    ${text(600, 890, 'Deterministic bounded page merge', 'card-title', { anchor: 'middle' })}
    ${text(600, 915, 'No global completeness or exact-count guarantee in an open Byzantine network.', 'body', { anchor: 'middle' })}

    ${card(50, 957, 1100, 66, { fill: '#301f2c', stroke: '#f472b6', strokeWidth: 2 })}
    ${text(600, 984, 'EVIDENCE BOUNDARY', 'eyebrow', { anchor: 'middle', fill: '#f9a8d4' })}
    ${text(600, 1008, 'These are composable protocol and manager primitives—not a shipped turnkey end-to-end distributed search workflow.', 'body-strong', { anchor: 'middle' })}`;

  return diagramFrame({
    id: 'distributed-index-flow',
    height: 1055,
    title: 'Distributed indexing trust flow',
    subtitle: 'Remote discovery nominates untrusted candidates; normal document security and a full local recheck remain authoritative.',
    description:
      'A signed collection manifest controls schema generation, search-key epoch, discovery mode, expiration, and response budgets. Peers can use signed expiring Bloom snapshots with blind routing tokens or signed bounded direct requests. Both paths yield untrusted peer and document-path claims. A requester must load each candidate through normal authorization, signature, decryption, history, and configured quorum or CID gates, then recheck the complete predicate locally before a deterministic bounded merge. Distributed completeness and exact global counts are not guaranteed. The diagram describes composable protocol and orchestration primitives, not a shipped turnkey end-to-end distributed search workflow.',
    body,
  });
}

function relayDataFlow() {
  const body = `
    ${pill(892, 51, 258, 'ENCRYPTED APP TRAFFIC', {
      fill: '#0f2b2e',
      stroke: '#2dd4bf',
      text: '#99f6e4',
    })}

    ${card(50, 250, 260, 142, { fill: '#18213c', stroke: '#818cf8', strokeWidth: 2 })}
    ${text(180, 292, 'Browser A', 'card-title', { anchor: 'middle' })}
    ${text(180, 322, 'libp2p client', 'body-strong', { anchor: 'middle' })}
    ${text(180, 349, 'behind NAT / firewall', 'body', { anchor: 'middle' })}
    ${pill(93, 366, 174, 'DOCUMENT PEER', {
      fill: '#172554',
      stroke: '#6366f1',
      text: '#c7d2fe',
    })}

    <g filter="url(#shadow)">
      ${card(430, 216, 340, 210, { fill: '#123038', stroke: '#14b8a6', strokeWidth: 2.5, radius: 24 })}
    </g>
    ${text(600, 260, 'Relay server', 'card-title', { anchor: 'middle', fill: '#99f6e4' })}
    ${lines(600, 294, ['Bootstrap + identify', 'Circuit Relay v2 forwarding', 'GossipSub peer discovery'], {
      anchor: 'middle',
      className: 'body-strong',
      lineHeight: 27,
    })}
    ${pill(494, 377, 212, 'NO DOCUMENT KEY', {
      fill: '#0f3b3b',
      stroke: '#2dd4bf',
      text: '#99f6e4',
    })}

    ${card(890, 250, 260, 142, { fill: '#18213c', stroke: '#818cf8', strokeWidth: 2 })}
    ${text(1020, 292, 'Browser B', 'card-title', { anchor: 'middle' })}
    ${text(1020, 322, 'libp2p client', 'body-strong', { anchor: 'middle' })}
    ${text(1020, 349, 'behind NAT / firewall', 'body', { anchor: 'middle' })}
    ${pill(933, 366, 174, 'DOCUMENT PEER', {
      fill: '#172554',
      stroke: '#6366f1',
      text: '#c7d2fe',
    })}

    <path d="M310 321H422" fill="none" stroke="#2dd4bf" stroke-width="4" marker-start="url(#arrowTeal)" marker-end="url(#arrowTeal)"/>
    <path d="M778 321H890" fill="none" stroke="#2dd4bf" stroke-width="4" marker-start="url(#arrowTeal)" marker-end="url(#arrowTeal)"/>
    ${text(366, 302, 'WebSocket', 'body-strong', { anchor: 'middle', fill: '#99f6e4' })}
    ${text(834, 302, 'WebSocket', 'body-strong', { anchor: 'middle', fill: '#99f6e4' })}
    ${text(600, 463, 'Circuit Relay v2 carries the live libp2p connection when a direct path is unavailable.', 'body', { anchor: 'middle' })}

    <path d="M180 240C350 116 850 116 1020 240" fill="none" stroke="#a78bfa" stroke-width="3" stroke-dasharray="10 8" marker-end="url(#arrowIndigo)"/>
    ${pill(419, 137, 362, 'OPTIONAL DIRECT WEBRTC UPGRADE', {
      fill: '#302441',
      stroke: '#a78bfa',
      text: '#ddd6fe',
    })}

    ${card(50, 510, 1100, 92, { fill: '#111d2e', stroke: '#475569', strokeWidth: 2 })}
    ${text(76, 544, 'PATH SEMANTICS', 'eyebrow', { fill: '#93c5fd' })}
    ${text(245, 544, 'The relay forwards encrypted Peerborne traffic and does not need document plaintext or signing private keys.', 'body-strong')}
    ${text(76, 576, 'If ICE establishes a direct WebRTC connection, libp2p can remove the relay from the data path; that upgrade is not guaranteed.', 'body')}`;

  return diagramFrame({
    id: 'relay-data-flow',
    height: 635,
    title: 'Browser data flow through Circuit Relay',
    subtitle: 'A reachable relay provides a cross-NAT path; a direct WebRTC upgrade may replace it when network conditions allow.',
    description:
      'Browser A and Browser B connect to a relay server over WebSocket. Circuit Relay version 2 forwards their encrypted Peerborne traffic when a direct path is unavailable. The relay also provides bootstrap identify and GossipSub peer discovery, but it does not need document keys, document plaintext, or signing private keys. A dashed optional path shows that libp2p may upgrade to direct WebRTC after ICE succeeds; this upgrade is not guaranteed.',
    body,
  });
}

function singleRelayTopology() {
  const body = `
    ${pill(881, 51, 269, 'DEVELOPMENT / LIMITED TRIAL', {
      fill: '#3b2b13',
      stroke: '#f59e0b',
      text: '#fde68a',
    })}

    ${card(50, 145, 245, 106, { fill: '#151f35', stroke: '#6366f1', strokeWidth: 2 })}
    ${text(172.5, 181, 'DNS + TLS', 'card-title', { anchor: 'middle' })}
    ${text(172.5, 210, 'relay.example.com', 'body-strong', { anchor: 'middle' })}
    ${text(172.5, 234, 'HTTPS origin requires WSS', 'body', { anchor: 'middle' })}
    ${arrow('M295 198H402')}

    <g filter="url(#shadow)">
      ${card(410, 132, 380, 248, { fill: '#123038', stroke: '#14b8a6', strokeWidth: 2.5, radius: 24 })}
    </g>
    ${text(600, 172, 'One relay / bootstrap process', 'card-title', { anchor: 'middle', fill: '#99f6e4' })}
    ${lines(600, 207, ['Bootstrap + identify', 'Circuit Relay v2', 'GossipSub peer discovery'], {
      anchor: 'middle',
      className: 'body-strong',
      lineHeight: 28,
    })}
    ${card(453, 300, 294, 52, { fill: '#0f2b2e', stroke: '#2dd4bf' })}
    ${text(600, 322, '9001 WebSocket · 9002 TCP', 'body-strong', { anchor: 'middle' })}
    ${text(600, 342, 'often 443/WSS through a reverse proxy', 'body', { anchor: 'middle' })}

    ${card(905, 145, 245, 106, { fill: '#302441', stroke: '#a78bfa', strokeWidth: 2 })}
    ${text(1027.5, 181, 'Public STUN', 'card-title', { anchor: 'middle' })}
    ${text(1027.5, 210, 'ICE candidate gathering', 'body-strong', { anchor: 'middle' })}
    ${text(1027.5, 234, 'for optional direct WebRTC', 'body', { anchor: 'middle' })}

    ${card(80, 510, 260, 112, { fill: '#18213c', stroke: '#818cf8', strokeWidth: 2 })}
    ${text(210, 552, 'Browser A', 'card-title', { anchor: 'middle' })}
    ${text(210, 583, 'configured relay multiaddr', 'body', { anchor: 'middle' })}
    ${pill(125, 590, 170, 'WSS CLIENT', {
      fill: '#172554',
      stroke: '#6366f1',
      text: '#c7d2fe',
    })}
    ${card(470, 510, 260, 112, { fill: '#18213c', stroke: '#818cf8', strokeWidth: 2 })}
    ${text(600, 552, 'Browser B', 'card-title', { anchor: 'middle' })}
    ${text(600, 583, 'configured relay multiaddr', 'body', { anchor: 'middle' })}
    ${pill(515, 590, 170, 'WSS CLIENT', {
      fill: '#172554',
      stroke: '#6366f1',
      text: '#c7d2fe',
    })}
    ${card(860, 510, 260, 112, { fill: '#18213c', stroke: '#818cf8', strokeWidth: 2 })}
    ${text(990, 552, 'Browser C', 'card-title', { anchor: 'middle' })}
    ${text(990, 583, 'configured relay multiaddr', 'body', { anchor: 'middle' })}
    ${pill(905, 590, 170, 'WSS CLIENT', {
      fill: '#172554',
      stroke: '#6366f1',
      text: '#c7d2fe',
    })}

    ${arrow('M520 380V432H210V502', { stroke: '#2dd4bf', marker: 'arrowTeal' })}
    ${arrow('M600 380V502', { stroke: '#2dd4bf', marker: 'arrowTeal' })}
    ${arrow('M680 380V432H990V502', { stroke: '#2dd4bf', marker: 'arrowTeal' })}
    <path d="M1027 251V446H990V502" fill="none" stroke="#a78bfa" stroke-width="2.5" stroke-dasharray="9 7" marker-end="url(#arrowIndigo)"/>
    <path d="M990 446H600V502" fill="none" stroke="#a78bfa" stroke-width="2.5" stroke-dasharray="9 7" marker-end="url(#arrowIndigo)"/>
    <path d="M600 446H210V502" fill="none" stroke="#a78bfa" stroke-width="2.5" stroke-dasharray="9 7" marker-end="url(#arrowIndigo)"/>

    ${card(50, 672, 1100, 112, { fill: '#301f2c', stroke: '#f472b6', strokeWidth: 2 })}
    ${text(76, 707, 'SINGLE POINT OF COORDINATION', 'eyebrow', { fill: '#f9a8d4' })}
    ${text(76, 739, 'If this process or host is unreachable, new peers lose the configured bootstrap and relay path.', 'body-strong')}
    ${text(76, 766, 'This topology has no high-availability or concurrent-peer guarantee and does not provide durable document storage.', 'body')}`;

  return diagramFrame({
    id: 'single-relay-topology',
    height: 820,
    title: 'Minimal single-relay topology',
    subtitle: 'One reachable process combines bootstrap discovery, Circuit Relay v2, and GossipSub peer discovery.',
    description:
      'A DNS name and TLS endpoint lead to one relay and bootstrap process. It exposes WebSocket service, commonly behind a port 443 WSS reverse proxy, and a TCP listener for node-to-node connections. Three browsers use a configured relay multiaddress; dashed connections to public STUN represent optional WebRTC ICE candidate gathering. The relay is a single point of coordination, has no high-availability or concurrent-peer guarantee, and does not provide durable document storage.',
    body,
  });
}

function multiRelayTopology() {
  const relay = (x, label, hostname, region) => `${card(x, 170, 300, 174, {
    fill: '#123038',
    stroke: '#14b8a6',
    strokeWidth: 2,
  })}
    ${text(x + 150, 208, label, 'card-title', { anchor: 'middle' })}
    ${text(x + 150, 238, hostname, 'body-strong', { anchor: 'middle' })}
    ${text(x + 150, 266, region, 'body', { anchor: 'middle' })}
    ${text(x + 150, 294, 'WSS for browsers · TCP for relay peers', 'body', { anchor: 'middle' })}
    ${pill(x + 57, 307, 186, 'OWN DNS + TLS', {
      fill: '#0f3b3b',
      stroke: '#2dd4bf',
      text: '#99f6e4',
    })}`;
  const client = (x, label, choice) => `${card(x, 400, 300, 112, {
    fill: '#18213c',
    stroke: '#818cf8',
    strokeWidth: 2,
  })}
    ${text(x + 150, 440, label, 'card-title', { anchor: 'middle' })}
    ${text(x + 150, 470, choice, 'body', { anchor: 'middle' })}
    ${text(x + 150, 494, 'from application configuration', 'body', { anchor: 'middle' })}`;

  const body = `
    ${pill(844, 51, 306, 'NO BUILT-IN MESH OR FAILOVER', {
      fill: '#3b2b13',
      stroke: '#f59e0b',
      text: '#fde68a',
    })}
    ${text(50, 142, 'INDEPENDENT RELAY ENDPOINTS', 'eyebrow', { fill: '#5eead4' })}
    ${relay(50, 'Relay US', 'relay-us.example.com', 'US region')}
    ${relay(450, 'Relay EU', 'relay-eu.example.com', 'EU region')}
    ${relay(850, 'Relay AP', 'relay-ap.example.com', 'Asia-Pacific region')}

    ${card(50, 548, 1100, 102, { fill: '#2d2518', stroke: '#f59e0b', strokeWidth: 2 })}
    ${text(76, 582, 'INDEPENDENT PROCESSES', 'eyebrow', { fill: '#fde68a' })}
    ${text(76, 614, 'Peerborne does not ship relay-to-relay startup dialing, a supported TCP mesh, shared discovery, or client failover.', 'body-strong')}
    ${text(76, 639, 'Any routing or peering across these processes is custom deployment code that must be implemented and verified.', 'body')}

    ${client(50, 'Browser A', 'chooses Relay US')}
    ${client(450, 'Browser B', 'chooses Relay EU')}
    ${client(850, 'Browser C', 'chooses Relay AP')}

    ${arrow('M200 392V352', { stroke: '#2dd4bf', marker: 'arrowTeal' })}
    ${arrow('M600 392V352', { stroke: '#2dd4bf', marker: 'arrowTeal' })}
    ${arrow('M1000 392V352', { stroke: '#2dd4bf', marker: 'arrowTeal' })}

    ${card(50, 730, 1100, 132, { fill: '#301f2c', stroke: '#f472b6', strokeWidth: 2 })}
    ${text(76, 767, 'WHAT MULTIPLE RELAYS DO NOT AUTOMATE', 'eyebrow', { fill: '#f9a8d4' })}
    ${text(76, 799, 'Clients do not discover a global relay pool or fail over automatically; applications supply explicit relay multiaddresses.', 'body-strong')}
    ${text(76, 826, 'Each relay forwards traffic only for its own established connections. Relays do not provide durable document storage.', 'body')}
    ${text(76, 850, 'Durability requires separate, application-specific publication, persistence, and recovery integration.', 'body')}

    ${card(50, 890, 1100, 66, { fill: '#111d2e', stroke: '#475569', strokeWidth: 2 })}
    ${text(600, 917, 'DEPLOYMENT BOUNDARY', 'eyebrow', { anchor: 'middle', fill: '#93c5fd' })}
    ${text(600, 941, 'Multiple processes become a high-availability design only after custom routing, connection policy, and failover are implemented and tested.', 'body', { anchor: 'middle' })}`;

  return diagramFrame({
    id: 'multi-relay-topology',
    height: 990,
    title: 'Multi-relay deployment boundary',
    subtitle: 'Each relay has its own DNS and TLS endpoint; Peerborne does not provide a mesh or automatic failover between them.',
    description:
      'Three independent relay processes use separate DNS names: relay-us, relay-eu, and relay-ap. Each provides WSS for configured browser clients and a TCP listener, but Peerborne does not ship relay-to-relay startup dialing, a supported mesh, shared relay discovery, or automatic client failover. Browser A is configured for the US relay, Browser B for the EU relay, and Browser C for the AP relay. Each process forwards traffic only for its own established connections and does not provide durable document storage. High availability, routing, peering, and durability require application-specific integration and verification.',
    body,
  });
}

function historyCompaction() {
  const changeNode = (x, y, label, options = {}) => `${card(x, y, options.width ?? 158, 66, {
    fill: options.root ? '#123038' : '#18213c',
    stroke: options.root ? '#14b8a6' : '#6366f1',
    strokeWidth: options.root ? 2.5 : 2,
  })}
    ${text(x + (options.width ?? 158) / 2, y + 40, label, 'body-strong', { anchor: 'middle' })}`;
  const body = `
    ${pill(865, 51, 285, 'SNAPSHOT STORED SEPARATELY', {
      fill: '#0f2b2e',
      stroke: '#2dd4bf',
      text: '#99f6e4',
    })}

    ${text(50, 146, 'BEFORE COMPACTION', 'eyebrow', { fill: '#a5b4fc' })}
    ${card(50, 167, 1100, 145, { fill: '#111f34', stroke: '#475569', strokeWidth: 2 })}
    ${changeNode(82, 208, 'change 1')}
    ${changeNode(282, 208, 'change 2')}
    ${text(490, 249, '…', 'card-title', { anchor: 'middle' })}
    ${changeNode(552, 208, '…')}
    ${changeNode(752, 208, 'change 499')}
    ${changeNode(952, 208, 'change 500', { root: true, width: 166 })}
    ${arrow('M282 241H248')}
    ${arrow('M552 241H518')}
    ${arrow('M752 241H718')}
    ${arrow('M952 241H918')}
    ${text(1035, 294, 'current root', 'body', { anchor: 'middle', fill: '#99f6e4' })}

    ${text(50, 363, 'AFTER COMPACTION', 'eyebrow', { fill: '#5eead4' })}
    ${card(50, 386, 475, 242, { fill: '#123038', stroke: '#14b8a6', strokeWidth: 2.5 })}
    ${text(287.5, 426, 'Latest snapshot record', 'card-title', { anchor: 'middle' })}
    ${lines(82, 464, ['Serialized full CRDT state', 'lastChangeNodeCID = change 500', 'compactedCount + timestamp', 'writer signature when signing is enabled'], {
      className: 'body-strong',
      lineHeight: 27,
    })}
    ${pill(82, 576, 411, 'LOAD / SNAPSHOT-LOAD RESPONSES', {
      fill: '#0f3b3b',
      stroke: '#2dd4bf',
      text: '#99f6e4',
    })}

    ${card(575, 386, 575, 242, { fill: '#151f35', stroke: '#6366f1', strokeWidth: 2.5 })}
    ${text(862.5, 426, 'Retained sync tree after prune', 'card-title', { anchor: 'middle' })}
    ${changeNode(600, 476, 'kept tail', { width: 105 })}
    ${changeNode(733, 476, '…', { width: 55 })}
    ${changeNode(816, 476, 'change 499', { width: 110 })}
    ${changeNode(954, 476, '500 · boundary/root', { root: true, width: 170 })}
    ${arrow('M733 509H713')}
    ${arrow('M816 509H796')}
    ${arrow('M954 509H934')}
    ${lines(862.5, 559, ['The recent tail includes the boundary and earlier nodes.', 'Later changes append as new roots; ACL leaves may also remain.'], {
      anchor: 'middle',
      lineHeight: 22,
    })}
    ${pill(676, 598, 373, 'CURRENT IN-MEMORY TREE AFTER PRUNE', {
      fill: '#172554',
      stroke: '#6366f1',
      text: '#c7d2fe',
    })}

    ${card(50, 662, 1100, 110, { fill: '#301f2c', stroke: '#f472b6', strokeWidth: 2 })}
    ${text(76, 696, 'BOUNDARY, NOT AN INLINE CHANGE LINK', 'eyebrow', { fill: '#f9a8d4' })}
    ${text(76, 728, 'The snapshot carries change 500’s CID as metadata; the snapshot itself is not linked into the sync tree as a change node.', 'body-strong')}
    ${text(76, 751, 'Pruning the in-memory tree does not delete old Helia blocks unless optional post-prune garbage collection is enabled.', 'body')}`;

  return diagramFrame({
    id: 'history-compaction',
    height: 806,
    title: 'History compaction and snapshot boundary',
    subtitle: 'A snapshot record is separate from a retained sync tree that can overlap the snapshotted history.',
    description:
      'Before compaction at change 500, a sync tree retains changes from change 1 through its current root at change 500. After compaction, a separate latest snapshot record contains serialized CRDT state, the boundary CID for change 500, a compacted count, timestamp, and a writer signature when signing is enabled. The retained in-memory sync tree keeps the boundary and a configurable recent tail of earlier nodes; later changes append to that retained tree and become new roots, and preserved ACL leaves can also remain. The snapshot itself is not an inline parent link. Snapshots are included in load or snapshot-load responses rather than ordinary incremental pubsub, and pruning the in-memory tree does not delete old Helia blocks unless optional garbage collection is enabled.',
    body,
  });
}

function syncEnvelopeLifecycle() {
  const body = `
    ${pill(930, 51, 220, 'TWO ARTIFACTS', {
      fill: '#0f2b2e',
      stroke: '#2dd4bf',
      text: '#99f6e4',
    })}

    ${text(50, 145, '1 · LOCAL STORED PAYLOAD', 'eyebrow', { fill: '#a5b4fc' })}
    ${card(50, 168, 230, 96, { fill: '#18213c', stroke: '#818cf8', strokeWidth: 2 })}
    ${text(165, 205, 'CRDT delta', 'card-title', { anchor: 'middle' })}
    ${text(165, 234, 'from CRDTProvider', 'body', { anchor: 'middle' })}
    ${card(340, 168, 250, 96, { fill: '#151f35', stroke: '#6366f1', strokeWidth: 2 })}
    ${text(465, 202, 'Serialize + encrypt', 'card-title', { anchor: 'middle' })}
    ${text(465, 230, 'with the document key', 'body', { anchor: 'middle' })}
    ${card(650, 148, 280, 136, { fill: '#123038', stroke: '#14b8a6', strokeWidth: 2.5 })}
    ${text(790, 186, 'Stored Helia payload', 'card-title', { anchor: 'middle' })}
    ${lines(790, 216, ['Encrypted serialized change', 'Unsigned at rest', 'No per-block ACL decision'], {
      anchor: 'middle',
      className: 'body-strong',
      lineHeight: 24,
    })}
    ${card(990, 168, 160, 96, { fill: '#0f2b2e', stroke: '#2dd4bf', strokeWidth: 2.5 })}
    ${text(1070, 205, 'CID', 'card-title', { anchor: 'middle', fill: '#99f6e4' })}
    ${text(1070, 234, 'content address', 'body', { anchor: 'middle' })}
    ${arrow('M280 216H332')}
    ${arrow('M590 216H642')}
    ${arrow('M930 216H982', { stroke: '#2dd4bf', marker: 'arrowTeal' })}

    ${text(50, 345, '2 · SEPARATE SYNC ENVELOPE', 'eyebrow', { fill: '#5eead4' })}
    ${card(50, 368, 250, 112, { fill: '#18213c', stroke: '#818cf8', strokeWidth: 2 })}
    ${text(175, 405, 'CRDTSyncMessage', 'card-title', { anchor: 'middle' })}
    ${lines(175, 434, ['Names the CID', 'May also carry inline history'], { anchor: 'middle', lineHeight: 24 })}
    ${card(350, 368, 250, 112, { fill: '#302441', stroke: '#a78bfa', strokeWidth: 2 })}
    ${text(475, 405, 'Sign when enabled', 'card-title', { anchor: 'middle' })}
    ${lines(475, 434, ['P-384 signature covers', 'the wire message'], { anchor: 'middle', lineHeight: 24 })}
    ${card(650, 368, 250, 112, { fill: '#123038', stroke: '#14b8a6', strokeWidth: 2 })}
    ${text(775, 405, 'Serialize + encrypt', 'card-title', { anchor: 'middle' })}
    ${lines(775, 434, ['Document-key encryption', 'protects the full envelope'], { anchor: 'middle', lineHeight: 24 })}
    ${card(950, 368, 200, 112, { fill: '#0f2b2e', stroke: '#2dd4bf', strokeWidth: 2 })}
    ${text(1050, 405, 'Publish', 'card-title', { anchor: 'middle', fill: '#99f6e4' })}
    ${lines(1050, 434, ['Encrypted envelope', 'on GossipSub'], { anchor: 'middle', lineHeight: 24 })}
    ${arrow('M300 424H342')}
    ${arrow('M600 424H642')}
    ${arrow('M900 424H942', { stroke: '#2dd4bf', marker: 'arrowTeal' })}

    ${text(50, 543, '3 · RECEIVER PROCESSING', 'eyebrow', { fill: '#fbbf24' })}
    ${card(50, 566, 235, 118, { fill: '#0f2b2e', stroke: '#2dd4bf', strokeWidth: 2 })}
    ${text(167.5, 605, 'Encrypted envelope', 'card-title', { anchor: 'middle' })}
    ${text(167.5, 636, 'received from GossipSub', 'body', { anchor: 'middle' })}
    ${card(325, 566, 235, 118, { fill: '#151f35', stroke: '#6366f1', strokeWidth: 2 })}
    ${text(442.5, 604, 'Decrypt + deserialize', 'card-title', { anchor: 'middle' })}
    ${lines(442.5, 635, ['Open the document-key frame', 'and recover the message'], { anchor: 'middle', lineHeight: 24 })}
    ${card(600, 566, 235, 118, { fill: '#302441', stroke: '#a78bfa', strokeWidth: 2 })}
    ${text(717.5, 604, 'Verify when required', 'card-title', { anchor: 'middle' })}
    ${lines(717.5, 635, ['Check a current writer', 'when signing is enabled'], { anchor: 'middle', lineHeight: 24 })}
    ${card(875, 566, 275, 118, { fill: '#18213c', stroke: '#818cf8', strokeWidth: 2 })}
    ${text(1012.5, 604, 'Apply inline / fetch CID', 'card-title', { anchor: 'middle' })}
    ${lines(1012.5, 635, ['Inline changes can apply now;', 'missing payloads use Helia'], { anchor: 'middle', lineHeight: 24 })}
    ${arrow('M285 625H317', { stroke: '#2dd4bf', marker: 'arrowTeal' })}
    ${arrow('M560 625H592')}
    ${arrow('M835 625H867')}

    ${arrow('M1012 684V736H265V758')}
    ${card(100, 766, 330, 112, { fill: '#111f34', stroke: '#475569', strokeWidth: 2 })}
    ${text(265, 804, 'Validate requested CID', 'card-title', { anchor: 'middle' })}
    ${lines(265, 835, ['Helia checks fetched bytes', 'against the content address'], { anchor: 'middle', lineHeight: 24 })}
    ${card(485, 766, 330, 112, { fill: '#123038', stroke: '#14b8a6', strokeWidth: 2 })}
    ${text(650, 804, 'Decrypt + deserialize block', 'card-title', { anchor: 'middle' })}
    ${lines(650, 835, ['Use the document key;', 'no separate block signature exists'], { anchor: 'middle', lineHeight: 24 })}
    ${card(870, 766, 280, 112, { fill: '#0f2b2e', stroke: '#2dd4bf', strokeWidth: 2 })}
    ${text(1010, 804, 'Apply CRDT change', 'card-title', { anchor: 'middle', fill: '#99f6e4' })}
    ${lines(1010, 835, ['Merge the validated,', 'decrypted provider delta'], { anchor: 'middle', lineHeight: 24 })}
    ${arrow('M430 822H477')}
    ${arrow('M815 822H862', { stroke: '#2dd4bf', marker: 'arrowTeal' })}

    ${card(50, 908, 1100, 102, { fill: '#301f2c', stroke: '#f472b6', strokeWidth: 2 })}
    ${text(76, 940, 'SIGNING BOUNDARY', 'eyebrow', { fill: '#f9a8d4' })}
    ${text(76, 968, 'The stored CID-addressed block remains unsigned; the wire-message signature is separate and conditional.', 'body-strong')}
    ${text(76, 994, 'Disabling ordinary signing leaves encryption in place but removes this writer-authentication gate for ordinary sync.', 'body')}`;

  return diagramFrame({
    id: 'sync-envelope-lifecycle',
    height: 1042,
    title: 'Stored payload and sync-envelope lifecycle',
    subtitle: 'A local change creates an unsigned encrypted stored block and a separate conditionally signed encrypted wire envelope.',
    description:
      'A CRDT delta is serialized and encrypted with the document key, stored in Helia without a block signature or per-block ACL decision, and content-addressed by a CID. A separate CRDT sync message names that CID and may carry inline history. When ordinary signing is enabled, Peerborne signs the wire message with P-384, then serializes and encrypts the full envelope before publishing it on GossipSub. A receiver decrypts and deserializes the envelope, verifies a current writer when required, applies inline changes or fetches missing CIDs, validates fetched bytes against the requested CID, decrypts and deserializes the unsigned stored block, and applies the CRDT delta.',
    body,
  });
}

export function diagramDefinitions() {
  return [
    ['package-dependencies.svg', packageDependencies],
    ['networking-stack.svg', networkingStack],
    ['encryption-identity.svg', encryptionIdentity],
    ['document-change-lifecycle.svg', changeLifecycle],
    ['shadow-sync-graph.svg', shadowSyncGraph],
    ['stored-change-payload.svg', storedPayload],
    ['local-index-pipeline.svg', localIndexPipeline],
    ['distributed-index-flow.svg', distributedIndexFlow],
    ['relay-data-flow.svg', relayDataFlow],
    ['single-relay-topology.svg', singleRelayTopology],
    ['multi-relay-topology.svg', multiRelayTopology],
    ['history-compaction.svg', historyCompaction],
    ['sync-envelope-lifecycle.svg', syncEnvelopeLifecycle],
  ];
}

export function generateDiagrams() {
  return new Map(
    diagramDefinitions().map(([filename, render]) => [filename, render()]),
  );
}

function run() {
  const diagrams = generateDiagrams();
  const checking = process.argv.includes('--check');
  if (!checking) mkdirSync(outputDirectory, { recursive: true });

  for (const [filename, svg] of diagrams) {
    const path = resolve(outputDirectory, filename);
    if (checking) {
      let current;
      try {
        current = readFileSync(path, 'utf8');
      } catch {
        throw new Error(`Missing generated documentation diagram: ${path}`);
      }
      if (current !== svg) {
        throw new Error(`Generated documentation diagram is stale: ${path}`);
      }
    } else {
      writeFileSync(path, svg);
    }
  }

  console.log(`${checking ? 'Verified' : 'Generated'} ${diagrams.size} documentation diagrams`);
}

if (resolve(process.argv[1] ?? '') === scriptPath) {
  run();
}
