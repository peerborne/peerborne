import { mkdtemp, mkdir, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import sharp from 'sharp';
import { syncStory } from '../src/lib/sync-story.ts';
import { pixelText } from './pixel-style.mjs';

const publicDir = fileURLToPath(new URL('../public/', import.meta.url));
const demoDir = join(publicDir, 'demo');
const check = process.argv.includes('--check');
if (check && process.argv.includes('--gif')) {
  throw new Error('Use --check for SVG verification or --gif for generation.');
}

async function writeSvg(path, content) {
  if (check) {
    if (await readFile(path, 'utf8') !== content) {
      throw new Error(`Generated sync asset is stale: ${path}`);
    }
  } else {
    await writeFile(path, content);
  }
}
const escape = (value) => String(value).replace(/[&<>"']/g, (char) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;',
})[char]);
const text = (x, y, value, size = 20, fill = '#f5f0e8', extra = '') =>
  `<text x="${x}" y="${y}" font-size="${size}" fill="${fill}" ${extra}>${escape(value)}</text>`;
const rect = (x, y, width, height, fill, extra = '') =>
  `<rect x="${x}" y="${y}" width="${width}" height="${height}" fill="${fill}" ${extra}/>`;

function renderFrame(frame, index) {
  const clients = ['a', 'b'].map((side, sideIndex) => {
    const x = sideIndex * 560;
    const connection = side === 'a' ? 'online' : frame.connection;
    const color = connection === 'offline' ? '#ffb887' : connection === 'syncing' ? '#d6c8ff' : '#a3efb8';
    const body = index === 3 ? '#382819' : index === 5 ? '#1b382a' : '#1b1929';
    const lines = JSON.stringify(frame[side], null, 2).split('\n');
    return `${rect(x, 60, 560, 364, body)}
      ${rect(x + 26, 79, 30, 30, side === 'a' ? '#30234c' : '#1b382a')}
      ${text(x + 35, 100, side.toUpperCase(), 18)}
      ${text(x + 70, 101, `Client ${side.toUpperCase()}`, 21, '#f5f0e8', 'font-weight="bold"')}
      ${text(x + 416, 101, connection === 'offline' ? '○ Offline' : connection === 'syncing' ? '↔ Syncing' : '● Online', 17, color)}
      ${rect(x, 126, 560, 34, '#242136')}
      ${text(x + 28, 149, 'workspace.ts', 16, '#a7a0b6')}
      ${text(x + 420, 149, 'local state', 13, '#a7a0b6')}
      ${lines.map((line, lineIndex) => text(x + 28, 190 + lineIndex * 23, line, 19, '#d6c8ff', 'xml:space="preserve"')).join('')}`;
  }).join('');

  return `<svg xmlns="http://www.w3.org/2000/svg" width="1120" height="660" viewBox="0 0 1120 660" role="img" aria-labelledby="title desc" shape-rendering="crispEdges">
    <title id="title">Peerborne: ${escape(frame.label)}</title>
    <desc id="desc">Scripted illustration of two local document replicas. No live transport, cryptography, or measured timing. The 124B and epoch frames are simulated.</desc>
    <g font-family="Menlo, Consolas, monospace">
      ${rect(0, 0, 1120, 660, '#1b1929')}
      ${[0, 1, 2].map((n) => `<rect x="${24 + n * 17}" y="25" width="8" height="8" fill="#a3efb8"/>`).join('')}
      ${text(94, 36, '/workspace/release', 18, '#a7a0b6')}
      ${text(920, 36, 'SIMULATION', 15, '#a7a0b6', 'letter-spacing="2"')}
      ${clients}
      <path d="M0 60H1120M560 60V424M0 424H1120" stroke="#756c89"/>
      ${rect(0, 425, 1120, 100, '#11101a')}
      ${text(28, 447, 'SIMULATED FRAMES · NO LIVE NETWORK', 12, '#a7a0b6', 'letter-spacing="1"')}
      ${frame.logs.map((line, logIndex) => text(28, 475 + logIndex * 25, line, 16, '#a3efb8')).join('')}
      ${text(28, 556, `${String(index + 1).padStart(2, '0')} / 06   ${frame.label}`, 21, '#f5f0e8', 'font-weight="bold"')}
      ${syncStory.map((step, stepIndex) => {
        const x = 28 + stepIndex * 182;
        const label = ['Start in sync', 'Edit on A', 'B goes offline', 'Both edit', 'Reconnect', 'Back in sync'][stepIndex];
        return `${rect(x, 581, 166, 3, stepIndex === index ? '#b7a1ff' : '#756c89')}
          ${text(x, 607, label, 14, stepIndex === index ? '#f5f0e8' : '#a7a0b6')}`;
      }).join('')}
      ${text(28, 643, 'Scripted UI · no measured timings · sample 124B / epoch frames · peerborne.io', 14, '#a7a0b6')}
    </g>
  </svg>`;
}

const finalIndex = syncStory.length - 1;
const finalFrame = renderFrame(syncStory[finalIndex], finalIndex);
if (!check) await mkdir(demoDir, { recursive: true });
await writeSvg(join(demoDir, 'sync-preview.svg'), `${finalFrame}\n`);

const social = `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630" role="img" aria-labelledby="title desc" shape-rendering="crispEdges">
  <title id="title">Peerborne — local-first TypeScript state with end-to-end encryption</title>
  <desc id="desc">TypeScript document state on two simulated clients. Alpha software, source workspaces only.</desc>
  ${rect(0, 0, 1200, 630, '#1b1929')}
  <g font-family="Menlo, Consolas, monospace">
    ${pixelText(52, 51, 'PEERBORNE', 3, '#b7a1ff')}
    ${text(1035, 72, 'ALPHA', 18, '#a7a0b6')}
    ${pixelText(52, 173, 'LOCAL-FIRST', 5, '#f5f0e8')}
    ${pixelText(52, 243, 'TYPESCRIPT STATE.', 4, '#f5f0e8')}
    ${text(52, 344, 'End-to-end encrypted.', 29, '#a3efb8')}
    ${text(52, 410, 'Your servers never see', 23, '#a7a0b6')}
    ${text(52, 443, 'document plaintext.', 23, '#a7a0b6')}
    <g transform="translate(588 167) scale(0.5)">${finalFrame.replace(/<\/?svg[^>]*>/g, '').replace(/<title[\s\S]*?<\/desc>/, '')}</g>
    <path d="M52 535H1148" stroke="#756c89"/>
    ${text(52, 583, 'Automerge / Yjs · React · libp2p', 20, '#a7a0b6')}
    ${text(824, 583, 'peerborne.io →', 25, '#d6c8ff')}
  </g>
</svg>`.replace(/[ \t]+$/gm, '');
await writeSvg(fileURLToPath(new URL('../src/assets/social-card.svg', import.meta.url)), `${social}\n`);
await writeSvg(join(publicDir, 'og-image.svg'), `${social}\n`);
if (!check) await sharp(Buffer.from(social)).png().toFile(join(publicDir, 'social-card.png'));

if (process.argv.includes('--gif')) {
  const frameDir = await mkdtemp(join(tmpdir(), 'peerborne-sync-'));
  try {
    const frames = [];
    for (const [index, frame] of syncStory.entries()) {
      const field = index === 1 ? 'title' : index === 3 ? 'status' : null;
      let typingDuration = 0;
      if (field) {
        const length = Math.max(frame.a[field].length, frame.b[field].length);
        for (let count = 1; count < length; count += 1) {
          frames.push({
            svg: renderFrame({
              ...frame,
              a: { ...frame.a, [field]: frame.a[field].slice(0, count) },
              b: { ...frame.b, [field]: frame.b[field].slice(0, count) },
            }, index),
            duration: 0.07,
          });
          typingDuration += 0.07;
        }
      }
      frames.push({ svg: renderFrame(frame, index), duration: frame.duration / 1000 - typingDuration });
    }
    const concat = [];
    for (const [index, frame] of frames.entries()) {
      const name = `frame-${index}.png`;
      await sharp(Buffer.from(frame.svg)).png().toFile(join(frameDir, name));
      concat.push(`file '${name}'`, `duration ${frame.duration.toFixed(3)}`);
    }
    concat.push(`file 'frame-${frames.length - 1}.png'`);
    const manifest = join(frameDir, 'frames.txt');
    await writeFile(manifest, `${concat.join('\n')}\n`);
    const result = spawnSync('ffmpeg', [
      '-hide_banner', '-loglevel', 'error', '-y',
      '-f', 'concat', '-safe', '0', '-i', manifest,
      '-filter_complex', 'fps=15,split[a][b];[a]palettegen=stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=3:diff_mode=rectangle',
      '-loop', '-1', join(demoDir, 'sync-preview.gif'),
    ], { stdio: 'inherit' });
    if (result.error) throw result.error;
    if (result.status !== 0) throw new Error(`ffmpeg exited with ${result.status}`);
  } finally {
    await rm(frameDir, { recursive: true, force: true });
  }
}
console.log(check
  ? 'Sync poster and social SVG assets match their generator.'
  : `Generated SVG poster, social card${process.argv.includes('--gif') ? ', and GIF' : ''}.`);
