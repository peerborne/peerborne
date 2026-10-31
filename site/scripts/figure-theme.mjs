import { pixelText } from './pixel-style.mjs';

export const figurePalette = {
  background: '#171521',
  surface: '#242136',
  border: '#756c89',
  grid: '#40394f',
  shadow: '#0c0b13',
  text: '#f5f0e8',
  body: '#cbc5d6',
  muted: '#a7a0b6',
  purple: '#b7a1ff',
  purpleLight: '#d6c8ff',
  purpleDark: '#30234c',
  green: '#a3efb8',
  greenLight: '#c7f5d3',
  greenDark: '#1b382a',
  orange: '#ffb887',
  orangeLight: '#ffd5b5',
  orangeDark: '#382819',
  pink: '#f0a5cf',
  pinkDark: '#382237',
};

const colorGroups = {
  background: '1b1929 0f172a 111827 0b1220 080d1a 090d1a 111936',
  surface: '0b1524 172033 111f34 142033 1e293b 111d2e 0f1b2e 121d30 101a2c 121f31 131b2c 101c2d 111c30 10172a 111b31 192332',
  border: '3a4860 475569 64748b',
  grid: '334155',
  shadow: '020617',
  text: 'f8fafc f0fdfa eef2ff',
  body: 'cbd5e1 e2e8f0',
  muted: '94a3b8',
  purple: '818cf8 6366f1 a5b4fc 8b5cf6 a78bfa 4f46e5 93c5fd 9aaacf',
  purpleLight: 'c7d2fe e0e7ff ddd6fe c4b5fd',
  purpleDark: '172554 18213c 151d35 151f35 151d35 151f35 16213a 1b2140 251b3b 32224e 271b42 1e1b4b 312e81 302441 171b35 17213a 202454 251f4b 24213f 25245c 16213b',
  green: '2dd4bf 14b8a6 5eead4',
  greenLight: '99f6e4',
  greenDark: '123038 0f2b2e 102a2a 0f3b3b 15343b 0f2f35 132e35 102a35 134e4a 123a3d 042f2e 0f3b3d 0f3539 0b2529 0f3f46 164e63 0f3638 10233a 10323a 102a43',
  orange: 'f59e0b fbbf24',
  orangeLight: 'fde68a',
  orangeDark: '3b2b13 2d2518 2b2112 422006 3b2613',
  pink: 'f472b6 f9a8d4 fbcfe8 fb7185 fecdd3 fda4af',
  pinkDark: '301f2c 301821 332742 31243b',
};
const colorMap = new Map(
  Object.entries(colorGroups).flatMap(([name, colors]) =>
    colors.split(' ').map((color) => [`#${color}`, figurePalette[name]]),
  ),
);
const themeColors = new Set(Object.values(figurePalette));
const mono = "'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace";

function attributes(source) {
  return Object.fromEntries(
    Array.from(source.matchAll(/([\w:-]+)\s*=\s*"([^"]*)"/g), (match) => [
      match[1],
      match[2],
    ]),
  );
}

function themedColor(color) {
  const normalized = color.toLowerCase();
  if (themeColors.has(normalized)) return normalized;
  const themed = colorMap.get(normalized);
  if (!themed) throw new Error(`Add a figure palette mapping for ${color}`);
  return themed;
}

function setAttribute(source, name, value) {
  const existing = new RegExp(`\\b${name}="[^"]*"`);
  return existing.test(source)
    ? source.replace(existing, `${name}="${value}"`)
    : `${source} ${name}="${value}"`;
}

function fontRules(svg) {
  const rules = new Map();
  for (const match of svg.matchAll(/\.([\w-]+)\s*\{([^}]+)\}/g)) {
    const size = /font-size:\s*([\d.]+)px/.exec(match[2]);
    const spacing = /letter-spacing:\s*([\d.]+)px/.exec(match[2]);
    const anchor = /text-anchor:\s*(\w+)/.exec(match[2]);
    rules.set(match[1], {
      size: Number(size?.[1]) || undefined,
      spacing: Number(spacing?.[1]) || 0,
      anchor: anchor?.[1],
    });
  }
  return rules;
}

function fitLabels(svg) {
  const rules = fontRules(svg);
  const rectangles = [];
  const labels = [];
  const stack = [{ x: 0, y: 0, scale: 1, size: 15, anchor: 'start' }];
  const containers = new Set(['svg', 'g', 'defs', 'marker', 'pattern', 'filter']);
  const definitions = new Set(['defs', 'marker', 'pattern', 'filter']);
  const tokens = /<\/?(?:svg|g|defs|marker|pattern|filter|text|rect)\b[^>]*>/g;
  for (const match of svg.matchAll(tokens)) {
    const tag = match[0];
    const closing = tag.startsWith('</');
    const name = /^<\/?(\w+)/.exec(tag)[1];
    if (closing) {
      if (containers.has(name)) stack.pop();
      continue;
    }
    const a = attributes(tag);
    const parent = stack[stack.length - 1];
    const rule = rules.get(a.class) ?? {};
    const translate = /translate\(\s*([\d.-]+)[ ,]+([\d.-]+)\s*\)/.exec(
      a.transform ?? '',
    );
    const scaling = /scale\(\s*([\d.]+)\s*\)/.exec(a.transform ?? '');
    const state = {
      x: parent.x + Number(translate?.[1] ?? 0) * parent.scale,
      y: parent.y + Number(translate?.[2] ?? 0) * parent.scale,
      scale: parent.scale * Number(scaling?.[1] ?? 1),
      size:
        Number(a['font-size']) ||
        Number(/font-size:\s*([\d.]+)/.exec(a.style ?? '')?.[1]) ||
        rule.size ||
        parent.size,
      anchor: a['text-anchor'] ?? rule.anchor ?? parent.anchor,
      skipped: parent.skipped || definitions.has(name),
    };
    if (containers.has(name) && !tag.endsWith('/>')) stack.push(state);
    if (state.skipped || a.transform?.includes('rotate')) continue;
    const x = state.x + Number(a.x ?? 0) * state.scale;
    const y = state.y + Number(a.y ?? 0) * state.scale;
    if (name === 'rect' && Number(a.width) >= 24 && Number(a.height) >= 18) {
      rectangles.push({
        index: match.index,
        x,
        y,
        width: Number(a.width) * state.scale,
        height: Number(a.height) * state.scale,
      });
    } else if (name === 'text') {
      const end = svg.indexOf('</text>', match.index);
      const value = svg.slice(match.index + tag.length, end).replace(/&[^;]+;/g, 'x');
      labels.push({
        ...state,
        index: match.index,
        tag,
        a,
        value,
        x,
        y,
        spacing: Number(a['letter-spacing']) || rule.spacing || 0,
      });
    }
  }
  for (const label of [...labels].reverse()) {
    const box = rectangles
      .filter(
        (r) =>
          r.index < label.index &&
          label.x >= r.x &&
          label.x <= r.x + r.width &&
          label.y > r.y &&
          label.y <= r.y + r.height,
      )
      .sort((a, b) => b.index - a.index)[0];
    if (!box || !label.value.trim()) continue;
    const padding = Math.min(16, Math.max(5, label.x - box.x));
    let available =
      label.anchor === 'middle'
        ? 2 * Math.min(label.x - box.x - 5, box.x + box.width - label.x - 5)
        : label.anchor === 'end'
          ? label.x - box.x - padding
          : box.x + box.width - label.x - padding;
    if (label.anchor === 'start') {
      const next = labels
        .filter(
          (other) =>
            other !== label &&
            Math.abs(other.y - label.y) < 5 &&
            other.x > label.x &&
            other.x < box.x + box.width,
        )
        .sort((a, b) => a.x - b.x)[0];
      if (next) available = Math.min(available, next.x - label.x - 10);
    }
    const natural =
      (label.value.length * label.size * 0.6 +
        Math.max(0, label.value.length - 1) * label.spacing) *
      label.scale;
    if (available > 0 && natural > available) {
      let tag = setAttribute(label.tag.slice(0, -1), 'x', '0');
      tag = setAttribute(tag, 'y', '0');
      tag = setAttribute(
        tag,
        'transform',
        `translate(${label.a.x ?? 0} ${label.a.y ?? 0}) scale(${(available / natural).toFixed(5)} 1)`,
      );
      svg =
        svg.slice(0, label.index) +
        `${tag}>` +
        svg.slice(label.index + label.tag.length);
    }
  }
  return svg;
}

export function pixelFigure(svg, { minimumFontSize = 0 } = {}) {
  const width = Number(/<svg[^>]*\bwidth="(\d+)"/.exec(svg)?.[1]);
  const gradients = new Map();
  svg = svg.replace(
    /<linearGradient\b([^>]*)>([\s\S]*?)<\/linearGradient>/g,
    (_match, a, body) => {
      const id = attributes(a).id;
      const color = /stop-color="(#[a-f\d]{6})"/i.exec(body)?.[1];
      gradients.set(
        id,
        id === 'background' ? figurePalette.background : themedColor(color),
      );
      return '';
    },
  );
  for (const [id, color] of gradients) svg = svg.replaceAll(`url(#${id})`, color);
  svg = svg.replace(/#[a-f\d]{6}\b/gi, themedColor);
  svg = svg.replace(
    /<filter\b([^>]*)>[\s\S]*?<\/filter>/g,
    (_match, a) =>
      `<filter ${a.trim()}><feDropShadow dx="4" dy="4" stdDeviation="0" flood-color="${figurePalette.shadow}" flood-opacity="1"/></filter>`,
  );
  svg = svg.replace(/\s+r[xy]="[\d.]+"/g, '');
  svg = svg.replace(/<circle\b([^>]*?)\s*\/>/g, (_match, source) => {
    const a = attributes(source);
    if (Number(a.r) > 100 && a.opacity && Number(a.opacity) < 0.1) return '';
    const extra = source.replace(/\b(?:cx|cy|r)="[^"]*"\s*/g, '').trim();
    return `<rect x="${Number(a.cx ?? 0) - Number(a.r)}" y="${Number(a.cy ?? 0) - Number(a.r)}" width="${2 * Number(a.r)}" height="${2 * Number(a.r)}" ${extra}/>`;
  });
  svg = svg
    .replace(/font-family:\s*[^;\n}]+/g, `font-family: ${mono}`)
    .replace(/font-family="[^"]*"/g, `font-family="${mono}"`)
    .replace(/stroke-linecap="round"/g, 'stroke-linecap="square"')
    .replace(/stroke-linejoin="round"/g, 'stroke-linejoin="miter"');
  svg = svg.replace(/<path\b[^>]*d="M0 (?:26|28)A[^>]+\/>/g, '');
  svg = svg
    .replace(
      /font-size:\s*([\d.]+)px/g,
      (_match, size) => `font-size: ${Math.max(Number(size), minimumFontSize)}px`,
    )
    .replace(
      /font-size="([\d.]+)"/g,
      (_match, size) => `font-size="${Math.max(Number(size), minimumFontSize)}"`,
    );
  const rules = fontRules(svg);
  svg = svg.replace(/<text\b([^>]*)>([^<]+)<\/text>/g, (original, source, value) => {
    const a = attributes(source);
    const size = Number(a['font-size']) || rules.get(a.class)?.size;
    if (!(size >= 29 && Number(a.y) <= 100 && value.trim().length > 3)) {
      return original;
    }
    const title = value.replaceAll('&amp;', '&').replace(/[–—]/g, '-');
    const x = Number(a.x);
    const scale = Math.min(3, (width - x - 40) / (title.length * 6));
    return `<g class="pixel-heading" aria-hidden="true">${pixelText(x, Number(a.y) - 7 * scale, title, scale, figurePalette.text)}</g>`;
  });
  svg = svg.replace(
    /(<marker\b[^>]*>)([\s\S]*?)(<\/marker>)/g,
    (_match, start, body, end) => {
      let marker = setAttribute(start.slice(0, -1), 'markerUnits', 'userSpaceOnUse');
      marker = setAttribute(marker, 'markerWidth', '16');
      marker = setAttribute(marker, 'markerHeight', '16');
      return (
        marker + '>' +
        body.replace(/\bd="[^"]*"/, 'd="M0 0H3V2H6V4H9V6H6V8H3V10H0Z"') +
        end
      );
    },
  );
  svg = svg.replace(
    '</svg>',
    `<path d="M0 0H${width}V8H0Z" fill="${figurePalette.green}"/>\n</svg>`,
  );
  return fitLabels(svg).replace(/[ \t]+$/gm, '');
}
