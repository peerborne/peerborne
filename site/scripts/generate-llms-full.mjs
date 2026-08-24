#!/usr/bin/env node

import {
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { dirname, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptPath = fileURLToPath(import.meta.url);
const root = resolve(dirname(scriptPath), '..', '..');
const docsRoot = resolve(root, 'site/src/content/docs');
const outputPath = resolve(root, 'site/dist/llms-full.txt');
const siteRoot = new URL('https://peerborne.io/');
const repositoryRoot = new URL('https://github.com/Peerborne/peerborne/');

function repositoryPath(path) {
  return relative(root, path).split(sep).join('/');
}

function pathIsInside(parent, path) {
  const child = relative(parent, path);
  return child !== '..' && !child.startsWith(`..${sep}`);
}

function collectMarkdown(directory) {
  const files = [];

  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) files.push(...collectMarkdown(path));
    else if (entry.isFile() && /\.mdx?$/.test(entry.name)) files.push(path);
  }

  return files;
}

function documentationOrder(path) {
  const relativePath = relative(docsRoot, path).split(sep).join('/');
  const sections = [
    'index.',
    'getting-started/',
    'concepts/',
    'cookbook/',
    'reference/',
    'community/',
  ];
  const section = sections.findIndex((prefix) =>
    relativePath.startsWith(prefix),
  );
  const rank = section === -1 ? sections.length : section;
  return `${String(rank).padStart(2, '0')}:${relativePath}`;
}

function splitFrontmatter(markdown) {
  const match = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?/.exec(markdown);
  if (!match) return { content: markdown, frontmatter: '' };
  return {
    content: markdown.slice(match[0].length),
    frontmatter: match[1],
  };
}

function unquote(value) {
  const trimmed = value.trim();
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function titleFor(path, frontmatter, content) {
  const frontmatterTitle = /^title:\s*(.+)$/m.exec(frontmatter)?.[1];
  if (frontmatterTitle) return unquote(frontmatterTitle);

  const heading = /^#\s+(.+)$/m.exec(content)?.[1];
  return heading?.trim() ?? repositoryPath(path);
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function protectFences(markdown, sourceName) {
  const output = [];
  const fences = [];
  let active;

  for (const [index, line] of markdown.split('\n').entries()) {
    if (!active) {
      const opening = /^([ \t]*)(`{3,}|~{3,})/.exec(line);
      if (!opening) {
        output.push(line);
        continue;
      }

      const token = `\0PEERBORNE_FENCE_${fences.length}\0`;
      if (markdown.includes(token)) {
        throw new Error(`${sourceName}: fence placeholder collision`);
      }
      active = {
        character: opening[2][0],
        indent: opening[1],
        length: opening[2].length,
        lines: [line],
        startLine: index + 1,
        token,
      };
      output.push(`${active.indent}${token}`);
      continue;
    }

    active.lines.push(line);
    const closing = /^([ \t]*)(`+|~+)\s*$/.exec(line);
    if (
      closing &&
      closing[2][0] === active.character &&
      closing[2].length >= active.length
    ) {
      fences.push(active);
      active = undefined;
    }
  }

  if (active) {
    throw new Error(
      `${sourceName}:${active.startLine}: unclosed ${active.character.repeat(active.length)} fence`,
    );
  }

  return { fences, markdown: output.join('\n') };
}

function restoreFences(markdown, fences, sourceName) {
  let restored = markdown;

  for (const fence of fences) {
    let replacements = 0;
    const placeholder = new RegExp(
      `^([ \\t]*)${escapeRegExp(fence.token)}[ \\t]*$`,
      'gm',
    );
    restored = restored.replace(placeholder, (_match, indent) => {
      replacements += 1;
      return fence.lines
        .map((line) => {
          if (!line) return '';
          const content = line.startsWith(fence.indent)
            ? line.slice(fence.indent.length)
            : line;
          return `${indent}${content}`;
        })
        .join('\n');
    });
    if (replacements !== 1) {
      throw new Error(`${sourceName}: lost fenced code placeholder`);
    }
  }

  if (restored.includes('\0PEERBORNE_FENCE_')) {
    throw new Error(`${sourceName}: unrestored fenced code placeholder`);
  }
  return restored;
}

export function mapOutsideFences(
  markdown,
  transform,
  sourceName = 'Markdown',
) {
  const protectedMarkdown = protectFences(markdown, sourceName);
  const transformed = transform(protectedMarkdown.markdown);
  return restoreFences(transformed, protectedMarkdown.fences, sourceName);
}

function attributeValue(attributes, name) {
  const match = new RegExp(
    `\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)')`,
  ).exec(attributes);
  return match?.[1] ?? match?.[2];
}

function dedent(markdown) {
  const lines = markdown.replace(/^\s*\n|\n\s*$/g, '').split('\n');
  const indents = lines
    .filter((line) => line.trim())
    .map((line) => /^ */.exec(line)?.[0].length ?? 0);
  const indent = indents.length > 0 ? Math.min(...indents) : 0;
  return lines.map((line) => line.slice(indent)).join('\n');
}

function removeMdxImports(markdown, sourceName) {
  const output = [];
  let importLine;

  for (const [index, line] of markdown.split('\n').entries()) {
    if (importLine === undefined && !/^\s*import\b/.test(line)) {
      output.push(line);
      continue;
    }
    if (importLine === undefined) importLine = index + 1;

    if (/(?:from\s+)?['"][^'"]+['"]\s*;?\s*$/.test(line)) {
      importLine = undefined;
    }
  }

  if (importLine !== undefined) {
    throw new Error(`${sourceName}:${importLine}: unclosed MDX import`);
  }
  return output.join('\n');
}

export function cleanMdx(markdown, sourceName = 'MDX') {
  return mapOutsideFences(markdown, (chunk) => {
    let clean = removeMdxImports(chunk, sourceName);

    clean = clean.replace(
      /^[ \t]*<Card\b([^>]*)>([\s\S]*?)^[ \t]*<\/Card>[ \t]*$/gm,
      (_match, attributes, body) => {
        const title = attributeValue(attributes, 'title');
        return `${title ? `**${title}**\n\n` : ''}${dedent(body)}\n\n`;
      },
    );
    clean = clean.replace(
      /^[ \t]*<Aside\b([^>]*)>([\s\S]*?)^[ \t]*<\/Aside>[ \t]*$/gm,
      (_match, attributes, body) => {
        const title = attributeValue(attributes, 'title');
        return `${title ? `**${title}**\n\n` : ''}${dedent(body)}\n\n`;
      },
    );
    clean = clean.replace(
      /<LinkButton\b([^>]*)>([\s\S]*?)<\/LinkButton>/g,
      (_match, attributes, label) => {
        const href = attributeValue(attributes, 'href');
        const text = label.replace(/\s+/g, ' ').trim();
        return href ? `- [${text}](${href})` : text;
      },
    );
    clean = clean.replace(
      /<\/?(?:Steps|CardGrid|SyncDemo)\b[^>]*>/g,
      '',
    );
    clean = clean.replace(/\{\s*(['"])\s+\1\s*\}/g, '');

    const component = /<\/?([A-Z][A-Za-z0-9.]*)(?:\s|\/?>)/.exec(clean);
    if (component) {
      throw new Error(
        `${sourceName}: unsupported MDX component ${component[1]}`,
      );
    }

    return clean;
  }, sourceName);
}

function siteUrlFor(path) {
  let route = relative(docsRoot, path).split(sep).join('/');
  route = route.replace(/\.mdx?$/, '');
  if (route === 'index') route = '';
  else route = route.replace(/\/index$/, '');
  return new URL(route ? `${route}/` : '', siteRoot);
}

function encodedRepositoryPath(path) {
  return path.split('/').map(encodeURIComponent).join('/');
}

function repositoryUrlForPath(path, search = '', hash = '') {
  const relativePath = repositoryPath(path);
  if (relativePath === '..' || relativePath.startsWith('../')) {
    throw new Error(`repository link escapes the checkout: ${path}`);
  }

  const kind = statSync(path).isDirectory() ? 'tree' : 'blob';
  const url = new URL(
    `${kind}/main/${encodedRepositoryPath(relativePath)}`,
    repositoryRoot,
  );
  url.search = search;
  url.hash = hash;
  return url;
}

function sourceUrlFor(path) {
  return pathIsInside(docsRoot, path)
    ? siteUrlFor(path)
    : repositoryUrlForPath(path);
}

function relativeTarget(sourcePath, href) {
  if (href.startsWith('/') || href.startsWith('#') || href.startsWith('?')) {
    return;
  }

  const pathPart = href.split(/[?#]/, 1)[0];
  if (!pathPart) return;

  try {
    return resolve(dirname(sourcePath), decodeURIComponent(pathPart));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(
      `${repositoryPath(sourcePath)} has an invalid link ${href}: ${message}`,
      { cause: error },
    );
  }
}

function rewriteHref(href, sourcePath) {
  if (/^[a-z][a-z\d+.-]*:/i.test(href) || href.startsWith('//')) return href;

  if (!pathIsInside(docsRoot, sourcePath)) {
    try {
      const base = new URL(
        repositoryPath(sourcePath),
        'https://repository.invalid/',
      );
      const parsed = new URL(href, base);
      const targetPath = resolve(
        root,
        decodeURIComponent(parsed.pathname.slice(1)),
      );
      return repositoryUrlForPath(targetPath, parsed.search, parsed.hash).href;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(
        `${repositoryPath(sourcePath)} has an invalid repository link ${href}: ${message}`,
        { cause: error },
      );
    }
  }

  const target = relativeTarget(sourcePath, href);
  if (target && pathIsInside(docsRoot, target) && /\.mdx?$/.test(target)) {
    const parsed = new URL(href, siteUrlFor(sourcePath));
    const url = siteUrlFor(target);
    url.search = parsed.search;
    url.hash = parsed.hash;
    return url.href;
  }
  if (target) {
    try {
      const stats = statSync(target);
      if (stats.isFile() || stats.isDirectory()) {
        const parsed = new URL(href, siteUrlFor(sourcePath));
        return repositoryUrlForPath(target, parsed.search, parsed.hash).href;
      }
    } catch {
      // Route-style documentation links do not map directly to source paths.
    }
  }

  return new URL(href, siteUrlFor(sourcePath)).href;
}

export function rewriteMarkdownLinks(markdown, sourcePath) {
  return mapOutsideFences(
    markdown,
    (chunk) => {
      const inline =
        /(!?\[[^\]\n]+\]\(\s*)(?:<([^>\n]+)>|([^\s)\n]+))((?:\s+(?:"[^"\n]*"|'[^'\n]*'|\([^\n)]*\)))?\s*\))/g;
      const references =
        /(^\s*\[[^\]\n]+\]:\s*)(?:<([^>\n]+)>|([^\s\n]+))/gm;

      let rewritten = chunk.replace(
        inline,
        (_match, prefix, angled, plain, suffix) => {
          const replacement = rewriteHref(angled ?? plain, sourcePath);
          return `${prefix}${angled ? `<${replacement}>` : replacement}${suffix}`;
        },
      );
      rewritten = rewritten.replace(
        references,
        (_match, prefix, angled, plain) => {
          const replacement = rewriteHref(angled ?? plain, sourcePath);
          return `${prefix}${angled ? `<${replacement}>` : replacement}`;
        },
      );
      return rewritten;
    },
    repositoryPath(sourcePath),
  );
}

function cleanContent(path) {
  const raw = readFileSync(path, 'utf8');
  const { content: withoutFrontmatter, frontmatter } = splitFrontmatter(raw);
  const title = titleFor(path, frontmatter, withoutFrontmatter);
  const sourceName = repositoryPath(path);
  let content = withoutFrontmatter.replace(/^#\s+[^\n]+\n+/, '');

  if (path.endsWith('.mdx')) content = cleanMdx(content, sourceName);
  content = mapOutsideFences(
    content,
    (chunk) => chunk.replace(/^(#{1,5})(?=\s)/gm, '#$1'),
    sourceName,
  );
  content = rewriteMarkdownLinks(content, path);
  content = mapOutsideFences(
    content,
    (chunk) => chunk.replace(/\n{3,}/g, '\n\n'),
    sourceName,
  ).trim();

  return { content, title };
}

export function generateLlmsFull() {
  const siteSources = collectMarkdown(docsRoot)
    .filter((path) => {
      const relativePath = relative(docsRoot, path).split(sep).join('/');
      return !relativePath.startsWith('reference/api/');
    })
    .sort((left, right) => {
      const leftOrder = documentationOrder(left);
      const rightOrder = documentationOrder(right);
      return leftOrder < rightOrder ? -1 : leftOrder > rightOrder ? 1 : 0;
    });
  const sources = [...siteSources, resolve(root, 'docs/feature-audit.md')];
  const sections = sources.map((path) => {
    const { content, title } = cleanContent(path);
    const sourceLabel = pathIsInside(docsRoot, path)
      ? 'Documentation page'
      : 'Feature and verification audit';
    return [
      `## ${title}`,
      '',
      `Source: [${sourceLabel}](${sourceUrlFor(path).href})`,
      '',
      content,
    ].join('\n');
  });

  const output = [
    '# Peerborne documentation site — full handwritten corpus',
    '',
    '> Concatenated hand-authored documentation pages plus the feature audit. Generated API detail and repository/package READMEs are indexed separately in llms.txt.',
    '> Peerborne is under active development. Check capability claims against the feature audit and documented limitations.',
    '',
    ...sections.flatMap((section) => [section, '', '---', '']),
  ].join('\n');

  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, `${output.trimEnd()}\n`);
  const lineCount = output.trimEnd().split('\n').length;
  console.log(
    `Generated ${outputPath} (${lineCount} lines from ${sources.length} sources)`,
  );
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  generateLlmsFull();
}
