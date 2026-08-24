#!/usr/bin/env node

import { readFileSync, readdirSync, realpathSync, statSync } from 'node:fs';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const defaultDistDirectory = fileURLToPath(new URL('../dist', import.meta.url));
const distDirectory = resolve(process.argv[2] ?? defaultDistDirectory);
const defaultRepositoryDirectory = fileURLToPath(
  new URL('../..', import.meta.url),
);
const repositoryDirectory = resolve(
  process.argv[3] ?? defaultRepositoryDirectory,
);
const repositoryUrl = new URL('https://github.com/Peerborne/peerborne/');
const repositoryWebRoutes = new Set([
  'actions',
  'branches',
  'commit',
  'commits',
  'compare',
  'discussions',
  'issues',
  'labels',
  'milestones',
  'network',
  'projects',
  'pull',
  'pulls',
  'releases',
  'security',
  'tags',
  'wiki',
]);
const maxDiagnostics = 100;

function decodeHtmlEntities(value) {
  const namedEntities = {
    amp: '&',
    apos: "'",
    gt: '>',
    lt: '<',
    nbsp: '\u00a0',
    quot: '"',
  };

  return value.replace(
    /&(#\d+|#x[\da-f]+|amp|apos|gt|lt|nbsp|quot);/gi,
    (entity, body) => {
      if (body.startsWith('#x') || body.startsWith('#X')) {
        return String.fromCodePoint(Number.parseInt(body.slice(2), 16));
      }
      if (body.startsWith('#')) {
        return String.fromCodePoint(Number.parseInt(body.slice(1), 10));
      }
      return namedEntities[body.toLowerCase()] ?? entity;
    },
  );
}

function attributesFor(tag) {
  const attributes = new Map();
  const attributePattern = /([\w:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;

  for (const match of tag.matchAll(attributePattern)) {
    attributes.set(
      match[1].toLowerCase(),
      decodeHtmlEntities(match[2] ?? match[3]),
    );
  }

  return attributes;
}

function* tagsIn(html) {
  let cursor = 0;

  while (cursor < html.length) {
    const start = html.indexOf('<', cursor);
    if (start === -1) return;

    if (html.startsWith('<!--', start)) {
      const end = html.indexOf('-->', start + 4);
      if (end === -1) return;
      cursor = end + 3;
      continue;
    }

    const name = /^<([a-z][\w:-]*)/i.exec(html.slice(start))?.[1];
    if (!name) {
      cursor = start + 1;
      continue;
    }

    let quote = '';
    let end = start + name.length + 1;
    for (; end < html.length; end += 1) {
      const character = html[end];
      if (quote) {
        if (character === quote) quote = '';
      } else if (character === '"' || character === "'") {
        quote = character;
      } else if (character === '>') {
        break;
      }
    }

    if (end === html.length) return;
    yield {
      name: name.toLowerCase(),
      source: html.slice(start, end + 1),
    };
    cursor = end + 1;
  }
}

function markdownOutsideFences(markdown, sourceName) {
  let fence;

  const searchable = markdown
    .split('\n')
    .map((line, index) => {
      if (!fence) {
        const opening = /^([ \t]*)(`{3,}|~{3,})/.exec(line);
        if (!opening) return line;
        fence = {
          character: opening[2][0],
          length: opening[2].length,
          startLine: index + 1,
        };
        return ' '.repeat(line.length);
      }

      const closing = /^([ \t]*)(`+|~+)\s*$/.exec(line);
      if (
        closing &&
        closing[2][0] === fence.character &&
        closing[2].length >= fence.length
      ) {
        fence = undefined;
      }
      return ' '.repeat(line.length);
    })
    .join('\n');

  if (fence) {
    throw new Error(
      `${sourceName}:${fence.startLine}: unclosed ${fence.character.repeat(fence.length)} fence`,
    );
  }
  return searchable;
}

function linksInMarkdown(markdown, sourceName) {
  const searchableMarkdown = markdownOutsideFences(markdown, sourceName);
  const inlineLinkPattern =
    /\[[^\]\n]+\]\(\s*(?:<([^>\n]+)>|([^\s)\n]+))(?:\s+(?:"[^"\n]*"|'[^'\n]*'|\([^\n)]*\)))?\s*\)/g;
  const inlineLinkOpeningPattern = /\[[^\]\n]+\]\(/g;
  const referenceLinkPattern =
    /^\s*\[([^\]\n]+)\]:\s*(?:<([^>\n]+)>|([^\s\n]+))/gm;
  const referenceUsePattern = /\[([^\]\n]+)\]\[([^\]\n]*)\]/g;
  const links = [];
  const validInlineStarts = new Set();
  const definitions = new Map();
  const undefinedReferences = [];
  const malformedInlineLinks = [];

  for (const match of searchableMarkdown.matchAll(inlineLinkPattern)) {
    validInlineStarts.add(match.index);
    links.push(match[1] ?? match[2]);
  }
  for (const match of searchableMarkdown.matchAll(referenceLinkPattern)) {
    const label = normalizeReferenceLabel(match[1]);
    if (!definitions.has(label)) {
      definitions.set(label, match[2] ?? match[3]);
    }
  }
  for (const match of searchableMarkdown.matchAll(referenceUsePattern)) {
    const label = normalizeReferenceLabel(match[2] || match[1]);
    const href = definitions.get(label);
    if (href) links.push(href);
    else undefinedReferences.push(match[2] || match[1]);
  }
  for (const match of searchableMarkdown.matchAll(inlineLinkOpeningPattern)) {
    if (!validInlineStarts.has(match.index)) {
      malformedInlineLinks.push(
        searchableMarkdown.slice(0, match.index).split('\n').length,
      );
    }
  }

  return { links, malformedInlineLinks, undefinedReferences };
}

function normalizeReferenceLabel(label) {
  return label.trim().replace(/\s+/g, ' ').toLowerCase();
}

function collectFiles(directory, relativeDirectory = '', files = new Set()) {
  const entries = readdirSync(resolve(directory, relativeDirectory), {
    withFileTypes: true,
  }).sort((left, right) => left.name.localeCompare(right.name));

  for (const entry of entries) {
    const relativePath = relativeDirectory
      ? `${relativeDirectory}/${entry.name}`
      : entry.name;
    if (entry.isDirectory()) {
      collectFiles(directory, relativePath, files);
    } else if (entry.isFile()) {
      files.add(relativePath);
    }
  }

  return files;
}

function findSiteRoot(indexHtml) {
  for (const tag of tagsIn(indexHtml)) {
    if (tag.name !== 'link') continue;
    const attributes = attributesFor(tag.source);
    const rel = attributes.get('rel')?.toLowerCase().split(/\s+/) ?? [];
    if (!rel.includes('canonical')) continue;

    const href = attributes.get('href');
    if (!href) break;

    const siteRoot = new URL(href);
    if (!['http:', 'https:'].includes(siteRoot.protocol)) break;
    siteRoot.hash = '';
    siteRoot.search = '';
    if (!siteRoot.pathname.endsWith('/')) siteRoot.pathname += '/';
    return siteRoot;
  }

  throw new Error('index.html has no HTTP canonical URL');
}

function pageUrl(relativePath, siteRoot) {
  if (relativePath === 'index.html') return new URL(siteRoot);
  if (relativePath.endsWith('/index.html')) {
    return new URL(relativePath.slice(0, -'index.html'.length), siteRoot);
  }
  return new URL(relativePath, siteRoot);
}

function anchorsFor(html, relativePath, diagnostics) {
  const anchors = new Set();
  const ids = new Set();

  for (const tag of tagsIn(html)) {
    const attributes = attributesFor(tag.source);
    const id = attributes.get('id');
    if (id !== undefined) {
      if (ids.has(id)) {
        diagnostics.push(`${relativePath}: duplicate id "${id}"`);
      }
      ids.add(id);
      anchors.add(id);
    }

    if (tag.name === 'a') {
      const name = attributes.get('name');
      if (name !== undefined) anchors.add(name);
    }
  }

  return anchors;
}

function decodedPath(pathname) {
  return pathname
    .split('/')
    .map((segment) => decodeURIComponent(segment))
    .join('/');
}

function repositoryTargetFor(url) {
  if (url.origin !== repositoryUrl.origin) return;

  const segments = decodedPath(url.pathname).split('/').filter(Boolean);
  const repositorySegments = decodedPath(repositoryUrl.pathname)
    .split('/')
    .filter(Boolean);
  if (
    repositorySegments.some(
      (segment, index) => segments[index] !== segment,
    )
  ) {
    return;
  }
  if (segments.length === repositorySegments.length) {
    return { kind: 'tree', relativePath: '' };
  }

  const [kind, branch, ...pathSegments] = segments.slice(
    repositorySegments.length,
  );
  if (!['blob', 'tree'].includes(kind)) {
    if (repositoryWebRoutes.has(kind)) return;
    const route = [kind, branch].filter(Boolean).join('/');
    return { error: `uses unsupported repository route "${route}"` };
  }
  if (branch !== 'main') {
    return { error: `uses unsupported repository branch "${branch ?? ''}"` };
  }
  if (
    pathSegments.some(
      (segment) =>
        segment === '.' ||
        segment === '..' ||
        segment === '' ||
        segment.includes('\\'),
    )
  ) {
    return { error: 'escapes the repository checkout' };
  }

  return { kind, relativePath: pathSegments.join('/') };
}

function pathEscapesDirectory(directory, path) {
  const relativePath = relative(directory, path);
  return (
    relativePath === '..' ||
    relativePath.startsWith(`..${sep}`) ||
    isAbsolute(relativePath)
  );
}

function artifactFor(url, files, basePath) {
  if (
    basePath &&
    url.pathname !== basePath &&
    !url.pathname.startsWith(`${basePath}/`)
  ) {
    return { error: `escapes base path "${basePath}/"` };
  }

  const pathname = decodedPath(url.pathname.slice(basePath.length));
  const segments = pathname.split('/').filter(Boolean);
  if (segments.some((segment) => segment === '.' || segment === '..')) {
    return { error: 'escapes the site output directory' };
  }

  const relativePath = segments.join('/');
  if (!relativePath) return { artifact: 'index.html' };

  const candidates = url.pathname.endsWith('/')
    ? [`${relativePath}/index.html`]
    : [relativePath, `${relativePath}/index.html`];
  const artifact = candidates.find((candidate) => files.has(candidate));

  return artifact
    ? { artifact }
    : {
        error: `missing target ${candidates
          .map((candidate) => `"${candidate}"`)
          .join(' or ')}`,
      };
}

function anchorFrom(hash) {
  if (!hash || hash === '#') return '';
  const fragment = hash.slice(1).split(':~:text=', 1)[0];
  return decodeURIComponent(fragment);
}

function checkSiteLink({
  href,
  sourceUrl,
  sourceName,
  siteRoot,
  files,
  basePath,
  anchorsByFile,
  diagnostics,
}) {
  let url;
  try {
    url = new URL(href, sourceUrl);
  } catch {
    diagnostics.push(`${sourceName}: invalid href="${href}"`);
    return {};
  }

  if (!['http:', 'https:'].includes(url.protocol)) return { url };
  if (url.origin !== siteRoot.origin) return { url };

  let result;
  try {
    result = artifactFor(url, files, basePath);
  } catch {
    diagnostics.push(
      `${sourceName}: href="${href}" has invalid percent encoding`,
    );
    return { internal: true, url };
  }

  if (result.error) {
    diagnostics.push(`${sourceName}: href="${href}" -> ${result.error}`);
    return { internal: true, url };
  }

  if (!result.artifact.endsWith('.html')) return { internal: true, url };

  let anchor;
  try {
    anchor = anchorFrom(url.hash);
  } catch {
    diagnostics.push(
      `${sourceName}: href="${href}" has invalid fragment encoding`,
    );
    return { internal: true, url };
  }

  if (anchor && !anchorsByFile.get(result.artifact)?.has(anchor)) {
    diagnostics.push(
      `${sourceName}: href="${href}" -> missing anchor "${anchor}"`,
    );
  }

  return { internal: true, url };
}

function checkRepositoryLink({ href, url, sourceName, diagnostics }) {
  let target;
  try {
    target = repositoryTargetFor(url);
  } catch {
    diagnostics.push(
      `${sourceName}: href="${href}" has invalid repository path encoding`,
    );
    return true;
  }
  if (!target) return false;
  if (target.error) {
    diagnostics.push(`${sourceName}: href="${href}" -> ${target.error}`);
    return true;
  }

  const targetPath = resolve(repositoryDirectory, target.relativePath);
  if (pathEscapesDirectory(repositoryDirectory, targetPath)) {
    diagnostics.push(
      `${sourceName}: href="${href}" -> escapes the repository checkout`,
    );
    return true;
  }

  let realRepositoryPath;
  let realTargetPath;
  try {
    realRepositoryPath = realpathSync(repositoryDirectory);
    realTargetPath = realpathSync(targetPath);
  } catch {
    diagnostics.push(
      `${sourceName}: href="${href}" -> missing repository target "${target.relativePath || '.'}"`,
    );
    return true;
  }
  if (pathEscapesDirectory(realRepositoryPath, realTargetPath)) {
    diagnostics.push(
      `${sourceName}: href="${href}" -> repository target escapes the checkout through a symbolic link`,
    );
    return true;
  }
  let stats;
  try {
    stats = statSync(realTargetPath);
  } catch {
    diagnostics.push(
      `${sourceName}: href="${href}" -> missing repository target "${target.relativePath || '.'}"`,
    );
    return true;
  }

  const hasExpectedType =
    target.kind === 'blob' ? stats.isFile() : stats.isDirectory();
  if (!hasExpectedType) {
    const expectedType = target.kind === 'blob' ? 'file' : 'directory';
    diagnostics.push(
      `${sourceName}: href="${href}" -> repository target "${target.relativePath || '.'}" is not a ${expectedType}`,
    );
  }
  return true;
}

function checkMarkdownArtifact({
  relativePath,
  files,
  siteRoot,
  basePath,
  anchorsByFile,
  diagnostics,
}) {
  let markdown;
  try {
    markdown = readFileSync(resolve(distDirectory, relativePath), 'utf8');
  } catch (error) {
    throw new Error(`${distDirectory}/${relativePath} does not exist`, {
      cause: error,
    });
  }

  const { links, malformedInlineLinks, undefinedReferences } =
    linksInMarkdown(markdown, relativePath);
  if (links.length === 0) {
    diagnostics.push(`${relativePath}: contains no Markdown links`);
  }
  for (const line of malformedInlineLinks) {
    diagnostics.push(`${relativePath}:${line}: malformed inline Markdown link`);
  }
  for (const label of undefinedReferences) {
    diagnostics.push(`${relativePath}: undefined link reference "${label}"`);
  }

  const sourceUrl = new URL(relativePath, siteRoot);
  let siteLinkCount = 0;
  let repositoryLinkCount = 0;
  for (const href of links) {
    const result = checkSiteLink({
      href,
      sourceUrl,
      sourceName: relativePath,
      siteRoot,
      files,
      basePath,
      anchorsByFile,
      diagnostics,
    });
    if (result.internal) {
      siteLinkCount += 1;
    } else if (
      result.url &&
      checkRepositoryLink({
        href,
        url: result.url,
        sourceName: relativePath,
        diagnostics,
      })
    ) {
      repositoryLinkCount += 1;
    }
  }

  return {
    externalLinkCount: links.length - siteLinkCount - repositoryLinkCount,
    linkCount: links.length,
    relativePath,
    repositoryLinkCount,
    siteLinkCount,
  };
}

function run() {
  let files;
  try {
    files = collectFiles(distDirectory);
  } catch (error) {
    throw new Error(`${distDirectory} does not exist; build the site first`, {
      cause: error,
    });
  }

  const htmlFiles = [...files]
    .filter((relativePath) => relativePath.endsWith('.html'))
    .sort();
  if (htmlFiles.length === 0) {
    throw new Error(`${distDirectory} contains no HTML files`);
  }

  const htmlByFile = new Map(
    htmlFiles.map((relativePath) => [
      relativePath,
      readFileSync(resolve(distDirectory, relativePath), 'utf8'),
    ]),
  );
  const siteRoot = findSiteRoot(htmlByFile.get('index.html') ?? '');
  const basePath =
    siteRoot.pathname === '/' ? '' : siteRoot.pathname.slice(0, -1);
  const diagnostics = [];
  const anchorsByFile = new Map(
    htmlFiles.map((relativePath) => [
      relativePath,
      anchorsFor(htmlByFile.get(relativePath), relativePath, diagnostics),
    ]),
  );
  let internalLinkCount = 0;

  for (const relativePath of htmlFiles) {
    const html = htmlByFile.get(relativePath) ?? '';
    const sourceUrl = pageUrl(relativePath, siteRoot);

    for (const tag of tagsIn(html)) {
      if (tag.name !== 'a') continue;
      const href = attributesFor(tag.source).get('href');
      if (href === undefined) continue;

      const result = checkSiteLink({
        href,
        sourceUrl,
        sourceName: relativePath,
        siteRoot,
        files,
        basePath,
        anchorsByFile,
        diagnostics,
      });
      if (result.internal) internalLinkCount += 1;
    }
  }

  const markdownResults = ['llms.txt', 'llms-full.txt'].map((relativePath) =>
    checkMarkdownArtifact({
      relativePath,
      files,
      siteRoot,
      basePath,
      anchorsByFile,
      diagnostics,
    }),
  );

  diagnostics.sort();
  if (diagnostics.length > 0) {
    console.error(`Site link check found ${diagnostics.length} issue(s):`);
    for (const diagnostic of diagnostics.slice(0, maxDiagnostics)) {
      console.error(`- ${diagnostic}`);
    }
    if (diagnostics.length > maxDiagnostics) {
      console.error(
        `- ... ${diagnostics.length - maxDiagnostics} more issue(s) omitted`,
      );
    }
    process.exitCode = 1;
    return;
  }

  const markdownSummary = markdownResults
    .map(
      (result) =>
        `${result.linkCount} links in ${result.relativePath} (${result.siteLinkCount} site, ${result.repositoryLinkCount} repository, ${result.externalLinkCount} external)`,
    )
    .join(' and ');
  console.log(
    `Checked ${internalLinkCount} internal links in ${htmlFiles.length} HTML files and ${markdownSummary}; 0 issues.`,
  );
}

try {
  run();
} catch (error) {
  console.error(`Site link check failed: ${error.message}`);
  process.exitCode = 1;
}
