// @ts-check
import { rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'astro/config';
import { unified } from '@astrojs/markdown-remark';
import starlight from '@astrojs/starlight';
import starlightTypeDoc, { typeDocSidebarGroup } from 'starlight-typedoc';
import rehypeDocsFigures from './scripts/rehype-docs-figures.mjs';

const removeGeneratedApiLanding = {
  name: 'remove-generated-api-landing',
  hooks: {
    'astro:config:setup': () => {
      rmSync(
        fileURLToPath(
          new URL(
            './src/content/docs/reference/api/README.md',
            import.meta.url,
          ),
        ),
        { force: true },
      );
    },
  },
};

const socialCard = {
  url: 'https://peerborne.io/social-card.png',
  alt: 'Peerborne — local-first TypeScript state with end-to-end encryption.',
};

// Deployed through GitHub Pages at the custom apex domain.
export default defineConfig({
  site: 'https://peerborne.io',
  markdown: {
    // Astro 7 deprecates markdown.rehypePlugins in favor of processor plugins.
    processor: unified({ rehypePlugins: [rehypeDocsFigures] }),
  },
  vite: {
    resolve: {
      alias: [
        {
          find: /^@peerborne\/core$/,
          replacement: fileURLToPath(
            new URL('./src/lib/peerborne-shim.ts', import.meta.url),
          ),
        },
      ],
    },
  },
  integrations: [
    starlight({
      plugins: [
        starlightTypeDoc({
          entryPoints: [
            '../packages/core',
            '../packages/yjs',
            '../packages/automerge',
            '../packages/react',
            '../packages/redux',
            '../packages/index',
            '../packages/store',
            '../packages/vue',
            '../packages/svelte',
            '../packages/loro',
          ],
          output: 'reference/api',
          sidebar: { label: 'Packages', collapsed: true },
          typeDoc: {
            entryPointStrategy: 'packages',
            excludePrivate: true,
            excludeProtected: true,
            excludeInternal: true,
            treatWarningsAsErrors: true,
          },
        }),
      ],
      title: 'Peerborne',
      description: 'Local-first TypeScript state with end-to-end encryption.',
      logo: {
        src: './src/assets/logo.svg',
        alt: 'Peerborne',
      },
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/Peerborne/peerborne',
        },
      ],
      editLink: {
        baseUrl: 'https://github.com/Peerborne/peerborne/edit/main/site/',
      },
      customCss: ['./src/styles/custom.css'],
      head: [
        {
          tag: 'meta',
          attrs: { property: 'og:image', content: socialCard.url },
        },
        {
          tag: 'meta',
          attrs: { property: 'og:image:width', content: '1200' },
        },
        {
          tag: 'meta',
          attrs: { property: 'og:image:height', content: '630' },
        },
        {
          tag: 'meta',
          attrs: { property: 'og:image:type', content: 'image/png' },
        },
        {
          tag: 'meta',
          attrs: { property: 'og:image:alt', content: socialCard.alt },
        },
        {
          tag: 'meta',
          attrs: { name: 'twitter:image', content: socialCard.url },
        },
        {
          tag: 'meta',
          attrs: { name: 'twitter:image:alt', content: socialCard.alt },
        },
      ],
      sidebar: [
        {
          label: 'Getting Started',
          items: [
            { label: 'Five-minute source tutorial', slug: 'getting-started/quick-start' },
            'getting-started/react-workspace',
            'getting-started/vanilla',
            {
              label: 'Frameworks and examples',
              collapsed: true,
              items: [
                'cookbook/react',
                'cookbook/redux',
                'cookbook/framework-integrations',
                'cookbook/peerborne-note',
                'cookbook/invitations',
                'cookbook/collaborative-wiki',
                'cookbook/password-manager',
                'cookbook/search-indexing',
                'cookbook/yjs-schema-design',
              ],
            },
            {
              label: 'Community',
              collapsed: true,
              items: [
                'community',
                'community/faq',
                'community/roadmap',
                'community/contributing',
                'community/help-wanted',
              ],
            },
          ],
        },
        {
          label: 'Core Concepts',
          items: [
            'concepts/documents',
            'concepts/identities',
            'concepts/epoch-transitions',
            'concepts/why-peerborne',
            'concepts/architecture',
            'concepts/local-first',
            'concepts/crdts',
            'concepts/networking',
            'concepts/storage',
            'concepts/security',
            'concepts/performance',
            'concepts/limitations',
          ],
        },
        {
          label: 'Production Runbooks',
          items: [
            'runbooks',
            'runbooks/offline-persistence',
            'cookbook/running-a-relay',
            'cookbook/pinning',
          ],
        },
        {
          label: 'API Reference',
          items: [
            'reference',
            'reference/comparisons',
            'reference/integration-status',
            {
              label: 'Security design decisions',
              collapsed: true,
              items: [
                'reference/security-design/0001-mls-document-security-architecture',
                'reference/security-design/0002-mls-implementation-dependency',
                'reference/security-design/0003-zero-knowledge-membership-proofs',
              ],
            },
            typeDocSidebarGroup,
          ],
        },
      ],
    }),
    removeGeneratedApiLanding,
  ],
});
