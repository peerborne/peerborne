// @ts-check
import { rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightTypeDoc, { typeDocSidebarGroup } from 'starlight-typedoc';

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
  alt: 'Peerborne — encrypted local-first state, carried by peers.',
};

// Deployed through GitHub Pages at the custom apex domain.
export default defineConfig({
  site: 'https://peerborne.io',
  redirects: {
    '/concepts/why-swarmbase/': '/concepts/why-peerborne/',
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
      description: 'Encrypted local-first state, carried by peers.',
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
          label: 'Getting started',
          items: ['getting-started/quick-start'],
        },
        {
          label: 'Concepts',
          items: [
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
          label: 'Cookbook',
          items: [
            'cookbook/collaborative-wiki',
            'cookbook/password-manager',
            'cookbook/react',
            'cookbook/redux',
            'cookbook/search-indexing',
            'cookbook/yjs-schema-design',
            'cookbook/running-a-relay',
            'cookbook/pinning',
          ],
        },
        {
          label: 'Reference',
          items: [
            'reference',
            'reference/comparisons',
            typeDocSidebarGroup,
          ],
        },
        {
          label: 'Community',
          items: [
            'community',
            'community/faq',
            'community/roadmap',
            'community/contributing',
            'community/help-wanted',
          ],
        },
      ],
    }),
    removeGeneratedApiLanding,
  ],
});
