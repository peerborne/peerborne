export const views = {
  vanilla: { label: 'Plain JavaScript', load: () => import('./views/vanilla') },
  react: { label: 'React', load: () => import('./views/react') },
  vue: { label: 'Vue', load: () => import('./views/vue') },
  svelte: { label: 'Svelte', load: () => import('./views/svelte') },
  loro: { label: 'Loro', load: () => import('./views/loro') },
  'tanstack-db': {
    label: 'TanStack DB',
    load: () => import('./views/tanstack-db'),
  },
  codemirror: { label: 'CodeMirror', load: () => import('./views/codemirror') },
};
