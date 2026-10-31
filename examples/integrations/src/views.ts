export const views = {
  vanilla: { label: 'Plain JavaScript', load: () => import('./views/vanilla') },
  react: { label: 'React', load: () => import('./views/react') },
  vue: { label: 'Vue', load: () => import('./views/vue') },
};
