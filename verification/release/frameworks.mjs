export function isFrameworkModule(name) {
  return /(?:^|\/)node_modules\/(?:react|react-dom|react-native|vue|svelte|next|@vue\/[^/]+)(?:\/|$)/u.test(
    name.replaceAll('\\', '/'),
  );
}
