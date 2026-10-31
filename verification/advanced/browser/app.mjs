const modules = import.meta.glob('./scenarios/*.mjs', { eager: true });
const scenarios = new Map(
  Object.values(modules).map((module) => [module.id, module]),
);
for (const level of ['log', 'debug', 'info', 'warn', 'error'])
  console[level] = () => {};
window.advanced = {
  async run(id, settings) {
    const module = scenarios.get(id);
    if (!module) throw new Error('Browser scenario is not registered');
    return module.run(settings);
  },
  modules,
};
