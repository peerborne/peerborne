export default {
  transpilePackages: ['@peerborne/react', '@peerborne/store'],
  webpack(config, { isServer, webpack }) {
    if (!isServer) {
      config.plugins.push(
        new webpack.NormalModuleReplacementPlugin(
          /^node:stream$/,
          (resource) => {
            resource.request = 'stream';
          },
        ),
      );
    }
    return config;
  },
};
