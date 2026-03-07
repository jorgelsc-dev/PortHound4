const { defineConfig } = require("@vue/cli-service");

module.exports = defineConfig({
  transpileDependencies: ["vuetify"],
  configureWebpack: {
    performance: {
      hints: false,
    },
  },
  chainWebpack: (config) => {
    config.when(process.env.NODE_ENV === "production", (prodConfig) => {
      const minimizers = prodConfig.optimization.minimizers;
      if (!minimizers || !minimizers.has("css")) {
        return;
      }

      prodConfig.optimization.minimizer("css").tap((args) => {
        const options = args[0] || {};
        const minimizerOptions = options.minimizerOptions || {};
        const preset = minimizerOptions.preset || ["default", {}];

        if (Array.isArray(preset)) {
          const presetName = preset[0] || "default";
          const presetOptions = { ...(preset[1] || {}), calc: false };
          options.minimizerOptions = {
            ...minimizerOptions,
            preset: [presetName, presetOptions],
          };
        } else {
          options.minimizerOptions = {
            ...minimizerOptions,
            preset: ["default", { calc: false }],
          };
        }

        args[0] = options;
        return args;
      });
    });
  },
});
