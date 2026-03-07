import { createApp } from "vue";
import App from "./App.vue";
import "./registerServiceWorker";
import "./styles/app.css";

import "vuetify/styles";
import "@mdi/font/css/materialdesignicons.css";
import { createVuetify } from "vuetify";
import * as components from "vuetify/components";
import * as directives from "vuetify/directives";
import { aliases, mdi } from "vuetify/iconsets/mdi";
import router from "./router";
import store from "./state/appStore";

const vuetify = createVuetify({
  components,
  directives,
  icons: {
    defaultSet: "mdi",
    aliases,
    sets: { mdi },
  },
  theme: {
    defaultTheme: "porthoundDark",
    themes: {
      porthoundDark: {
        dark: true,
        colors: {
          background: "#0b1016",
          surface: "#141b24",
          primary: "#34e6ff",
          secondary: "#ff9f43",
          error: "#ff5468",
          info: "#4a88ff",
          success: "#35e6b1",
          warning: "#f3b14b",
        },
      },
    },
  },
});

store.initApiBase();
store.initRealtime();

createApp(App).use(vuetify).use(router).mount("#app");
