import { createApp } from "vue";
import App from "./App.vue";
import { router } from "./router";
// Brand type, bundled as local woff2 so an air-gapped deploy never
// reaches for a font CDN. Latin subsets only: every extra file here
// is embedded into the sbproxy binary via include_dir.
import "@fontsource/instrument-sans/latin-400.css";
import "@fontsource/instrument-sans/latin-500.css";
import "@fontsource/instrument-sans/latin-600.css";
import "@fontsource/instrument-sans/latin-700.css";
import "@fontsource/jetbrains-mono/latin-400.css";
import "@fontsource/jetbrains-mono/latin-500.css";
import "@fontsource/jetbrains-mono/latin-600.css";
import "./styles/base.css";

createApp(App).use(router).mount("#app");
