import { renderToString } from "@vue/server-renderer";
import { createSSRApp, h } from "vue";
import { createMemoryHistory, createRouter } from "vue-router";
import { describe, expect, it } from "vitest";

import PageHeader from "./PageHeader.vue";

describe("PageHeader", () => {
  it("shows the current view documentation as an isolated external link", async () => {
    const routeComponent = { render: () => null };
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [
        {
          path: "/",
          component: routeComponent,
          meta: {
            title: "Overview",
            documentation: "admin-ui",
          },
        },
      ],
    });
    await router.push("/");
    await router.isReady();

    const app = createSSRApp({
      render: () => h(PageHeader, { title: "Overview" }),
    });
    app.use(router);
    const html = await renderToString(app);

    expect(html).toContain("> Documentation <span");
    expect(html).toContain('href="https://sbproxy.dev/docs/admin-ui"');
    expect(html).toContain('target="_blank"');
    expect(html).toContain('rel="noopener noreferrer"');
  });
});
