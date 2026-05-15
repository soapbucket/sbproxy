import { useEffect, useState } from "react";

// WOR-227 scaffold. This is intentionally a one-screen placeholder
// so the embed wiring, the cargo feature, and the `/admin/ui` mount
// can land independently of any real views. Follow-up tickets fill
// in providers, models, routing-strategy preview, metrics, and the
// chat playground.

type HealthState =
  | { kind: "loading" }
  | { kind: "ok"; body: string }
  | { kind: "error"; message: string };

export function App() {
  const [state, setState] = useState<HealthState>({ kind: "loading" });

  useEffect(() => {
    const controller = new AbortController();
    fetch("/admin/api/health", {
      signal: controller.signal,
      credentials: "include",
    })
      .then(async (res) => {
        const text = await res.text();
        if (!res.ok) {
          throw new Error(`HTTP ${res.status}: ${text}`);
        }
        setState({ kind: "ok", body: text });
      })
      .catch((err: unknown) => {
        if (controller.signal.aborted) {
          return;
        }
        const message = err instanceof Error ? err.message : String(err);
        setState({ kind: "error", message });
      });
    return () => controller.abort();
  }, []);

  return (
    <main
      style={{
        fontFamily: "system-ui, -apple-system, sans-serif",
        maxWidth: "720px",
        margin: "4rem auto",
        padding: "0 1.5rem",
        color: "#1f2328",
      }}
    >
      <h1 style={{ margin: 0, fontSize: "1.75rem", fontWeight: 600 }}>
        SBproxy Admin
      </h1>
      <p style={{ color: "#57606a", marginTop: "0.5rem" }}>
        Scaffold build. Real views land in follow-up tickets.
      </p>
      <section
        style={{
          marginTop: "2rem",
          padding: "1rem 1.25rem",
          border: "1px solid #d0d7de",
          borderRadius: "6px",
          background: "#f6f8fa",
        }}
      >
        <h2 style={{ margin: 0, fontSize: "1rem", fontWeight: 600 }}>
          /admin/api/health
        </h2>
        <HealthBlock state={state} />
      </section>
    </main>
  );
}

function HealthBlock({ state }: { state: HealthState }) {
  switch (state.kind) {
    case "loading":
      return <p style={{ color: "#57606a", margin: "0.75rem 0 0" }}>Loading...</p>;
    case "ok":
      return (
        <pre
          style={{
            margin: "0.75rem 0 0",
            padding: "0.75rem",
            background: "#ffffff",
            border: "1px solid #d0d7de",
            borderRadius: "4px",
            fontSize: "0.8125rem",
            overflowX: "auto",
          }}
        >
          {state.body}
        </pre>
      );
    case "error":
      return (
        <p style={{ color: "#cf222e", margin: "0.75rem 0 0" }}>
          Health check failed: {state.message}
        </p>
      );
  }
}
