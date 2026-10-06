import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { api, isApiError, setToken } from "./lib/api";
import { LiveProvider, useLiveConnection } from "./lib/live";
import { useRoute } from "./lib/router";
import { Layout, LoginPage } from "./components/Layout";
import { OverviewPage } from "./pages/Overview";
import { EventsPage } from "./pages/Events";
import { AttackersPage } from "./pages/Attackers";
import { DeceptionPage } from "./pages/Deception";
import { ReportsPage } from "./pages/Reports";
import { SystemPage } from "./pages/System";

type Boot = "loading" | "login" | "app";

function needsLogin(): Promise<boolean> {
  return (async () => {
    try {
      await api<{ username: string }>("/auth/me");
      return false;
    } catch (error) {
      if (!isApiError(error) || error.status !== 401) return false;
      try {
        await api("/metrics");
        return false;
      } catch (fallback) {
        return isApiError(fallback) && fallback.status === 401;
      }
    }
  })();
}

function Routes(): ReactNode {
  const [path] = useRoute();
  if (path === "/" || path === "") return <OverviewPage />;
  if (path.startsWith("/events")) return <EventsPage />;
  if (path.startsWith("/attackers")) return <AttackersPage />;
  if (path.startsWith("/deception")) return <DeceptionPage />;
  if (path.startsWith("/reports")) return <ReportsPage />;
  if (path.startsWith("/system")) return <SystemPage />;
  return <OverviewPage />;
}

function Shell({ username, onSignOut }: { username: string | null; onSignOut: () => void }): ReactNode {
  const { connected } = useLiveConnection();
  return (
    <Layout connected={connected} username={username} onSignOut={onSignOut}>
      <Routes />
    </Layout>
  );
}

export function App(): ReactNode {
  const [boot, setBoot] = useState<Boot>("loading");
  const [username, setUsername] = useState<string | null>(null);

  useEffect(() => {
    void (async () => {
      if (await needsLogin()) {
        setBoot("login");
        return;
      }
      try {
        const me = await api<{ username: string }>("/auth/me");
        setUsername(me.username);
      } catch {
        setUsername(null);
      }
      setBoot("app");
    })();
  }, []);

  if (boot === "loading") {
    return (
      <div className="login-wrap">
        <div className="empty">
          <span className="spinner" /> connecting to HoneyMesh
        </div>
      </div>
    );
  }

  if (boot === "login") {
    return (
      <LoginPage
        onSignIn={(name) => {
          setUsername(name);
          setBoot("app");
        }}
      />
    );
  }

  return (
    <LiveProvider>
      <Shell
        username={username}
        onSignOut={() => {
          void api("/auth/logout", { method: "POST" }).catch(() => undefined);
          setToken("");
          setUsername(null);
          setBoot("login");
        }}
      />
    </LiveProvider>
  );
}
