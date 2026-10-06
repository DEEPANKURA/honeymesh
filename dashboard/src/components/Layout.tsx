import type { ReactNode } from "react";
import { useRoute } from "../lib/router";
import { getToken, setToken } from "../lib/api";

const NAV = [
  { path: "/", label: "Overview" },
  { path: "/events", label: "Events" },
  { path: "/attackers", label: "Attackers" },
  { path: "/deception", label: "Deception" },
  { path: "/reports", label: "Reports" },
  { path: "/system", label: "System" },
];

interface LayoutProps {
  children: ReactNode;
  connected: boolean;
  username: string | null;
  onSignOut: () => void;
}

export function Layout({ children, connected, username, onSignOut }: LayoutProps): ReactNode {
  const [path, navigate] = useRoute();

  const isActive = (target: string) =>
    target === "/" ? path === "/" || path.startsWith("/attackers/") : path.startsWith(target);

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">H</div>
          <div>
            <div className="brand-name">HoneyMesh</div>
            <div className="brand-sub">adaptive deception</div>
          </div>
        </div>
        {NAV.map((item) => (
          <button
            key={item.path}
            type="button"
            className={`nav-item ${isActive(item.path) ? "active" : ""}`}
            onClick={() => navigate(item.path)}
          >
            <span>{item.label}</span>
          </button>
        ))}
        <div className="sidebar-foot">
          <span>
            live stream:{" "}
            {connected ? (
              <span className="badge low">connected</span>
            ) : (
              <span className="badge neutral">offline</span>
            )}
          </span>
          <span>token: {getToken() ? "stored" : "none"}</span>
          {username ? (
            <button type="button" className="btn" onClick={onSignOut}>
              sign out ({username})
            </button>
          ) : null}
        </div>
      </aside>
      <main className="main">{children}</main>
    </div>
  );
}

export function LoginPage({ onSignIn }: { onSignIn: (username: string) => void }): ReactNode {
  return (
    <div className="login-wrap">
      <form
        className="login-card"
        onSubmit={(event) => {
          event.preventDefault();
          const form = new FormData(event.currentTarget);
          void (async () => {
            const response = await fetch("/api/v1/auth/login", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                username: String(form.get("username") ?? ""),
                password: String(form.get("password") ?? ""),
              }),
            });
            if (!response.ok) return;
            const payload = (await response.json()) as { access_token: string; username: string };
            setToken(payload.access_token);
            onSignIn(payload.username);
          })();
        }}
      >
        <h1>HoneyMesh Console</h1>
        <p>Sign in with an operator account to view telemetry and drive deception.</p>
        <label className="field">
          username
          <input name="username" autoComplete="username" defaultValue="admin" required />
        </label>
        <label className="field">
          password
          <input name="password" type="password" autoComplete="current-password" required />
        </label>
        <button className="btn primary" type="submit" style={{ width: "100%" }}>
          sign in
        </button>
      </form>
    </div>
  );
}
