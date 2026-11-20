import { type ReactNode, type SyntheticEvent, useCallback, useEffect, useState } from "react";

import { ApiError } from "../../lib/api";
import { Dashboard } from "./Dashboard";
import {
  ENTRA_LOGIN_PATH,
  type Me,
  type Providers,
  fetchMe,
  fetchProviders,
  login,
  loginErrorMessage,
} from "./api";

type State =
  | { kind: "loading" }
  | { kind: "anonymous"; providers: Providers }
  | { kind: "authenticated"; me: Me }
  | { kind: "error"; message: string; correlationId: string | null };

function errorState(error: unknown): State {
  if (error instanceof ApiError)
    return { kind: "error", message: error.message, correlationId: error.correlationId };
  return {
    kind: "error",
    message: "The service returned an unexpected response.",
    correlationId: null,
  };
}

async function loadSession(signal?: AbortSignal): Promise<State | null> {
  try {
    return { kind: "authenticated", me: await fetchMe(signal) };
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") return null;
    if (!(error instanceof ApiError) || error.status !== 401) return errorState(error);
  }
  try {
    return { kind: "anonymous", providers: await fetchProviders(signal) };
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") return null;
    return errorState(error);
  }
}

function initialNotice(): string | null {
  return loginErrorMessage(new URLSearchParams(window.location.search).get("login_error"));
}

export function SessionPanel({ statusSlot }: { statusSlot?: ReactNode } = {}) {
  const [state, setState] = useState<State>({ kind: "loading" });
  const [notice, setNotice] = useState<string | null>(initialNotice);

  const refresh = useCallback((signal?: AbortSignal) => {
    void loadSession(signal).then((next) => {
      if (next) setState(next);
    });
  }, []);

  useEffect(() => {
    if (window.location.search.includes("login_error")) {
      window.history.replaceState(null, "", window.location.pathname);
    }
    const controller = new AbortController();
    refresh(controller.signal);
    return () => {
      controller.abort();
    };
  }, [refresh]);

  if (state.kind === "loading") {
    return (
      <div className="auth-stage">
        <div className="auth-atmosphere" aria-hidden="true" />
        <section className="auth-panel" aria-live="polite">
          <p className="muted">Checking session…</p>
        </section>
      </div>
    );
  }

  if (state.kind === "error") {
    return (
      <div className="auth-stage">
        <div className="auth-atmosphere" aria-hidden="true" />
        <section className="auth-panel" role="alert">
          <p>
            <span className="badge badge-bad">Error</span> {state.message}
          </p>
          {state.correlationId && (
            <p className="muted">
              Correlation ID: <code>{state.correlationId}</code>
            </p>
          )}
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => {
              setState({ kind: "loading" });
              refresh();
            }}
          >
            Retry
          </button>
        </section>
      </div>
    );
  }

  if (state.kind === "authenticated") {
    return (
      <Dashboard
        me={state.me}
        statusSlot={statusSlot}
        onSignedOut={() => {
          setNotice("You have signed out.");
          setState({ kind: "loading" });
          refresh();
        }}
      />
    );
  }

  return (
    <div className="auth-stage">
      <div className="auth-atmosphere" aria-hidden="true" />
      <div className="auth-composition">
        <header className="auth-brand">
          <p className="brand-mark">SentinelDesk</p>
          <p className="auth-tagline">Policy-governed software provisioning</p>
        </header>
        <LoginCard
          providers={state.providers}
          notice={notice}
          onSignedIn={(me) => {
            setNotice(null);
            setState({ kind: "authenticated", me });
          }}
        />
        {statusSlot && <div className="auth-status">{statusSlot}</div>}
      </div>
    </div>
  );
}

function LoginCard({
  providers,
  notice,
  onSignedIn,
}: {
  providers: Providers;
  notice: string | null;
  onSignedIn: (me: Me) => void;
}) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = (event: SyntheticEvent<HTMLFormElement>) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    login(email, password)
      .then((me) => {
        setPassword("");
        onSignedIn(me);
      })
      .catch((err: unknown) => {
        setError(err instanceof ApiError ? err.message : "Sign-in failed.");
      })
      .finally(() => {
        setBusy(false);
      });
  };

  return (
    <section className="auth-panel" aria-labelledby="sign-in-title">
      <h2 id="sign-in-title">Sign in</h2>
      <p className="muted auth-lede">
        Enter SentinelDesk — chat with Sentinel to provision approved software on your devices.
      </p>
      {notice && <p className="notice">{notice}</p>}
      {providers.entra && (
        <p>
          <a className="btn btn-secondary button-link" href={ENTRA_LOGIN_PATH}>
            Sign in with Microsoft
          </a>
        </p>
      )}
      {providers.local ? (
        <form className="login-form" onSubmit={submit} noValidate>
          <label>
            Email
            <input
              type="email"
              autoComplete="username"
              value={email}
              maxLength={254}
              required
              onChange={(e) => {
                setEmail(e.target.value);
              }}
            />
          </label>
          <label>
            Password
            <input
              type="password"
              autoComplete="current-password"
              value={password}
              maxLength={256}
              required
              onChange={(e) => {
                setPassword(e.target.value);
              }}
            />
          </label>
          {error && (
            <p className="form-error" role="alert">
              {error}
            </p>
          )}
          <button type="submit" className="btn btn-primary" disabled={busy || !email || !password}>
            {busy ? "Signing in…" : "Sign in"}
          </button>
        </form>
      ) : (
        !providers.entra && <p className="muted">No sign-in method is configured.</p>
      )}
    </section>
  );
}
