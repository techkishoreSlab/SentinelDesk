import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { SessionPanel } from "../src/features/session/SessionPanel";
import { loginErrorMessage, parseMe } from "../src/features/session/api";
import { readCsrfToken } from "../src/lib/api";

// Unit tests stub `fetch`; the real session flow is covered by backend integration tests
// and the manual browser validation.
const ME = {
  id: "8d0f6a3e-0000-4000-8000-000000000001",
  email: "employee.one@sentinel.test",
  display_name: "Employee One (synthetic)",
  identity_provider: "local",
  roles: ["EMPLOYEE"],
  permissions: ["request:create"],
};

function json(body: unknown, status = 200): Response {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "x-correlation-id": "cid" },
  });
}

const UNAUTH = {
  error: { code: "UNAUTHENTICATED", message: "Sign in required.", correlation_id: "c" },
};

type Handler = (init: RequestInit | undefined) => Response;

function stubFetch(routes: Record<string, Handler>) {
  return vi.spyOn(globalThis, "fetch").mockImplementation((input, init) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const method = init?.method ?? "GET";
    const handler = routes[`${method} ${url}`];
    if (!handler) throw new Error(`unexpected fetch ${method} ${url}`);
    return Promise.resolve(handler(init));
  });
}

afterEach(() => {
  document.cookie = "sd_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT";
  window.history.replaceState(null, "", "/");
});

describe("session helpers", () => {
  it("reads the CSRF cookie by exact name", () => {
    expect(readCsrfToken("a=1; sd_csrf=tok-123; b=2")).toBe("tok-123");
    expect(readCsrfToken("__Host-sd_csrf=prod-tok")).toBe("prod-tok");
    expect(readCsrfToken("not_sd_csrf=x")).toBeNull();
  });

  it("validates the /me payload", () => {
    expect(parseMe(ME).displayName).toBe("Employee One (synthetic)");
    expect(() => parseMe({ ...ME, roles: [1] })).toThrow();
    expect(() => parseMe({ ...ME, identity_provider: "github" })).toThrow();
  });

  it("maps only known login error codes", () => {
    expect(loginErrorMessage("ACCOUNT_LINK_REQUIRED")).toMatch(/already exists/);
    expect(loginErrorMessage("<script>alert(1)</script>")).toMatch(/did not complete/);
    expect(loginErrorMessage(null)).toBeNull();
  });
});

describe("SessionPanel", () => {
  it("shows the login form and hides Microsoft when Entra is not configured", async () => {
    stubFetch({
      "GET /api/v1/me": () => json(UNAUTH, 401),
      "GET /api/v1/auth/providers": () => json({ local: true, entra: false }),
    });
    render(<SessionPanel />);
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    expect(screen.queryByText("Sign in with Microsoft")).toBeNull();
  });

  it("offers Microsoft sign-in as a top-level navigation when configured", async () => {
    stubFetch({
      "GET /api/v1/me": () => json(UNAUTH, 401),
      "GET /api/v1/auth/providers": () => json({ local: false, entra: true }),
    });
    render(<SessionPanel />);
    const link = await screen.findByRole("link", { name: "Sign in with Microsoft" });
    expect(link).toHaveAttribute("href", "/api/v1/auth/entra/login");
    expect(screen.queryByLabelText("Password")).toBeNull();
  });

  it("signs in, shows roles, then signs out with the CSRF header", async () => {
    const fetchSpy = stubFetch({
      "GET /api/v1/me": () => json(UNAUTH, 401),
      "GET /api/v1/auth/providers": () => json({ local: true, entra: false }),
      "POST /api/v1/auth/login": () => {
        document.cookie = "sd_csrf=csrf-abc";
        return json(ME);
      },
      "POST /api/v1/auth/logout": () => json(null, 204),
    });
    render(<SessionPanel />);
    await userEvent.type(await screen.findByLabelText("Email"), "employee.one@sentinel.test");
    await userEvent.type(screen.getByLabelText("Password"), "a-password-value");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));

    expect(await screen.findByText("Employee One (synthetic)")).toBeInTheDocument();
    expect(screen.getByText("EMPLOYEE")).toBeInTheDocument();
    const loginCall = fetchSpy.mock.calls.find(([, init]) => init?.method === "POST");
    expect(loginCall?.[1]?.credentials).toBe("same-origin");

    await userEvent.click(screen.getByRole("button", { name: "Sign out" }));
    expect(await screen.findByText("You have signed out.")).toBeInTheDocument();
    const logoutCall = fetchSpy.mock.calls.find(([url]) => url === "/api/v1/auth/logout");
    expect((logoutCall?.[1]?.headers as Record<string, string>)["X-CSRF-Token"]).toBe("csrf-abc");
  });

  it("shows the server's generic error on bad credentials", async () => {
    stubFetch({
      "GET /api/v1/me": () => json(UNAUTH, 401),
      "GET /api/v1/auth/providers": () => json({ local: true, entra: false }),
      "POST /api/v1/auth/login": () =>
        json(
          {
            error: {
              code: "INVALID_CREDENTIALS",
              message: "The email or password is incorrect.",
              correlation_id: "c",
            },
          },
          401,
        ),
    });
    render(<SessionPanel />);
    await userEvent.type(await screen.findByLabelText("Email"), "x@sentinel.test");
    await userEvent.type(screen.getByLabelText("Password"), "wrong");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "The email or password is incorrect.",
    );
  });

  it("shows a whitelisted Entra error and strips it from the URL", async () => {
    window.history.replaceState(null, "", "/?login_error=ACCOUNT_LINK_REQUIRED");
    stubFetch({
      "GET /api/v1/me": () => json(UNAUTH, 401),
      "GET /api/v1/auth/providers": () => json({ local: true, entra: true }),
    });
    render(<SessionPanel />);
    expect(await screen.findByText(/already exists/)).toBeInTheDocument();
    expect(window.location.search).toBe("");
  });

  it("renders the signed-in user directly when a session exists", async () => {
    stubFetch({ "GET /api/v1/me": () => json({ ...ME, display_name: "<b>x</b>" }) });
    const { container } = render(<SessionPanel />);
    expect(await screen.findByText("<b>x</b>")).toBeInTheDocument();
    expect(container.querySelector("b")).toBeNull();
  });
});
