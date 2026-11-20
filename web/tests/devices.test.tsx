import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { EnrollDevice, FleetDevices, MyDevices } from "../src/features/devices/DevicePanels";
import { parseDevice, parseEligibleOwners, parseIssuedToken } from "../src/features/devices/api";

const DEVICE = {
  id: "6b0c3c54-2f87-4d43-9c0e-1d1a8c3b2e10",
  device_name: "Synthetic MacBook",
  os_family: "macos",
  os_version: "26.5",
  architecture: "x86_64",
  agent_version: "0.1.0",
  device_status: "ACTIVE",
  last_seen_at: "2026-11-17T10:00:00Z",
  enrolled_at: "2026-11-17T09:00:00Z",
};
const TOKEN = `sde_${"A".repeat(43)}`;
const USERS = {
  items: [
    {
      id: "u1",
      email: "employee.one@sentinel.test",
      display_name: "Employee One",
      is_active: true,
      roles: ["EMPLOYEE"],
    },
    {
      id: "u2",
      email: "auditor@sentinel.test",
      display_name: "Auditor",
      is_active: true,
      roles: ["AUDITOR"],
    },
    {
      id: "u3",
      email: "gone@sentinel.test",
      display_name: "Gone",
      is_active: false,
      roles: ["EMPLOYEE"],
    },
  ],
  total: 3,
  limit: 100,
  offset: 0,
};

function json(body: unknown, status = 200): Response {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

type Handler = (init: RequestInit | undefined) => Response;

function stubFetch(routes: Record<string, Handler>) {
  return vi.spyOn(globalThis, "fetch").mockImplementation((input, init) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const handler = routes[`${init?.method ?? "GET"} ${url}`];
    if (!handler) throw new Error(`unexpected fetch ${init?.method ?? "GET"} ${url}`);
    return Promise.resolve(handler(init));
  });
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("device parsers", () => {
  it("validates device payloads", () => {
    expect(parseDevice(DEVICE).status).toBe("ACTIVE");
    expect(() => parseDevice({ ...DEVICE, device_name: 7 })).toThrow();
  });

  it("offers only active employees as enrollment owners", () => {
    expect(parseEligibleOwners(USERS).map((o) => o.id)).toEqual(["u1"]);
  });

  it("rejects malformed enrollment tokens", () => {
    const base = { token: TOKEN, owner_email: "a@b", expires_at: "2026-11-17T10:10:00Z" };
    expect(parseIssuedToken(base).token).toBe(TOKEN);
    expect(() => parseIssuedToken({ ...base, token: "sde_<script>" })).toThrow();
  });
});

describe("device panels", () => {
  it("lists the employee's own devices", async () => {
    stubFetch({ "GET /api/v1/devices": () => json([DEVICE]) });
    render(<MyDevices />);
    expect(await screen.findByText("Synthetic MacBook")).toBeInTheDocument();
    expect(screen.getByText("ACTIVE")).toBeInTheDocument();
  });

  it("creates a one-time token and hides it on dismiss", async () => {
    const spy = stubFetch({
      "GET /api/v1/admin/users?limit=100": () => json(USERS),
      "POST /api/v1/admin/enrollment-tokens": () =>
        json(
          {
            id: "t1",
            token: TOKEN,
            owner_user_id: "u1",
            owner_email: "employee.one@sentinel.test",
            expires_at: "2026-11-17T10:10:00Z",
          },
          201,
        ),
    });
    document.cookie = "sd_csrf=csrf-1";
    const user = userEvent.setup();
    render(<EnrollDevice />);
    const select = await screen.findByLabelText("Device owner");
    await screen.findByRole("option", { name: /Employee One/ });
    expect(screen.queryByRole("option", { name: /Auditor/ })).toBeNull();
    await user.selectOptions(select, "u1");
    await user.click(screen.getByRole("button", { name: "Create enrollment token" }));

    expect(await screen.findByLabelText("Enrollment token")).toHaveTextContent(TOKEN);
    const post = spy.mock.calls.find(([, init]) => init?.method === "POST");
    expect(post?.[1]?.body).toBe(JSON.stringify({ owner_user_id: "u1" }));
    expect(new Headers(post?.[1]?.headers).get("X-CSRF-Token")).toBe("csrf-1");

    await user.click(screen.getByRole("button", { name: /hide token/ }));
    expect(screen.queryByText(TOKEN)).toBeNull();
    document.cookie = "sd_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT";
  });

  it("quarantines a device only after a reason is chosen", async () => {
    let quarantined = false;
    stubFetch({
      "GET /api/v1/admin/devices": () =>
        json([
          {
            ...DEVICE,
            owner_email: "employee.one@sentinel.test",
            device_status: quarantined ? "QUARANTINED" : "ACTIVE",
          },
        ]),
      [`POST /api/v1/admin/devices/${DEVICE.id}/quarantine`]: (init) => {
        expect(init?.body).toBe(JSON.stringify({ reason: "LOST_DEVICE" }));
        quarantined = true;
        return json(null, 204);
      },
    });
    const user = userEvent.setup();
    render(<FleetDevices />);
    const item = (await screen.findByText("Synthetic MacBook")).closest("li");
    if (!item) throw new Error("device row missing");
    const button = within(item).getByRole("button", { name: "Quarantine" });
    expect(button).toBeDisabled();
    await user.selectOptions(within(item).getByLabelText(/Quarantine reason/), "LOST_DEVICE");
    await user.click(button);
    expect(await screen.findByText("QUARANTINED")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Quarantine" })).toBeNull();
  });
});
