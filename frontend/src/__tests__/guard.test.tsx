import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";

const state = { status: "signed-in", roles: ["user"] };
vi.mock("../auth/AuthContext", () => ({
  useAuth: () => ({
    status: state.status,
    me: { roles: state.roles },
    hasRole: (...r: string[]) => r.some((x) => state.roles.includes(x)),
  }),
}));

import { RequireRole } from "../auth/RequireRole";

function renderAt(roles?: string[]) {
  return render(
    <MemoryRouter initialEntries={["/alerts"]}>
      <Routes>
        <Route path="/login" element={<p>login page</p>} />
        <Route path="/alerts" element={<RequireRole roles={roles}><p>secret alerts</p></RequireRole>} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("RequireRole", () => {
  it("redirects signed-out users to login", () => {
    state.status = "signed-out";
    renderAt(["admin"]);
    expect(screen.getByText("login page")).toBeInTheDocument();
  });

  it("blocks users without the role", () => {
    state.status = "signed-in";
    state.roles = ["user"];
    renderAt(["admin", "analyst"]);
    expect(screen.queryByText("secret alerts")).not.toBeInTheDocument();
    expect(screen.getByText("Access denied")).toBeInTheDocument();
  });

  it("allows users with the role", () => {
    state.roles = ["analyst"];
    renderAt(["admin", "analyst"]);
    expect(screen.getByText("secret alerts")).toBeInTheDocument();
  });
});
