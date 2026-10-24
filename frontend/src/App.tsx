import { BrowserRouter, Route, Routes } from "react-router-dom";
import { AuthProvider } from "./auth/AuthContext";
import { RequireRole } from "./auth/RequireRole";
import { Layout } from "./components/Layout";
import AlertDetail from "./pages/AlertDetail";
import Alerts from "./pages/Alerts";
import Audit from "./pages/Audit";
import AuthComplete from "./pages/AuthComplete";
import HuntPage from "./pages/Hunt";
import Lab from "./pages/Lab";
import Lifecycle from "./pages/Lifecycle";
import Login from "./pages/Login";
import Overview from "./pages/Overview";
import Rules from "./pages/Rules";
import Sessions from "./pages/Sessions";
import Settings from "./pages/Settings";
import Timeline from "./pages/Timeline";

const SEC = ["admin", "analyst"];

export default function App() {
  return (
    <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/auth/complete" element={<AuthComplete />} />
          <Route element={<RequireRole><Layout /></RequireRole>}>
            <Route index element={<RequireRole roles={SEC}><Overview /></RequireRole>} />
            <Route path="alerts" element={<RequireRole roles={SEC}><Alerts /></RequireRole>} />
            <Route path="alerts/:id" element={<RequireRole roles={SEC}><AlertDetail /></RequireRole>} />
            <Route path="hunt" element={<RequireRole roles={SEC}><HuntPage /></RequireRole>} />
            <Route path="timeline" element={<RequireRole roles={SEC}><Timeline /></RequireRole>} />
            <Route path="lifecycle" element={<RequireRole roles={["admin", "hr", "analyst"]}><Lifecycle /></RequireRole>} />
            <Route path="sessions" element={<Sessions />} />
            <Route path="rules" element={<RequireRole roles={SEC}><Rules /></RequireRole>} />
            <Route path="audit" element={<RequireRole roles={SEC}><Audit /></RequireRole>} />
            <Route path="settings" element={<Settings />} />
            <Route path="lab" element={<RequireRole roles={["admin"]}><Lab /></RequireRole>} />
            <Route path="*" element={<p className="p-10 text-center text-slate-500">Page not found.</p>} />
          </Route>
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}
