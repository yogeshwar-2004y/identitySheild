import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import "./index.css";

try {
  if ((localStorage.getItem("is-theme") ?? (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light")) === "dark") {
    document.documentElement.classList.add("dark");
  }
} catch {
  /* storage unavailable */
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
