import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
// Self-hosted fonts (Latin subset only): no CDN, as required by the CSP (ADR 0005/0006).
import "@fontsource/fira-sans/latin-400.css";
import "@fontsource/fira-sans/latin-500.css";
import "@fontsource/fira-sans/latin-600.css";
import "@fontsource/fira-sans/latin-700.css";
import "@fontsource/fira-code/latin-400.css";
import "@fontsource/fira-code/latin-500.css";
import "./index.css";
import "./i18n";
import { applyCspNonce } from "@/lib/csp";
import { applyTheme, readTheme } from "@/lib/theme";
import { ApiProvider } from "@/api/hooks";
import { createMockApi } from "@/api/mock";
import App from "./App";

applyCspNonce(); // before anything can open a menu or dialog
applyTheme(readTheme());

// U0: the mock. U2 replaces this one line with the HTTP implementation of LockkeeperApi.
const api = createMockApi();
const queryClient = new QueryClient({ defaultOptions: { queries: { retry: 1, refetchOnWindowFocus: true } } });

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <ApiProvider api={api}>
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </ApiProvider>
    </QueryClientProvider>
  </StrictMode>,
);
