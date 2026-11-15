import type { ReactElement } from "react";
import { render } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { I18nextProvider } from "react-i18next";
import i18n from "@/i18n";
import { ApiProvider } from "@/api/hooks";
import type { LockkeeperApi } from "@/api/client";
import { createMockApi } from "@/api/mock";

/** Renders a page with the mock API, an isolated query cache and a memory router. */
export function renderPage(ui: ReactElement, opts: { route?: string; api?: LockkeeperApi; lang?: "en" | "id" } = {}) {
  void i18n.changeLanguage(opts.lang ?? "en");
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, refetchInterval: false, gcTime: 0 } } });
  return render(
    <I18nextProvider i18n={i18n}>
      <QueryClientProvider client={client}>
        <ApiProvider api={opts.api ?? createMockApi()}>
          <MemoryRouter initialEntries={[opts.route ?? "/"]}>{ui}</MemoryRouter>
        </ApiProvider>
      </QueryClientProvider>
    </I18nextProvider>,
  );
}
