import { useEffect, useRef } from "react";
import { Activity, ArrowRightLeft, Bell, LayoutDashboard, Server, Settings } from "lucide-react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { cn } from "@/lib/utils";
import { useApi } from "@/api/hooks";
import { LanguageSwitch } from "./LanguageSwitch";
import { ThemeToggle } from "./ThemeToggle";

const NAV = [
  { to: "/", key: "overview", icon: LayoutDashboard, end: true },
  { to: "/servers", key: "servers", icon: Server, end: false },
  { to: "/alerts", key: "alerts", icon: Bell, end: false },
  { to: "/migrations", key: "migrations", icon: ArrowRightLeft, end: false },
  { to: "/settings", key: "settings", icon: Settings, end: false },
] as const;

export function AppShell() {
  const { t } = useTranslation();
  const api = useApi();
  const { pathname } = useLocation();
  const main = useRef<HTMLElement>(null);
  const first = useRef(true);

  // After a route change, move focus to the main region so keyboard and screen-reader users land on
  // the new content instead of staying on the link they activated (WCAG 2.4.3).
  useEffect(() => {
    if (first.current) {
      first.current = false;
      return;
    }
    main.current?.focus({ preventScroll: true });
    window.scrollTo({ top: 0 });
  }, [pathname]);

  return (
    <div className="min-h-dvh md:grid md:grid-cols-[15rem_1fr]">
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-3 focus:top-3 focus:z-50 focus:rounded-md focus:bg-primary focus:px-3 focus:py-2 focus:text-primary-foreground">
        {t("skipToContent")}
      </a>

      <aside className="hidden border-r bg-card md:sticky md:top-0 md:flex md:h-dvh md:flex-col md:self-start md:overflow-y-auto">
        <div className="flex h-14 items-center gap-2 border-b px-4">
          <Activity aria-hidden="true" className="size-5 text-primary" />
          <span className="font-mono text-base font-semibold">{t("appName")}</span>
        </div>
        <nav aria-label={t("nav.label")} className="flex flex-col gap-1 p-3">
          {NAV.map(({ to, key, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                cn("flex h-10 items-center gap-3 rounded-md px-3 text-sm font-medium transition-colors", isActive ? "bg-accent text-accent-foreground" : "text-muted-foreground hover:bg-accent/60 hover:text-foreground")
              }
            >
              <Icon aria-hidden="true" className="size-4" />
              {t(`nav.${key}`)}
            </NavLink>
          ))}
        </nav>
      </aside>

      <div className="flex min-w-0 flex-col pb-16 md:pb-0">
        <header className="sticky top-0 z-30 flex h-14 items-center justify-between gap-2 border-b bg-background/95 px-4 backdrop-blur md:px-6">
          <div className="flex items-center gap-2 md:hidden">
            <Activity aria-hidden="true" className="size-5 text-primary" />
            <span className="font-mono font-semibold">{t("appName")}</span>
          </div>
          <div className="hidden md:block" />
          <div className="flex items-center gap-1">
            <LanguageSwitch />
            <ThemeToggle />
          </div>
        </header>

        {api.isDemo ? (
          <div role="note" className="border-b border-warn/40 bg-warn-soft px-4 py-2 text-sm font-medium text-warn md:px-6">
            {t("demo.banner")}
          </div>
        ) : null}

        <main id="main" ref={main} tabIndex={-1} className="mx-auto w-full max-w-[1400px] flex-1 px-4 py-6 outline-none md:px-6">
          <Outlet />
        </main>
      </div>

      <nav aria-label={t("nav.label")} className="fixed inset-x-0 bottom-0 z-30 grid grid-cols-5 border-t bg-card md:hidden">
        {NAV.map(({ to, key, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) => cn("flex min-h-14 flex-col items-center justify-center gap-0.5 px-1 text-xs font-medium", isActive ? "text-primary" : "text-muted-foreground")}
          >
            <Icon aria-hidden="true" className="size-5" />
            <span className="max-w-full truncate">{t(`nav.${key}`)}</span>
          </NavLink>
        ))}
      </nav>
    </div>
  );
}
