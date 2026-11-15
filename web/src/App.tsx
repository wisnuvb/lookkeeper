import { lazy, Suspense } from "react";
import { Route, Routes } from "react-router-dom";
import { AppShell } from "@/components/AppShell";
import { CardGridSkeleton } from "@/components/States";

// Routes load on demand to keep the first paint small (the UI is embedded in the Go binary).
const Overview = lazy(() => import("@/pages/Overview"));
const Servers = lazy(() => import("@/pages/Servers"));
const ServerDetail = lazy(() => import("@/pages/ServerDetail"));
const AddServer = lazy(() => import("@/pages/AddServer"));
const Alerts = lazy(() => import("@/pages/Alerts"));
const Migrations = lazy(() => import("@/pages/Migrations"));
const MigrationNew = lazy(() => import("@/pages/MigrationNew"));
const MigrationRun = lazy(() => import("@/pages/MigrationRun"));
const Settings = lazy(() => import("@/pages/Settings"));
const NotFound = lazy(() => import("@/pages/NotFound"));

export default function App() {
  return (
    <Suspense fallback={<div className="p-6"><CardGridSkeleton /></div>}>
      <Routes>
        <Route element={<AppShell />}>
          <Route index element={<Overview />} />
          <Route path="servers" element={<Servers />} />
          <Route path="servers/new" element={<AddServer />} />
          <Route path="servers/:id" element={<ServerDetail />} />
          <Route path="alerts" element={<Alerts />} />
          <Route path="migrations" element={<Migrations />} />
          <Route path="migrations/new" element={<MigrationNew />} />
          <Route path="migrations/:id" element={<MigrationRun />} />
          <Route path="settings" element={<Settings />} />
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
    </Suspense>
  );
}
