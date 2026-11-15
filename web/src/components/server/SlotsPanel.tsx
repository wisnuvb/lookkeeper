import { CircleCheck, CirclePause } from "lucide-react";
import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import type { ReplicationSlot } from "@/api/types";
import { formatBytes } from "@/lib/format";
import { Callout } from "./Callout";

export function SlotsPanel({ slots, serverName }: { slots: ReplicationSlot[]; serverName: string }) {
  const { t, i18n } = useTranslation("server");
  const lang = i18n.language;
  const orphans = slots.filter((s) => !s.active && s.retainedWalBytes > 0);
  const orphanTotal = orphans.reduce((n, s) => n + s.retainedWalBytes, 0);
  const th = "px-4 py-2.5 text-xs font-medium uppercase tracking-wide text-muted-foreground";

  const owner = (s: ReplicationSlot) =>
    s.ownedByMigration ? (
      <Link to={`/migrations/${s.ownedByMigration}`} className="font-medium underline-offset-4 hover:underline">
        {t("slots.ownerMigration", { id: s.ownedByMigration })}
      </Link>
    ) : (
      <span className="text-muted-foreground">{t("slots.ownerNone")}</span>
    );
  const state = (s: ReplicationSlot) =>
    s.active ? (
      <span className="inline-flex items-center gap-1.5">
        <CircleCheck aria-hidden="true" className="size-4 text-ok" />
        {t("slots.active")}
      </span>
    ) : (
      <span className="inline-flex items-center gap-1.5 text-warn">
        <CirclePause aria-hidden="true" className="size-4" />
        {t("slots.inactive")}
      </span>
    );

  return (
    <div className="space-y-4">
      <p className="max-w-prose text-sm text-muted-foreground">{t("slots.readOnlyNote")}</p>

      {orphans.length > 0 ? (
        <Callout tone="warning" title={t("slots.orphanTitle")} role="status">
          <p>{t("slots.orphanBody", { count: orphans.length, names: orphans.map((s) => s.name).join(", "), size: formatBytes(orphanTotal, lang) })}</p>
        </Callout>
      ) : null}

      {slots.length === 0 ? (
        <p className="rounded-xl border border-dashed p-6 text-center text-sm text-muted-foreground">{t("slots.empty")}</p>
      ) : (
        <div className="overflow-x-auto rounded-xl border bg-card">
          <table className="w-full text-sm">
            <caption className="sr-only">{t("slots.tableCaption", { server: serverName })}</caption>
            <thead className="border-b bg-muted/50">
              <tr>
                <th scope="col" className={`${th} text-left`}>{t("slots.columns.name")}</th>
                <th scope="col" className={`${th} text-left`}>{t("slots.columns.type")}</th>
                <th scope="col" className={`${th} text-left`}>{t("slots.columns.database")}</th>
                <th scope="col" className={`${th} text-left`}>{t("slots.columns.state")}</th>
                <th scope="col" className={`${th} text-right`}>{t("slots.columns.retained")}</th>
                <th scope="col" className={`${th} text-left`}>{t("slots.columns.owner")}</th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {slots.map((s) => (
                <tr key={s.name} className="hover:bg-accent/40">
                  <th scope="row" className="wrap-anywhere px-4 py-3 text-left font-mono font-medium">{s.name}</th>
                  <td className="px-4 py-3">{t(`slots.type.${s.type}`)}</td>
                  <td className="px-4 py-3 font-mono">{s.database ?? "–"}</td>
                  <td className="px-4 py-3">{state(s)}</td>
                  <td className="tnum px-4 py-3 text-right font-mono">{formatBytes(s.retainedWalBytes, lang)}</td>
                  <td className="px-4 py-3">{owner(s)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
