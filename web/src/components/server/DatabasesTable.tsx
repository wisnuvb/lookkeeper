import { useMemo, useState } from "react";
import { ArrowDown, ArrowUp, ChevronsUpDown } from "lucide-react";
import { useTranslation } from "react-i18next";
import type { DatabaseInfo, Engine, Health } from "@/api/types";
import { formatBytes, formatNumber, formatPercent } from "@/lib/format";
import { StatusBadge } from "@/components/StatusBadge";
import { Card, CardContent, CardHeader } from "@/components/ui/card";

type SortKey = "name" | "sizeBytes" | "connections" | "cacheHitRatio" | "xidAgeRatio" | "tablesWithoutPrimaryKey" | "health";
type Dir = "asc" | "desc";

const HEALTH_RANK: Record<Health, number> = { critical: 3, warning: 2, unknown: 1, ok: 0 };
const dash = "–";

function value(d: DatabaseInfo, key: SortKey): number | string | null {
  return key === "health" ? HEALTH_RANK[d.health] : d[key];
}

function compare(a: DatabaseInfo, b: DatabaseInfo, key: SortKey, dir: Dir): number {
  const x = value(a, key);
  const y = value(b, key);
  // Missing values (e.g. XID age on MySQL) always sort last, whichever the direction.
  if (x === null && y === null) return 0;
  if (x === null) return 1;
  if (y === null) return -1;
  const c = typeof x === "string" && typeof y === "string" ? x.localeCompare(y) : Number(x) - Number(y);
  return dir === "asc" ? c : -c;
}

export function DatabasesTable({ databases, engine, serverName }: { databases: DatabaseInfo[]; engine: Engine; serverName: string }) {
  const { t, i18n } = useTranslation("server");
  const lang = i18n.language;
  const [sort, setSort] = useState<{ key: SortKey; dir: Dir }>({ key: "name", dir: "asc" });
  const rows = useMemo(() => [...databases].sort((a, b) => compare(a, b, sort.key, sort.dir)), [databases, sort]);

  const columns: Array<{ key: SortKey; label: string; numeric?: boolean }> = [
    { key: "name", label: t("databases.columns.name") },
    { key: "sizeBytes", label: t("databases.columns.size"), numeric: true },
    { key: "connections", label: t("databases.columns.connections"), numeric: true },
    { key: "cacheHitRatio", label: t("databases.columns.cacheHit"), numeric: true },
    { key: "xidAgeRatio", label: t("databases.columns.xidAge"), numeric: true },
    { key: "tablesWithoutPrimaryKey", label: t("databases.columns.noPk"), numeric: true },
    { key: "health", label: t("databases.columns.health") },
  ];

  const toggle = (key: SortKey) => setSort((s) => (s.key === key ? { key, dir: s.dir === "asc" ? "desc" : "asc" } : { key, dir: "asc" }));
  const xid = (d: DatabaseInfo) => (engine === "postgres" && d.xidAgeRatio !== null ? formatPercent(d.xidAgeRatio, lang, 0) : dash);
  const noPk = (d: DatabaseInfo) => (d.tablesWithoutPrimaryKey > 0 ? <StatusBadge tone="warning" label={formatNumber(d.tablesWithoutPrimaryKey, lang)} /> : <span className="tnum font-mono">0</span>);

  return (
    <>
      <div className="hidden overflow-x-auto rounded-xl border bg-card md:block">
        <table className="w-full text-sm">
          <caption className="sr-only">{t("databases.tableCaption", { server: serverName })}</caption>
          <thead className="border-b bg-muted/50">
            <tr>
              {columns.map((c) => {
                const active = sort.key === c.key;
                const ariaSort = active ? (sort.dir === "asc" ? "ascending" : "descending") : "none";
                const Icon = !active ? ChevronsUpDown : sort.dir === "asc" ? ArrowUp : ArrowDown;
                return (
                  <th key={c.key} scope="col" aria-sort={ariaSort} className={`px-4 py-2.5 text-xs font-medium uppercase tracking-wide text-muted-foreground ${c.numeric ? "text-right" : "text-left"}`}>
                    <button
                      type="button"
                      onClick={() => toggle(c.key)}
                      aria-label={t("databases.sortBy", { column: c.label })}
                      className={`-mx-1 inline-flex min-h-8 items-center gap-1 rounded px-1 uppercase tracking-wide hover:text-foreground ${c.numeric ? "flex-row-reverse" : ""}`}
                    >
                      <span>{c.label}</span>
                      <Icon aria-hidden="true" className="size-3.5 shrink-0" />
                    </button>
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody className="divide-y">
            {rows.map((d) => (
              <tr key={d.name} className="hover:bg-accent/40">
                <th scope="row" className="wrap-anywhere px-4 py-3 text-left font-mono font-medium">{d.name}</th>
                <td className="tnum px-4 py-3 text-right font-mono">{formatBytes(d.sizeBytes, lang)}</td>
                <td className="tnum px-4 py-3 text-right font-mono">{formatNumber(d.connections, lang)}</td>
                <td className="tnum px-4 py-3 text-right font-mono">{d.cacheHitRatio !== null ? formatPercent(d.cacheHitRatio, lang) : dash}</td>
                <td className="tnum px-4 py-3 text-right font-mono">{xid(d)}</td>
                <td className="px-4 py-3 text-right">{noPk(d)}</td>
                <td className="px-4 py-3"><StatusBadge tone={d.health} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <ul className="grid gap-3 sm:grid-cols-2 md:hidden">
        {rows.map((d) => (
          <li key={d.name}>
            <Card>
              <CardHeader className="flex-row items-start justify-between gap-2">
                <h3 className="wrap-anywhere font-mono text-base font-semibold">{d.name}</h3>
                <StatusBadge tone={d.health} />
              </CardHeader>
              <CardContent>
                <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
                  <Item label={t("databases.columns.size")} v={formatBytes(d.sizeBytes, lang)} />
                  <Item label={t("databases.columns.connections")} v={formatNumber(d.connections, lang)} />
                  <Item label={t("databases.columns.cacheHit")} v={d.cacheHitRatio !== null ? formatPercent(d.cacheHitRatio, lang) : dash} />
                  <Item label={t("databases.columns.xidAge")} v={xid(d)} />
                  <Item label={t("databases.columns.noPk")} v={formatNumber(d.tablesWithoutPrimaryKey, lang)} />
                </dl>
              </CardContent>
            </Card>
          </li>
        ))}
      </ul>
    </>
  );
}

function Item({ label, v }: { label: string; v: string }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="tnum font-mono">{v}</dd>
    </div>
  );
}
