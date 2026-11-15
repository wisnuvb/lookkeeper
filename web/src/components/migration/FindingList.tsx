import { useTranslation } from "react-i18next";
import type { Finding, FindingSeverity } from "@/api/types";
import { StatusBadge } from "@/components/StatusBadge";
import { CodeBlock } from "./CodeBlock";

export const SEVERITY_ORDER: FindingSeverity[] = ["blocker", "warning", "info"];

/** Finding text (title, detail, remedy) comes from the server and is shown as received. */
export function FindingList({ findings }: { findings: Finding[] }) {
  const { t } = useTranslation("migration");
  return (
    <ul className="divide-y">
      {findings.map((f) => (
        <li key={f.id} className="space-y-2 py-3">
          <div className="flex flex-wrap items-center gap-2">
            <StatusBadge tone={f.severity} />
            <span className="font-medium">{f.title}</span>
          </div>
          <p className="text-sm text-muted-foreground">{f.detail}</p>
          {f.remedy ? (
            <div className="space-y-1.5">
              <p className="text-sm font-medium">{t("findings.remedy")}</p>
              <CodeBlock code={f.remedy} copyLabel={t("findings.copyRemedy")} failedLabel={t("copyFailed")} />
            </div>
          ) : null}
        </li>
      ))}
    </ul>
  );
}

/** Findings under one heading per severity, blockers first. Empty groups are omitted. */
export function GroupedFindings({ findings }: { findings: Finding[] }) {
  const { t } = useTranslation("migration");
  return (
    <div className="space-y-6">
      {SEVERITY_ORDER.map((sev) => {
        const group = findings.filter((f) => f.severity === sev);
        if (group.length === 0) return null;
        return (
          <section key={sev} aria-labelledby={`find-${sev}`}>
            <h3 id={`find-${sev}`} className="mb-1 text-base font-semibold">
              {t(`findings.group.${sev}`, { count: group.length })}
            </h3>
            <FindingList findings={group} />
          </section>
        );
      })}
    </div>
  );
}
