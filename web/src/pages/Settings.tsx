import { Settings as SettingsIcon } from "lucide-react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { EmptyState } from "@/components/States";

export default function Settings() {
  const { t } = useTranslation("settings");
  const items = ["users", "vault", "channels", "retention", "audit"] as const;
  return (
    <>
      <PageHeader title={t("title")} description={t("subtitle")} />
      <EmptyState icon={<SettingsIcon className="size-8" />} title={t("notBuiltTitle")} hint={t("notBuiltHint")} />
      <h2 className="mb-2 mt-6 text-sm font-medium text-muted-foreground">{t("planned")}</h2>
      <ul className="list-inside list-disc space-y-1 text-sm">
        {items.map((k) => (
          <li key={k}>{t(`items.${k}`)}</li>
        ))}
      </ul>
    </>
  );
}
