import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";

export default function NotFound() {
  const { t } = useTranslation();
  return (
    <>
      <PageHeader title={t("notFound.title")} description={t("notFound.hint")} />
      <Button asChild>
        <Link to="/">{t("nav.overview")}</Link>
      </Button>
    </>
  );
}
