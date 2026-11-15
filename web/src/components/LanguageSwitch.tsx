import { ChevronDown, Languages } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuLabel, DropdownMenuRadioGroup, DropdownMenuRadioItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { LANGUAGES, type Language } from "@/i18n";

export function LanguageSwitch() {
  const { t, i18n } = useTranslation();
  const current: Language = i18n.language.startsWith("id") ? "id" : "en";
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="sm" aria-label={`${t("language.label")}: ${t(`language.${current}`)}`}>
          <Languages aria-hidden="true" />
          <span aria-hidden="true" className="font-mono text-xs uppercase">{current}</span>
          <ChevronDown aria-hidden="true" className="size-3 opacity-70" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuLabel>{t("language.label")}</DropdownMenuLabel>
        <DropdownMenuRadioGroup value={current} onValueChange={(v) => void i18n.changeLanguage(v)}>
          {LANGUAGES.map((l) => (
            // Each language is written in itself and tagged with its code, so it is findable even if
            // the current UI language is one the visitor cannot read.
            <DropdownMenuRadioItem key={l} value={l} lang={l}>
              {t(`language.${l}`)}
            </DropdownMenuRadioItem>
          ))}
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
