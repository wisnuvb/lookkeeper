import { useEffect, useState } from "react";
import { ChevronDown, Monitor, Moon, Sun } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuLabel, DropdownMenuRadioGroup, DropdownMenuRadioItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { applyTheme, readTheme, type ThemeChoice } from "@/lib/theme";

const CHOICES: ThemeChoice[] = ["system", "light", "dark"];
const ICON = { system: Monitor, light: Sun, dark: Moon } as const;

export function ThemeToggle() {
  const { t } = useTranslation();
  const [choice, setChoice] = useState<ThemeChoice>(readTheme);

  useEffect(() => {
    applyTheme(choice);
    if (choice !== "system") return;
    // "System" must keep following the OS setting while the app is open.
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const on = () => applyTheme("system");
    mq.addEventListener("change", on);
    return () => mq.removeEventListener("change", on);
  }, [choice]);

  const Icon = ICON[choice];
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="sm" aria-label={`${t("theme.label")}: ${t(`theme.${choice}`)}`}>
          <Icon aria-hidden="true" />
          <ChevronDown aria-hidden="true" className="size-3 opacity-70" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuLabel>{t("theme.label")}</DropdownMenuLabel>
        <DropdownMenuRadioGroup value={choice} onValueChange={(v) => setChoice(v as ThemeChoice)}>
          {CHOICES.map((c) => {
            const ItemIcon = ICON[c];
            return (
              <DropdownMenuRadioItem key={c} value={c}>
                <ItemIcon aria-hidden="true" className="size-4 text-muted-foreground" />
                {t(`theme.${c}`)}
              </DropdownMenuRadioItem>
            );
          })}
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
