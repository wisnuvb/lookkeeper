import { useEffect, useRef, useState } from "react";
import { Check, Copy } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";

/** Copies text to the clipboard. The outcome is announced politely and, on failure, shown as text. */
export function CopyButton({ text, label, failedLabel }: { text: string; label: string; failedLabel: string }) {
  const { t } = useTranslation();
  const [state, setState] = useState<"idle" | "done" | "failed">("idle");
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined);
  useEffect(() => () => clearTimeout(timer.current), []);

  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setState("done");
    } catch {
      setState("failed"); // clipboard blocked (insecure origin, permissions): tell the operator
    }
    clearTimeout(timer.current);
    timer.current = setTimeout(() => setState("idle"), 3000);
  }

  return (
    <span className="inline-flex flex-wrap items-center gap-2">
      <Button variant="outline" size="sm" onClick={() => void copy()} aria-label={label}>
        {state === "done" ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
        {state === "done" ? t("copied") : t("copy")}
      </Button>
      <span role="status" className={state === "failed" ? "text-sm text-crit" : "sr-only"}>
        {state === "failed" ? failedLabel : state === "done" ? t("copied") : ""}
      </span>
    </span>
  );
}
