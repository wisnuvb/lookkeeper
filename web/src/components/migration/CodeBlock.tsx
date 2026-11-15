import { CopyButton } from "@/components/form/CopyButton";

/** A command or SQL text exactly as it will be used, wrapped (never clipped) and copyable. */
export function CodeBlock({ code, copyLabel, failedLabel }: { code: string; copyLabel: string; failedLabel: string }) {
  return (
    <div className="rounded-md border bg-muted">
      {/* Scrollable region: focusable so keyboard users can scroll it. */}
      <pre tabIndex={0} className="wrap-anywhere max-h-60 overflow-auto whitespace-pre-wrap p-3 font-mono text-xs leading-relaxed">
        <code>{code}</code>
      </pre>
      <div className="flex justify-end border-t p-1.5">
        <CopyButton text={code} label={copyLabel} failedLabel={failedLabel} />
      </div>
    </div>
  );
}
