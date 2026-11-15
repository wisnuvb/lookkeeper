import type { ReactNode } from "react";
import { OctagonAlert } from "lucide-react";
import { Label } from "@/components/ui/label";

export interface FieldControlProps {
  id: string;
  "aria-describedby"?: string;
  "aria-invalid"?: true;
  "aria-required"?: true;
}

/**
 * A visible label, optional persistent hint and an error that sits next to the control and is linked
 * to it with aria-describedby. The control is built by the caller through the render prop.
 */
export function Field({
  id,
  label,
  required,
  hint,
  error,
  children,
}: {
  id: string;
  label: string;
  required?: boolean;
  hint?: ReactNode;
  error?: string;
  children: (p: FieldControlProps) => ReactNode;
}) {
  const hintId = hint ? `${id}-hint` : undefined;
  const errorId = error ? `${id}-error` : undefined;
  const describedBy = [hintId, errorId].filter(Boolean).join(" ") || undefined;
  return (
    <div className="space-y-1.5">
      <Label htmlFor={id}>
        {label}
        {required ? <span aria-hidden="true" className="text-destructive"> *</span> : null}
      </Label>
      {children({ id, "aria-describedby": describedBy, "aria-invalid": error ? true : undefined, "aria-required": required ? true : undefined })}
      {hint ? (
        <p id={hintId} className="text-sm text-muted-foreground">
          {hint}
        </p>
      ) : null}
      {error ? (
        <p id={errorId} role="alert" className="flex items-start gap-1.5 text-sm font-medium text-crit">
          <OctagonAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
          {error}
        </p>
      ) : null}
    </div>
  );
}
