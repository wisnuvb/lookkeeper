import * as React from "react";
import { ChevronDown } from "lucide-react";
import { cn } from "@/lib/utils";

/** A styled native select: free keyboard support, free mobile pickers, no extra dependency. */
export const Select = React.forwardRef<HTMLSelectElement, React.SelectHTMLAttributes<HTMLSelectElement>>(({ className, children, ...props }, ref) => (
  <div className="relative">
    <select
      ref={ref}
      className={cn(
        "h-10 w-full appearance-none rounded-md border border-input bg-transparent px-3 pr-9 text-base disabled:cursor-not-allowed disabled:opacity-50 aria-[invalid=true]:border-destructive pointer-coarse:h-11 md:text-sm [&>option]:bg-popover [&>option]:text-popover-foreground",
        className,
      )}
      {...props}
    >
      {children}
    </select>
    <ChevronDown aria-hidden="true" className="pointer-events-none absolute right-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
  </div>
));
Select.displayName = "Select";
