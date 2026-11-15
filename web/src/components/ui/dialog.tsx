import * as React from "react";
import * as DialogPrimitive from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import { useTranslation } from "react-i18next";
import { cn } from "@/lib/utils";

export const Dialog = DialogPrimitive.Root;
export const DialogTrigger = DialogPrimitive.Trigger;
export const DialogClose = DialogPrimitive.Close;

export const DialogContent = React.forwardRef<React.ComponentRef<typeof DialogPrimitive.Content>, React.ComponentPropsWithoutRef<typeof DialogPrimitive.Content>>(
  ({ className, children, ...props }, ref) => {
    const { t } = useTranslation();
    return (
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className="fixed inset-0 z-40 bg-black/60 lk-pop" />
        <DialogPrimitive.Content
          ref={ref}
          className={cn(
            "fixed left-1/2 top-1/2 z-50 grid max-h-[90dvh] w-[calc(100%-2rem)] max-w-lg -translate-x-1/2 -translate-y-1/2 gap-4 overflow-y-auto rounded-xl border bg-popover p-5 text-popover-foreground shadow-lg lk-pop",
            className,
          )}
          {...props}
        >
          {children}
          <DialogPrimitive.Close className="absolute right-3 top-3 inline-flex size-9 items-center justify-center rounded-md text-muted-foreground hover:bg-accent hover:text-foreground">
            <X aria-hidden="true" className="size-4" />
            <span className="sr-only">{t("close")}</span>
          </DialogPrimitive.Close>
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    );
  },
);
DialogContent.displayName = "DialogContent";
export const DialogHeader = ({ className, ...p }: React.HTMLAttributes<HTMLDivElement>) => <div className={cn("flex flex-col gap-1.5 pr-8", className)} {...p} />;
export const DialogFooter = ({ className, ...p }: React.HTMLAttributes<HTMLDivElement>) => (
  <div className={cn("flex flex-col-reverse gap-2 sm:flex-row sm:justify-end", className)} {...p} />
);
export const DialogTitle = React.forwardRef<React.ComponentRef<typeof DialogPrimitive.Title>, React.ComponentPropsWithoutRef<typeof DialogPrimitive.Title>>(
  ({ className, ...p }, ref) => <DialogPrimitive.Title ref={ref} className={cn("text-lg font-semibold leading-tight", className)} {...p} />,
);
DialogTitle.displayName = "DialogTitle";
export const DialogDescription = React.forwardRef<React.ComponentRef<typeof DialogPrimitive.Description>, React.ComponentPropsWithoutRef<typeof DialogPrimitive.Description>>(
  ({ className, ...p }, ref) => <DialogPrimitive.Description ref={ref} className={cn("text-sm text-muted-foreground", className)} {...p} />,
);
DialogDescription.displayName = "DialogDescription";
