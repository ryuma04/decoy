import React from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { AlertTriangle, X } from "lucide-react";

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: string;
  confirmLabel?: string;
  danger?: boolean;
  onConfirm: () => void | Promise<void>;
  loading?: boolean;
}

export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel = "Confirm Action",
  danger = true,
  onConfirm,
  loading = false,
}: Props) {
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/40 backdrop-blur-xs animate-in fade-in" />
        <Dialog.Content className="fixed left-1/2 top-1/2 z-50 w-full max-w-md -translate-x-1/2 -translate-y-1/2 rounded-[16px] border border-hairline bg-elevated p-6 shadow-xl animate-in fade-in zoom-in-95">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-full bg-amber-50 text-amber-600 border border-amber-200">
                <AlertTriangle className="h-5 w-5" />
              </div>
              <div>
                <Dialog.Title className="text-[17px] font-semibold text-ink">
                  {title}
                </Dialog.Title>
                <span className="inline-block mt-0.5 rounded px-2 py-0.5 text-[11px] font-mono font-medium uppercase tracking-wide bg-amber-100 text-amber-900 border border-amber-200">
                  Lab environment only
                </span>
              </div>
            </div>
            <Dialog.Close asChild>
              <button
                className="rounded-md p-1.5 text-mute hover:bg-hairline hover:text-ink"
                aria-label="Close"
              >
                <X className="h-4 w-4" />
              </button>
            </Dialog.Close>
          </div>

          <Dialog.Description className="mt-4 text-[13px] leading-relaxed text-body">
            {description}
          </Dialog.Description>

          <div className="mt-6 flex justify-end gap-3">
            <Dialog.Close asChild>
              <button type="button" className="btn" disabled={loading}>
                Cancel
              </button>
            </Dialog.Close>
            <button
              type="button"
              onClick={async () => {
                await onConfirm();
                onOpenChange(false);
              }}
              disabled={loading}
              className={`btn ${
                danger
                  ? "bg-[#ee0000] text-white border-[#ee0000] hover:bg-[#c50000]"
                  : "btn-primary"
              }`}
            >
              {loading ? "Applying..." : confirmLabel}
            </button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
