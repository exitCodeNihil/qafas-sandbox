import { useState } from "react";
import { MoreMenu } from "@astryxdesign/core/MoreMenu";
import { useImperativeAlertDialog } from "@astryxdesign/core/AlertDialog";
import type { DropdownMenuOption } from "@astryxdesign/core/DropdownMenu";
import { lifecycleActions, canDelete } from "../lib/sandboxActions";
import { useSandboxActions } from "../lib/sandboxLifecycle";
import { IconPlay, IconPause, IconStop, IconArchiveBox, IconTrash } from "./icons";
import type { SandboxInfo } from "../lib/types";

const VERB_ICON = {
  stop: IconStop,
  start: IconPlay,
  pause: IconPause,
  resume: IconPlay,
  archive: IconArchiveBox,
} as const;

/**
 * Row-level lifecycle menu — same actions and disabled logic on the
 * Sandboxes table and the sandbox detail header.
 */
export function SandboxRowMenu({ sandbox, variant = "ghost" }: { sandbox: SandboxInfo; variant?: "ghost" | "secondary" }) {
  const { runVerb, destroy } = useSandboxActions();
  const alertDialog = useImperativeAlertDialog();
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState(false);

  if (sandbox.state === "destroyed") return null;

  const confirmDelete = () => {
    alertDialog.show({
      title: `Delete ${sandbox.name || sandbox.id}?`,
      description: "This stops the sandbox immediately and any in-flight tool calls will fail. This cannot be undone.",
      actionLabel: "Delete",
      onAction: async () => {
        setBusy(true);
        await destroy(sandbox);
        setBusy(false);
        alertDialog.hide();
      },
    });
  };

  const items: DropdownMenuOption[] = [
    ...lifecycleActions(sandbox).map((a) => ({
      label: a.disabledReason ? `${a.label} (${a.disabledReason})` : a.label,
      icon: VERB_ICON[a.verb],
      isDisabled: !!a.disabledReason || busy,
      onClick: () => {
        setBusy(true);
        void runVerb(sandbox, a.verb).finally(() => setBusy(false));
      },
    })),
    { type: "divider" as const },
    {
      label: "Delete",
      icon: IconTrash,
      isDisabled: !canDelete(sandbox) || busy,
      onClick: confirmDelete,
    },
  ];

  return (
    <>
      <MoreMenu items={items} label={`Actions for ${sandbox.name || sandbox.id}`} variant={variant} isMenuOpen={open} onOpenChange={setOpen} />
      {/* On the detail page header (variant="secondary") the menu floats right above the
       * info grid; reserving its own height while open pushes that grid down instead of
       * the panel silently covering values like Auto-stop. Table-row usage (variant
       * "ghost") has no grid beneath it to protect, so it skips this. */}
      {variant === "secondary" && open && <div style={{ height: items.length * 34 + 24 }} aria-hidden="true" />}
      {alertDialog.element}
    </>
  );
}
