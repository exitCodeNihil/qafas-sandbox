import type { ReactNode } from "react";
import { Dialog } from "@astryxdesign/core/Dialog";
import { IconButton } from "@astryxdesign/core/IconButton";
import { IconClose } from "./icons";

/**
 * Right-side panel (Daytona's "Create Sandbox" drawer): 560 wide, 32px
 * padding, a 64px header bar with the title and a close button, a scrolling
 * body whose sections are 24 apart, and a sticky 72px footer bar.
 *
 * Astryx has no drawer variant, so this pins a Dialog to the right edge and
 * supplies its own chrome. `purpose="form"` blocks backdrop-click dismissal
 * so an in-progress form isn't lost by a stray click; Esc still closes.
 */
export function Drawer({
  isOpen,
  onOpenChange,
  title,
  footer,
  width = 560,
  children,
}: {
  isOpen: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  footer?: ReactNode;
  width?: number;
  children: ReactNode;
}) {
  return (
    <Dialog
      isOpen={isOpen}
      onOpenChange={onOpenChange}
      purpose="form"
      width={width}
      maxHeight="100vh"
      position={{ top: 0, right: 0, bottom: 0 }}
      style={{ borderRadius: 0, height: "100vh", padding: 0 }}
    >
      <div style={{ display: "flex", flexDirection: "column", height: "100vh", minHeight: 0 }}>
        <div className="sbx-drawer-head">
          <h2 className="sbx-drawer-title">{title}</h2>
          <IconButton
            label="Close"
            variant="ghost"
            size="sm"
            icon={<IconClose width={16} height={16} />}
            onClick={() => onOpenChange(false)}
          />
        </div>
        <div className="sbx-drawer-body">{children}</div>
        {footer && <div className="sbx-drawer-foot">{footer}</div>}
      </div>
    </Dialog>
  );
}

/** A labelled block inside a drawer: 13px label row then its fields. */
export function DrawerSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="sbx-field-group">
      <span className="sbx-field-label">{title}</span>
      {children}
    </div>
  );
}
