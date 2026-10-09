import { VStack, HStack } from "@astryxdesign/core/Stack";
import { Text } from "@astryxdesign/core/Text";
import { TextInput } from "@astryxdesign/core/TextInput";
import { IconButton } from "@astryxdesign/core/IconButton";
import { Button } from "@astryxdesign/core/Button";
import { IconTrash, IconPlus } from "./icons";

export type KVRow = { key: string; value: string };

/** `KEY=VALUE` lines from a pasted .env file (quotes stripped, comments and
 * blank lines skipped). Returns null when the paste doesn't look like one. */
function parseEnvPaste(text: string): KVRow[] | null {
  const lines = text.split(/\r?\n/);
  const rows: KVRow[] = [];
  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const m = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (!m) continue;
    let value = m[2];
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    rows.push({ key: m[1], value });
  }
  // Require at least two matches (or one with an actual '=' body) so a
  // plain single-word paste into a key field still behaves like normal text.
  return rows.length > 0 && (rows.length > 1 || text.includes("\n")) ? rows : null;
}

/**
 * Key/value rows with add/remove — used for both Environment Variables and
 * Labels in the create drawers. When `hasEnvPaste` is set, pasting a whole
 * `.env` file's contents into any key field explodes it into rows, Daytona-
 * style, instead of pasting literally.
 */
export function KeyValueEditor({
  label,
  rows,
  onChange,
  addLabel = "Add variable",
  keyPlaceholder = "KEY",
  valuePlaceholder = "value",
  hasEnvPaste = false,
}: {
  label: string;
  rows: KVRow[];
  onChange: (rows: KVRow[]) => void;
  addLabel?: string;
  keyPlaceholder?: string;
  valuePlaceholder?: string;
  hasEnvPaste?: boolean;
}) {
  const set = (i: number, patch: Partial<KVRow>) => onChange(rows.map((r, idx) => (idx === i ? { ...r, ...patch } : r)));
  const remove = (i: number) => onChange(rows.filter((_, idx) => idx !== i));
  const add = () => onChange([...rows, { key: "", value: "" }]);

  const onKeyPaste = (i: number, e: React.ClipboardEvent<HTMLElement>) => {
    if (!hasEnvPaste) return;
    const text = e.clipboardData.getData("text");
    const parsed = parseEnvPaste(text);
    if (!parsed) return;
    e.preventDefault();
    const next = [...rows];
    next.splice(i, 1, ...parsed);
    onChange(next.filter((r) => r.key || r.value));
  };

  return (
    <VStack gap={2}>
      <Text type="body" style={{ fontSize: 13, fontWeight: 500 }}>
        {label}
      </Text>
      {rows.map((r, i) => (
        <HStack key={i} gap={2} vAlign="center">
          <TextInput
            label={`${label} key ${i + 1}`}
            isLabelHidden
            size="sm"
            value={r.key}
            onChange={(v) => set(i, { key: v })}
            onPaste={(e) => onKeyPaste(i, e)}
            placeholder={keyPlaceholder}
            width="45%"
          />
          <TextInput
            label={`${label} value ${i + 1}`}
            isLabelHidden
            size="sm"
            value={r.value}
            onChange={(v) => set(i, { value: v })}
            placeholder={valuePlaceholder}
            width="45%"
          />
          <IconButton label="Remove" variant="ghost" size="sm" icon={<IconTrash width={14} height={14} />} onClick={() => remove(i)} />
        </HStack>
      ))}
      <HStack gap={2} vAlign="center">
        <Button label={addLabel} size="sm" variant="secondary" icon={<IconPlus width={14} height={14} />} onClick={add} />
        {hasEnvPaste && (
          <Text type="body" color="secondary" style={{ fontSize: 12 }}>
            Paste .env contents into any key field
          </Text>
        )}
      </HStack>
    </VStack>
  );
}
