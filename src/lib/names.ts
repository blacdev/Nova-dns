/**
 * Station names (spec section 1): lowercase letters, digits and hyphens, 3-63
 * characters, no hyphen at either end, no punycode (`xn--`) and no `--` in
 * positions 3-4, not reserved or blocked, not in a cooldown. Uniqueness is the
 * database's job (a unique index), so two claims at once cannot both win.
 */

import type { Queryable } from "../db/db.js";

export const LABEL = /^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])$/;
export const COOLDOWN_DAYS = 30;

export type NameState = "available" | "taken" | "reserved" | "cooldown" | "invalid";

export interface NameCheck {
  label: string;
  state: NameState;
  message: string;
}

/** `KFM`, ` kfm.example.com ` -> `kfm` (the root is taken off when given). */
export function normaliseLabel(input: string, rootDomain: string): string {
  let name = String(input ?? "").trim().toLowerCase().replace(/^[a-z]+:\/\//, "").split("/")[0].split(":")[0].replace(/\.$/, "");
  const root = `.${rootDomain.toLowerCase()}`;
  if (name.endsWith(root)) name = name.slice(0, -root.length);
  return name;
}

/** Why a label breaks the rules, or null when its form is fine. */
export function formError(label: string): string | null {
  if (label.length < 3) return "At least 3 characters.";
  if (label.length > 63) return "At most 63 characters.";
  if (!LABEL.test(label)) return "Only lowercase letters, digits and hyphens, not starting or ending with a hyphen.";
  if (label.startsWith("xn--")) return "Names starting with xn-- are not allowed.";
  if (label.slice(2, 4) === "--") return "A double hyphen in the third and fourth places is not allowed.";
  return null;
}

/** Whether `label` could be claimed now, and why not. */
export async function checkName(db: Queryable, label: string): Promise<NameCheck> {
  const form = formError(label);
  if (form) return { label, state: "invalid", message: form };
  const reserved = await db.query("SELECT kind FROM reserved_names WHERE label = $1", [label]);
  if (reserved.rowCount) return { label, state: "reserved", message: reserved.rows[0].kind === "blocked" ? "This name is not allowed." : "This name is reserved." };
  const cooling = await db.query<{ available_after: Date }>("SELECT available_after FROM name_cooldowns WHERE label = $1 AND available_after > now()", [label]);
  if (cooling.rowCount) return { label, state: "cooldown", message: `This name was recently released; it is free again on ${cooling.rows[0].available_after.toISOString().slice(0, 10)}.` };
  const taken = await db.query("SELECT 1 FROM subdomains WHERE label = $1", [label]);
  if (taken.rowCount) return { label, state: "taken", message: "Someone already has this name." };
  return { label, state: "available", message: "Available." };
}

/** Put a released name in its 30-day cooldown. */
export async function coolDown(db: Queryable, label: string, days = COOLDOWN_DAYS): Promise<void> {
  await db.query(
    "INSERT INTO name_cooldowns (label, available_after) VALUES ($1, now() + make_interval(days => $2)) " +
      "ON CONFLICT (label) DO UPDATE SET available_after = EXCLUDED.available_after",
    [label, days],
  );
}

export const fqdnOf = (label: string, rootDomain: string) => `${label}.${rootDomain}`;
