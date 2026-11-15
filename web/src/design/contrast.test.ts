// @vitest-environment node
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// Parses src/index.css and measures WCAG contrast for every token pair that carries text or a
// meaningful control boundary. This is how "contrast is measured, not assumed" is enforced.

const css = readFileSync(fileURLToPath(new URL("../index.css", import.meta.url)), "utf8");

function block(selector: string): Record<string, string> {
  const start = css.indexOf(`${selector} {`);
  if (start < 0) throw new Error(`block ${selector} not found`);
  const body = css.slice(css.indexOf("{", start) + 1, css.indexOf("}", start));
  const out: Record<string, string> = {};
  for (const m of body.matchAll(/--([a-z0-9-]+):\s*(#[0-9a-fA-F]{6})\s*;/g)) out[m[1]!] = m[2]!;
  return out;
}

function lum(hex: string): number {
  const c = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255);
  const [r, g, b] = c.map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4)) as [number, number, number];
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}
function ratio(a: string, b: string): number {
  const [hi, lo] = [lum(a), lum(b)].sort((x, y) => y - x) as [number, number];
  return (hi + 0.05) / (lo + 0.05);
}

const themes = { light: block(":root"), dark: block(".dark") };
const status = ["ok", "warn", "crit", "info", "unknown"];

describe.each(Object.entries(themes))("%s theme contrast", (_name, t) => {
  const get = (k: string) => {
    const v = t[k];
    if (!v) throw new Error(`token --${k} missing`);
    return v;
  };

  const textPairs: Array<[string, string]> = [
    ["foreground", "background"],
    ["card-foreground", "card"],
    ["popover-foreground", "popover"],
    ["muted-foreground", "background"],
    ["muted-foreground", "card"],
    ["muted-foreground", "muted"],
    ["secondary-foreground", "secondary"],
    ["accent-foreground", "accent"],
    ["primary-foreground", "primary"],
    ["destructive-foreground", "destructive"],
    ["primary", "background"], // links / accents used as text
    ["primary", "card"],
    ...status.flatMap((s): Array<[string, string]> => [
      [s, "card"],
      [s, "background"],
      [s, `${s}-soft`],
    ]),
  ];
  it.each(textPairs)("text %s on %s is at least 4.5:1", (fg, bg) => {
    expect(ratio(get(fg), get(bg))).toBeGreaterThanOrEqual(4.5);
  });

  const nonText: Array<[string, string]> = [
    ["input", "background"],
    ["input", "card"],
    ["ring", "background"],
    ["ring", "card"],
    ["chart-1", "card"],
    ["chart-2", "card"],
    ["chart-3", "card"],
    ["chart-4", "card"],
  ];
  it.each(nonText)("non-text %s on %s is at least 3:1", (fg, bg) => {
    expect(ratio(get(fg), get(bg))).toBeGreaterThanOrEqual(3);
  });
});
