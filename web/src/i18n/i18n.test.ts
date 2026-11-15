// @vitest-environment node
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// Indonesian and English must stay in lock-step: same files, same keys, same {{placeholders}}.
const root = fileURLToPath(new URL(".", import.meta.url));
const load = (lng: string) =>
  Object.fromEntries(
    readdirSync(`${root}${lng}`)
      .filter((f) => f.endsWith(".json"))
      .map((f) => [f, JSON.parse(readFileSync(`${root}${lng}/${f}`, "utf8")) as Record<string, unknown>]),
  );

function flatten(o: Record<string, unknown>, prefix = ""): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(o)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === "object") Object.assign(out, flatten(v as Record<string, unknown>, key));
    else out[key] = String(v);
  }
  return out;
}
const placeholders = (s: string) => [...s.matchAll(/\{\{\s*([a-zA-Z0-9_]+)\s*\}\}/g)].map((m) => m[1]!).sort().join(",");

const en = load("en");
const id = load("id");

describe("i18n parity (en <-> id)", () => {
  it("has the same namespace files", () => {
    expect(Object.keys(id).sort()).toEqual(Object.keys(en).sort());
  });
  for (const file of Object.keys(en)) {
    it(`${file}: same keys and placeholders`, () => {
      const a = flatten(en[file]!);
      const b = flatten(id[file] ?? {});
      expect(Object.keys(b).sort()).toEqual(Object.keys(a).sort());
      for (const k of Object.keys(a)) {
        expect(placeholders(b[k] ?? ""), `placeholders of ${file}:${k}`).toEqual(placeholders(a[k]!));
        expect((b[k] ?? "").trim().length, `${file}:${k} is empty in id`).toBeGreaterThan(0);
      }
    });
  }
});
