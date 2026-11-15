import { describe, expect, it } from "vitest";
import i18n from "./index";

describe("document language", () => {
  it("follows the UI language so screen readers use the right voice", async () => {
    await i18n.changeLanguage("id");
    expect(document.documentElement.lang).toBe("id");
    await i18n.changeLanguage("en");
    expect(document.documentElement.lang).toBe("en");
  });
  // The startup case (stored preference -> correct lang before first paint) is checked in a real
  // browser, because a unit test cannot re-run the module's init with a different stored language.
});
