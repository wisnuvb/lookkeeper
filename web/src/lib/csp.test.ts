import { describe, expect, it } from "vitest";
import { applyCspNonce, NONCE_PLACEHOLDER } from "./csp";

function docWith(content: string | null): Document {
  const d = document.implementation.createHTMLDocument("t");
  if (content !== null) {
    const m = d.createElement("meta");
    m.setAttribute("name", "csp-nonce");
    m.setAttribute("content", content);
    d.head.appendChild(m);
  }
  return d;
}

describe("applyCspNonce", () => {
  it("publishes the server's nonce where Radix looks for it", () => {
    const target: { __webpack_nonce__?: string } = {};
    expect(applyCspNonce(docWith("abc123=="), target)).toBe("abc123==");
    expect(target.__webpack_nonce__).toBe("abc123==");
  });

  it("ignores the unreplaced placeholder (Vite dev server), an empty value and a missing tag", () => {
    for (const d of [docWith(NONCE_PLACEHOLDER), docWith(""), docWith("   "), docWith(null)]) {
      const target: { __webpack_nonce__?: string } = {};
      expect(applyCspNonce(d, target)).toBe("");
      expect(target.__webpack_nonce__).toBeUndefined();
    }
  });
});
