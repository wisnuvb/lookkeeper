// The server serves index.html with a per-response CSP nonce in <meta name="csp-nonce"> (internal/web).
// Radix UI injects a <style> element when a menu or dialog locks page scroll; it reads its nonce from
// the global __webpack_nonce__ (the `get-nonce` convention). Without this hand-over a strict CSP
// blocks that style and the browser console fills with violations.

export const NONCE_PLACEHOLDER = "__CSP_NONCE__";

type WithNonce = { __webpack_nonce__?: string };

/** Reads the nonce from the page and publishes it for Radix. Returns the nonce, or "" when there is none
 *  (Vite dev server, tests): then nothing is set and nothing is needed, because there is no CSP either. */
export function applyCspNonce(doc: Document = document, target: WithNonce = window as unknown as WithNonce): string {
  const nonce = doc.querySelector('meta[name="csp-nonce"]')?.getAttribute("content")?.trim() ?? "";
  if (!nonce || nonce === NONCE_PLACEHOLDER) return "";
  target.__webpack_nonce__ = nonce;
  return nonce;
}
