import { vi } from "vitest";

/**
 * jsdom has no layout and no ResizeObserver, so recharts' ResponsiveContainer measures 0x0 and draws
 * nothing. This stub reports a fixed size as soon as an element is observed, so the SVG is really
 * rendered and the structural a11y checks in tests cover it. Tests only.
 */
export function stubResizeObserver(width = 640, height = 240): void {
  class RO {
    private readonly cb: ResizeObserverCallback;
    constructor(cb: ResizeObserverCallback) {
      this.cb = cb;
    }
    observe(target: Element) {
      const rect = { width, height, top: 0, left: 0, right: width, bottom: height, x: 0, y: 0, toJSON: () => ({}) } as DOMRectReadOnly;
      const entry = { target, contentRect: rect, borderBoxSize: [], contentBoxSize: [], devicePixelContentBoxSize: [] } as unknown as ResizeObserverEntry;
      queueMicrotask(() => this.cb([entry], this as unknown as ResizeObserver));
    }
    unobserve() {}
    disconnect() {}
  }
  vi.stubGlobal("ResizeObserver", RO);
}
