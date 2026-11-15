import { useEffect, useState } from "react";

const QUERY = "(prefers-reduced-motion: reduce)";

/** True when the user asked for less motion. Safe where matchMedia does not exist (tests, old browsers). */
export function useReducedMotion(): boolean {
  const supported = typeof window !== "undefined" && typeof window.matchMedia === "function";
  const [reduced, setReduced] = useState(() => (supported ? window.matchMedia(QUERY).matches : false));
  useEffect(() => {
    if (!supported) return;
    const mq = window.matchMedia(QUERY);
    const on = () => setReduced(mq.matches);
    mq.addEventListener("change", on);
    return () => mq.removeEventListener("change", on);
  }, [supported]);
  return reduced;
}
