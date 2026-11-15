export type ThemeChoice = "light" | "dark" | "system";
const KEY = "lk.theme";

// localStorage can throw (private windows, blocked storage): the UI must still work without it.
export function readTheme(): ThemeChoice {
  try {
    const v = localStorage.getItem(KEY);
    if (v === "light" || v === "dark" || v === "system") return v;
  } catch {
    /* ignore */
  }
  return "system";
}

export function applyTheme(choice: ThemeChoice): void {
  const dark = choice === "dark" || (choice === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.classList.toggle("dark", dark);
  try {
    localStorage.setItem(KEY, choice);
  } catch {
    /* ignore */
  }
}
