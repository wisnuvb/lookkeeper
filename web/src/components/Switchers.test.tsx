import { act, fireEvent, render, screen } from "@testing-library/react";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { I18nextProvider } from "react-i18next";
import i18n from "@/i18n";
import { LanguageSwitch } from "./LanguageSwitch";
import { ThemeToggle } from "./ThemeToggle";
import { expectNoA11yViolations } from "@/test/a11y";

// Radix popper needs ResizeObserver, which jsdom lacks.
beforeAll(() => {
  globalThis.ResizeObserver ??= class {
    observe() {}
    unobserve() {}
    disconnect() {}
  } as unknown as typeof ResizeObserver;
  window.matchMedia ??= ((q: string) => ({ matches: false, media: q, addEventListener() {}, removeEventListener() {} })) as unknown as typeof window.matchMedia;
});

beforeEach(async () => {
  localStorage.clear();
  document.documentElement.classList.remove("dark");
  await act(() => i18n.changeLanguage("en"));
});

const open = (name: RegExp) => {
  const trigger = screen.getByRole("button", { name });
  fireEvent.keyDown(trigger, { key: "Enter" });
  return trigger;
};

describe("language dropdown", () => {
  it("lists both languages, marks the current one, and switches the whole UI", async () => {
    render(<I18nextProvider i18n={i18n}><LanguageSwitch /></I18nextProvider>);
    open(/language: english/i);
    const en = await screen.findByRole("menuitemradio", { name: "English" });
    const id = screen.getByRole("menuitemradio", { name: "Bahasa Indonesia" });
    expect(en).toHaveAttribute("aria-checked", "true");
    expect(id).toHaveAttribute("aria-checked", "false");
    fireEvent.click(id);
    await act(async () => {});
    expect(i18n.language).toBe("id");
    expect(document.documentElement.lang).toBe("id");
    expect(screen.getByRole("button", { name: /bahasa: bahasa indonesia/i })).toBeInTheDocument();
  });

  it("has no accessibility violations while open", async () => {
    render(<I18nextProvider i18n={i18n}><LanguageSwitch /></I18nextProvider>);
    open(/language/i);
    await screen.findByRole("menu");
    await expectNoA11yViolations(document.body);
  });
});

describe("theme dropdown", () => {
  it("offers system, light and dark; dark adds the class and is remembered", async () => {
    render(<I18nextProvider i18n={i18n}><ThemeToggle /></I18nextProvider>);
    open(/theme: system/i);
    expect(await screen.findByRole("menuitemradio", { name: "System" })).toHaveAttribute("aria-checked", "true");
    fireEvent.click(screen.getByRole("menuitemradio", { name: "Dark" }));
    await act(async () => {});
    expect(document.documentElement.classList.contains("dark")).toBe(true);
    expect(localStorage.getItem("lk.theme")).toBe("dark");
    open(/theme: dark/i);
    fireEvent.click(await screen.findByRole("menuitemradio", { name: "Light" }));
    await act(async () => {});
    expect(document.documentElement.classList.contains("dark")).toBe(false);
  });

  it("has no accessibility violations while open", async () => {
    render(<I18nextProvider i18n={i18n}><ThemeToggle /></I18nextProvider>);
    open(/theme/i);
    await screen.findByRole("menu");
    await expectNoA11yViolations(document.body);
  });
});
