import i18n from "i18next";
import LanguageDetector from "i18next-browser-languagedetector";
import { initReactI18next } from "react-i18next";

// One JSON file per namespace and language, so parallel work on different screens never collides.
// src/i18n/i18n.test.ts fails if a key exists in one language and not in the other.
const modules = import.meta.glob("./*/*.json", { eager: true, import: "default" }) as Record<string, Record<string, unknown>>;

export const LANGUAGES = ["en", "id"] as const;
export type Language = (typeof LANGUAGES)[number];

const resources: Record<string, Record<string, Record<string, unknown>>> = {};
for (const [path, json] of Object.entries(modules)) {
  const m = /^\.\/([a-z]+)\/([a-z]+)\.json$/.exec(path);
  if (!m) continue;
  const [, lng, ns] = m as unknown as [string, string, string];
  (resources[lng] ??= {})[ns] = json;
}

// <html lang> must follow the UI language (screen readers pick the voice from it). The listener is
// registered BEFORE init: the detector sets the initial language during init, and a listener added
// afterwards would miss it and leave lang="en" on an Indonesian page.
const setDocumentLang = (lng: string) => {
  document.documentElement.lang = lng.startsWith("id") ? "id" : "en";
};
i18n.on("languageChanged", setDocumentLang);

void i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources,
    fallbackLng: "en",
    supportedLngs: [...LANGUAGES],
    nonExplicitSupportedLngs: true,
    defaultNS: "common",
    ns: ["common"],
    interpolation: { escapeValue: false }, // React escapes
    detection: { order: ["localStorage", "navigator"], lookupLocalStorage: "lk.lang", caches: ["localStorage"] },
  });

setDocumentLang(i18n.language || "en");

export default i18n;
