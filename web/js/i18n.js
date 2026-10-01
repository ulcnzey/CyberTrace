const CODES = ["tr", "en", "ar"];
const catalogs = {};
const listeners = new Set();
let current = "en";

export function language() {
  return current;
}

export function t(key, vars) {
  const catalog = catalogs[current] || {};
  const value = key.split(".").reduce((node, part) => (node && typeof node === "object" ? node[part] : undefined), catalog);
  let text = typeof value === "string" ? value : key;
  if (vars) {
    Object.entries(vars).forEach(([name, replacement]) => {
      text = text.replaceAll(`{${name}}`, String(replacement));
    });
  }
  return text;
}

export function knownPhrase(text) {
  if (!text) return "";
  const phrases = (catalogs[current] && catalogs[current].phrases) || {};
  if (phrases[text]) return phrases[text];
  const started = text.match(/^Analysis started for (.+)\.$/);
  if (started) return t("phrases.analysisStarted", { label: started[1] });
  return text;
}

export async function initI18n() {
  const stored = localStorage.getItem("cybertrace-lang");
  const browser = (navigator.language || "en").slice(0, 2).toLowerCase();
  const initial = CODES.includes(stored) ? stored : (CODES.includes(browser) ? browser : "en");
  await setLanguage(initial, false);
}

export async function setLanguage(code, notify = true) {
  if (!CODES.includes(code)) return;
  if (!catalogs[code]) {
    const response = await fetch(`/static/locales/${code}.json?v=9`);
    if (!response.ok) throw new Error("locale");
    catalogs[code] = await response.json();
  }
  current = code;
  localStorage.setItem("cybertrace-lang", code);
  document.documentElement.lang = code;
  document.documentElement.dir = code === "ar" ? "rtl" : "ltr";
  applyChrome();
  if (notify) listeners.forEach((listener) => listener(code));
}

export function onLanguage(listener) {
  listeners.add(listener);
}

export function applyChrome() {
  document.querySelectorAll("[data-i18n]").forEach((node) => {
    node.textContent = t(node.dataset.i18n);
  });
  document.querySelectorAll("[data-i18n-aria]").forEach((node) => {
    node.setAttribute("aria-label", t(node.dataset.i18nAria));
  });
  document.querySelectorAll("[data-lang]").forEach((node) => {
    if (node.value !== current) node.value = current;
  });
}
