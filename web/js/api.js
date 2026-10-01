import { t, knownPhrase } from "./i18n.js";

export async function api(path, options) {
  let response;
  try {
    response = await fetch(path, options);
  } catch {
    throw new Error(t("errors.backend"));
  }
  const text = await response.text();
  let body = null;
  if (text) {
    try { body = JSON.parse(text); } catch { body = { detail: text }; }
  }
  if (!response.ok) {
    const detail = body && typeof body.detail === "string" ? body.detail : "";
    throw new Error(knownPhrase(detail) || detail || t("errors.requestFailed"));
  }
  return body;
}
