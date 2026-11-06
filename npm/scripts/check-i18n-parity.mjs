#!/usr/bin/env node
/**
 * Fail when the zh/en dictionaries in src/web/static/js/i18n.mjs drift out
 * of key parity: a key present in one language but missing in the other
 * renders English fallback (or the raw key) in production. Run via
 * `npm run i18n:check` (wired into CI).
 */
if (!globalThis.localStorage) {
  // i18n.mjs reads the stored language at import time; node >= 21 ships a
  // localStorage stub, older versions need this shim.
  globalThis.localStorage = {
    getItem: () => null,
    setItem: () => {},
    removeItem: () => {},
  };
}
if (!globalThis.navigator) {
  globalThis.navigator = { language: "zh-CN" };
}

const { dictionaryKeys } = await import(
  new URL("../../src/web/static/js/i18n.mjs", import.meta.url)
);

const { zh, en } = dictionaryKeys();
const missingInEn = zh.filter((key) => !en.includes(key));
const missingInZh = en.filter((key) => !zh.includes(key));

if (missingInEn.length > 0 || missingInZh.length > 0) {
  console.error(
    `i18n key parity broken — missing in en: [${missingInEn.join(", ") || "none"}]; ` +
      `missing in zh: [${missingInZh.join(", ") || "none"}]`
  );
  process.exit(1);
}

console.log(`i18n key parity OK: ${zh.length} keys in zh and en`);
