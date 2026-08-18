import { describe, expect, it } from "vitest";
import { detectLocale, matchLocale, SUPPORTED_LOCALES, TRANSLATIONS } from "./i18n";

describe("localization", () => {
  it("contains the same non-empty catalog for every supported locale", () => {
    const englishKeys = Object.keys(TRANSLATIONS.en);
    for (const locale of SUPPORTED_LOCALES) {
      expect(Object.keys(TRANSLATIONS[locale])).toEqual(englishKeys);
      expect(Object.values(TRANSLATIONS[locale]).every((value) => value.length > 0)).toBe(true);
    }
  });

  it("selects saved locale before browser languages and falls back to English", () => {
    expect(detectLocale({ saved: "tr", languages: ["ja-JP"] })).toBe("tr");
    expect(detectLocale({ saved: null, languages: ["ja-JP"] })).toBe("ja");
    expect(detectLocale({ saved: null, languages: ["xx-ZZ"] })).toBe("en");
  });

  it("maps Chinese script and region subtags deliberately", () => {
    expect(matchLocale("zh-TW")).toBe("zh-Hant");
    expect(matchLocale("zh-Hans-CN")).toBe("zh-Hans");
    expect(matchLocale("zh-HK")).toBe("zh-Hant");
  });
});
