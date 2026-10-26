"""
Request-aware i18n helper for Koneksaun Saudavel.

Languages
---------
'tet' : Tetum (default) — the official language of Timor-Leste
'id'  : Bahasa Indonesia

Resolution order
----------------
1. Explicit choice stored in the `ks_lang` cookie (set by /lang/<code>)
2. `Accept-Language` header (browser preference)
3. DEFAULT_LANG ('tet')

No Flask-Babel needed: the project ships a plain dict of translations.
"""

from flask import request

from app.translations import DEFAULT_LANG, LANG_NAMES, TRANSLATIONS

LANG_COOKIE = 'ks_lang'
COOKIE_MAX_AGE = 60 * 60 * 24 * 365  # 1 year


def available_languages():
    """List of language codes the UI supports."""
    return list(TRANSLATIONS.keys())


def get_lang():
    """Resolve the language for the current request."""
    cookie = request.cookies.get(LANG_COOKIE)
    if cookie in TRANSLATIONS:
        return cookie

    best = request.accept_languages.best_match(available_languages())
    if best:
        return best

    return DEFAULT_LANG


def translate(key, lang=None, **kwargs):
    """Look up `key` in the active language, falling back to the default.

    `kwargs` fills `{placeholders}` in the translation value.
    """
    if lang is None:
        lang = get_lang()

    table = TRANSLATIONS.get(lang) or {}
    value = None
    if key in table:
        value = table[key]
    else:
        fallback = TRANSLATIONS.get(DEFAULT_LANG) or {}
        if key in fallback:
            value = fallback[key]

    if value is None:
        # Unknown key: show it verbatim so the gap is obvious instead of
        # silently rendering an empty string.
        return key

    if kwargs:
        try:
            value = value.format(**kwargs)
        except (KeyError, IndexError, ValueError):
            pass
    return value


def flash_translated(key, category='error', **kwargs):
    """Flash a translated message (used by auth routes for user-facing errors)."""
    from flask import flash

    flash(translate(key, **kwargs), category)
    return key


def set_lang_response(response, lang):
    """Attach the language cookie to a response."""
    response.set_cookie(
        LANG_COOKIE,
        lang,
        max_age=COOKIE_MAX_AGE,
        samesite='Lax',
        secure=request.is_secure,
    )
    return response


__all__ = [
    'COOKIE_MAX_AGE',
    'DEFAULT_LANG',
    'LANG_COOKIE',
    'LANG_NAMES',
    'TRANSLATIONS',
    'available_languages',
    'flash_translated',
    'get_lang',
    'set_lang_response',
    'translate',
]
