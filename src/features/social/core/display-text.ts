/**
 * Text a friend chose for themselves — their cryptid name and handle — made safe to draw.
 *
 * A profile is signature-verified, which proves who sent it, not that its text is benign. Without
 * this a friend could name themselves with a right-to-left override (U+202E) and have the roster,
 * the reveal screen or a removal confirmation render it reversed or appearing to end in someone
 * else's handle, hide characters with zero-width or invisible ones, break a row with control
 * characters or line separators, or push a megabyte of text into every row that shows them.
 *
 * What goes: C0/C1 controls and DEL; every bidi embedding, override, isolate and mark (U+061C,
 * U+200E/F, U+202A-E, U+2066-9); line and paragraph separators; zero-width spaces, the word
 * joiner, invisible operators, BOM, soft hyphen, the deprecated format characters and the Hangul
 * and Mongolian fillers that render as nothing. What stays, deliberately: ZWJ and ZWNJ between two
 * visible characters, because emoji sequences and Persian, Arabic and Indic scripts need them —
 * only repeats of them and ones at either end (which join nothing) are removed. Whitespace runs
 * collapse to one space.
 *
 * Every character here is written as an escape: a literal bidi control in source is the same
 * spoof aimed at whoever reads the code.
 */

// Ranges, not a list, so the reasoning above maps to it line by line.
const STRIP =
  /[\u0000-\u001F\u007F-\u009F\u00AD\u061C\u115F\u1160\u180E\u200B\u200E\u200F\u2028-\u202E\u2060-\u2064\u2066-\u206F\u3164\uFEFF\uFFF9-\uFFFB]/g;
const JOINER_RUN = /[\u200C\u200D]{2,}/g;
const EDGE_JOINERS = /^[\u200C\u200D\s]+|[\u200C\u200D\s]+$/g;
const WHITESPACE_RUN = /\s+/g;

/** The longest cryptid name the app's own editor and generator produce (24), with headroom. */
export const MAX_FRIEND_NAME_CODE_POINTS = 32;
/** The longest handle the editor allows (20 plus the `@`), with headroom. */
export const MAX_FRIEND_HANDLE_CODE_POINTS = 32;

/**
 * Clean `text` for display and cut it to `maxCodePoints`. Counted in code points, never UTF-16
 * units, so an astral character (most emoji) is never split into a lone surrogate. Returns `''`
 * when nothing visible is left, which callers treat as "no value".
 */
export function sanitizeDisplayText(text: string, maxCodePoints: number): string {
  const cleaned = tidy(text.replace(STRIP, ''));
  const points = Array.from(cleaned);
  if (points.length <= maxCodePoints) return cleaned;
  // Cutting can strand a joiner or a space at the new end; tidy again.
  return tidy(points.slice(0, maxCodePoints).join(''));
}

function tidy(text: string): string {
  return text
    .replace(WHITESPACE_RUN, ' ')
    .replace(JOINER_RUN, (run) => run[0])
    .replace(EDGE_JOINERS, '');
}
