#!/usr/bin/env python3
"""
minimizer.py — Standalone Hashcat Rule Minimizer
======================================================
Reads a hashcat rule file and eliminates functionally redundant rules by
computing each rule's *signature* — the tuple of outputs produced when the
rule is applied to a fixed probe set of words.

Two rules are considered equivalent if they produce identical output on
every probe word.  When a collision is found, the rule appearing *earlier*
in the input file is kept (preserving the original sort order / frequency
ranking) and the later duplicate is discarded.

Changelog
---------
v1.3 — new feature + probe fix
  * New: --debug-file FILE traces every rule in FILE against the probe set
    and exits.  Designed for bulk inspection of rules from comm/diff output.
  * Fix: four remaining printable ASCII chars not covered by earlier probe
    words (backtick 0x60, double-quote 0x22, single-quote 0x27, backslash
    0x5C) are now represented by dedicated mid-word probe strings ("a`b",
    'a"b', "a'b", "a\\b").  This closes the last gap in printable-ASCII
    coverage and eliminates the residual 8-output difference seen after
    the v1.2 fixes.

v1.2 — bug fixes
  * Fix: probe set extended with three "alphabet" words covering all 95
    printable ASCII code-points.  Before this fix, rules like @j / @x / @z
    (purge j/x/z), sja / sxA / szB (replace j/x/z with something), and all
    rules targeting uppercase letters B C D E F G I J K L N O Q R T V X Y Z
    or most punctuation chars were no-ops on the entire probe set and were
    falsely eliminated as duplicates of ":".  In a large ruleset this could
    easily account for thousands of incorrectly removed rules.
  * Fix: probe set extended to length-36 words so that rules targeting
    positions B(11)–Z(35) — e.g. 'B–'Z, TB–TZ, DB–DZ, LB–LZ, etc. —
    get distinct signatures instead of collapsing into the same no-op
    bucket and being falsely eliminated.
  * Fix: opcode E now uses only ASCII space (0x20) as the word separator,
    matching hashcat's documented behaviour.  Previously hyphen (0x2D)
    and underscore (0x5F) were also treated as separators.
  * Note: an earlier draft of v1.2 incorrectly stripped mid-line '#' as
    inline comments.  This has been reverted — '#' is a valid hashcat
    argument character (e.g. i3#, iB#) and hashcat does not support
    inline comments in rule files.

Usage
-----
    # Basic — uses only the built-in probe set
    python minimizer.py ruleset.rule -o minimized.rule

    # Add extra probe words on the CLI
    python minimizer.py ruleset.rule -o minimized.rule \\
        --extra-probes password admin letmein root test

    # Draw additional probes from a wordlist
    python minimizer.py ruleset.rule -o minimized.rule \\
        --probe-file rockyou.txt --probe-words 100

    # Combine all three sources
    python minimizer.py ruleset.rule -o minimized.rule \\
        --extra-probes password admin \\
        --probe-file rockyou.txt --probe-words 80
"""

import argparse
import datetime
import hashlib
import multiprocessing
import os
import random
import sys
import numpy as np
from concurrent.futures import ProcessPoolExecutor
from typing import List, Optional, Tuple, Union

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False


# ====================================================================
# --- INVALID UTF-8 BYTE WRAPPER ---
# ====================================================================

class InvalidUTF8Bytes:
    """
    Wrapper for a byte sequence that is NOT valid UTF-8.

    Produced when a structural rule (r, d, {, }, q, …) splits a
    multibyte UTF-8 code-point across a byte boundary in ``--multibyte``
    mode.

    Instead of silently falling back to latin-1 (which returns a plain
    ``str`` indistinguishable from correctly decoded text), this type
    explicitly signals that the data is byte-corrupted.

    Properties:
      • hashed and compared by raw bytes
        → safe as a signature element in ``dict`` / ``set`` / ``pickle``
      • ``repr`` clearly flags invalid UTF-8
      • ``.raw`` : ``bytes`` — original bytes without conversion
    """

    __slots__ = ('raw',)

    def __init__(self, data: bytes) -> None:
        self.raw: bytes = data

    def __eq__(self, other: object) -> bool:
        if isinstance(other, InvalidUTF8Bytes):
            return self.raw == other.raw
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.raw)

    def __repr__(self) -> str:
        return f"<InvalidUTF8 {self.raw.hex(' ')!r}>"

    def __reduce__(self):
        return (self.__class__, (self.raw,))


# ====================================================================
# --- TERMINAL COLORS (gracefully disabled if not a TTY) ---
# ====================================================================
_IS_TTY = sys.stdout.isatty()

class C:
    RED    = '\033[91m' if _IS_TTY else ''
    GREEN  = '\033[92m' if _IS_TTY else ''
    YELLOW = '\033[93m' if _IS_TTY else ''
    CYAN   = '\033[96m' if _IS_TTY else ''
    BOLD   = '\033[1m'  if _IS_TTY else ''
    DIM    = '\033[2m'  if _IS_TTY else ''
    END    = '\033[0m'  if _IS_TTY else ''

def red(t):    return f"{C.RED}{t}{C.END}"
def green(t):  return f"{C.GREEN}{t}{C.END}"
def yellow(t): return f"{C.YELLOW}{t}{C.END}"
def cyan(t):   return f"{C.CYAN}{t}{C.END}"
def bold(t):   return f"{C.BOLD}{t}{C.END}"
def dim(t):    return f"{C.DIM}{t}{C.END}"


# ====================================================================
# --- DEBUG INFRASTRUCTURE ---
# ====================================================================
_DEBUG: bool = False          # set to True via --debug flag at runtime
_DEBUG_FILE = sys.stderr      # debug output target


def dbg(msg: str, *, level: str = "DBG") -> None:
    """Print a debug message to stderr when debug mode is active."""
    if _DEBUG:
        tag = {
            "DBG":  dim(f"[{level}]"),
            "INFO": cyan(f"[{level}]"),
            "WARN": yellow(f"[{level}]"),
            "RULE": bold(f"[{level}]"),
            "DUP":  red(f"[{level}]"),
        }.get(level, dim(f"[{level}]"))
        print(f"{tag} {msg}", file=_DEBUG_FILE)


def debug_rule(rule: str, probe: List[str], multibyte: bool = False) -> None:
    """
    Trace *rule* applied to every word in *probe* and print the results.
    Used by --debug-rule to inspect what a specific rule does.
    """
    print(f"\n{bold(cyan('Rule trace:'))} {bold(repr(rule))}\n")
    atoms = tokenize_rule(rule)
    print(f"  Atoms : {atoms}\n")
    any_unsupported  = False
    any_invalid_utf8 = False
    for word in probe:
        result = apply_chain(rule, word, multibyte=multibyte)
        if result is None:
            tag = yellow("→  <unsupported>")
            any_unsupported = True
        elif isinstance(result, InvalidUTF8Bytes):
            tag = yellow(f"→  <invalid UTF-8: {result.raw.hex(' ')}>")
            any_invalid_utf8 = True
        elif result == word:
            tag = dim(f"→  {result!r}  (no change)")
        else:
            tag = green(f"→  {result!r}")
        print(f"  {dim(repr(word)):32s}  {tag}")
    if any_unsupported:
        print(f"\n  {yellow('Warning:')} rule contains unsupported opcode(s).")
    if any_invalid_utf8:
        print(
            f"\n  {yellow('Note:')} rule produced invalid UTF-8 byte sequences "
            f"on some probe words.\n"
            f"  This happens when a structural rule (r, d, {{, }}, q, …) splits\n"
            f"  a multibyte code-point across a byte boundary.  hashcat will\n"
            f"  process the raw bytes — the rule is still valid and kept."
        )
    print()


# ====================================================================
# --- BUILT-IN PROBE SET ---
# ====================================================================
# Hand-curated to exercise every interesting opcode category:
#
#   len 2–3  → k, K, {, }, [, ] edge cases; x/O/D on short words
#   len 4–6  → T3, i0X, D0, position ops within short words
#   len 7–9  → the typical real-world password base word range
#   len 10+  → truncation and repeat ops ('y','Y','z','Z','p')
#   Mixed-case → l, u, c, C, t, E, T, k, K
#   Digits   → @, s, o on numeric chars; pure numeric suffix probing
#   Specials → @-removal, s-substitution on punctuation chars
#   Repeated → q (char doubling), z/Z (char extension)
#
# "password" is intentionally included because it is the single most
# common probe word in hashcat rule debugging workflows.
BUILTIN_PROBES: List[str] = [
    # ── very short — edge cases for k, K, {, }, [, ] ────────────────
    "ab",
    "abc",
    "abcd",
    # ── short alphanumeric (len 4–6) ─────────────────────────────────
    "pass",
    "root",
    "test",
    "admin",
    "login",
    # ── typical password base words (len 7–9) ────────────────────────
    "letmein",          # len 7
    "welcome",          # len 7
    "password",         # len 8
    "sunshine",         # len 8
    "football",         # len 8
    "baseball",         # len 8
    "princess",         # len 8
    "dragon12",         # len 8, ends with digits
    # ── longer words (len 10–11) — truncation / repeat ops ──────────
    "qwertyuiop",       # len 10
    "iloveyou12",       # len 10, trailing digits
    "monkey12345",      # len 11
    "superman123",      # len 11
    "mustang2024",      # len 11
    # ── extended-length words — cover high-position opcodes (B–Z) ────
    # Hashcat position args go 0-9 then A(10), B(11), ..., Z(35).
    # Without words of length ≥ 12 every rule that only touches position
    # 11+ is a no-op on the entire probe set and collapses into the same
    # signature as ":" — causing massive false deduplication.
    # We add words at lengths 12, 16, 20, 24, 28 and 36 so that:
    #   • 'B (truncate@11) differs from 'C (truncate@12) etc.
    #   • TB-TZ, DB-DZ, LB-LZ, RB-RZ, +B-+Z, -B--Z, .B-.Z, ,B-,Z
    #     oNX, iNX, xNM  all get distinguishable signatures.
    "administrator1",   # len 14  — covers positions B(11)..D(13)
    "iloveyouforever",  # len 15  — covers positions B(11)..E(14)
    "qwertyuiopasdfgh", # len 16  — covers positions B(11)..F(15)
    "correcthorsebattery",   # len 20  — covers ..J(19)
    "averylongpassword1234",  # len 22  — covers ..L(21)
    "averylongpassword12345678",    # len 26  — covers ..P(25)
    "averylongpassword1234567890ab", # len 30  — covers ..T(29)
    "averylongpassword1234567890abcdef",  # len 34  — covers ..X(33)
    "averylongpassword1234567890abcdefghi",  # len 36  — covers Z(35)
    # ── alphabet coverage — every printable ASCII char in at least one word ──
    # Rules like @X (purge X) and sXY (replace X→Y) are no-ops on all probe
    # words when X does not appear anywhere in the probe set.  Without coverage,
    # every such rule collapses into the same ":"-equivalent signature and is
    # falsely eliminated.  Three words cover all 95 printable ASCII code-points:
    #   missing lowercase before this fix : j, x, z
    #   missing uppercase before this fix : B C D E F G I J K L N O Q R T V X Y Z
    #   missing specials                  : most punctuation characters
    "abcdefghijklmnopqrstuvwxyz",       # all 26 lowercase letters
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",       # all 26 uppercase letters
    "!@#$%^&*()-_=+[]{}|;:,.<>?/~",    # 30 common special / punctuation chars
    # The four printable ASCII chars not covered by the line above — each
    # embedded mid-word so that sXY / @X / oNX rules targeting them are
    # distinguishable from no-ops and from each other:
    "a`b",    # backtick  (0x60)
    'a"b',    # double-quote (0x22)
    "a'b",    # single-quote / apostrophe (0x27)
    "a\\b",   # backslash (0x5C)
    "a b",    # space (0x20) — completes full 95-char printable ASCII coverage
    # ── mixed-case — l/u/c/C/t/E/T/k/K ─────────────────────────────
    "Password",
    "AdminUser",
    "MySecret",
    "HelloWorld",
    # ── words with embedded digits — s, o, @, T ──────────────────────
    "pass123",
    "admin2024",
    "test1234",
    "user9999",
    # ── words with special chars — @ removal, s substitution ─────────
    "p@ssw0rd",
    "s3cur1ty",
    # ── repeated chars — q (double each), z/Z (extend) ───────────────
    "aaaa",
    "bbbb",
]

# Extra probes activated only in multibyte mode (--multibyte).
# These exercise multibyte UTF-8 encodings: Polish, German, French, CJK, emoji.
MULTIBYTE_PROBES: List[str] = [
    # ── Polish ───────────────────────────────────────────────────────
    "hasło",          # "password" in Polish  (ł = U+0142, 2-byte UTF-8)
    "żółw",           # "tortoise"            (ż ó ł w — all 2-byte)
    "źródło",         # "source"
    # ── German ───────────────────────────────────────────────────────
    "straße",         # "street"              (ß = U+00DF, 2-byte)
    "münchen",        # city name             (ü = U+00FC)
    "übermensch",     # "superhuman"
    # ── French ───────────────────────────────────────────────────────
    "café",           # (é = U+00E9)
    "naïve",          # (ï = U+00EF)
    # ── Russian ──────────────────────────────────────────────────────
    "пароль",         # "password" in Russian (all 2-byte Cyrillic)
    # ── CJK / emoji (3–4 byte sequences) ─────────────────────────────
    "密码",            # "password" in Chinese (each char = 3-byte UTF-8)
    "パスワード",       # "password" in Japanese katakana
]

# Deduplicate while preserving order
_seen: set = set()
_deduped: List[str] = []
for _w in BUILTIN_PROBES:
    if _w not in _seen:
        _seen.add(_w)
        _deduped.append(_w)
BUILTIN_PROBES = _deduped
del _seen, _deduped, _w


# ====================================================================
# --- PYTHON-SIDE HASHCAT RULE APPLICATOR ---
# ====================================================================
# Ported from rulest_v2.py (lines 272–413).
# Implements every opcode that the hashcat GPU kernel supports.
# Returns None for any unrecognised opcode so callers can handle it.

def _arg_ord(token: str, pos: int) -> int:
    """
    Return the integer code-point of the argument character at *pos* inside
    *token*, resolving \\xNN hex-escape sequences transparently.
    """
    if (pos < len(token)
            and token[pos] == "\\"
            and pos + 3 < len(token)
            and token[pos + 1] == "x"
            and all(c in "0123456789abcdefABCDEF"
                    for c in token[pos + 2:pos + 4])):
        return int(token[pos + 2:pos + 4], 16)
    return ord(token[pos]) if pos < len(token) else 0


def _encode_word(word: Union[str, "InvalidUTF8Bytes"], multibyte: bool) -> List[int]:
    """
    Encode *word* into a list of byte integers for rule processing.

    When *word* is an ``InvalidUTF8Bytes`` instance (produced by a previous
    rule in the chain that split a multibyte code-point) we reuse its raw
    bytes directly — there is no meaningful re-encoding to do.

    When *multibyte* is False (default / hashcat-compatible mode) the word is
    encoded as latin-1.  Characters outside the latin-1 range raise
    ``UnicodeEncodeError``, which the caller catches and re-raises or handles.

    When *multibyte* is True the word is encoded as UTF-8 so that any Unicode
    character is accepted.  Rules then operate on the raw UTF-8 byte sequence,
    exactly as hashcat does on a UTF-8 wordlist.
    """
    if isinstance(word, InvalidUTF8Bytes):
        # Already raw bytes from a previous rule in the chain — use as-is.
        return list(word.raw)
    enc = 'utf-8' if multibyte else 'latin-1'
    return list(word.encode(enc))


def _decode_bytes(
    byte_list: List[int],
    multibyte: bool,
) -> Union[str, InvalidUTF8Bytes]:
    """
    Decode a list of byte integers back to a Python string (or an
    ``InvalidUTF8Bytes`` wrapper when the bytes are not valid UTF-8).

    Non-multibyte mode
    ------------------
    Latin-1 is bijective over 0x00–0xFF and never raises — every byte
    becomes the Unicode code-point of the same value.

    Multibyte mode
    --------------
    UTF-8 is tried first.  If the byte sequence is invalid (happens when
    structural rules like ``r``, ``d``, ``{``, ``}``, ``q``, … split a
    multibyte code-point across a byte boundary) we return
    ``InvalidUTF8Bytes(raw)`` instead of silently falling back to latin-1.

    Why not return ``None``?
    ~~~~~~~~~~~~~~~~~~~~~~~~
    ``None`` would cause ``compute_signature`` to emit the global
    ``_UNSUPPORTED_SIG`` sentinel, making *all* rules that produce invalid
    UTF-8 look identical and collapsing them into false duplicates.
    ``InvalidUTF8Bytes`` is hashed and compared by its raw bytes, so each
    rule retains a unique signature — while callers can still detect the
    invalid-UTF-8 case via ``isinstance(result, InvalidUTF8Bytes)``.
    """
    raw = bytes(byte_list)

    if not multibyte:
        return raw.decode('latin-1')

    try:
        return raw.decode('utf-8')
    except (UnicodeDecodeError, ValueError):
        return InvalidUTF8Bytes(raw)


def _apply_single(
    rule: str,
    word: str,
    multibyte: bool = False,
) -> Union[str, InvalidUTF8Bytes, None]:
    """Apply one hashcat rule atom to *word*.

    Returns ``None`` on unsupported opcode, ``InvalidUTF8Bytes`` when a
    structural rule splits a multibyte code-point (multibyte mode only).

    Parameters
    ----------
    rule : str
        A single hashcat opcode atom (e.g. ``'l'``, ``'$1'``, ``'sab'``).
    word : str
        The current candidate password string.
    multibyte : bool
        When ``True`` the word is treated as a sequence of UTF-8 *bytes*,
        enabling correct handling of multibyte characters (Polish, German,
        CJK, emoji, …).  When ``False`` (default) latin-1 byte semantics are
        used — identical to the original behaviour and to hashcat's default.
    """
    if not rule:
        return word

    try:
        w = _encode_word(word, multibyte)
    except UnicodeEncodeError:
        # Word contains characters outside latin-1; silently escalate to UTF-8
        # even when multibyte mode was not explicitly requested.
        dbg(
            f"Word {word!r} contains non-latin-1 chars — forcing UTF-8 encoding",
            level="WARN",
        )
        try:
            w = list(word.encode('utf-8'))
            multibyte = True          # decode back as UTF-8 at the end
        except Exception:
            return None

    cmd = rule[0]

    def dg(c: str) -> int:
        """Parse a single position character: 0-9 → 0-9, A-Z → 10-35, else -1."""
        if '0' <= c <= '9': return ord(c) - 48
        if 'A' <= c <= 'Z': return ord(c) - 55   # A=10, B=11, …, Z=35
        return -1

    def parg(chain: str, pos: int) -> Tuple[int, int]:
        """Read a position/count argument (handles \\xNN escapes), return (dg-value, new_pos)."""
        s, np = _read_arg_char(chain, pos)
        if s.startswith('\\x') and len(s) == 4:
            ch = chr(int(s[2:], 16))
        else:
            ch = s
        return dg(ch), np

    dbg(f"  atom={rule!r}  word_before={word!r}", level="DBG")

    try:
        # ── no-op ────────────────────────────────────────────────────
        if cmd == ':':
            pass

        # ── case transforms ──────────────────────────────────────────
        elif cmd == 'l':
            w = [c | 0x20 if 65 <= c <= 90 else c for c in w]
        elif cmd == 'u':
            w = [c & ~0x20 if 97 <= c <= 122 else c for c in w]
        elif cmd == 'c':
            if w:
                w[0] = w[0] & ~0x20 if 97 <= w[0] <= 122 else w[0]
                w[1:] = [c | 0x20 if 65 <= c <= 90 else c for c in w[1:]]
        elif cmd == 'C':
            if w:
                w[0] = w[0] | 0x20 if 65 <= w[0] <= 90 else w[0]
                w[1:] = [c & ~0x20 if 97 <= c <= 122 else c for c in w[1:]]
        elif cmd == 't':
            w = [c | 0x20 if 65 <= c <= 90 else
                 (c & ~0x20 if 97 <= c <= 122 else c) for c in w]
        elif cmd == 'E':
            # Title-case: lowercase everything, then uppercase the first letter
            # and every letter that immediately follows a space (0x20).
            # Hashcat v1.2 fix: only ASCII space is a word separator for E —
            # hyphen and underscore are NOT separators (hashcat-compatible behaviour).
            # wiki example: "p@ssW0rd w0rld" → "P@ssw0rd W0rld"
            # The 'W' in W0rd must become 'w' — so we also lowercase uppercase
            # letters that are NOT at a word-start position.
            out = []
            cap = True
            for c in w:
                if cap and 97 <= c <= 122:
                    out.append(c & ~0x20)   # lowercase → uppercase (word start)
                elif not cap and 65 <= c <= 90:
                    out.append(c | 0x20)    # uppercase → lowercase (non-word-start)
                else:
                    out.append(c)
                cap = (c == 32)  # only space is a word separator for E (hashcat-compatible)
            w = out

        # ── structural transforms ────────────────────────────────────
        elif cmd == 'r':
            w = w[::-1]
        elif cmd == 'd':
            w = w + w
        elif cmd == 'f':
            w = w + w[::-1]
        elif cmd == '{':
            if len(w) > 1: w = w[1:] + [w[0]]
        elif cmd == '}':
            if len(w) > 1: w = [w[-1]] + w[:-1]
        elif cmd == '[':
            if w: w = w[1:]
        elif cmd == ']':
            if w: w = w[:-1]
        elif cmd == 'k':
            if len(w) >= 2: w[0], w[1] = w[1], w[0]
        elif cmd == 'K':
            if len(w) >= 2: w[-1], w[-2] = w[-2], w[-1]
        elif cmd == 'q':
            out = []
            for c in w: out += [c, c]
            w = out

        # ── single-char argument ops (len >= 2) ──────────────────────
        # Guards use >= instead of == so that \xNN hex-escape arguments
        # (which produce longer atom strings like "^\x41") are accepted.
        elif cmd == '^' and len(rule) >= 2:
            w = [_arg_ord(rule, 1)] + w
        elif cmd == '$' and len(rule) >= 2:
            w = w + [_arg_ord(rule, 1)]
        elif cmd == '@' and len(rule) >= 2:
            ch = _arg_ord(rule, 1)
            w  = [c for c in w if c != ch]
        elif cmd == 'p' and len(rule) >= 2:
            n, _ = parg(rule, 1)
            if n > 0:
                orig = w[:]
                for _ in range(n): w += orig
        elif cmd == 'T' and len(rule) >= 2:
            p, _ = parg(rule, 1)
            if 0 <= p < len(w):
                c = w[p]
                w[p] = (c | 0x20 if 65 <= c <= 90
                        else (c & ~0x20 if 97 <= c <= 122 else c))
        elif cmd == 'D' and len(rule) >= 2:
            p, _ = parg(rule, 1)
            if 0 <= p < len(w): w.pop(p)
        elif cmd == 'L' and len(rule) >= 2:
            p, _ = parg(rule, 1)
            if 0 <= p < len(w): w[p] = (w[p] << 1) & 0xFF
        elif cmd == 'R' and len(rule) >= 2:
            p, _ = parg(rule, 1)
            if 0 <= p < len(w): w[p] = (w[p] >> 1) & 0xFF
        elif cmd == '+' and len(rule) >= 2:
            p, _ = parg(rule, 1)
            if 0 <= p < len(w): w[p] = (w[p] + 1) & 0xFF
        elif cmd == '-' and len(rule) >= 2:
            p, _ = parg(rule, 1)
            if 0 <= p < len(w): w[p] = (w[p] - 1) & 0xFF
        elif cmd in ('.', ',') and len(rule) >= 2:
            p, _ = parg(rule, 1)
            delta = 1 if cmd == '.' else -1
            if 0 <= p < len(w): w[p] = (w[p] + delta) & 0xFF
        elif cmd == "'" and len(rule) >= 2:
            # 'N — truncate: keep only the first N characters (w[:N])
            # wiki example: '6 on "p@ssW0rd" → "p@ssW0" (6 chars, indices 0-5)
            p, _ = parg(rule, 1)
        elif cmd == 'z' and len(rule) >= 2:
            n, _ = parg(rule, 1)
            if n > 0 and w: w = [w[0]] * n + w
        elif cmd == 'Z' and len(rule) >= 2:
            n, _ = parg(rule, 1)
            if n > 0 and w: w = w + [w[-1]] * n
        elif cmd == 'y' and len(rule) >= 2:
            n, _ = parg(rule, 1)
            if n > 0: w = w[:n] + w
        elif cmd == 'Y' and len(rule) >= 2:
            n, _ = parg(rule, 1)
            if n > 0 and len(w) >= n: w = w + w[-n:]

        # ── two-char argument ops (len >= 3) ─────────────────────────
        elif cmd == 's' and len(rule) >= 3:
            # Use _read_arg_char to correctly advance past \xNN escapes
            arg1_str, pos2 = _read_arg_char(rule, 1)
            a = _arg_ord(rule, 1)
            b = _arg_ord(rule, pos2)
            w = [b if c == a else c for c in w]
        elif cmd == 'i' and len(rule) >= 3:
            p, pos2 = parg(rule, 1)
            ch = _arg_ord(rule, pos2)
            if 0 <= p <= len(w): w.insert(p, ch)
        elif cmd == 'o' and len(rule) >= 3:
            p, pos2 = parg(rule, 1)
            ch = _arg_ord(rule, pos2)
            if 0 <= p < len(w): w[p] = ch
        elif cmd == 'e' and len(rule) >= 2:
            # Title-case with custom separator: lowercase everything, then uppercase
            # the first letter and every letter after the separator character.
            sep = _arg_ord(rule, 1)
            out = []
            cap = True
            for c in w:
                if cap and 97 <= c <= 122:
                    out.append(c & ~0x20)   # lowercase → uppercase
                elif not cap and 65 <= c <= 90:
                    out.append(c | 0x20)    # uppercase → lowercase
                else:
                    out.append(c)
                cap = (c == sep)
            w = out
        elif cmd == 'x' and len(rule) >= 3:
            # xNM — extract M characters starting at position N
            # hashcat semantics: w = w[N : N+M]  (M is a count, not an end index)
            n, pos2 = parg(rule, 1)
            m, _ = parg(rule, pos2)
            if n >= 0 and m >= 0:
                w = w[n:n + m]
        elif cmd == 'O' and len(rule) >= 3:
            p, pos2 = parg(rule, 1)
            m, _ = parg(rule, pos2)
            if 0 <= p < len(w) and m > 0: w = w[:p] + w[p + m:]
        elif cmd == '*' and len(rule) >= 3:
            a, pos2 = parg(rule, 1)
            b, _ = parg(rule, pos2)
            if 0 <= a < len(w) and 0 <= b < len(w) and a != b:
                w[a], w[b] = w[b], w[a]
        elif cmd == '3' and len(rule) >= 3:
            # 3NX — toggle case of the letter after the Nth instance of separator X
            # N is 0-based: 30- toggles after the FIRST '-', 31- after the SECOND, etc.
            # Bug fix: previously cnt was incremented BEFORE the comparison, so n=0
            # (first separator) would require cnt==0 AFTER incrementing (impossible).
            # Fix: compare cnt == n after incrementing — but n is 0-based so we
            # compare cnt == n+1, i.e. match on the (n+1)th time we see the separator.
            n, pos2 = parg(rule, 1)
            sep = _arg_ord(rule, pos2)
            cnt = 0
            for i, c in enumerate(w):
                if c == sep:
                    cnt += 1
                    if cnt == n + 1 and i + 1 < len(w):
                        ci = w[i + 1]
                        w[i + 1] = (ci | 0x20 if 65 <= ci <= 90
                                    else (ci & ~0x20 if 97 <= ci <= 122 else ci))
                        break
        else:
            return None  # unsupported opcode

    except Exception:
        return None

    result = _decode_bytes(w, multibyte)
    dbg(f"  atom={rule!r}  word_after={result!r}", level="DBG")
    return result



# ── opcode arity tables ───────────────────────────────────────────────────────
# How many *argument* characters follow the command byte in a concatenated rule.
_ZERO_ARG_OPS = frozenset(':lucCtErdfkK{}[]q')
_ONE_ARG_OPS  = frozenset([
    '^', '$', '@', 'p', 'T', 'D', 'L', 'R',
    '+', '-', '.', ',', "'", 'z', 'Z', 'y', 'Y',
    'e',   # title-case by separator  (technically ≥1, but only 1 sep char)
])
_TWO_ARG_OPS  = frozenset(['s', 'i', 'o', 'x', 'O', '*', '3'])


def _read_arg_char(chain: str, pos: int) -> Tuple[str, int]:
    """
    Read one argument character from *chain* starting at *pos*.

    Handles hashcat's ``\\xNN`` hex-escape notation so that, e.g.,
    ``s\\x41B`` is parsed as substitute(0x41, ord('B')).

    Returns ``(char_str, new_pos)`` where *char_str* is the raw slice
    that represents the single logical character (either 1 byte or the
    4-byte ``\\xNN`` sequence).
    """
    if pos >= len(chain):
        return ('', pos)
    if (chain[pos] == '\\'
            and pos + 3 < len(chain)
            and chain[pos + 1] == 'x'
            and all(c in '0123456789abcdefABCDEF' for c in chain[pos + 2:pos + 4])):
        return (chain[pos:pos + 4], pos + 4)
    return (chain[pos], pos + 1)


def tokenize_rule(chain: str) -> List[str]:
    """
    Split a hashcat rule line into individual opcode atoms.

    Handles **both** the space-separated format used by some tools
    (e.g. ``l r $1``) and the concatenated format used natively by
    hashcat (e.g. ``lr$1``).  The two formats may also be mixed on the
    same line (e.g. ``l r$1`` is legal).

    Supports ``\\xNN`` hex-escape notation in argument positions.

    Returns a list of atom strings, each suitable for ``_apply_single``.
    Unknown / unrecognised opcodes are returned as a single trailing
    token so the caller can decide how to handle them (``_apply_single``
    will return ``None`` for them, which is the existing behaviour).
    """
    tokens: List[str] = []
    i = 0
    n = len(chain)

    while i < n:
        c = chain[i]

        if c == ' ':          # skip spaces (space-separated format)
            i += 1
            continue

        if c in _ZERO_ARG_OPS:
            tokens.append(c)
            i += 1

        elif c in _ONE_ARG_OPS:
            arg, i2 = _read_arg_char(chain, i + 1)
            tokens.append(c + arg)
            i = i2

        elif c in _TWO_ARG_OPS:
            arg1, i2 = _read_arg_char(chain, i + 1)
            arg2, i3 = _read_arg_char(chain, i2)
            tokens.append(c + arg1 + arg2)
            i = i3

        else:
            # Unknown opcode — consume the rest of the line as one token
            # so _apply_single can return None and trigger _UNSUPPORTED_SIG.
            tokens.append(chain[i:])
            break

    return tokens


def apply_chain(
    chain: str,
    word: str,
    multibyte: bool = False,
) -> Union[str, InvalidUTF8Bytes, None]:
    """
    Apply a hashcat rule chain to *word*.

    Accepts **both** space-separated (``l r $1``) and concatenated
    (``lr$1``) formats, as well as mixed lines.  ``\\xNN`` hex-escape
    notation in argument positions is also supported.

    Parameters
    ----------
    chain : str
        The full rule string (possibly multiple opcode atoms).
    word : str
        The candidate password to transform.
    multibyte : bool
        When ``True`` the word is processed as UTF-8 bytes, enabling support
        for multibyte Unicode characters (Polish, German, CJK, emoji, …).

    Returns
    -------
    str
        Normal transformed word.
    InvalidUTF8Bytes
        Multibyte mode only: the rule produced an invalid UTF-8 byte sequence.
    None
        Any atom contained an unsupported opcode.
    """
    cur: Union[str, InvalidUTF8Bytes, None] = word
    for atom in tokenize_rule(chain):
        cur = _apply_single(atom, cur, multibyte=multibyte)  # type: ignore[arg-type]
        if cur is None:
            return None
    return cur


# ====================================================================
# --- SIGNATURE COMPUTATION ---
# ====================================================================
# Sentinel PREFIX — the actual per-rule sentinel is ('__UNSUPPORTED__', rule_text).
# Using a 2-tuple ensures two different unsupported rules never share a signature.
# The old form ('__UNSUPPORTED__',) caused all unsupported rules to collapse into
# one bucket; this string constant is kept only as a readable reference.
_UNSUPPORTED_SIG_PREFIX: str = '__UNSUPPORTED__'


def compute_signature(
    rule: str,
    probe_words: List[str],
    multibyte: bool = False,
) -> tuple:
    """
    Return the functional signature of *rule* — a tuple of its outputs on
    every word in *probe_words*.

    If the rule contains an unsupported opcode, returns a unique sentinel
    tuple that embeds the rule text itself, so that two different unsupported
    rules are never mistakenly identified as duplicates of each other.

    The old behaviour (all unsupported rules → one shared bucket) caused
    false deduplication: e.g. 100 rules using reject ops (<, >, !, /, …) or
    memory ops (M, 4, 6, X) would all collapse to a single kept rule.

    Parameters
    ----------
    multibyte : bool
        Passed through to ``apply_chain`` / ``_apply_single``.  When ``True``
        words are treated as UTF-8 byte sequences.
    """
    outputs = []
    for word in probe_words:
        out = apply_chain(rule, word, multibyte=multibyte)
        if out is None:
            # Unsupported opcode — return a signature that is unique to THIS rule
            # so it is never collapsed with a different unsupported rule.
            return ('__UNSUPPORTED__', rule)
        outputs.append(out)
    return tuple(outputs)


# ====================================================================
# --- PROBE SET BUILDER ---
# ====================================================================
def build_probe_set(
    extra_probes: List[str],
    probe_file:   Optional[str],
    probe_words:  int,
    seed:         int = 42,
    multibyte:    bool = False,
) -> List[str]:
    """
    Assemble the probe set used for signature computation.

    Assembly order (later duplicates are silently dropped):
      1. BUILTIN_PROBES   — always included
      2. MULTIBYTE_PROBES — included when *multibyte* is ``True``
      3. extra_probes     — words supplied via --extra-probes
      4. sample from probe_file — up to *probe_words* random words

    Parameters
    ----------
    extra_probes : list of str
        Additional words from the CLI (--extra-probes).
    probe_file : str or None
        Path to a wordlist to sample from, or None.
    probe_words : int
        Maximum number of words to sample from *probe_file*.
    seed : int
        RNG seed for reproducible sampling.
    multibyte : bool
        When ``True`` the extra MULTIBYTE_PROBES list is added to the set.
    """
    seen: set = set()
    probe: List[str] = []

    def add(w: str) -> None:
        w = w.strip()
        if w and w not in seen:
            seen.add(w)
            probe.append(w)

    for w in BUILTIN_PROBES:
        add(w)

    if multibyte:
        dbg(f"Adding {len(MULTIBYTE_PROBES)} multibyte probe words", level="INFO")
        for w in MULTIBYTE_PROBES:
            add(w)

    for w in (extra_probes or []):
        add(w)

    if probe_file:
        try:
            file_words: List[str] = []
            with open(probe_file, encoding='latin-1', errors='ignore') as fh:
                for line in fh:
                    w = line.strip()
                    if w:
                        file_words.append(w)
            if len(file_words) > probe_words:
                rng = random.Random(seed)
                file_words = rng.sample(file_words, probe_words)
            for w in file_words:
                add(w)
        except FileNotFoundError:
            print(red(f"[ERROR] Probe file not found: {probe_file}"), file=sys.stderr)
            sys.exit(1)

    if not probe:
        print(red("[ERROR] Probe set is empty — cannot minimize."), file=sys.stderr)
        sys.exit(1)

    return probe


# ====================================================================
# --- RULE FILE I/O ---
# ====================================================================
def read_rules(path: str) -> List[str]:
    """
    Read *path* and return all non-blank, non-comment lines.

    Comment lines start with '#'.  Both Windows (\\r\\n) and Unix (\\n)
    line endings are handled.

    NOTE: '#' mid-line is NOT treated as an inline comment because '#' is a
    valid hashcat argument character (e.g. ``i3#`` inserts '#' at position 3).
    Hashcat itself does not support inline comments, so every non-blank line
    that doesn't start with '#' is kept verbatim.
    """
    rules: List[str] = []
    try:
        with open(path, encoding='utf-8', errors='ignore') as fh:
            for line in fh:
                r = line.rstrip('\r\n')
                if r and not r.startswith('#'):
                    rules.append(r)
    except FileNotFoundError:
        print(red(f"[ERROR] Rule file not found: {path}"), file=sys.stderr)
        sys.exit(1)
    return rules


# ====================================================================
# --- PROGRESSIVE SIGNATURE MINIMIZER ---
# ====================================================================

# Keep the same progressive strategy used by RULEST: an early, diverse probe
# batch separates most rules; only colliding signatures are refined with later
# probes. The complete probe set is still evaluated for every unresolved
# collision, so the equivalence relation is unchanged.
MINIMIZER_PROBE_BATCH_SIZE = 8
MINIMIZER_BATCH_SIZE = 25_000
_MINIMIZER_UNSUPPORTED_PREFIX = "__UNSUPPORTED__::"
_MINIMIZER_PRIORITY_PROBES = (
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "!@#$%^&*()-_=+[]{}|;:,.<>?/~",
    "averylongpassword1234567890abcdefghi",
    "qwertyuiopasdfgh",
    "a b",
    "Password",
    "p@ssw0rd",
    "correcthorsebattery",
    "averylongpassword1234567890abcdef",
    "superman123",
    "test1234",
)
_MINIMIZER_UNSUPPORTED_KIND = 1
_MINIMIZER_SUPPORTED_KIND = 0


def _minimizer_record_dtype(rule_count: int):
    index_dtype = "<u4" if rule_count <= 0xFFFFFFFF else "<u8"
    return np.dtype([("kind", "u1"), ("sig", "V16"), ("idx", index_dtype)])


_MINIMIZER_WORKER_PROBES: List[str] = []
_MINIMIZER_WORKER_MULTIBYTE = False


def _minimizer_worker_init(probe_words: List[str], multibyte: bool) -> None:
    """Initialize immutable probe state once in each worker process."""
    global _MINIMIZER_WORKER_PROBES, _MINIMIZER_WORKER_MULTIBYTE
    _MINIMIZER_WORKER_PROBES = probe_words
    _MINIMIZER_WORKER_MULTIBYTE = bool(multibyte)


def _ordered_minimizer_probes(probe_words: List[str]) -> List[str]:
    """Prioritize diverse built-in probes without dropping/replacing any."""
    remaining = list(probe_words)
    ordered: List[str] = []
    for preferred in _MINIMIZER_PRIORITY_PROBES:
        try:
            index = remaining.index(preferred)
        except ValueError:
            continue
        ordered.append(remaining.pop(index))
    ordered.extend(remaining)
    return ordered


def _minimizer_probe_ranges(probe_count: int):
    batch_size = max(1, int(MINIMIZER_PROBE_BATCH_SIZE))
    if probe_count <= 0:
        return [(0, 0)]
    return [
        (start, min(probe_count, start + batch_size))
        for start in range(0, probe_count, batch_size)
    ]


def _minimizer_unsupported_signature(rule: str) -> bytes:
    # The separate kind byte prevents unsupported rules from ever colliding
    # with supported output signatures. Exact text is checked if hashes tie.
    return hashlib.blake2b(
        rule.encode("utf-8", errors="surrogatepass"), digest_size=16
    ).digest()


def _minimizer_probe_chunk_signature_raw(
    rule: str, probe_words: List[str], start: int, stop: int,
    multibyte: bool = False,
):
    """Return a compact (16-byte signature, kind) pair."""
    atoms = tokenize_rule(rule)
    digest = hashlib.blake2b(digest_size=16)
    for word in probe_words[start:stop]:
        current: Union[str, InvalidUTF8Bytes, None] = word
        for atom in atoms:
            current = _apply_single(atom, current, multibyte=multibyte)  # type: ignore[arg-type]
            if current is None:
                return _minimizer_unsupported_signature(rule), _MINIMIZER_UNSUPPORTED_KIND
        if isinstance(current, InvalidUTF8Bytes):
            kind = b"\x01"
            encoded = current.raw
        else:
            kind = b"\x00"
            encoded = current.encode("utf-8", errors="surrogatepass")
        digest.update(kind)
        digest.update(len(encoded).to_bytes(8, "little"))
        digest.update(encoded)
    return digest.digest(), _MINIMIZER_SUPPORTED_KIND


def _minimizer_probe_chunk_signature(
    rule: str, probe_words: List[str], start: int, stop: int,
    multibyte: bool = False,
) -> str:
    """Backward-compatible textual representation for diagnostic callers."""
    signature, kind = _minimizer_probe_chunk_signature_raw(
        rule, probe_words, start, stop, multibyte=multibyte
    )
    if kind == _MINIMIZER_UNSUPPORTED_KIND:
        return _MINIMIZER_UNSUPPORTED_PREFIX + rule
    return signature.hex()


def _extend_minimizer_signature_raw(previous, previous_kind, chunk_signature, chunk_kind):
    if previous_kind == _MINIMIZER_UNSUPPORTED_KIND or chunk_kind == _MINIMIZER_UNSUPPORTED_KIND:
        if chunk_kind == _MINIMIZER_UNSUPPORTED_KIND:
            return chunk_signature, _MINIMIZER_UNSUPPORTED_KIND
        return previous, previous_kind
    digest = hashlib.blake2b(digest_size=16)
    digest.update(previous)
    digest.update(chunk_signature)
    return digest.digest(), _MINIMIZER_SUPPORTED_KIND


def _extend_minimizer_signature(previous: str, chunk_signature: str) -> str:
    """Backward-compatible textual signature extension."""
    if previous.startswith(_MINIMIZER_UNSUPPORTED_PREFIX):
        return previous
    if chunk_signature.startswith(_MINIMIZER_UNSUPPORTED_PREFIX):
        return chunk_signature
    digest = hashlib.blake2b(digest_size=16)
    digest.update(bytes.fromhex(previous))
    digest.update(bytes.fromhex(chunk_signature))
    return digest.hexdigest()


def _minimizer_initial_worker(task):
    index, rule, start, stop = task
    signature, kind = _minimizer_probe_chunk_signature_raw(
        rule, _MINIMIZER_WORKER_PROBES, start, stop,
        multibyte=_MINIMIZER_WORKER_MULTIBYTE,
    )
    return int(index), signature, kind


def _minimizer_refine_worker(task):
    slot, rule, previous, previous_kind, start, stop = task
    chunk_signature, chunk_kind = _minimizer_probe_chunk_signature_raw(
        rule, _MINIMIZER_WORKER_PROBES, start, stop,
        multibyte=_MINIMIZER_WORKER_MULTIBYTE,
    )
    signature, kind = _extend_minimizer_signature_raw(
        previous, previous_kind, chunk_signature, chunk_kind
    )
    return int(slot), signature, kind


def _minimizer_map(executor, function, tasks):
    if executor is None:
        return map(function, tasks)
    return executor.map(function, tasks, chunksize=128)


def _minimizer_progress(total: int, description: str):
    if HAS_TQDM:
        return tqdm(
            total=max(0, int(total)),
            desc=green(description),
            unit="rule",
            mininterval=0.5,
        )
    return None


def _minimizer_classify_and_compact(records, active_count: int, keep_mask):
    """Mark singleton source offsets and compact collision records in-place."""
    if active_count <= 0:
        return 0
    active = records[:active_count]
    active.sort(order=("kind", "sig", "idx"), kind="quicksort")
    if active_count == 1:
        keep_mask[int(active["idx"][0])] = True
        return 0

    same = (active["kind"][1:] == active["kind"][:-1]) & (
        active["sig"][1:] == active["sig"][:-1]
    )
    if not np.any(same):
        keep_mask[active["idx"]] = True
        return 0

    collision_mask = np.zeros(active_count, dtype=np.bool_)
    collision_mask[:-1] |= same
    collision_mask[1:] |= same
    collision_count = int(np.count_nonzero(collision_mask))
    if collision_count * 2 < active_count:
        keep_mask[active["idx"]] = True
        collision_offsets = active["idx"][collision_mask]
        keep_mask[collision_offsets] = False
    else:
        single_offsets = active["idx"][~collision_mask]
        keep_mask[single_offsets] = True
    if collision_count:
        np.compress(collision_mask, active, axis=0, out=active[:collision_count])
    return collision_count


def _minimizer_resolve_final(records, active_count: int, rules: List[str], keep_mask):
    """Keep the earliest input rule from each final signature group."""
    if active_count <= 0:
        return
    active = records[:active_count]
    active.sort(order=("kind", "sig", "idx"), kind="quicksort")
    pos = 0
    while pos < active_count:
        kind = int(active["kind"][pos])
        signature = active["sig"][pos]
        end = pos + 1
        while end < active_count and int(active["kind"][end]) == kind and active["sig"][end] == signature:
            end += 1
        if kind == _MINIMIZER_UNSUPPORTED_KIND:
            # Use the hash to locate possible duplicates, then compare exact
            # text: distinct unsupported rules must always survive.
            seen_rules = set()
            for cursor in range(pos, end):
                index = int(active["idx"][cursor])
                rule = rules[index]
                if rule not in seen_rules:
                    seen_rules.add(rule)
                    keep_mask[index] = True
        else:
            # idx is the final sort field, so the first item is earliest.
            keep_mask[int(active["idx"][pos])] = True
        pos = end


def _minimizer_in_memory(
    rules: List[str], probe: List[str], multibyte: bool, executor=None,
) -> Tuple[List[str], int, int]:
    """Offset-indexed minimization with a fixed-size signature buffer."""
    if not rules:
        return [], 0, 0

    ranges = _minimizer_probe_ranges(len(probe))
    batch_size = max(1, int(MINIMIZER_BATCH_SIZE))
    total = len(rules)
    records = np.empty(total, dtype=_minimizer_record_dtype(total))
    records["idx"] = np.arange(total, dtype=records.dtype["idx"])
    keep_mask = np.zeros(total, dtype=np.bool_)

    first_start, first_stop = ranges[0]
    progress = _minimizer_progress(total, f"  Compute probes {first_start + 1}-{first_stop}")
    try:
        for offset in range(0, total, batch_size):
            stop_at = min(total, offset + batch_size)
            tasks = (
                (index, rules[index], first_start, first_stop)
                for index in range(offset, stop_at)
            )
            for index, signature, kind in _minimizer_map(
                    executor, _minimizer_initial_worker, tasks):
                records["sig"][index] = signature
                records["kind"][index] = kind
            if progress is not None:
                progress.update(stop_at - offset)
    finally:
        if progress is not None:
            progress.close()

    active_count = _minimizer_classify_and_compact(records, total, keep_mask)
    if active_count == 0:
        return rules, len(rules), 0

    for pass_number, (start, stop) in enumerate(ranges[1:], start=2):
        if active_count == 0:
            break
        progress = _minimizer_progress(
            active_count, f"  Refine probes {start + 1}-{stop}"
        )
        processed = 0
        try:
            for offset in range(0, active_count, batch_size):
                stop_at = min(active_count, offset + batch_size)

                def tasks_for_batch():
                    for slot in range(offset, stop_at):
                        index = int(records["idx"][slot])
                        yield (
                            slot,
                            rules[index],
                            bytes(records["sig"][slot]),
                            int(records["kind"][slot]),
                            start,
                            stop,
                        )

                for slot, signature, kind in _minimizer_map(
                        executor, _minimizer_refine_worker, tasks_for_batch()):
                    records["sig"][slot] = signature
                    records["kind"][slot] = kind
                processed += stop_at - offset
                if progress is not None:
                    progress.update(stop_at - offset)
        finally:
            if progress is not None:
                progress.close()

        active_count = _minimizer_classify_and_compact(records, active_count, keep_mask)
        print(
            f"  {dim('[MIN]')} Probe pass {pass_number}/{len(ranges)}: "
            f"refined={processed:,}, unresolved={active_count:,}"
        )

    _minimizer_resolve_final(records, active_count, rules, keep_mask)
    kept_count = int(np.count_nonzero(keep_mask))
    if kept_count == total:
        return rules, kept_count, 0
    kept = [rule for index, rule in enumerate(rules) if keep_mask[index]]
    return kept, len(kept), total - len(kept)


def minimizer(
    rules: List[str],
    probe: List[str],
    multibyte: bool = False,
    workers: int = 1,
) -> Tuple[List[str], int, int]:
    """Deduplicate rules with an in-RAM offset buffer (no temporary database).

    Each candidate is represented by a compact signature record and an offset
    into the caller's original rule list. Only collisions are refined, while
    surviving rules retain their original input order.
    """
    if not rules:
        return [], 0, 0
    ordered_probe = _ordered_minimizer_probes(probe)
    worker_count = max(1, int(workers))
    _minimizer_worker_init(ordered_probe, multibyte)
    print(
        f"  {cyan('[MIN]')}  Strategy: in-memory offsets; "
        f"compact fixed-width records; probe batch={max(1, int(MINIMIZER_PROBE_BATCH_SIZE))}; "
        f"workers={worker_count}"
    )
    if worker_count > 1:
        with ProcessPoolExecutor(
            max_workers=worker_count,
            initializer=_minimizer_worker_init,
            initargs=(ordered_probe, multibyte),
        ) as executor:
            return _minimizer_in_memory(
                rules, ordered_probe, multibyte=multibyte, executor=executor,
            )
    return _minimizer_in_memory(
        rules, ordered_probe, multibyte=multibyte, executor=None,
    )


# ====================================================================
# --- ENTRY POINT ---
# ====================================================================
def main() -> None:
    ap = argparse.ArgumentParser(
        prog='minimizer',
        description=(
            'Standalone Hashcat Rule Minimizer (v1.4)\n\n'
            'Eliminates functionally redundant rules by computing each rule\'s\n'
            'signature — the tuple of outputs on a fixed probe set of words.\n\n'
            'Rules with identical signatures produce identical output on every\n'
            'probe word and are therefore indistinguishable by hashcat.  Only\n'
            'the rule appearing first in the input file is retained.\n\n'
            'The built-in probe set covers short words (including "password"),\n'
            'mixed-case words, words with digits/specials, repeated-char\n'
            'words, and words up to length 36 so that rules using high\n'
            'position arguments (A–Z) are correctly distinguished.'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    ap.add_argument('rules_file', nargs='?', default=None,
                    help='Input hashcat rule file to minimize')
    ap.add_argument('-o', '--output', default=None,
                    help='Output file  (default: <rules_file>.minimized.rule)')

    grp = ap.add_argument_group('Probe set options')
    grp.add_argument('--extra-probes', nargs='+', default=[], metavar='WORD',
                     help='Additional probe words appended to the built-in set '
                          '(e.g. --extra-probes password admin letmein)')
    grp.add_argument('--probe-file', default=None, metavar='FILE',
                     help='Wordlist to draw extra probe words from')
    grp.add_argument('--probe-words', type=int, default=50, metavar='N',
                     help='Max words to sample from --probe-file  (default: 50)')
    grp.add_argument('--seed', type=int, default=42,
                     help='RNG seed for reproducible probe sampling  (default: 42)')
    grp.add_argument('--list-probes', action='store_true',
                     help='Print the built-in probe set and exit')

    # ── multibyte / unicode ───────────────────────────────────────────
    grp2 = ap.add_argument_group('Multibyte / Unicode options')
    grp2.add_argument('--multibyte', action='store_true',
                      help=(
                          'Process words as UTF-8 byte sequences instead of '
                          'latin-1.  Required for correct handling of Polish, '
                          'German, French, Russian, CJK, and other non-ASCII '
                          'characters.  Also adds extra multibyte probe words '
                          '(see --list-probes).'))

    # ── performance options ───────────────────────────────────────────
    grp4 = ap.add_argument_group('Performance options')
    grp4.add_argument(
        '--workers', type=int,
        default=1,
        metavar='N',
        help=(
            'Number of worker processes for parallel signature computation.  '
            f'Use --workers 0 to auto-detect (os.cpu_count() = {os.cpu_count()}).  '
            'Default: 1 (single-process).'
        ),
    )

    # ── debug options ─────────────────────────────────────────────────
    grp3 = ap.add_argument_group('Debug options')
    grp3.add_argument('--debug', action='store_true',
                      help=(
                          'Enable verbose debug output on stderr.  '
                          'Shows every rule that is kept or removed, '
                          'and which earlier rule it duplicates.'))
    grp3.add_argument('--debug-rule', metavar='RULE', default=None,
                      help=(
                          'Trace a single rule against the probe set and exit.  '
                          'Shows the transformation applied to each probe word.  '
                          'Example: --debug-rule "l r $1"'))
    grp3.add_argument('--debug-file', metavar='FILE', default=None,
                      help=(
                          'Trace every rule in FILE against the probe set and exit.  '
                          'FILE must contain one rule per line (same format as a rule '
                          'file; blank lines and # comment lines are skipped).  '
                          'Useful to bulk-inspect rules from comm / diff output.  '
                          'Example: --debug-file dropped_rules.txt'))

    args = ap.parse_args()

    # ── activate debug mode ───────────────────────────────────────────
    global _DEBUG
    _DEBUG = args.debug

    if _DEBUG:
        print(f"{cyan('[DEBUG]')} Debug mode enabled — verbose output on stderr\n",
              file=sys.stderr)

    # ── list probes and exit ──────────────────────────────────────────
    if args.list_probes:
        # ── category 1: built-in (ASCII) ─────────────────────────────
        print(f"\n{bold(cyan('Category 1 — built-in ASCII probe set'))}  "
              f"{dim(f'({len(BUILTIN_PROBES)} words)')}\n")
        # group by the inline comment categories from BUILTIN_PROBES
        _categories = [
            ("very short  (edge cases: k K {{ }} [ ])",              slice(0, 3)),
            ("short alphanumeric  (len 4–6)",                        slice(3, 8)),
            ("typical password base words  (len 7–9)",               slice(8, 16)),
            ("longer words  (len 10–11, truncation / repeat ops)",   slice(16, 21)),
            ("extended-length words  (len 12–36, positions B–Z)",    slice(21, 30)),
            ("alphabet coverage  (all 95 printable ASCII chars)",    slice(30, 38)),
            ("mixed-case  (l/u/c/C/t/E/T/k/K)",                     slice(38, 42)),
            ("words with digits  (s o @ T)",                         slice(42, 46)),
            ("special chars  (@ removal, s substitution)",           slice(46, 48)),
            ("repeated chars  (q doubling, z/Z extend)",             slice(48, 50)),
        ]
        for label, sl in _categories:
            words = BUILTIN_PROBES[sl]
            if not words:
                continue
            print(f"  {bold(label)}")
            for w in words:
                print(f"      {dim(repr(w)):32s}  len={len(w)}")
            print()

        # ── category 2: multibyte (UTF-8) ────────────────────────────
        print(f"{bold(cyan('Category 2 — multibyte (UTF-8) probe set'))}  "
              f"{dim(f'({len(MULTIBYTE_PROBES)} words)')}"
              f"  {dim('activated by --multibyte')}\n")
        _mb_groups = [
            ("Polish",    ["hasło", "żółw", "źródło"]),
            ("German", ["straße", "münchen", "übermensch"]),
            ("French", ["café", "naïve"]),
            ("Russian",  ["пароль"]),
            ("CJK / emoji  (3–4 byte UTF-8 sequences)", ["密码", "パスワード"]),
        ]
        for lang, words in _mb_groups:
            print(f"  {bold(lang)}")
            for w in words:
                utf8 = w.encode('utf-8')
                hex_repr = ' '.join(f'{b:02X}' for b in utf8)
                active = cyan("✓ active") if args.multibyte else dim("○ inactive")
                print(f"      {w!r:20s}  "
                      f"{len(w)} ch / {len(utf8)} B  "
                      f"utf8=[{hex_repr}]  {active}")
            print()

        total = len(BUILTIN_PROBES) + (len(MULTIBYTE_PROBES) if args.multibyte else 0)
        print(f"  {dim('Total active probe words:')} {bold(str(total))}")
        if not args.multibyte:
            print(f"  {dim('Use --multibyte --list-probes to activate category 2.')}")
        print()
        sys.exit(0)

    # ── rules_file is required for all other operations ───────────────
    if args.rules_file is None:
        ap.error("rules_file is required (or use --list-probes)")

    # ── default output name ───────────────────────────────────────────
    if args.output is None:
        base, ext = os.path.splitext(args.rules_file)
        args.output = f"{base}.minimized{ext or '.rule'}"

    # ── banner ────────────────────────────────────────────────────────
    print(f"\n{bold(cyan('minimizer'))}  —  Standalone Hashcat Rule Minimizer\n")
    if args.multibyte:
        print(f"  {cyan('[MB]')}  Multibyte (UTF-8) mode enabled\n")

    # ── resolve workers ───────────────────────────────────────────────
    workers = os.cpu_count() if args.workers == 0 else max(1, args.workers)
    if workers > 1:
        print(f"  {cyan('[MP]')}  Multiprocessing enabled: "
              f"{bold(str(workers))} workers\n")

    # ── read rules ───────────────────────────────────────────────────
    rules = read_rules(args.rules_file)
    print(f"[IN ]  {bold(args.rules_file)}: "
          f"{bold(cyan(f'{len(rules):,}'))} rules loaded")

    # ── build probe set ───────────────────────────────────────────────
    probe = build_probe_set(
        extra_probes=args.extra_probes,
        probe_file=args.probe_file,
        probe_words=args.probe_words,
        seed=args.seed,
        multibyte=args.multibyte,
    )

    # ── --debug-rule: trace one rule and exit ─────────────────────────
    if args.debug_rule is not None:
        debug_rule(args.debug_rule, probe, multibyte=args.multibyte)
        sys.exit(0)

    # ── --debug-file: trace every rule in a file and exit ─────────────
    if args.debug_file is not None:
        try:
            batch = read_rules(args.debug_file)
        except SystemExit:
            sys.exit(1)
        if not batch:
            print(red(f"[ERROR] No rules found in {args.debug_file}"), file=sys.stderr)
            sys.exit(1)
        print(f"\n{bold(cyan('[DEBUG-FILE]'))}  {len(batch)} rule(s) loaded from "
              f"{bold(args.debug_file)}\n")
        for idx, rule in enumerate(batch, 1):
            print(f"{dim(f'  [{idx}/{len(batch)}]')}  {bold(repr(rule))}")
            debug_rule(rule, probe, multibyte=args.multibyte)
            # separator every 10 rules to keep long outputs readable
            if idx % 10 == 0 and idx < len(batch):
                print(dim("  " + "─" * 60))
        sys.exit(0)
    print(f"[PRB]  Probe set: {bold(str(len(probe)))} words")
    if len(probe) <= 40:
        # print the probe set so the user can verify it looks right
        cols = 4
        rows = [probe[i:i + cols] for i in range(0, len(probe), cols)]
        for row in rows:
            print("       " + "  ".join(f"{dim(repr(w)):32s}" for w in row))
    print()

    # ── minimize ─────────────────────────────────────────────────────
    kept, n_kept, n_removed = minimizer(
        rules, probe, multibyte=args.multibyte, workers=workers
    )
    pct = n_removed / max(1, len(rules)) * 100

    print()
    print(f"[MIN]  Rules in    : {bold(str(len(rules))):>12s}")
    print(f"[MIN]  Rules kept  : {bold(green(str(n_kept))):>12s}")
    print(f"[MIN]  Removed     : {bold(red(str(n_removed))):>12s}  ({pct:.1f}%)")

    # ── write output ─────────────────────────────────────────────────
    with open(args.output, 'w', encoding='utf-8') as fh:
        fh.write("# minimizer — Standalone Hashcat Rule Minimizer\n")
        fh.write(f"# Generated  : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        fh.write(f"# Source     : {os.path.basename(args.rules_file)}\n")
        fh.write(f"# Probe set  : {len(probe)} words\n")
        fh.write(f"# Input rules: {len(rules):,}\n")
        fh.write(f"# Kept       : {n_kept:,}\n")
        fh.write(f"# Removed    : {n_removed:,}  ({pct:.1f}%)\n")
        fh.write("#\n")
        for rule in kept:
            fh.write(f"{rule}\n")

    print(f"[OUT]  Written to: {bold(args.output)}")
    print()

    # ── quick verification hint ───────────────────────────────────────
    print(dim("  Verify with:"))
    print(dim(f"    hashcat --stdout -r {args.output} password.txt | sort -u | wc -l"))
    print()


if __name__ == '__main__':
    # freeze_support() is a no-op on Linux/macOS but required on Windows
    # when the script is bundled with PyInstaller (spawn start method).
    multiprocessing.freeze_support()
    main()
