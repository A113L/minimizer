#!/usr/bin/env python3
"""
minimize_rules.py — Standalone Hashcat Rule Minimizer
======================================================
Reads a hashcat rule file and eliminates functionally redundant rules by
computing each rule's *signature* — the tuple of outputs produced when the
rule is applied to a fixed probe set of words.

Two rules are considered equivalent if they produce identical output on
every probe word.  When a collision is found, the rule appearing *earlier*
in the input file is kept (preserving the original sort order / frequency
ranking) and the later duplicate is discarded.

Usage
-----
    # Basic — uses only the built-in probe set (30 words)
    python minimize_rules.py ruleset.rule -o minimized.rule

    # Add extra probe words on the CLI
    python minimize_rules.py ruleset.rule -o minimized.rule \\
        --extra-probes password admin letmein root test

    # Draw additional probes from a wordlist
    python minimize_rules.py ruleset.rule -o minimized.rule \\
        --probe-file rockyou.txt --probe-words 100

    # Combine all three sources
    python minimize_rules.py ruleset.rule -o minimized.rule \\
        --extra-probes password admin \\
        --probe-file rockyou.txt --probe-words 80
"""

import argparse
import datetime
import os
import pickle
import random
import sqlite3
import sys
from typing import List, Optional, Tuple

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False


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
    "password",         # len 8  ← THE critical one missing in rulest_v2
    "sunshine",         # len 8
    "football",         # len 8
    "baseball",         # len 8
    "princess",         # len 8
    "dragon12",         # len 8, ends with digits
    # ── longer words (len 10+) — truncation / repeat ops ─────────────
    "qwertyuiop",       # len 10
    "iloveyou12",       # len 10, trailing digits
    "monkey12345",      # len 11
    "superman123",      # len 11
    "mustang2024",      # len 11
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


def _apply_single(rule: str, word: str) -> Optional[str]:
    """Apply one hashcat rule atom to *word*.  Returns None on unsupported opcode."""
    if not rule:
        return word
    w   = list(word.encode('latin-1'))
    cmd = rule[0]

    def dg(c: str) -> int:
        """Parse a single decimal digit character, return -1 on failure."""
        return ord(c) - 48 if '0' <= c <= '9' else -1

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
            out: list = []; cap = True
            for c in w:
                out.append(c & ~0x20 if cap and 97 <= c <= 122 else c)
                cap = c in (32, 45, 95)
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
            n = dg(rule[1])
            if n > 0:
                orig = w[:]
                for _ in range(n): w += orig
        elif cmd == 'T' and len(rule) >= 2:
            p = dg(rule[1])
            if 0 <= p < len(w):
                c = w[p]
                w[p] = (c | 0x20 if 65 <= c <= 90
                        else (c & ~0x20 if 97 <= c <= 122 else c))
        elif cmd == 'D' and len(rule) >= 2:
            p = dg(rule[1])
            if 0 <= p < len(w): w.pop(p)
        elif cmd == 'L' and len(rule) >= 2:
            p = dg(rule[1])
            if 0 <= p < len(w): w[p] = (w[p] << 1) & 0xFF
        elif cmd == 'R' and len(rule) >= 2:
            p = dg(rule[1])
            if 0 <= p < len(w): w[p] = (w[p] >> 1) & 0xFF
        elif cmd == '+' and len(rule) >= 2:
            p = dg(rule[1])
            if 0 <= p < len(w): w[p] = (w[p] + 1) & 0xFF
        elif cmd == '-' and len(rule) >= 2:
            p = dg(rule[1])
            if 0 <= p < len(w): w[p] = (w[p] - 1) & 0xFF
        elif cmd in ('.', ',') and len(rule) >= 2:
            p     = dg(rule[1])
            delta = 1 if cmd == '.' else -1
            if 0 <= p < len(w): w[p] = (w[p] + delta) & 0xFF
        elif cmd == "'" and len(rule) >= 2:
            p = dg(rule[1])
            if 0 <= p < len(w): w = w[:p + 1]
        elif cmd == 'z' and len(rule) >= 2:
            n = dg(rule[1])
            if n > 0 and w: w = [w[0]] * n + w
        elif cmd == 'Z' and len(rule) >= 2:
            n = dg(rule[1])
            if n > 0 and w: w = w + [w[-1]] * n
        elif cmd == 'y' and len(rule) >= 2:
            n = dg(rule[1])
            if n > 0: w = w[:n] + w
        elif cmd == 'Y' and len(rule) >= 2:
            n = dg(rule[1])
            if n > 0 and len(w) >= n: w = w + w[-n:]

        # ── two-char argument ops (len >= 3) ─────────────────────────
        elif cmd == 's' and len(rule) >= 3:
            a, b = _arg_ord(rule, 1), _arg_ord(rule, 2 if rule[1] != '\\' else 5)
            w = [b if c == a else c for c in w]
        elif cmd == 'i' and len(rule) >= 3:
            p, ch = dg(rule[1]), _arg_ord(rule, 2)
            if 0 <= p <= len(w): w.insert(p, ch)
        elif cmd == 'o' and len(rule) >= 3:
            p, ch = dg(rule[1]), _arg_ord(rule, 2)
            if 0 <= p < len(w): w[p] = ch
        elif cmd == 'e' and len(rule) >= 2:
            sep = _arg_ord(rule, 1); out = []; cap = True
            for c in w:
                out.append(c & ~0x20 if cap and 97 <= c <= 122 else c)
                cap = (c == sep)
            w = out
        elif cmd == 'x' and len(rule) >= 3:
            a, b = dg(rule[1]), dg(rule[2])
            if a > b: a, b = b, a
            w = w[a:b + 1]
        elif cmd == 'O' and len(rule) >= 3:
            p, m = dg(rule[1]), dg(rule[2])
            if 0 <= p < len(w) and m > 0: w = w[:p] + w[p + m:]
        elif cmd == '*' and len(rule) >= 3:
            a, b = dg(rule[1]), dg(rule[2])
            if 0 <= a < len(w) and 0 <= b < len(w) and a != b:
                w[a], w[b] = w[b], w[a]
        elif cmd == '3' and len(rule) >= 3:
            n, sep = dg(rule[1]), _arg_ord(rule, 2)
            cnt = 0
            for i, c in enumerate(w):
                if c == sep:
                    cnt += 1
                    if cnt == n and i + 1 < len(w):
                        ci = w[i + 1]
                        w[i + 1] = (ci | 0x20 if 65 <= ci <= 90
                                    else (ci & ~0x20 if 97 <= ci <= 122 else ci))
                        break
        else:
            return None  # unsupported opcode

    except Exception:
        return None

    try:
        return bytes(w).decode('latin-1')
    except Exception:
        return None



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


def apply_chain(chain: str, word: str) -> Optional[str]:
    """
    Apply a hashcat rule chain to *word*.

    Accepts **both** space-separated (``l r $1``) and concatenated
    (``lr$1``) formats, as well as mixed lines.  ``\\xNN`` hex-escape
    notation in argument positions is also supported.

    Returns ``None`` if any atom contains an unsupported opcode.
    """
    cur: Optional[str] = word
    for atom in tokenize_rule(chain):
        cur = _apply_single(atom, cur)  # type: ignore[arg-type]
        if cur is None:
            return None
    return cur


# ====================================================================
# --- SIGNATURE COMPUTATION ---
# ====================================================================
_UNSUPPORTED_SIG: tuple = ('__UNSUPPORTED__',)


def compute_signature(rule: str, probe_words: List[str]) -> tuple:
    """
    Return the functional signature of *rule* — a tuple of its outputs on
    every word in *probe_words*.

    If the rule contains an unsupported opcode, returns the sentinel tuple
    ``('__UNSUPPORTED__',)`` so all such rules land in one bucket and the
    first one in file order is retained.
    """
    outputs = []
    for word in probe_words:
        out = apply_chain(rule, word)
        if out is None:
            return _UNSUPPORTED_SIG
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
) -> List[str]:
    """
    Assemble the probe set used for signature computation.

    Assembly order (later duplicates are silently dropped):
      1. BUILTIN_PROBES   — always included
      2. extra_probes     — words supplied via --extra-probes
      3. sample from probe_file — up to *probe_words* random words

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
# --- CORE MINIMIZER ---
# ====================================================================

# Rulesets larger than this use a SQLite temp-DB instead of an in-memory
# dict so that the signature map never blows up RAM.
_SQLITE_THRESHOLD = 1_000_000


def _minimize_rules_sqlite(
    rules: List[str],
    probe: List[str],
) -> "tuple[List[str], int, int]":
    """
    SQLite-backed deduplication for large rulesets (> _SQLITE_THRESHOLD rules).

    The signature map lives entirely inside a temporary ``minimizer_tmp_<pid>.db``
    file in the current working directory, which is deleted unconditionally on
    completion (success or error).  Only the ``kept`` list (unique rules) is
    held in Python memory, which is far smaller than storing every signature.

    Commit batching (every 10 000 rows) keeps SQLite write throughput high
    while avoiding one transaction per rule.
    """
    db_path = os.path.join(os.getcwd(), f"minimizer_tmp_{os.getpid()}.db")
    # Remove any stale temp file from a previous crashed run
    if os.path.exists(db_path):
        os.remove(db_path)

    print(f"  {cyan('[DB]')}  Ruleset exceeds {_SQLITE_THRESHOLD:,} rules — "
          f"using SQLite backing store\n"
          f"       {dim(db_path)}")

    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        # Performance pragmas: WAL mode + no fsync (temp file, loss is fine)
        cur.executescript("""
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous  = OFF;
            PRAGMA temp_store   = MEMORY;
            PRAGMA cache_size   = -65536;
        """)
        cur.execute("CREATE TABLE sigs (sig BLOB PRIMARY KEY)")
        conn.commit()

        kept: List[str] = []
        n_removed       = 0
        _BATCH          = 10_000

        # ── progress bar (same pattern as the in-memory path) ────────
        if HAS_TQDM:
            iterator = tqdm(
                rules,
                desc=green("  Minimizing"),
                unit="rule",
                ncols=88,
                bar_format=(
                    "{l_bar}{bar}| {n_fmt}/{total_fmt} "
                    "[{elapsed}<{remaining}] {postfix}"
                ),
            )
            set_postfix = iterator.set_postfix
        else:
            _counter = [0]

            def _noop_postfix(**_kw):
                pass

            def _simple_iter(rules):
                for r in rules:
                    _counter[0] += 1
                    if _counter[0] % _BATCH == 0:
                        pct = _counter[0] / len(rules) * 100 if rules else 0
                        print(
                            f"  {_counter[0]:,}/{len(rules):,}  ({pct:.0f}%)  "
                            f"kept={len(kept):,}",
                            end="\r", flush=True,
                        )
                    yield r

            iterator    = _simple_iter(rules)
            set_postfix = _noop_postfix

        pending = 0
        conn.execute("BEGIN")

        for rule in iterator:
            sig      = compute_signature(rule, probe)
            sig_blob = pickle.dumps(sig, protocol=4)

            cur.execute(
                "INSERT OR IGNORE INTO sigs (sig) VALUES (?)",
                (sig_blob,),
            )
            if cur.rowcount:          # 1 = newly inserted → unique rule
                kept.append(rule)
                if HAS_TQDM:
                    set_postfix({"unique": cyan(str(len(kept)))}, refresh=False)
            else:
                n_removed += 1

            pending += 1
            if pending >= _BATCH:
                conn.commit()
                conn.execute("BEGIN")
                pending = 0

        conn.commit()

        if not HAS_TQDM:
            print()   # newline after \r progress line

    finally:
        conn.close()
        if os.path.exists(db_path):
            os.remove(db_path)
            print(f"  {dim('[DB]  Temporary database removed.')}")

    return kept, len(kept), n_removed


def minimize_rules(
    rules: List[str],
    probe: List[str],
) -> Tuple[List[str], int, int]:
    """
    Deduplicate *rules* by functional signature over *probe*.

    When two rules share the same signature the one appearing *earlier*
    in *rules* is kept (file order = priority).

    Returns
    -------
    kept : list of str
        Surviving rules in their original file order.
    n_kept : int
        ``len(kept)``
    n_removed : int
        Number of rules eliminated.
    """
    # ── delegate to SQLite path for large rulesets ───────────────────
    if len(rules) > _SQLITE_THRESHOLD:
        return _minimize_rules_sqlite(rules, probe)

    sig_map: dict       = {}   # signature -> rule (first seen)
    kept:    List[str]  = []
    n_removed           = 0

    # ── progress bar (gracefully falls back to a plain counter) ──────
    if HAS_TQDM:
        iterator = tqdm(
            rules,
            desc=green("  Minimizing"),
            unit="rule",
            ncols=88,
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}] {postfix}",
        )
        set_postfix = iterator.set_postfix
    else:
        # simple fallback: print progress every 10 000 rules
        _counter = [0]
        def _noop_postfix(**_kw): pass
        def _simple_iter(rules):
            for r in rules:
                _counter[0] += 1
                if _counter[0] % 10_000 == 0:
                    pct = _counter[0] / len(rules) * 100 if rules else 0
                    print(f"  {_counter[0]:,}/{len(rules):,}  ({pct:.0f}%)  "
                          f"kept={len(kept):,}", end='\r', flush=True)
                yield r
        iterator     = _simple_iter(rules)
        set_postfix  = _noop_postfix

    for rule in iterator:
        sig = compute_signature(rule, probe)
        if sig not in sig_map:
            sig_map[sig] = rule
            kept.append(rule)
            if HAS_TQDM:
                set_postfix({"unique": cyan(str(len(kept)))}, refresh=False)
        else:
            n_removed += 1

    if not HAS_TQDM:
        print()   # newline after \r progress

    return kept, len(kept), n_removed


# ====================================================================
# --- ENTRY POINT ---
# ====================================================================
def main() -> None:
    ap = argparse.ArgumentParser(
        prog='minimize_rules',
        description=(
            'Standalone Hashcat Rule Minimizer\n\n'
            'Eliminates functionally redundant rules by computing each rule\'s\n'
            'signature — the tuple of outputs on a fixed probe set of words.\n\n'
            'Rules with identical signatures produce identical output on every\n'
            'probe word and are therefore indistinguishable by hashcat.  Only\n'
            'the rule appearing first in the input file is retained.\n\n'
            'The built-in probe set covers short words (including "password"),\n'
            'mixed-case words, words with digits/specials, and repeated-char\n'
            'words — so the minimization is accurate without a wordlist file.'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    ap.add_argument('rules_file',
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

    args = ap.parse_args()

    # ── list probes and exit ──────────────────────────────────────────
    if args.list_probes:
        print(f"\n{bold('Built-in probe set')}  ({len(BUILTIN_PROBES)} words):\n")
        for i, w in enumerate(BUILTIN_PROBES, 1):
            print(f"  {str(i).rjust(3)}.  {w!r}  (len={len(w)})")
        print()
        sys.exit(0)

    # ── default output name ───────────────────────────────────────────
    if args.output is None:
        base, ext = os.path.splitext(args.rules_file)
        args.output = f"{base}.minimized{ext or '.rule'}"

    # ── banner ────────────────────────────────────────────────────────
    print(f"\n{bold(cyan('minimize_rules'))}  —  Standalone Hashcat Rule Minimizer\n")

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
    )
    print(f"[PRB]  Probe set: {bold(str(len(probe)))} words")
    if len(probe) <= 40:
        # print the probe set so the user can verify it looks right
        cols = 4
        rows = [probe[i:i + cols] for i in range(0, len(probe), cols)]
        for row in rows:
            print("       " + "  ".join(f"{dim(repr(w)):32s}" for w in row))
    print()

    # ── minimize ─────────────────────────────────────────────────────
    kept, n_kept, n_removed = minimize_rules(rules, probe)
    pct = n_removed / max(1, len(rules)) * 100

    print()
    print(f"[MIN]  Rules in    : {bold(str(len(rules))):>12s}")
    print(f"[MIN]  Rules kept  : {bold(green(str(n_kept))):>12s}")
    print(f"[MIN]  Removed     : {bold(red(str(n_removed))):>12s}  ({pct:.1f}%)")

    # ── write output ─────────────────────────────────────────────────
    with open(args.output, 'w', encoding='utf-8') as fh:
        fh.write("# minimize_rules — Standalone Hashcat Rule Minimizer\n")
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
    main()
