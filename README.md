# minimizer — Hashcat Rule Minimizer

A standalone Python tool that eliminates functionally redundant rules from hashcat rule files. Two rules are considered equivalent if they produce **identical output on every word in the probe set** — if they can't be told apart, one of them is waste.

---

## How it works

For each rule, the tool computes a **signature** — the tuple of transformed outputs when that rule is applied to every word in the probe set. Rules that share a signature are functionally identical. When a collision is found, the rule appearing **earlier** in the file is kept and the later one is discarded, preserving the original frequency/priority ranking.

```
rule "l"   applied to ["password", "Admin", ...]  →  ("password", "admin", ...)
rule "l"   (duplicate) ──────────────────────────  →  same signature → dropped
```

The built-in probe set (50 words) is hand-curated to exercise every opcode category:

- **Very short words** — edge cases for `k`, `K`, `{`, `}`, `[`, `]`
- **Short alphanumeric** — position ops within short words
- **Typical base words** (len 7–9) — the real-world password range
- **Longer words** (len 10–11) — truncation and repeat ops
- **Extended-length words** (len 12–36) — ensures rules using position arguments `B`–`Z` (positions 11–35) have distinct signatures; without these, rules like `'B`–`'Z`, `TB`–`TZ`, `DB`–`DZ` etc. would all falsely collapse into the same no-op signature
- **Alphabet coverage** — 8 words collectively containing all 95 printable ASCII code-points (0x20–0x7E); ensures rules like `@j`, `@x`, `s\"a`, `` s`z `` etc. are distinguishable from no-ops and from each other
- **Mixed-case, digit, special-char, repeated-char** — exercises `l`/`u`/`c`/`C`/`t`/`E`/`T`, `s`/`o`/`@`, `q`/`z`/`Z`

Every hashcat opcode the GPU kernel supports is implemented in pure Python.

In `--multibyte` mode a second probe category (11 words) is added covering Polish, German, French, Russian, and CJK characters. Words are then processed as raw UTF-8 byte sequences, matching hashcat's behaviour on non-ASCII wordlists.

### Signature store

All deduplication uses a temporary **SQLite database** regardless of ruleset size. Signatures are stored as binary blobs keyed by `INSERT OR IGNORE`, so the signature map never occupies Python heap memory. The temp file (`minimizer_tmp_<pid>.db`) is created in the current working directory and deleted unconditionally on completion, including on error or `Ctrl+C`.

---

## Requirements

- Python 3.7+
- No mandatory dependencies — `sqlite3`, `pickle`, and `multiprocessing` are stdlib
- [`tqdm`](https://github.com/tqdm/tqdm) *(optional)* — enables rich progress bars

```bash
pip install tqdm
```

---

## Installation

```bash
git clone https://github.com/A113L/minimizer.git
cd minimizer
```

No build step required. Run directly with `python minimizer.py`.

---

## Usage

```
python minimizer.py <rules_file> [options]
```

### Basic

```bash
# Minimise a ruleset — output defaults to <input>.minimized.rule
python minimizer.py rockyou-30000.rule

# Specify output path explicitly
python minimizer.py rockyou-30000.rule -o rockyou-min.rule
```

### Parallel processing

Use `--workers N` to distribute the signature-computation phase across multiple CPU cores. The deduplication step always runs on the main process.

```bash
# Use 8 worker processes
python minimizer.py rockyou-30000.rule -o out.rule --workers 8

# Auto-detect CPU count
python minimizer.py rockyou-30000.rule -o out.rule --workers 0
```

`--workers 1` (default) disables multiprocessing entirely — no subprocess overhead for small rulesets.

### Probe set options

The probe set determines how finely rules are discriminated. More probe words = fewer false equivalences, but slower processing. The built-in 50-word set covers all 95 printable ASCII characters and positions 0–35, giving accurate results for all standard opcodes without any wordlist.

```bash
# Add extra probe words on the CLI
python minimizer.py ruleset.rule -o minimized.rule \
    --extra-probes password admin letmein root test

# Draw additional probes from a wordlist (sampled randomly)
python minimizer.py ruleset.rule -o minimized.rule \
    --probe-file rockyou.txt --probe-words 100

# Combine all three sources
python minimizer.py ruleset.rule -o minimized.rule \
    --extra-probes password admin \
    --probe-file rockyou.txt --probe-words 80

# Reproducible sampling — fix the RNG seed (default: 42)
python minimizer.py ruleset.rule --probe-file rockyou.txt --seed 1337
```

### Multibyte / Unicode mode

Pass `--multibyte` when your wordlists contain non-ASCII characters (Polish, German, French, Russian, CJK, emoji, etc.). Without this flag, words are processed as latin-1 bytes and any character outside that range triggers an automatic UTF-8 fallback with a warning.

```bash
# Enable UTF-8 byte-level processing
python minimizer.py ruleset.rule -o minimized.rule --multibyte

# Multibyte + extra non-ASCII probes from a wordlist
python minimizer.py ruleset.rule -o minimized.rule \
    --multibyte --probe-file polish-wordlist.txt --probe-words 50
```

**What changes in multibyte mode:**

- Words are encoded as UTF-8 bytes rather than latin-1 bytes before rules are applied.
- The 11-word multibyte probe set (see `--list-probes --multibyte`) is added to the signature computation.
- Structural rules (`r`, `d`, `f`, `{`, `}`, `q`, etc.) that split a multibyte code-point across a byte boundary produce byte sequences that are no longer valid UTF-8. These are wrapped in an `InvalidUTF8Bytes` object rather than silently decoded as latin-1, preserving each rule's unique signature so no rules are falsely collapsed.

### Debug options

#### `--debug`

Prints every keep/drop decision to stderr. Dropped rules show which earlier rule they duplicate.

```bash
python minimizer.py ruleset.rule -o out.rule --debug 2>debug.log
```

```
[RULE] KEPT  [     1]  'l'
[RULE] KEPT  [     2]  'u'
[DUP]  DROP  'l' ≡ 'l'
[RULE] KEPT  [     3]  'r'
```

#### `--debug-rule RULE`

Traces a single rule against the entire probe set and exits — no input file required. Useful for understanding what a rule does or confirming why two rules were treated as equivalent.

```bash
python minimizer.py --debug-rule "l r \$1"
python minimizer.py --debug-rule "sab" --multibyte
```

```
Rule trace: 'l r $1'

  Atoms : ['l', 'r', '$1']

  'ab'          →  'ba1'
  'Password'    →  'drowssap1'
  'hasło'       →  <invalid UTF-8: 6f 82 c5 73 61 68 31>
```

Changed words are highlighted in green; unchanged words are dimmed. Unsupported opcodes and invalid UTF-8 byte sequences are flagged with explanatory notes.

#### `--debug-file FILE`

Traces every rule in FILE against the probe set and exits. FILE uses the same format as a rule file — blank lines and lines starting with `#` are skipped. Designed for bulk inspection of rules from `comm` or `diff` output.

```bash
# Find rules present in original but missing from minimized, then inspect them
comm -23 <(sort original.rule) <(sort minimized.rule) > dropped.txt
python minimizer.py original.rule --debug-file dropped.txt | less

# Can also be combined with --multibyte for non-ASCII rulesets
python minimizer.py original.rule --debug-file dropped.txt --multibyte
```

Output is identical to running `--debug-rule` for each rule in sequence, with a separator line every 10 rules for readability.

> **Note:** `#` mid-line is **not** treated as an inline comment because `#` is a valid hashcat argument character (e.g. `i3#` inserts `#` at position 3, `iB#` inserts `#` at position 11). Hashcat itself does not support inline comments in rule files.

### Listing the probe set

`--list-probes` can be used **without a rules file**:

```bash
# Show built-in ASCII probes only
python minimizer.py --list-probes

# Show both categories with multibyte activation status
python minimizer.py --list-probes --multibyte
```

Output is grouped into two categories:

**Category 1 — built-in ASCII** (50 words, always active):

| Group | Words |
|---|---|
| Very short — edge cases | `ab` `abc` `abcd` |
| Short alphanumeric (len 4–6) | `pass` `root` `test` `admin` `login` |
| Typical password base words (len 7–9) | `letmein` `welcome` `password` … |
| Longer words (len 10–11) | `qwertyuiop` `iloveyou12` … |
| Extended-length (len 12–36, positions B–Z) | `administrator1` … `averylongpassword1234567890abcdefghi` |
| Alphabet coverage (all 95 printable ASCII) | `abcdefghijklmnopqrstuvwxyz` `ABCDEFGHIJKLMNOPQRSTUVWXYZ` `!@#$%^&*()-_=+[]{}|;:,.<>?/~` `` a`b `` `a"b` `a'b` `a\b` `a b` |
| Mixed-case | `Password` `AdminUser` `MySecret` `HelloWorld` |
| Words with digits | `pass123` `admin2024` `test1234` `user9999` |
| Special chars | `p@ssw0rd` `s3cur1ty` |
| Repeated chars | `aaaa` `bbbb` |

**Category 2 — multibyte UTF-8** (11 words, active with `--multibyte`):

| Language | Words |
|---|---|
| Polish | `hasło` `żółw` `źródło` |
| German | `straße` `münchen` `übermensch` |
| French | `café` `naïve` |
| Russian | `пароль` |
| CJK / emoji | `密码` `パスワード` |

Each category 2 entry is shown with its character count, byte count, and full UTF-8 hex encoding.

### All options

| Flag | Default | Description |
|---|---|---|
| `rules_file` | *(required unless `--list-probes` or `--debug-rule`/`--debug-file`)* | Input hashcat rule file |
| `-o / --output` | `<input>.minimized.rule` | Output file path |
| `--extra-probes WORD …` | — | Extra probe words appended to the built-in set |
| `--probe-file FILE` | — | Wordlist to sample extra probes from |
| `--probe-words N` | `50` | Max words to sample from `--probe-file` |
| `--seed N` | `42` | RNG seed for reproducible probe sampling |
| `--list-probes` | — | Print probe set in two categories and exit |
| `--multibyte` | — | Process words as UTF-8 bytes; add multibyte probe words |
| `--workers N` | `1` | Worker processes for parallel signature computation; `0` = auto-detect |
| `--debug` | — | Log every keep/drop decision to stderr |
| `--debug-rule RULE` | — | Trace one rule against the probe set and exit |
| `--debug-file FILE` | — | Trace every rule in FILE against the probe set and exit |

---

## Progress bars

Two progress bars are shown for every run, regardless of ruleset size:

```
  Computing  |████████████| 30,000/30,000 [00:08<00:00]
  Deduplicating  |████████████| 30,000/30,000 [00:01<00:00] unique=21438
```

With `--workers N > 1` the first bar tracks completed chunks rather than individual rules:

```
  [MP]  Parallel signature computation: 8 workers, 32 chunks (~938 rules each)
  Computing  |████████████| 32/32 chunks [00:02<00:00]
  Deduplicating  |████████████| 30,000/30,000 [00:01<00:00] unique=21438
```

Both bars fall back gracefully to plain `N/total (X%)` counter lines when `tqdm` is not installed.

---

## Output format

The output file is a valid hashcat rule file with a short header comment block:

```
# minimizer — Standalone Hashcat Rule Minimizer
# Generated  : 2026-04-24 14:30:00
# Source     : rockyou-30000.rule
# Probe set  : 50 words
# Input rules: 30000
# Kept       : 21438
# Removed    : 8562  (28.5%)
```

### Verification

```bash
echo password | hashcat --stdout -r minimized.rule | sort -u | wc -l
```

Compare against the same command run on the original — the unique output count should be identical (or within a negligible margin), confirming no distinct transformations were removed.

---

## Supported opcodes

All hashcat GPU kernel opcodes are implemented:

| Category | Opcodes |
|---|---|
| No-op | `:` |
| Case | `l` `u` `c` `C` `t` `E` `T` |
| Structure | `r` `d` `f` `{` `}` `[` `]` `k` `K` `q` |
| Insert / delete | `^` `$` `@` `[` `]` `D` `i` `O` |
| Overwrite | `o` `s` |
| Truncate | `'` `x` |
| Extend / repeat | `p` `y` `Y` `z` `Z` |
| Bitwise | `L` `R` `+` `-` `.` `,` |
| Swap | `*` |
| Title-case | `E` `e` `3` |

`\xNN` hex-escape notation in argument positions is fully supported. Rules containing unrecognised opcodes (memory ops `M`/`4`/`6`/`X`, reject rules `<`/`>`/`_`/`!`/`/`/`(`/`)`/`=`/`%`/`Q`) are each given a unique signature and kept unconditionally.

---

## License

MIT

