# minimizer — Hashcat Rule Minimizer

A standalone Python tool that eliminates functionally redundant rules from hashcat rule files. Two rules are considered equivalent if they produce **identical output on every word in the probe set** — if they can't be told apart, one of them is waste.

---

## How it works

For each rule, the tool computes a **signature** — the tuple of transformed outputs when that rule is applied to every word in the probe set. Rules that share a signature are functionally identical. When a collision is found, the rule appearing **earlier** in the file is kept and the later one is discarded, preserving the original frequency/priority ranking.

```
rule "l"   applied to ["password", "Admin", ...]  →  ("password", "admin", ...)
rule "l"   (duplicate) ──────────────────────────  →  same signature → dropped
```

The built-in probe set (33 words) is hand-curated to exercise every opcode category: very short words for edge cases (`k`, `K`, `{`, `}`, `[`, `]`), mixed-case words for `l`/`u`/`c`/`C`/`t`/`E`/`T`, digit-bearing words for `s`/`o`/`@`, special-char words, repeated-char words for `q`/`z`/`Z`, and words of length 7–11 for truncation and repeat ops. Every hashcat opcode the GPU kernel supports is implemented in pure Python.

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

The probe set determines how finely rules are discriminated. More probe words = fewer false equivalences, but slower processing. The built-in 33-word set is accurate for all standard opcodes without any wordlist.

```bash
# Add extra probe words on the CLI
python minimizer.py ruleset.rule -o minimized.rule \
    --extra-probes password admin letmein root test

# Draw additional probes from a wordlist (50 sampled randomly)
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
- The 11-word multibyte probe set (see `--list-probes --multibyte`) is added to the signature computation, giving the minimizer more signal to distinguish rules that behave differently on non-ASCII input.
- Structural rules (`r`, `d`, `f`, `{`, `}`, `q`, etc.) that split a multibyte code-point across a byte boundary produce byte sequences that are no longer valid UTF-8. These are wrapped in an `InvalidUTF8Bytes` object rather than silently decoded as latin-1. This preserves each rule's unique signature so no rules are falsely collapsed, and makes the invalid-UTF-8 case explicitly detectable when the tool is used as a library.

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

Traces a single rule against the entire probe set and exits — no input file required. Useful for understanding what a rule does before or after minimisation.

```bash
python minimizer.py --debug-rule "l r \$1"
python minimizer.py --debug-rule "sab" --multibyte
```

```
Rule trace: 'l r $1'

  Atoms : ['l', 'r', '$1']

  'ab'          →  'ba1'
  'Password'    →  'drowssap1'
  'hasło'       →  <invalid UTF-8: 6f 82 c5 73 61 68 31>   ← structural split
```

Changed words are highlighted in green; unchanged words are dimmed. Rules producing invalid UTF-8 byte sequences (structural rules on multibyte characters) are flagged with an explanatory note. Unsupported opcodes are flagged with a warning.

### Listing the probe set

`--list-probes` can be used **without a rules file**:

```bash
# Show built-in ASCII probes only
python minimizer.py --list-probes

# Show both categories with multibyte activation status
python minimizer.py --list-probes --multibyte
```

Output is grouped into two categories:

**Category 1 — built-in ASCII** (33 words, always active):

| Group | Words |
|---|---|
| Very short — edge cases | `ab` `abc` `abcd` |
| Short alphanumeric | `pass` `root` `test` `admin` `login` |
| Typical password base words | `letmein` `welcome` `password` … |
| Longer words | `qwertyuiop` `iloveyou12` … |
| Mixed-case | `Password` `AdminUser` `MySecret` `HelloWorld` |
| Words with digits | `pass123` `admin2024` … |
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
| `rules_file` | *(required unless `--list-probes` or `--debug-rule`)* | Input hashcat rule file |
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
# Probe set  : 33 words
# Input rules: 30000
# Kept       : 21438
# Removed    : 8562  (28.5%)
```

### Verification

```bash
hashcat --stdout -r minimized.rule password.txt | sort -u | wc -l
```

Compare against the same command run on the original — the unique output count should be similar, confirming no distinct transformations were removed.

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

`\xNN` hex-escape notation in argument positions is fully supported. Rules containing unrecognised opcodes are treated as a single equivalence class — the first such rule in the file is kept.

---

## License

MIT
