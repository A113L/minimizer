# minimizer — Hashcat Rule Minimizer

A standalone Python tool that eliminates functionally redundant rules from hashcat rule files. Two rules are considered equivalent if they produce **identical output on every word in the probe set** — if they can't be told apart, one of them is waste.

Rulesets with more than 1 million rules automatically use a SQLite-backed signature store to avoid out-of-memory errors, with no change in behaviour or output.

---

## How it works

For each rule, the tool computes a **signature** — the tuple of transformed outputs when that rule is applied to every word in the probe set. Rules that share a signature are functionally identical. When a collision is found, the rule appearing **earlier** in the file is kept and the later one is discarded, preserving the original frequency/priority ranking.

```
rule "l"   applied to ["password", "Admin", ...]  →  ("password", "admin", ...)
rule "l"   (duplicate) ──────────────────────────  →  same signature → dropped
```

The built-in probe set (33 words) is hand-curated to exercise every opcode category: very short words for edge cases (`k`, `K`, `{`, `}`, `[`, `]`), mixed-case words for `l`/`u`/`c`/`C`/`t`/`E`/`T`, digit-bearing words for `s`/`o`/`@`, special-char words, repeated-char words for `q`/`z`/`Z`, and words of length 7–11 for truncation and repeat ops. Every hashcat opcode the GPU kernel supports is implemented in pure Python.

In `--multibyte` mode a second probe category (11 words) is added covering Polish, German, French, Russian, and CJK characters. Words are then processed as raw UTF-8 byte sequences, matching hashcat's behaviour on non-ASCII wordlists.

---

## Requirements

- Python 3.7+
- No mandatory dependencies — `sqlite3` and `pickle` are stdlib
- [`tqdm`](https://github.com/tqdm/tqdm) *(optional)* — enables the progress bar

```bash
pip install tqdm
```

---

## Installation

```bash
git clone https://github.com/yourname/minimizer.git
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
- Structural rules (`r`, `d`, `f`, `{`, `}`, `q`, etc.) that split a multibyte code-point across a byte boundary produce byte sequences that are no longer valid UTF-8. These are decoded as latin-1 rather than returning `None`, so each rule retains its own unique signature and is not falsely collapsed with other rules that happen to produce different invalid sequences.

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
  'hasło'       →  ...
```

Changed words are highlighted in green; unchanged words are dimmed. Unsupported opcodes are flagged with a warning.

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
| `--debug` | — | Log every keep/drop decision to stderr |
| `--debug-rule RULE` | — | Trace one rule against the probe set and exit |

---

## Large rulesets (SQLite mode)

Rulesets over **1 million rules** automatically switch to a SQLite-backed signature store. This keeps the signature map off the Python heap, preventing OOM kills that occur when storing millions of tuple-keyed dict entries.

```
[DB]  Ruleset exceeds 1,000,000 rules — using SQLite backing store
      /your/cwd/minimizer_tmp_12345.db
  Minimizing  |████████████| 1,200,000/1,200,000 [02:14<00:00] unique=847,312
  [DB]  Temporary database removed.
```

The temp file (`minimizer_tmp_<pid>.db`) is created in the **current working directory** and deleted unconditionally on completion, including on error or `Ctrl+C`. Nothing is left behind.

In-memory mode is used for rulesets under the threshold — no SQLite overhead for everyday use.

---

## Output format

The output file is a valid hashcat rule file with a short header comment block:

```
# minimize_rules — Standalone Hashcat Rule Minimizer
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
