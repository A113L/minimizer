# minimize_rules — Hashcat Rule Minimizer

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

### All options

| Flag | Default | Description |
|---|---|---|
| `rules_file` | *(required)* | Input hashcat rule file |
| `-o / --output` | `<input>.minimized.rule` | Output file path |
| `--extra-probes WORD …` | — | Extra probe words appended to the built-in set |
| `--probe-file FILE` | — | Wordlist to sample extra probes from |
| `--probe-words N` | `50` | Max words to sample from `--probe-file` |
| `--seed N` | `42` | RNG seed for reproducible probe sampling |
| `--list-probes` | — | Print built-in probe set and exit |

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
