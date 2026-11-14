# verifier

An acceptance checker for **matching decompilation** of 64-bit Windows binaries built with MSVC. You annotate
each decompiled function in your source with the address of the original function it reproduces and build the
source with the original compiler. verifier then tells you, function by function, whether the rebuilt machine
code is the original's, and when it is not, what differs, in terms you can act on in the source.

It compares the two binaries, not their source. The rebuild is laid out at other addresses, so every field that
holds an address is resolved to what it refers to and compared by meaning. The data and metadata the code
depends on (constants, string literals, tables, vtables, RTTI, unwind and exception-handling tables) are
compared too. A function matches only when all of it does.

## Contents

- [Quick start](#quick-start)
- [Annotations](#annotations)
- [Configuration and inputs](#configuration-and-inputs)
- [Running](#running)
- [Reading the output](#reading-the-output)
- [What a match means](#what-a-match-means)
- [Caching](#caching)
- [Architecture](#architecture)
- [Building and testing](#building-and-testing)
- [Limitations](#limitations)
- [License](#license)

## Quick start

1. Build verifier (see [Building and testing](#building-and-testing)).
2. Export the original binary's function list from your disassembler as JSON Lines
   (see [Disassembler exports](#disassembler-exports)).
3. Write `verifier.conf` at your project root, starting from [`verifier.conf.example`](verifier.conf.example).
4. Annotate your source:

   ```cpp
   // FUNCTION: GAME 0x140012340
   int Player::Update(float dt) { ... }
   ```

5. Build your source with the original compiler and have the linker write a map (`/MAP`).
6. Run:

   ```bash
   verifier --rebuilt build/game.exe --map build/game.map --src src
   ```

Once functions match, keep them matching with a regression list: add `--matched matched.txt --update` to record
the current matches, and run with `--matched matched.txt --check` in CI.

## Annotations

An annotation is a comment directly above a definition (within three lines). It carries a kind, your project's
tag (the `module` key of the configuration) and the address of the original.

```cpp
// FUNCTION: GAME 0x140012340
int Player::Update(float dt) { ... }

// FUNCTION: GAME 0x140012400 (char const*)
void Log(const char* text) { ... }

// SYNTHETIC: GAME 0x140012500 Player::`scalar deleting destructor'
// TEMPLATE: GAME 0x140012600 Vector<int>::push_back
// LIBRARY: GAME 0x140012700 memcpy
// STUB: GAME 0x140012800
void Unfinished();

// GLOBAL: GAME 0x140200000
int g_counter = 0;

// VTABLE: GAME 0x140180000
class Player { ... };
```

| Kind | Use it for | Compared | Counted |
|---|---|---|---|
| `FUNCTION` | a function you wrote | yes | yes |
| `SYNTHETIC` | compiler-generated code with no definition of its own, named on the annotation line | yes | yes |
| `TEMPLATE` | a template instantiation, named on the annotation line | yes | yes |
| `LIBRARY` | linked library code, named on the annotation line | yes | no, reported separately |
| `STUB` | a placeholder for a callee you have not decompiled | no | no |
| `GLOBAL` | a variable | read-only ones, by content | no |
| `VTABLE` | a class's vtable | when compared code references it | no |

`STUB`, `GLOBAL` and `VTABLE` tell verifier what a rebuilt address stands for, so that references to it from
compared functions resolve.

### Rules

- **Overloads.** A parameter list after the address (`FUNCTION`, `STUB`) or at the end of the name (the other
  kinds) picks one overload. Namespaces are optional inside it. Without a list, every overload of the name
  pairs and the one at the lowest address is compared.
- **Folded functions.** When the linker's identical-code folding (`/OPT:ICF`) gave several functions one
  address, write `FOLDED` after the address. Two annotations on one address without it are an error.
- **Destructors.** A `FUNCTION` above `X::~X` pairs with the scalar deleting destructor when the original
  address is a vtable slot, otherwise with the plain destructor.
- **Annotations that name nothing.** An annotation with no definition, variable or class within three lines is
  reported as `IGNORED ANNOTATION`.
- **Library code.** A counted annotation on code your configuration attributes to a linked library is reported
  as `LIBCODE` and fails `--check`: library code is linked, not decompiled.

### How names are spelled

Names and parameter lists are spelled the way MSVC's tools print them (`unsigned __int64`, `char const*`,
`` `anonymous namespace'::f ``), with four differences:

| Case | Spelling | Example |
|---|---|---|
| Function types | no `__cdecl` | `void (*)(int)`, `std::function<void(int)>` |
| Constructor or destructor of a class template | the class's name alone | `Vector<int>::Vector`, `Vector<int>::~Vector` |
| A name inside a function | qualified by the function | `Player::Update::s_count`, `Player::Update::Local::Get` |
| A template argument that is an address | `&name` | `Table<&g_entries>` |

The words `class` and `struct`, `__ptr64`, and whitespace next to `< > , * &` do not matter. When in doubt,
copy the spelling verifier prints: a DIFF's `overloads:` line and the JSON report give the rebuilt symbols'
spelling.

## Configuration and inputs

Everything about the original goes in a configuration file, `verifier.conf` in the working directory by default.
Relative paths in it are relative to the file, and its directory is the project root that source paths in the
report are given from. Lines are `key = value`; `#` starts a comment.

| Key | Required | Meaning |
|---|---|---|
| `module` | yes | the annotation tag, one word (`GAME` in `// FUNCTION: GAME 0x...`) |
| `original` | yes | the original binary |
| `original_sha256` | no | its SHA-256; a different file stops the run |
| `functions` | yes | export: the original's functions |
| `vtables` | no | export: the original's vtables |
| `data_items` | no | export: the items of the data sections |
| `data_names` | no | export: named data |
| `library_matches` | no | library functions identified in the original |
| `library_functions` | no | other code attributed to a library |
| `symbols` | no | extra `<decorated name> 0x<va>` lines for addresses nothing else names |
| `cache_dir` | no | where to keep caches between runs (see [Caching](#caching)) |

The rebuild and its linker map are given on the command line, since they change with every build.

### Disassembler exports

The exports are JSON Lines: one object per line, keys in any order, unknown keys ignored, addresses as decimal
integers. The key names follow IDA's, but any disassembler or script that writes these objects will do.

| File | Object | Notes |
|---|---|---|
| `functions` | `{"ea": <va>, "size": <bytes>}` | Optional keys: `"name"` (the original's name, used to pair references by name), `"lib"` and `"thunk"` (booleans; such functions are left out of coverage). |
| `vtables` | `{"vtable_ea": <va>, "name": "<decorated ??_7 name>", "slots": [<va>, ...]}` | |
| `data_items` | `{"ea": <va>, "size": <bytes>, "kind": "..."}` | Each item ends the object before it; items of kind `"align"` are padding. |
| `data_names` | `{"ea": <va>, "kind": "data", ...}` | |

`data_items` is worth exporting. With it, a data object is compared up to its original end. Without it, a data
object is compared only up to the rebuilt object's last nonzero byte, so a table whose last entries the rebuild
leaves zero, or a string cut short, still matches.

### Library attribution

Both files are plain JSON:

- `library_matches`: `{"matches": [{"ea": <va>, "lib": "x.lib", "symbol": "<decorated>"}, ...]}`, library
  functions found in the original, for example by signature matching.
- `library_functions`: `[{"ea": <va>, "lib": "x.lib"}, ...]`, other code attributed to a library.

Attributed code is left out of coverage, and its symbols name references.

## Running

```bash
verifier --rebuilt build/game.exe --map build/game.map --src src stubs \
         --matched matched.txt --check --json out/report.json
```

| Option | Meaning |
|---|---|
| `--rebuilt FILE` | the rebuilt binary (required) |
| `--map FILE` | its linker map (required) |
| `--src DIR...` | one or more source trees to read annotations from (required) |
| `--config FILE` | the configuration (default `verifier.conf`) |
| `--matched FILE` | the regression list: functions that must keep matching; must exist unless `--update` starts it |
| `--check` | exit 1 when a listed function no longer matches, or on `LIBCODE`; needs `--matched` |
| `--update` | add the new matches to the list; refuses while something regressed; needs `--matched` |
| `--json FILE` | write the full report |
| `--show 0x<va>` | print that function's two instruction streams side by side |

| Exit status | Meaning |
|---|---|
| 0 | the run completed; without `--check` or `--update`, DIFFs do not change the status |
| 1 | with `--check` or `--update`: a listed function regressed, or there is `LIBCODE`. Always: duplicate annotations, or the original is not the configured `original_sha256` |
| 2 | bad arguments, configuration or inputs; a missing regression list; a report or list that could not be written |

The regression list is a text file of `0x<va> <name>` lines that `--update` maintains. Commit it with your
source.

Environment switches, all for diagnosis:

| Variable | Effect |
|---|---|
| `VERIFIER_TIMING=1` | print each phase's time and memory on stderr |
| `VERIFIER_CHECK_FAST=1` | check every shortcut comparison against a full decode |
| `VERIFIER_CHECK_DIFFS=1` | remake every cached DIFF report and stop on a difference |
| `VERIFIER_CHECK_ALIGN=1` | name each instruction diff whose alignment is longer than a shortest edit script |

## Reading the output

One line per annotated function, then warnings, then totals:

```text
MATCH     0x140012340   398/398                Player::Update
DIFF      0x140012400    65/50    unexplained  Log
            @2: orig `mov qword ptr [rip+0xb426f0], rax` | rebuilt `xorps xmm0, xmm0`
DIFF      0x140012600  1245/1245  reference    Vector<int>::push_back
            @15: orig `call 0x1400dcac0` | rebuilt `call 0x140169cb0`
MISSING   0x140012900     -/-                  Player::Reset
NEW MATCH  0x140012340

annotated 4: 1 match, 3 do not (unexplained 1, reference 1, MISSING 1)
coverage: 1/5210 functions (0.02%), 398/1830112 bytes (0.02%)
linked library code (not counted): 812 functions, 96440 bytes (libcmt.lib 310, ...)
```

The columns are status, original address, original/rebuilt size in bytes, category and name. A DIFF adds the
first differing instruction (`@2` is the instruction's index) or the first problem, and where they apply an
`unresolved:` line (rebuilt targets with no original counterpart) and an `overloads:` line.

### Statuses

| Status | Meaning |
|---|---|
| `MATCH` | the rebuilt function is the original's (see [What a match means](#what-a-match-means)) |
| `DIFF` | it is not; the category says how |
| `MISSING` | no rebuilt symbol has the annotation's name, for example because the linker dropped unreferenced code |
| `AMBIGUOUS` | the name matches several rebuilt symbols; add a parameter list |
| `BADADDR` | the original has no function at the address |
| `LIBCODE` | the annotation is on code attributed to a linked library |

### DIFF categories

A DIFF lists the problems found (up to eight) and has one category. When the instruction streams differ, the
category describes how they differ; otherwise it is the first problem's.

| Category | Group | Meaning |
|---|---|---|
| `reorder` | instructions differ | the same instructions in another order |
| `regalloc` | instructions differ | the same instructions with other registers |
| `immediate` | instructions differ | the same instructions with other immediates or displacements |
| `inlining` | instructions differ | another number of calls, or many more or fewer instructions |
| `unexplained` | instructions differ | the streams differ in some other way |
| `encoding` | same instructions, other bytes | an instruction's bytes or prefixes, or a switch table |
| `undecodable` | same instructions, other bytes | bytes that do not decode |
| `length` | same instructions, other bytes | another number of instructions or bytes |
| `reference` | something referenced differs | an address field names another target |
| `data` | something referenced differs | a referenced constant, string, table or global differs |
| `vtable` | something referenced differs | a referenced vtable's slots or RTTI differ |
| `unwind` | metadata differs | `.pdata` or `UNWIND_INFO` |
| `eh` | metadata differs | the language handler's data (C++ EH, GS cookie, SEH) |

### Other lines

| Line | Meaning |
|---|---|
| `REGRESSION 0x<va> <name>` | a function on the regression list no longer matches |
| `NEW MATCH  0x<va>` | a function matches that is not on the list yet |
| `GLOBAL DIFFERS 0x<va> <name>` | a read-only `GLOBAL`'s bytes are not the original's (a warning) |
| `IGNORED ANNOTATION <file>:<line>` | the annotation names nothing |

Coverage counts the original's functions and bytes, excluding library code, thunks and EH funclets.

### The JSON report

`--json` writes the totals (`matched`, `universe`, `matched_bytes`, `universe_bytes`, `categories`,
`linked_functions`, `linked_bytes`) and a `results` array with one object per annotation:

| Key | Content |
|---|---|
| `orig`, `name`, `kind`, `src` | the original address, the name, the annotation kind and `file:line` |
| `status`, `category` | as on stdout |
| `osize`, `rsize` | original and rebuilt size |
| `problems` | every problem reported, as `<category>: <detail>` |
| `first_diff` | the first differing instruction: `index`, `orig`, `rebuilt` |
| `diff` | a unified instruction diff with targets shown by name |
| `unresolved`, `overloads`, `library` | present when they apply |

In the instruction diff, lines pair when the comparison treats them as the same: equal bytes outside the address
fields, and each field standing for the same thing. A paired line is marked `; encoding <bytes>` when only its
bytes differ and `; target not aligned` when two branches to the same offset reach instructions that do not
pair.

## What a match means

A function is a `MATCH` when all four of these hold.

**Code.** Every byte of the function decodes, and the instructions are byte-identical except for address fields.
The address fields are:

- `call`, `jmp` and `jcc` targets outside the function
- RIP-relative displacements
- switch-table displacements
- image-relative (`__ImageBase`-indexed) displacements
- relocated 64-bit immediates

**References.** Each pair of address fields names the same original target at the same offset. A rebuilt target
is paired with an original one by:

- an annotation
- a name the original has for it (the disassembler's, a library symbol, the `symbols` file)
- the symbol containing it, plus the offset into that symbol
- inference: an unannotated rebuilt function, vtable or table stands for the original target when it compares
  equal to it, its own references included

What a reference points at is compared according to what it is:

| Target | Compared by |
|---|---|
| Compiler constants (`__real@`, `__xmm@`, `__mask@`) and string literals (`??_C@`) | value, also when read at an offset |
| Read-only data | content up to the object's end; pointers inside it by what they point at |
| Writable data that code reads | its initial bytes |
| Vtables | their slots and RTTI (type name, offsets, base classes) |
| `ThrowInfo` | its catchable types |
| vbtables | their offsets |
| A function's local statics | paired before any comparison, by the evidence of every function that references them |

**Tables.** Switch-table entries compare relative to the function. Other table bytes inside the function compare
raw. A byte table after the function's end is compared as far as the range check before it allows.

**Unwind and exception handling.** Every `.pdata` range of the function sits at the same offsets with identical
`UNWIND_INFO`, chained entries included. The language handler is the same function, and its data compares
structurally:

- C++ EH `FuncInfo`: unwind map, try blocks, catch types and the IP-to-state map, with catch and unwind
  funclets compared as functions
- GS cookie data
- SEH scope tables

## Caching

With a `cache_dir`, a run keeps what the next run can use again. A warm run is several times faster than a cold
one.

| File | Holds | Used while |
|---|---|---|
| `original-snapshot.bin` | the original laid out in memory, with the tables from the exports and library attribution | the original and every export keep their size and modification time |
| `original-code.bin` | the original's functions as decoded | the snapshot is |
| `rebuilt-code.bin` | the rebuilt functions as decoded, found again by name and size wherever the next link puts them | a function's bytes outside its address fields, and its relocations, are unchanged |
| `names-cache.bin` | what was read from the map's decorated names (qualified name, signature, owner) | always; new names are added |
| `sources-cache.bin` | each source file's annotations and their lookup keys | the file keeps its size and modification time |
| `diff-cache.bin` | each DIFF's category, instruction diff and first difference | the code and everything the report read are unchanged (by hash) |

Things to know:

- The directory can be deleted at any time. The next run rebuilds what it needs.
- Every file but the snapshot belongs to the verifier build that wrote it. A new verifier build starts them
  afresh.
- A file modified within two seconds of the run is read directly and not cached, because its modification time
  cannot yet tell a later change apart.
- `original_sha256` is checked when the snapshot is made, not on every run that uses the snapshot.
- Caches change how fast a result is produced, never the result. The `VERIFIER_CHECK_*` switches test that.

## Architecture

### Pipeline

A run is one pass through these phases (`run` in `verify.cpp`), on one thread:

| # | Phase | What happens | Code |
|---|---|---|---|
| 1 | Original | Load the image and its exports, or map the snapshot. | `inputs.cpp`, `pe.cpp` |
| 2 | Annotations | Read every annotation in the source trees. | `annotations.cpp` |
| 3 | Rebuilt | Load the image and its map; read each symbol's decorated name for its qualified name, signature and owner. | `inputs.cpp`, `demangle.cpp`, `name_cache.cpp` |
| 4 | Pairing | Decide which rebuilt symbol each annotation names, and what every other rebuilt address stands for in the original. Pair local statics by votes from the code that references them. | `pairing.cpp` |
| 5 | Explore and solve | Compare every annotated function and `GLOBAL` with each guess assumed, then keep the guesses that hold together. | `matching.cpp`, `compare.cpp`, `compare_refs.cpp`, `compare_eh.cpp` |
| 6 | Evaluate | Judge each function against the kept guesses; make each result's line, category and instruction diff. | `result.cpp`, `report.cpp`, `align.cpp` |
| 7 | Summary and gate | Totals, coverage, the regression list, the JSON report, cache saves. | `verify.cpp` |

### Guesses

Annotations and names do not cover everything a function refers to. An unannotated helper, a vtable, a jump
table or a local static has to be paired by evidence: does it compare equal to the original target? Such a
pairing is a guess, and guesses depend on each other, since a helper matches only if the helpers it calls do.

The matching (`matching.cpp`) decides the guesses for all functions at once, by fixed rules, and keeps them
one-to-one. The results therefore do not depend on the order the functions are compared in.

### Shortcuts

A rebuilt function whose bytes are the original's outside the address fields is not decoded: its fields are read
at the places the original's decode found them (`same_code_fields` in `x64.cpp`). Functions decoded in an
earlier run are restored from `rebuilt-code.bin` under the same condition.

### Code layout

| Part | Files | Role |
|---|---|---|
| Engine | `pe.cpp`, `x64.cpp`, `layouts.cpp`, `compare.cpp`, `compare_refs.cpp`, `compare_eh.cpp`, `matching.cpp`, `report.cpp`, `align.cpp`, `names.cpp`, `demangle.cpp` | Knows MSVC x64 binaries and nothing of a project: images, decoding, EH and RTTI record layouts, the comparison, the matching, the instruction diff and its classifier, names. |
| Inputs | `inputs.cpp`, `annotations.cpp`, `pairing.cpp`, `config.cpp`, `args.cpp`, `name_cache.cpp`, `code_store.cpp`, `diff_store.cpp`, `cache_file.cpp` | The original with its exports, the rebuild with its map, the annotations, what each rebuilt address stands for, and the caches. |
| Policy | `policy.cpp` | Project rules: which annotation kinds are compared and counted, `FOLDED`, `LIBCODE`. |
| Run | `verify.cpp`, `result.cpp`, `main.cpp` | The phases, each result, the output. |

Two design points to know before changing the code:

- The comparison never reads the pairing's tables. It asks its questions through the `ComparerContext`
  interface (`compare.hpp`), and the tests answer the same questions with small fakes.
- EH and RTTI records are described once as layouts (`layouts.cpp`) and compared generically, so supporting a
  new record starts with describing it.

The x86-64 decoder is [fadec](https://github.com/aengelke/fadec). The demangler is verifier's own: it reads a
decorated name once into a small tree and prints the qualified name, signature and owner from it.

## Building and testing

Requirements: CMake 3.23+, a C++20 compiler (MSVC 2022, Clang 17+ or GCC 13+) and Python 3.9+. fadec is fetched
at configure time at a pinned commit and linked statically; its build generates the decode tables with Python.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release
```

`ctest` runs `verifier-tests` and fadec's own decoder tests. `verifier-tests` has two kinds of cases:

- **Fixtures** (`tests/data/fixtures.json`): pairs of small synthetic PE images, each with the exact problems
  the comparison must report. They run twice, the second time with every shortcut answer checked against a full
  decode.
- **Cases in code** (`tests/*_test.cpp`): pairing and guesses, data comparison, each EH record, name handling,
  the demangler (each kind of decorated name, and damaged, truncated and deeply nested ones), the annotation
  parser, the exports, the instruction diff, the report, and each cache file.

The sources are formatted with clang-format 18 (`.clang-format`): `cmake --build build --target format`.

## Limitations

- **x64 MSVC only.** 32-bit binaries and other compilers are not supported.
- **`__CxxFrameHandler4`.** Its compressed `FuncInfo` is not described yet. A function that uses it is reported
  as a DIFF whose handler data is not verifiable.
- **The map is required.** Rebuilt symbols come from the linker map, so the rebuild must be linked with `/MAP`.
- **Names it cannot read.** A decorated name the demangler cannot read keeps its decorated spelling, and each
  run lists such names on stderr.
- **Single-threaded.** A run uses one core.

## License

MIT: see [LICENSE](LICENSE). The build fetches and statically links [fadec](https://github.com/aengelke/fadec),
which is under the BSD 3-Clause license. A distributed binary must carry fadec's copyright notice and license
(its `LICENSE`) as well.
