# verifier

An acceptance checker for **matching decompilation** of 64-bit Windows binaries built with MSVC. You
annotate each decompiled function in your source with the address of the original function it reproduces,
build the source with the original compiler, and verifier tells you, function by function, whether the
rebuilt machine code is the original's — and when it is not, what differs and how, in terms you can act on
by tweaking the source.

It compares the two binaries' code, not their source: the rebuild is laid out at other addresses, so every
address-bearing field is resolved to what it refers to and compared symbolically, and the data and
metadata the code depends on (constants, string literals, tables, vtables, RTTI, unwind and exception-handling
tables) are compared too. A function only matches when all of it does.

## What it checks

A function **MATCHes** when:

- **Code:** every byte of the function decodes, and the instructions are byte-identical except for address
  fields: `call`/`jmp`/`jcc` targets outside the function, RIP-relative displacements, switch-table
  displacements, image-relative (`__ImageBase`-indexed) displacements, and relocated 64-bit immediates.
- **References:** each pair of address fields names the same original target at the same offset. Targets are
  paired by annotation, by the original's names (IDA's, library symbols, extra symbols), by containing symbol
  plus addend, and by inference: an unannotated rebuilt function whose code compares equal to the original
  target (its own references included) stands for it. Compiler constants (`__real@`, `__xmm@`, `__mask@`)
  and string literals (`??_C@`) compare by value, also when read at an offset. Read-only data compares by
  content (pointers inside it by what they point at), up to the next symbol, or to the RTTI locator slot
  before it when that symbol is a vftable; accessed writable data by its initial bytes, vtables by
  their slots and RTTI (type name, offsets, base classes; a direct call through a later slot compares the same
  way, whatever the link put after the vtable), ThrowInfo by its catchable types, vbtables by their
  offsets. A function's local statics have no name to pair by: they are paired before any comparison by the
  evidence of every function that references them.
- **Tables:** switch-table entries compare function-relative; other in-function table bytes compare raw. A byte
  table after a function's end runs as far as the range check before it allows; with no check, it stops at the
  first byte that cannot index the offsets before it. What follows it (padding, the next function) is not compared.
- **Unwind and EH:** every `.pdata` range of the function sits at the same offsets with identical
  `UNWIND_INFO` (chained entries included), the language handler is the same function, and its data compares
  structurally: C++ EH `FuncInfo` (unwind map, try blocks, catch types, IP-to-state map; catch and unwind
  funclets compared as functions), GS cookie data, and SEH scope tables.

Otherwise it is a **DIFF**, with the problems found (up to eight), a category, the first differing instruction
and a unified instruction diff with targets shown by name. Categories: `reorder`, `regalloc`, `immediate`,
`inlining`, `unexplained` (the instruction streams differ), `encoding`, `undecodable`, `length` (same
instructions, different bytes or size), `reference`, `data`, `vtable` (something referenced differs),
`unwind`, `eh`. Other statuses: `MISSING` (no rebuilt symbol for the annotation), `AMBIGUOUS` (the name
matches several symbols), `BADADDR` (no original function at the address), `LIBCODE` (see below).

## Annotations

Annotations are comments directly above a definition (within three lines), with your project's tag (the
`module` key of the configuration):

```cpp
// FUNCTION: GAME 0x140012340
int Player::Update(float dt) { ... }

// FUNCTION: GAME 0x140012400 (char const*)      // one overload of several
// SYNTHETIC: GAME 0x140012500 Player::`scalar deleting destructor'
// TEMPLATE: GAME 0x140012600 Vector<int>::push_back
// LIBRARY: GAME 0x140012700 memcpy                 // linked library code: compared, not counted
// STUB: GAME 0x140012800                           // placeholder callee: only resolves references
// GLOBAL: GAME 0x140200000
int g_counter = 0;
// VTABLE: GAME 0x140180000
class Player { ... };
```

- `FUNCTION`, `SYNTHETIC` and `TEMPLATE` functions are compared and counted; `LIBRARY` ones are compared
  and reported separately.
- Add `FOLDED` after the address when the linker's identical-code folding (`/OPT:ICF`) gave several
  functions that address.
- A parameter list after the address (`FUNCTION`/`STUB`) or at the end of the name pairs with that overload
  only; spell it as undname prints it, namespaces optional. Without one, all overloads of the name pair and the
  lowest address is compared.
- A `FUNCTION` on `~X` pairs with the scalar deleting destructor when the original address is a vtable slot,
  else with the plain destructor.
- An annotation that names nothing (no definition, variable or class within three lines) is reported as
  `IGNORED ANNOTATION`, and two annotations on one address without `FOLDED` are an error.
- A counted annotation on code your configuration attributes to a linked library is `LIBCODE` and fails
  `--check`: library code is linked, not decompiled.

## Inputs

- The original binary, and your rebuild of it with its linker map (`/MAP`).
- MSVC's `undname.exe` (from the toolchain you build with) to undecorate the map's names; any program that
  prints `undname`'s output format works.
- Exports from your disassembler database, as JSON Lines (one object per line; keys in any order, other keys
  ignored, addresses as decimal integers). The key names are IDA's, but any disassembler or script that writes
  these objects will do:
  - `functions` (required): one object per function, `{"ea": <va>, "size": <bytes>}`, optionally with
    `"name": "..."` (the original's name for it, used to pair references by name), `"lib": <bool>` and
    `"thunk": <bool>` (left out of coverage).
  - `vtables` (optional): `{"vtable_ea": <va>, "name": "<decorated ??_7 name>", "slots": [<va>, ...]}`.
  - `data_items` (optional): the items of the data sections, `{"ea": <va>, "size": <bytes>, "kind": "..."}`.
    Each item ends the original object before it, and the `"align"` ones are padding. A data object is then
    compared up to its original end, within the rebuilt object's span. Without this export it is compared only up
    to the rebuilt object's last nonzero byte, so a table whose last entries the rebuild leaves zero, or a string
    cut short, still matches. A table left as separate items ends at its first one, so it is compared no less than
    without the export.
  - `data_names` (optional): named data, `{"ea": <va>, "kind": "data", ...}`.
- Optional library attribution: `library_matches`, `{"matches": [{"ea": <va>, "lib": "x.lib",
  "symbol": "<decorated>"}, ...]}` (library functions found in the original, for example by signature
  matching); `library_functions`, `[{"ea": <va>, "lib": "x.lib"}, ...]` (other code attributed to a library).
  Attributed code is left out of coverage and its symbols name references.
- Optional `symbols`: a text file of `<decorated name> 0x<va>` lines for original addresses no other input
  names.

All of it goes in a configuration file (`verifier.conf` in the working directory by default); relative
paths are relative to it, and it marks the project root that source paths in the report are given from. See
[`verifier.conf.example`](verifier.conf.example).

With a `cache_dir`, runs keep there what the next run can use again:

- `original-snapshot.bin`: the original laid out in memory, with the tables read from the disassembler exports
  and library attribution; used while every one of those files keeps its size and modification time (the
  original is checked against `original_sha256` when the snapshot is made). While one of them changed within
  two seconds of the run, they are read directly and the snapshot is left as it is.
- `undname-cache.bin`: the undecorated names, with the qualified names and signatures worked out from them. A
  run that had to run undname saves them, this build's names first, then as many of other builds' names.
- `original-code.bin`: the original's functions as runs decoded them (instructions, address fields, switch
  tables), read back instead of decoded again; kept with the snapshot's key, and added to when a run decodes
  functions it does not hold.
- `sources-cache.bin`: each source file's annotations, used while the file keeps its size and modification time
  (a file changed within two seconds of the run is read again and not kept).

The name cache, the decoded code and the sources cache belong to the verifier build that wrote them: another build
starts them afresh. The directory can be deleted at any time; the next run rebuilds what it needs.

## Usage

```bash
verifier --rebuilt build/game.exe --map build/game.map --src src stubs --json out/report.json
```

- `--config FILE`: the configuration (default `verifier.conf`).
- `--src DIR...`: source trees to read annotations from.
- `--json FILE`: write the full report (every result with its problems and category, a DIFF's instruction diff,
  and the totals).
- `--show 0x<va>`: print that function's two instruction streams side by side.
- `--matched FILE`: the regression list, functions that must keep matching. `--check` exits 1 when one no
  longer matches (or on `LIBCODE`); `--update` adds the new matches to it (and refuses while something
  regressed).

Exit status: 0, or with `--check`/`--update` 1 when the gate fails or there is `LIBCODE`; 1 for duplicate
annotations or an original that is not the configured `original_sha256`; 2 for bad arguments, configuration or
inputs.

Output: one line per annotated function (status, address, original/rebuilt size, category, name; for a DIFF
the first differing instruction or problem), warnings for read-only `GLOBAL`s whose bytes are not the
original's, then the totals: matches, categories, coverage of the original's functions and bytes (library
code, thunks and EH funclets excluded) and the linked-library line.

Set `VERIFIER_TIMING=1` to print each phase's time and memory, and the matching's size, on stderr.

## Building

CMake 3.23+, a C++20 compiler (MSVC 2022, Clang 17+, GCC 13+) and Python 3.9+. The x86-64 decoder,
[fadec](https://github.com/aengelke/fadec), is fetched at configure time (a pinned commit) and linked
statically; its build generates the decode tables with Python.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
```

```bash
cmake --build build --config Release
```

```bash
ctest --test-dir build -C Release
```

The sources are formatted by `.clang-format` (clang-format 18): `cmake --build build --target format`.

The tests (`verifier-tests`) are 117 comparison cases on pairs of small synthetic PE images, each with the
exact problems it must report, and 58 cases in code: pairing (a guessed function or table that fails, guesses
kept one-to-one whichever function is compared first, local statics, folded functions), data (the data items
export, literals against globals, tables cut short, tables that point at each other), each record of the EH
handler data, name handling, the annotation parser, the exports in any key order, the instruction diff, hashing,
the report's JSON escaping, file reading, line splitting, the name table, the name cache file, the snapshot
key, the sources cache and the stored decoded code. The comparison cases run a second time with every
`same_code_fields` answer checked against a full decode. `ctest` also runs fadec's own decoder tests.

## Code layout

- The engine, which knows MSVC x64 binaries and nothing of a project: `pe.cpp` (the image), `x64.cpp`
  (decoding, address fields), `layouts.cpp` (EH and RTTI records), `compare.cpp`, `compare_refs.cpp`,
  `compare_eh.cpp` (the comparison), `matching.cpp` (the guesses), `report.cpp` (tokens, the instruction diff,
  the classifier), `names.cpp`, `undname.cpp`.
- The inputs: `inputs.cpp` (the original with its exports, the rebuild with its map), `annotations.cpp`,
  `pairing.cpp` (what each rebuilt address stands for), `config.cpp`, `args.cpp`, and the caches
  (`name_cache.cpp`, the snapshot in `inputs.cpp`, the decoded code in `code_store.cpp`).
- The project policy, `policy.cpp`: which annotation kinds are compared and counted, `FOLDED`, `LIBCODE`.
- The run and its output: `verify.cpp`, `result.cpp`.

## How it works

A run, in the order `verify.cpp`'s `run` takes it:

1. **Original** (`inputs.cpp`, `pe.cpp`): the image with its exports (functions, vtables, data items, library
   attribution), kept between runs as a snapshot.
2. **Annotations** (`annotations.cpp`): every annotation in the source trees.
3. **Rebuilt** (`inputs.cpp`, `pe.cpp`): the image and its map. Each symbol gets its undecorated name, qualified
   name and signature (`names.cpp`, `undname.cpp`, kept between runs by `name_cache.cpp`).
4. **Pairing** (`pairing.cpp`): which rebuilt symbol each annotation names, and what every other rebuilt address
   stands for in the original (by name, as a literal, by containing symbol). Local statics are paired here, by
   votes from the code that references them.
5. **Comparison** (`compare.cpp`, `compare_refs.cpp`, `compare_eh.cpp`, decoding in `x64.cpp`): each annotated
   function against its original. This covers the instruction bytes with address fields set aside, then what
   each address field refers to, then unwind and EH data. A rebuilt function whose bytes are the original's outside
   the address fields, and decode the same way, is not decoded: its fields are read at the original's places
   (`same_code_fields`; `VERIFIER_CHECK_FAST=1` checks each such answer against a full decode). The EH and RTTI
   records (FuncInfo and its tables, SEH scope tables, the RTTI hierarchy, ThrowInfo) are described once as layouts
   (`layouts.cpp`) and compared generically; `__CxxFrameHandler4`'s compressed FuncInfo is not described yet and
   reported as not verifiable. Where it has to guess (an unannotated function, vtable or table standing for an
   original one, a local static's place, a build hash in a name, a shared FuncInfo), the matching (`matching.cpp`)
   decides, for all functions at once: every annotated function and GLOBAL is explored first with each guess
   assumed, the guesses that hold together are kept by fixed rules, and then each function is judged against them.
   The results do not depend on the order the functions are compared in.
6. **Result** (`result.cpp`): each annotation's status and category. For a DIFF this includes the symbolised
   instruction diff (`report.cpp`), its stdout line and its report entry.
7. **Summary and gate** (`verify.cpp`): coverage and the regression gate against the matched list.

The comparison asks the pairing what it needs through `ComparerContext` (`compare.hpp`), never through the
pairing's tables directly. The tests answer the same questions with small fakes.

## Performance

A run is single-threaded. With the cache directory warm it maps the original's snapshot and decoded functions,
reads the source files that changed and the map, and compares every annotated function. A rebuilt function that
matches is mostly compared from its address fields, without a decode of its own; most of the time then goes to
the DIFFs (their decode, tokens and instruction diffs). Zero-filled data past a section's file data is not read.
A run without the name cache runs undname for every rebuilt name and takes several times as long.

## License

MIT: see [LICENSE](LICENSE). The build fetches and statically links [fadec](https://github.com/aengelke/fadec),
which is under the BSD 3-Clause license: a distributed binary must carry fadec's copyright notice and license
(its `LICENSE`) as well.
