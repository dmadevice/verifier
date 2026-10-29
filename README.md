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
  content (pointers inside it by what they point at), accessed writable data by its initial bytes, vtables by
  their slots and RTTI (type name, offsets, base classes), ThrowInfo by its catchable types, vbtables by their
  offsets. A function's local statics have no name to pair by: they are paired before any comparison by the
  evidence of every function that references them.
- **Tables:** switch-table entries compare function-relative; other in-function table bytes compare raw.
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
- Exports from your disassembler database (IDA's field names), as JSON Lines:
  - `functions` (required): one object per function, `{"ea": <va>, "size": <bytes>, "name": "...",
    "lib": <bool>, "thunk": <bool>}`.
  - `vtables` (optional): `{"vtable_ea": <va>, "name": "<decorated ??_7 name>", "slots": [<va>, ...]}`.
  - `data_items` (optional): data items; the alignment ones, `{"ea": <va>, "size": <bytes>, "kind": "align"}`,
    tell where original objects end and where padding lies.
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

## Usage

```bash
verifier --rebuilt build/game.exe --map build/game.map --src src stubs --json out/report.json
```

- `--config FILE`: the configuration (default `verifier.conf`).
- `--src DIR...`: source trees to read annotations from.
- `--json FILE`: write the full report (every result with its problems, category, diff; and the totals).
- `--show 0x<va>`: print that function's two instruction streams side by side.
- `--matched FILE`: the regression list, functions that must keep matching. `--check` exits 1 when one no
  longer matches (or on `LIBCODE`); `--update` adds the new matches to it (and refuses while something
  regressed) and saves the undname cache.
- A `--check` run with `--json` keeps its output beside the report; the next run with identical inputs
  (arguments, binaries, map, sources, configuration and every input file) replays it instantly.

Output: one line per annotated function (status, address, original/rebuilt size, category, name; for a DIFF
the first differing instruction or problem), warnings for read-only `GLOBAL`s whose bytes are not the
original's, then the totals: matches, categories, coverage of the original's functions and bytes (library
code, thunks and EH funclets excluded) and the linked-library line.

Set `VERIFIER_TIMING=1` to print each phase's time and memory on stderr.

## Building

CMake 3.20+ and a C++20 compiler (MSVC 2022, Clang 17+, GCC 13+). [capstone](https://github.com/capstone-engine/capstone)
5.0.9 is fetched at configure time and linked statically.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
```

```bash
cmake --build build --config Release
```

```bash
ctest --test-dir build -C Release
```

The tests (`verifier-tests`) are 92 comparison cases on pairs of small synthetic PE images, each with the
exact problems it must report, and 27 cases in code: pairing (inference taken back when it fails, local
statics, folded functions), name handling, the annotation parser, the instruction diff, the replay key,
hashing and line splitting.

## Performance

On a 20 MB binary with 5,500 annotated functions, a run takes about 2 seconds and 250 MB on one core
(with the undname cache warm).
