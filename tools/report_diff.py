#!/usr/bin/env python3
"""Compare two verifier reports (--json) result by result.

    report_diff.py OLD.json NEW.json [--all] [--limit N]

Results are matched by (orig, name, src). For each, the status, category, problems and sizes are compared (with
--all also the unresolved names, the first differing instruction and the instruction diff), then the totals.
Prints one block per changed result and a summary; exits 1 when anything differs.
"""
import argparse
import json
import sys
from collections import Counter

FIELDS = ["status", "category", "problems", "osize", "rsize"]
MORE = ["unresolved", "first_diff", "diff", "overloads", "library"]


def key(r):
    return (r.get("orig"), r.get("name"), r.get("src"))


def load(path):
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    results = {}
    dups = 0
    for r in doc.get("results", []):
        k = key(r)
        if k in results:
            dups += 1
            k = k + (dups,)
        results[k] = r
    totals = {k: v for k, v in doc.items() if k != "results"}
    return results, totals


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("old")
    ap.add_argument("new")
    ap.add_argument("--all", action="store_true", help="also compare unresolved names, first_diff and the diff")
    ap.add_argument("--limit", type=int, default=200, help="changed results printed at most (default 200)")
    a = ap.parse_args()
    old, old_t = load(a.old)
    new, new_t = load(a.new)
    fields = FIELDS + (MORE if a.all else [])
    changed = []
    for k in sorted(set(old) | set(new), key=lambda k: tuple(str(x) for x in k)):
        o, n = old.get(k), new.get(k)
        if o is None or n is None:
            changed.append((k, "only in " + ("new" if o is None else "old"), []))
            continue
        diffs = [(f, o.get(f), n.get(f)) for f in fields if o.get(f) != n.get(f)]
        if diffs:
            changed.append((k, "changed", diffs))
    transitions = Counter()
    for k, what, diffs in changed:
        o, n = old.get(k), new.get(k)
        so = (o or {}).get("status"), (o or {}).get("category")
        sn = (n or {}).get("status"), (n or {}).get("category")
        transitions["%s/%s -> %s/%s" % (so + sn)] += 1
    out = sys.stdout
    for k, what, diffs in changed[: a.limit]:
        out.write("%s %s  [%s]\n" % (k[0], k[1], what))
        for f, x, y in diffs:
            out.write("  %s:\n    old %s\n    new %s\n" % (f, json.dumps(x)[:600], json.dumps(y)[:600]))
    if len(changed) > a.limit:
        out.write("... %d more changed results\n" % (len(changed) - a.limit))
    tdiff = {k: (old_t.get(k), new_t.get(k)) for k in set(old_t) | set(new_t) if old_t.get(k) != new_t.get(k)}
    for k, (x, y) in sorted(tdiff.items()):
        out.write("total %s: %s -> %s\n" % (k, json.dumps(x), json.dumps(y)))
    out.write("\n%d results compared, %d changed\n" % (len(set(old) | set(new)), len(changed)))
    for t, c in transitions.most_common():
        out.write("  %5d  %s\n" % (c, t))
    return 1 if changed or tdiff else 0


if __name__ == "__main__":
    sys.exit(main())
