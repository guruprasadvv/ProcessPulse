#!/bin/bash
S=/mnt/c/Users/mypc/AppData/Local/Temp/claude/C--Users-mypc-Desktop-vit-5th-sem-os-os-project-os-project/9876636c-1e2c-4d80-acd7-117e962f6bb7/scratchpad
cd "/mnt/c/Users/mypc/Desktop/vit/5th sem/os/os project/os project"
python3 -W ignore tools/acceptance/s1_equivalence.py "$S/equivalence-s23.json" > /dev/null
echo "equivalence rc=$?"
python3 - "$S/equivalence-s23.json" results/acceptance/m1b/s1/equivalence-post-s1.json <<'PY'
import json, sys
a, b = (json.load(open(p)) for p in sys.argv[1:3])
def flat(d, p=""):
    out = {}
    for k, v in d.items():
        if isinstance(v, dict):
            out.update(flat(v, p + k + "."))
        else:
            out[p + k] = v
    return out
fa, fb = flat(a), flat(b)
diff = sorted(k for k in set(fa) | set(fb) if fa.get(k) != fb.get(k))
print(f"fields: S2.3 {len(fa)}, S1 baseline {len(fb)}; identical {len(fa) - len(diff)}; different {len(diff)}")
for k in diff:
    print("  DIFF", k, fb.get(k), "->", fa.get(k))
PY
