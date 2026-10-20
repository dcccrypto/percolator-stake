#!/usr/bin/env python3
"""v22kani MS (2026-10-20): width-free arithmetic lemmas for the stake LP money claims.

NOT Kani. z3 over mathematical (unbounded) Int. Each lemma composes the EXACT formulas that the
full-width Kani harnesses in tests/kani_v22_gaps_ms.rs pin on the REAL production functions
(MS-S1 mint = floor(d(S+1)/(V+1)), MS-S2 burn = floor(lp(V+1)/(S+1)), junior full burn = V,
MS-S4 units floor/ceil/floor) into the money claim.

Per lemma:  (1) premises SAT (non-vacuous),  (2) premises AND NOT goal UNSAT (the lemma),
            (3) controls: a tight control (the boundary case is reachable) and/or a mutant control
                (a deliberately wrong rounding) that must be SAT, showing the encoding can fail.
Run: python3 -I stake_lemmas.py   (prints one line per check; exit 1 on any unexpected result)
"""
import sys
from z3 import Ints, Solver, And, Not, Implies, sat, unsat

TIMEOUT_MS = 600_000
bad = 0

def floor_div(q, n, d):
    # q = floor(n / d) for d > 0, n >= 0
    return And(q >= 0, q * d <= n, n < (q + 1) * d)

def ceil_div(c, n, d):
    return And(c >= 0, c * d >= n, n > (c - 1) * d)

def check(name, prem, goal, expect):
    global bad
    s = Solver(); s.set("timeout", TIMEOUT_MS)
    s.add(prem)
    if goal is not None:
        s.add(Not(goal))
    r = s.check()
    ok = (r == expect)
    if not ok:
        bad += 1
    extra = ""
    if r == sat:
        extra = " model=" + str(s.model())
    print(f"{name}: {r} (expected {expect}) {'OK' if ok else 'UNEXPECTED'}{extra}", flush=True)

S, V, d, lp, back, a, b, blp, S1, V1, before, after, delta, pl, ps, pb, v = Ints(
    "S V d lp back a b blp S1 V1 before after delta pl ps pb v")

# ---- RT: deposit then burn the minted lp never returns more than the deposit (G5) ----
rt = And(S >= 1, V >= 1, d >= 1,
         floor_div(lp, d * (S + 1), V + 1), lp >= 1,
         floor_div(back, lp * (V + d + 1), S + lp + 1))
check("RT premises", rt, None, sat)
check("RT  back <= d", rt, back <= d, unsat)
check("RT  tight control (back == d reachable)", rt, back < d, sat)
rt_mut = And(S >= 1, V >= 1, d >= 1,
             ceil_div(lp, d * (S + 1), V + 1), lp >= 1,
             floor_div(back, lp * (V + d + 1), S + lp + 1))
check("RT  mutant control (mint rounded UP)", rt_mut, back <= d, sat)

# ---- LOSS: pool value falls (delta <= 0) between deposit and burn: still back <= d ----
loss = And(S >= 1, V >= 1, d >= 1, delta <= 0, V + d + delta >= 1,
           floor_div(lp, d * (S + 1), V + 1), lp >= 1,
           floor_div(back, lp * (V + d + delta + 1), S + lp + 1))
check("LOSS premises", loss, None, sat)
check("LOSS back <= d", loss, back <= d, unsat)
check("LOSS control (a GAIN delta > 0 can exceed d)",
      And(S >= 1, V >= 1, d >= 1, delta > 0,
          floor_div(lp, d * (S + 1), V + 1), lp >= 1,
          floor_div(back, lp * (V + d + delta + 1), S + lp + 1)), back <= d, sat)

# ---- ND: a later deposit never lowers an earlier holder's redemption value ----
nd = And(S1 >= 1, V1 >= 1, a >= 1, a <= S1, b >= 1,
         floor_div(blp, b * (S1 + 1), V1 + 1), blp >= 1,
         floor_div(before, a * (V1 + 1), S1 + 1),
         floor_div(after, a * (V1 + b + 1), S1 + blp + 1))
check("ND premises", nd, None, sat)
check("ND  after >= before", nd, after >= before, unsat)
check("ND  tight control (after == before reachable)", nd, after > before, sat)
nd_mut = And(S1 >= 1, V1 >= 1, a >= 1, a <= S1, b >= 1,
             ceil_div(blp, b * (S1 + 1), V1 + 1), blp >= 1,
             floor_div(before, a * (V1 + 1), S1 + 1),
             floor_div(after, a * (V1 + b + 1), S1 + blp + 1))
check("ND  mutant control (late mint rounded UP dilutes)", nd_mut, after >= before, sat)

# ---- ST5B: a partial junior burn pays at most the junior balance (so never refused at u64) ----
st5b = And(ps >= 1, pl >= 1, pl < ps, pb >= 0, floor_div(v, pl * (pb + 1), ps + 1))
check("ST5B premises", st5b, None, sat)
check("ST5B v <= pb", st5b, v <= pb, unsat)
check("ST5B mutant control (partial burn rounded UP)",
      And(ps >= 1, pl >= 1, pl < ps, pb >= 0, ceil_div(v, pl * (pb + 1), ps + 1)), v <= pb, sat)

# ---- UNITS (round-1 kani_s3_units_mint_burn_no_dilution statements) ----
U, I, m, r, bb, Us, I2, val, val2 = Ints("U I m r bb Us I2 val val2")
mint = And(U >= 1, I >= 1, a >= 0, floor_div(m, a * U, I))
check("UNITS mint premises", mint, None, sat)
check("UNITS mint: incumbents not diluted (I+a)U >= I(U+m)", mint, (I + a) * U >= I * (U + m), unsat)
check("UNITS mint: new units worth <= paid m(I+a) <= a(U+m)", mint, m * (I + a) <= a * (U + m), unsat)
check("UNITS mint mutant control (rounded UP dilutes)",
      And(U >= 1, I >= 1, a >= 0, ceil_div(m, a * U, I)), (I + a) * U >= I * (U + m), sat)
burn = And(U >= 1, I >= 1, r >= 0, r <= I, ceil_div(bb, r * U, I))
check("UNITS burn premises", burn, None, sat)
check("UNITS burn: burned units worth >= paid bb*I >= r*U", burn, bb * I >= r * U, unsat)
check("UNITS burn: stayers not diluted (I-r)U >= I(U-bb) when bb < U",
      And(burn, bb < U), (I - r) * U >= I * (U - bb), unsat)
check("UNITS burn mutant control (rounded DOWN dilutes stayers)",
      And(U >= 1, I >= 1, r >= 0, r <= I, floor_div(bb, r * U, I), bb < U), (I - r) * U >= I * (U - bb), sat)
value = And(U >= 1, I >= 0, Us >= 0, Us <= U, I2 >= 0, I2 <= I,
            floor_div(val, Us * I, U), floor_div(val2, Us * I2, U))
check("UNITS value premises", value, None, sat)
check("UNITS value <= I", value, val <= I, unsat)
check("UNITS value: a loss never raises it", value, val2 <= val, unsat)
check("UNITS value control (Us = U+1, more units than exist, can exceed I)",
      And(U >= 1, I >= 0, Us >= 0, Us <= U + 1, floor_div(val, Us * I, U)), val <= I, sat)

print("RESULT:", "ALL AS EXPECTED" if bad == 0 else f"{bad} UNEXPECTED")
sys.exit(1 if bad else 0)
