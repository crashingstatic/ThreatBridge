"""How well the map finds an attack, on the synthetic case (item 13, D35): floors that CI holds.

The floors are the first measured numbers (2026-11-24) less a margin; raise them as features
land. The table: python -m threatbridge.measure
"""
import pytest

from threatbridge import measure

# First measured: suspect hops 24/24, at most 239 suspect hosts of 525 active; path hops 18/18,
# every chain listed; chain hosts on the threat line 24/30 (the C2 address is reached only by
# the victim's own outbound flow, which a threat line through the last hop doesn't follow).
FLOORS = {"suspect_hops": 0.95, "path_hops": 0.95, "chains_listed": 6, "line_hosts": 0.75}
CEILINGS = {"suspect_hosts": 290, "path_hosts": 8, "line_hosts": 20, "seconds": 2.0}


@pytest.fixture(scope="module")
def results():
    case, found = measure.synthetic()
    return [(c.name, measure.measure(case, c)) for c in found]


def total(results, method, key="found", of="of"):
    return sum(r[method][key] for _, r in results) / sum(r[method][of] for _, r in results)


def test_the_true_hops_are_found(results):
    table = measure.table(results)
    print("\n" + table)
    assert total(results, "suspects") >= FLOORS["suspect_hops"], table
    assert total(results, "paths") >= FLOORS["path_hops"], table
    assert sum(r["paths"]["chain"] for _, r in results) >= FLOORS["chains_listed"], table
    assert total(results, "line") >= FLOORS["line_hosts"], table


def test_the_analyst_is_not_pointed_at_everything(results):
    table = measure.table(results)
    assert max(r["suspects"]["hosts"] for _, r in results) <= CEILINGS["suspect_hosts"], table
    assert max(r["paths"]["hosts"] for _, r in results) <= CEILINGS["path_hosts"], table
    assert max(r["line"]["hosts"] for _, r in results) <= CEILINGS["line_hosts"], table
    assert all(r[m]["seconds"] <= CEILINGS["seconds"] for _, r in results for m in ("suspects", "paths", "line")), table


def test_both_kinds_of_chain_and_a_busy_background(results):
    assert [name.split()[0] for name, _ in results] == ["busy"] * 3 + ["quiet"] * 3
    assert all(r["active"] > 500 for _, r in results)
