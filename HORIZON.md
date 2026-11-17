# Over the horizon

Things that are **not planned**. Nothing here is waiting to be done, and nothing here is a defect or a risk today.
Each is written down so that, if a catalog or a site ever grows to where it matters, the idea, its cost and its test
are already worked out, and nobody has to rediscover them. Until then, leave them alone.

An item moves to ROADMAP.md only when its *Come back when* is true, and only then. Item numbers are the same series as
ROADMAP.md and REARVIEW.md, and are never reused. What is built is in REARVIEW.md.

## 48. (c) Counts kept per root

*Scalability; also security.* The home page counts every present file of every root, all and hidden, under row-level
security, on every visit (`queries.roots()`). Built so far (REARVIEW.md 48): the policy evaluated once per query and one
pass over all roots. That is 0.18 s at 2M files and 1.3 s at 10M, on generated catalogs; the first deployment has
445k files.

**Come back when:** the home page takes more than about a second on a real catalog, or a site has more than about
10M files. Not before.

**What it would be:** keep the counts, present files and bytes per root, ACL and hidden flag, rewritten for a root
when its scan completes (where `last_complete_on` is set) and for the roots a batch, a retire-root or an ACL change
touched; under the same policy as `files`, so the home page sums the few rows a person may see and gets exactly
today's numbers, for a person, a group token or a token held to some roots. Keyed by ACL, a change of group membership
needs no rewrite. Not one total per root: totals differ by person, and a shared number would tell a person how many
files others have. `upgrades/root-counts.sql` fills it once. Sits next to: hidden files (the count left out), the
operator page (10), growth (47), which could read the same table.

Cost: M. Risk: counts going stale when a write path forgets them, which is why it is not worth doing early.
*Done when:* the home page's numbers equal a live count for two people, a group token and a token held to some roots,
hidden shown and not, after a full scan, a partial batch, a retire-root and an ACL change; and the page's time on the
generated catalog is stated before and after.
