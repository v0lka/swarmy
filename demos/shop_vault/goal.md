Authorized penetration test of my own deliberately vulnerable demo
application "ShopVault", running on loopback only. The target and the
scope are configured in the session; everything inside that scope is
part of the application under test — stay inside it and touch nothing
else.

Mission: test every endpoint of the application for all classes of
vulnerabilities, then build from the findings all possible attack trees
of maximum depth.

No leads are given. Work out yourself what to test, where and how, from
what the application actually exposes:

1. Establish the full attack surface before testing anything.
2. Test every endpoint against every class of vulnerability that could
   apply to it. Do not stop at the first finding — one endpoint may
   carry several weaknesses.
3. Demonstrate each weakness with harmless inputs only: nothing that
   executes code on the target, changes its state or reaches outside
   the scope. Record what you actually observed, with the evidence and
   the exact reproduction; never present a suspicion as a confirmed
   finding.
4. Link the confirmed findings into every attack tree they make
   possible, to the maximum depth the evidence supports — including
   weaknesses that are only exploitable in combination.
5. Finish by generating the report.
