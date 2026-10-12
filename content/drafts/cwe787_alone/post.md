# Caption — CWE-787 Alone (`cwe787_alone`)

Image: `graphs/cwe787_alone_<ratio>_<date>.png`.
House style: no em dashes; no "n="; factual Title-Case heading + labels; post-date stamp.
Weakness lane. Prompted by a third-party post asking vendors to stop listing CWE-787
(out-of-bounds write) as the only CWE when it is the last link in a chain (CWE-190 ->
CWE-131 -> CWE-787). Built 2026-10-01.

Finding (verified, CVE List V5 CNA container, published and non-rejected, by publication
date, data through Sep 27, 2026):

**3,201 CVEs have a CNA that listed CWE-787. 2,827 of them (88%) list CWE-787 and nothing
else. 374 (12%) map it alongside at least one other CWE.** So the post describes about
nine in ten CWE-787 records.

By year (alone / with another CWE): 2018 43/0, 2019 36/5, 2020 55/4, 2021 240/6,
2022 282/44, 2023 315/25, 2024 506/26, 2025 453/26, 2026 (to Sep 27) 893/238.

The absolute count is growing with volume, not with behaviour: CWE-787-alone has been a
flat 1.3% to 3.5% of all CWE-tagged CVEs every year since 2018 (1.6% in 2026). Do not
frame the rise in bar height as vendors getting worse.

**The chain share did move in 2026: 21% of CWE-787 records list a second CWE, against
5% in 2024 and 2025.** That is almost entirely one CNA: GitHub_M (the GitHub advisory
database) is 142 of the 238 chain-mapped records in 2026. Outside GitHub the chain rate
is unchanged. Credit GitHub if the post names a mover.

Who lists CWE-787 alone, 2024 onward: Adobe 258, ZDI 205, VulnCheck 170, MediaTek 132,
IBM 79, GitHub_M 78, Samsung Mobile 75, Chrome 69, Red Hat 65, Autodesk 64.
Who maps the chain, 2024 onward: GitHub_M 142, VulDB 26, VulnCheck 19, Zephyr 10,
Document Foundation 9, CPANSec 7, FreeBSD 7, GovTech CSG 7, wolfSSL 6.

What gets co-listed with CWE-787 (2024 onward): CWE-122 heap overflow 63, CWE-125 OOB
read 59, CWE-190 integer overflow 46, CWE-119 34, CWE-121 stack overflow 29, CWE-131
incorrect buffer size 16, CWE-120 14. The post's hypothetical chain (190 -> 131 -> 787)
is real in the data but rare: 46 records name CWE-190 next to 787, 16 name CWE-131.

Excluded on purpose: **2,052 CVEs where the CNA listed no CWE-787 and CISA's ADP added
it.** Those vendors did not under-map the chain, they mapped nothing; that is a different
post (`cwe_provenance`). Also not visible here: CNAs that wrote CWE-119 or CWE-120 where
CWE-787 would have been more precise. Only records that name CWE-787 are counted.

Caveats for the copy: the data cannot tell whether a given OOB write actually had an
upstream integer overflow, so "88% are wrong" is not defensible. Defensible: "88% of
CWE-787 records give the reader one weakness and no root cause".
