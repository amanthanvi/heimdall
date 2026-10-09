| ID | Primary | Pinned primary (16) | HTTP today | Raw = pin | Norm = pin | Markers = pin | run3 = run4 | Result / classification |
|---|---|---|---|---|---|---|---|---|
| S01 | raw | `3d8e498373fc78cf` | 200 | yes | yes | yes | yes | MATCH (primary and raw identical) |
| S02 | raw | `16c3540970d44f49` | 200 | yes | yes | yes | yes | MATCH (primary and raw identical) |
| S03 | raw | `28939c425c736c78` | 200 | yes | yes | yes | yes | MATCH (primary and raw identical) |
| S04 | raw | `3c4c65d0221c28f1` | 200 | yes | yes | yes | yes | MATCH (primary and raw identical) |
| S05 | raw | `76b5b91d17571ea5` | 200 | yes | yes | yes | yes | MATCH (primary and raw identical) |
| S06 | norm | `e6e8c6609fe52509` | 200 | no | yes | no | yes | MATCH on primary (raw differs); `compare` still reports normalized_same=False because a date marker moved (page_dateModified). Compare gap: volatile markers counted as content. |
| S07 | norm | `0c5ee2dc8039aa82` | 200 | no | yes | yes | yes | MATCH on primary; raw differs (page chrome) - expected mutable doc |
| S08 | norm | `002f6741c79eb7c8` | 200 | no | yes | yes | yes | MATCH on primary; raw differs (page chrome) - expected mutable doc |
| S09 | norm | `3526471b48747058` | 200 | no | yes | no | yes | MATCH on primary (raw differs); `compare` still reports normalized_same=False because a date marker moved (page_dateModified). Compare gap: volatile markers counted as content. |
| S10 | raw | `163d73c60b555592` | 200 | yes | yes | yes | yes | MATCH (primary and raw identical) |
| S11 | norm | `b70565475abd28d0` | 200 | no | yes | yes | yes | MATCH on primary; raw differs (page chrome) - expected mutable doc |
| S12 | norm | `e081095a090c9c2c` | 200 | no | yes | no | yes | MATCH on primary (raw differs); `compare` still reports normalized_same=False because a date marker moved (page_dateModified). Compare gap: volatile markers counted as content. |
| S13 | norm | `c39cdaad6475f67f` | 200 | no | yes | yes | yes | MATCH on primary; raw differs (page chrome) - expected mutable doc |
| S14 | norm | `16a5c1dc482cb4ec` | 200 | no | yes | yes | yes | MATCH on primary; raw differs (page chrome) - expected mutable doc |
| S15 | norm | `4929438e0c7651d5` | 200 | no | yes | yes | yes | MATCH on primary; raw differs (page chrome) - expected mutable doc |
| S16 | raw | `196f958196577f42` | 200 | yes | yes | yes | yes | MATCH (primary and raw identical) |
| S17 | raw | `2ea79169cb0f384a` | 200 | yes | yes | yes | yes | MATCH (primary and raw identical) |
| S18 | raw | `4f6c365fe60836a1` | 200 | yes | yes | yes | yes | MATCH (primary and raw identical) |
| S19 | raw | `577dbc3e19f9155a` | 200 | yes | yes | yes | yes | MATCH (primary and raw identical) |
| S20 | norm | `e2b026250fe2ac35` | 200 | no | yes | yes | yes | MATCH on primary; raw differs (page chrome) - expected mutable doc |
| S21 | norm | `a96c1837085523bf` | 200 | no | yes | yes | yes | MATCH on primary; raw differs (page chrome) - expected mutable doc |
| S22 | norm | `5e7ff1b110b49b91` | 200 | no | yes | yes | yes | MATCH on primary; raw differs (page chrome) - expected mutable doc |
| S23 | raw | `f29e59ef0ff58b0f` | 200 | no | yes | yes | yes | PRIMARY MISMATCH, text identical: raw page bytes changed (site rebuild, -284 bytes), normalized text identical. Expected mutable doc; raw primary was too brittle for this HTML page (pin-kind choice). |
| S24 | norm | `51a9bd1593d64e8a` | 200 | yes | yes | no | yes | MATCH on primary (raw identical); `compare` still reports normalized_same=False because a date marker moved (http_last_modified). Compare gap: volatile markers counted as content. |
| S25 | norm | `6bbf6cd1028ec1d6` | 200 | yes | yes | yes | yes | MATCH (primary and raw identical) |
| S26 | norm | `f6ecbbe14400b8f7` | 200 | no | no | no | yes | PRIMARY MISMATCH: content edit on 2026-10-08 (Last-Modified 23:50Z) to Fast-mode/data-residency text (+10 words, 12 ops, two copies of one passage); claim-relevant sections and all S26 excerpt quotes still present. Expected mutable doc; snapshot keeps the pinned text. |
| S27 | raw | `5039b3d120bccea1` | 200 | yes | yes | yes | yes | MATCH (primary and raw identical) |
| S28 | norm | `cfe35cc965427aa5` | 200 | no | no | yes | yes | PRIMARY MISMATCH: only live counters changed (crates 6000+->6200+, stars, downloads; snapdiff 8 numeric tokens). Expected mutable doc, pre-labelled in pins.json S28 note; drift detector will keep firing. |
| S29 | raw | `6266260d556e4511` | 200 | yes | yes | yes | yes | MATCH (primary and raw identical) |
| S30 | raw | `ee873a3e04c28616` | 200 | yes | yes | yes | yes | MATCH (primary and raw identical) |
| S31 | norm | `1d11c6880da3275e` | 200 | yes | yes | no | yes | MATCH on primary (raw identical); `compare` still reports normalized_same=False because a date marker moved (http_last_modified). Compare gap: volatile markers counted as content. |
| S32 | norm | `30b9b23c5c754b05` | 200 | yes | yes | no | yes | MATCH on primary (raw identical); `compare` still reports normalized_same=False because a date marker moved (http_last_modified). Compare gap: volatile markers counted as content. |
| S33 | norm | `f9b8be94ef4a431f` | 200 | yes | yes | no | yes | MATCH on primary (raw identical); `compare` still reports normalized_same=False because a date marker moved (http_last_modified). Compare gap: volatile markers counted as content. |
| S34 | raw | `e743ed4c50da6603` | 200 | yes | yes | yes | yes | MATCH (primary and raw identical) |

Counts: MATCH=31; PRIMARY MISMATCH=2; PRIMARY MISMATCH, text identical=1
