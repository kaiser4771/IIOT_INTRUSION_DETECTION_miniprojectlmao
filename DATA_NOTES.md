# Data notes

Working notes on the Edge-IIoTset data for the IIoT intrusion-detection mini project.

Every statement carries a tag:
- **[observed]**: seen in our own output (notebook cells or terminal).
- **[inferred]**: my reading of the evidence, not verified.
- **[provisional]**: a decision made on the evidence so far; can still change before Step 4.
- **[pending]**: not decided or not checked yet.

Update this file when a finding or decision changes, and add a line to the change log at the bottom. Do not edit old findings silently.

---

## 1. Source and files

- Source: Edge-IIoTset on Kaggle, folder "Selected dataset for ML and DL".
  https://www.kaggle.com/datasets/mohamedamineferrag/edgeiiotset-cyber-security-dataset-of-iot-iiot
- Downloaded: [fill in the date you downloaded the files]
- Hashes recorded: [fill in the date you ran sha256sum]
- The data files are **not** in the repository (`data/raw/` is in `.gitignore`). Each teammate downloads the files and checks them against the hashes below.

| File | Size | Lines | Notes |
|---|---|---|---|
| `ML-EdgeIIoT-dataset.csv` | 79 MB | 157,801 (157,800 rows + header) | Working file |
| `DNN-EdgeIIoT-dataset.csv` | 1.2 GB | 2,219,202 | Not used for now |

SHA-256 (recorded from `sha256sum` output):

```
1d3ef6c7cc22784a528a117f1158f5cad750273679437e18a39c360ee6b79fd7  data/raw/DNN-EdgeIIoT-dataset.csv
53101fad091af20bee815860962a5016b802ee45d456a141042f6183094c3c1a  data/raw/ML-EdgeIIoT-dataset.csv
```

Check your copy against these lines (run from the repo root; the 1.2 GB file takes a while):

```bash
grep -E '^[0-9a-f]{64}  data/raw/' DATA_NOTES.md | sha256sum -c -
```

Each file should print `OK`. If one prints `FAILED`, either the copy is damaged or a character was mistyped when the hash was copied into this file. Recompute with `sha256sum data/raw/*.csv` and correct the lines above.

Relationship between the two files:
- **[observed, earlier check]** Same 63-column header, different rows (`cmp` reported a difference at byte 927, line 2).
- **[pending]** How the ML file was built from the full data is unknown. The DNN file has not been examined. Check the Edge-IIoTset paper and the Kaggle description.

## 2. Working environment

- **[observed]** VM: antiX Linux on VMware, 8 GB RAM, 60 GB disk. The OS reports Debian GNU/Linux 13.7 ("trixie"); Python 3.13.5; virtual environment `.venv`.
- Analysis so far was run in a JupyterLab notebook, `audit.ipynb`. Notebooks are gitignored, so it is not in the repo.
- `src/01_audit.py` runs the same checks and saves `results/audit.txt`. [pending] Commit it so the numbers can be reproduced.

## 3. What the ML file contains

All **[observed]** from notebook cells 2 to 5.

- 157,800 rows, 63 columns: 61 features plus `Attack_label` and `Attack_type`.
- `Attack_label` is 1 exactly when `Attack_type` is not "Normal" (checked on every row).
- **Sorted by type:** `Attack_type` forms 15 blocks for 15 types, so each type fills one unbroken stretch of the file. Shuffle before any split. Never use head/tail sampling.
- No missing values.
- Duplicates: 814 rows repeat an earlier row in the original columns, **all in MITM**. No feature pattern appears with both labels.

| Attack_type | Rows |
|---|---|
| Normal | 24,301 |
| DDoS_UDP | 14,498 |
| DDoS_ICMP | 14,090 |
| Ransomware | 10,925 |
| DDoS_HTTP | 10,561 |
| SQL_injection | 10,311 |
| Uploading | 10,269 |
| DDoS_TCP | 10,247 |
| Backdoor | 10,195 |
| Vulnerability_scanner | 10,076 |
| Port_Scanning | 10,071 |
| XSS | 10,052 |
| Password | 9,989 |
| MITM | 1,214 |
| Fingerprinting | 1,001 |
| **Total** | **157,800** |

- Binary labels: 133,499 attack (1), 24,301 normal (0). About 5.5 attack rows per normal row.
- **[inferred]** Most attack types have close to 10,000 rows, which looks like capped sampling. If so, the 84.6% attack share is not a real traffic proportion. Unverified.
- **[inferred]** The column names look like packet-level fields, so each row may be one packet and not one flow. Unverified.

## 4. Baseline and metrics

- **[observed]** Majority-class share: 0.846. A model that always answers "attack" is 84.6% accurate, scores an F1 of about 0.917 on the attack class, and has a false-positive rate of 100% and a balanced accuracy of 0.5.
- **[provisional]** Report false-positive rate, normal-class recall, precision, balanced accuracy, F1 and the confusion matrix. Never report accuracy without the baseline next to it.
- Recompute the baseline after any cleaning step. Removing identical rows changes the class mix. In an earlier split run the attack share rose to 91.4%.
- **[pending]** Target false-positive rate, to be fixed before any model is trained. Choose it with the supervisor.

## 5. Column review

### 5.1 Constant columns (8) **[observed]**
`icmp.unused`, `http.tls_port`, `dns.qry.type`, `dns.retransmit_request_in`, `mqtt.msg_decoded_as`, `mbtcp.len`, `mbtcp.trans_id`, `mbtcp.unit_id`.
They hold one value and carry no information. The split script drops them automatically.

### 5.2 Text (non-numeric) columns (19) **[observed]**
`frame.time`, `ip.src_host`, `ip.dst_host`, `arp.dst.proto_ipv4`, `arp.src.proto_ipv4`, `http.file_data`, `http.request.uri.query`, `http.request.method`, `http.referer`, `http.request.full_uri`, `http.request.version`, `tcp.options`, `tcp.payload`, `tcp.srcport`, `dns.qry.name.len`, `mqtt.conack.flags`, `mqtt.msg`, `mqtt.protoname`, `mqtt.topic`.

Two oddities:
- `dns.qry.name.len` is a length, but is stored as text (8 distinct values), so it probably mixes numbers with stray strings.
- `dns.qry.name` is stored as numbers (1,430 distinct values), which is odd for a name column. **[pending]** meaning unknown.

### 5.3 Format scan (notebook cell 6) **[observed]**
For each column: the share of values that look odd (not a number, or a decimal in a whole-number column), per attack type. "Spread" is the biggest share minus the smallest.

| Column | Spread | Highest type | Lowest type | Reading |
|---|---|---|---|---|
| `frame.time` | 1.000 | Backdoor | MITM | **MITM artifact**: numeric in MITM only, timestamp text elsewhere |
| `ip.dst_host` | 1.000 | DDoS_ICMP | MITM | **MITM-odd**: all MITM values are numbers, not addresses |
| `tcp.options` | 0.995 | Vulnerability_scanner | DDoS_ICMP | Natural: ICMP traffic has no TCP options |
| `tcp.payload` | 0.855 | Vulnerability_scanner | DDoS_ICMP | Natural: protocol content |
| `http.file_data` | 0.783 | Vulnerability_scanner | Backdoor | Natural: HTTP content |
| `ip.src_host` | 0.719 | DDoS_ICMP | MITM | **MITM-odd** |
| `http.request.version` | 0.428 | Vulnerability_scanner | Backdoor | Natural: HTTP |
| `http.request.method` | 0.428 | Vulnerability_scanner | Backdoor | Natural: HTTP |
| `http.request.full_uri` | 0.426 | Vulnerability_scanner | Backdoor | Natural: HTTP |
| `tcp.srcport` | 0.302 | MITM | Backdoor | **MITM artifact**: text values (host names) in MITM only |
| `tcp.seq` | 0.258 | MITM | Backdoor | **MITM artifact**: decimals in a whole-number column, MITM only |
| `http.request.uri.query` | 0.191 | Vulnerability_scanner | Backdoor | Natural: HTTP |
| `arp.dst.proto_ipv4` | 0.097 | DDoS_UDP | DDoS_HTTP | Small; address column |
| `arp.src.proto_ipv4` | 0.082 | Fingerprinting | DDoS_HTTP | Small; address column |
| `mqtt.conack.flags`, `mqtt.msg`, `mqtt.protoname`, `mqtt.topic` | 0.051 to 0.053 | Normal | Backdoor | MQTT text appears only in Normal traffic (see 8.3) |

A protocol column can differ by type for a natural reason: traffic that does not use the protocol has 0 there. The test is whether the attack itself explains the difference.

### 5.4 Single-label shortcuts (notebook cell 7) **[observed]**
"Only-one-class share" is the share of rows whose value in that column never appears with the other label. With nearly one value per row it is trivially high, so read it together with the distinct count (rows per value is about 157,800 divided by the distinct count).

| Column | Distinct values | Only-one-class share | Reading |
|---|---|---|---|
| `mqtt.protoname` | 3 | 100.0% | **Perfectly separates the labels** |
| `mqtt.topic` | 3 | 100.0% | **Perfectly separates the labels** |
| `mqtt.msg` | 117 | 100.0% | **Perfectly separates the labels** |
| `dns.qry.name.len` | 8 | 100.0% | **Perfectly separates the labels** |
| `tcp.srcport` | 32,186 | 74.6% | Mostly rarity; also a MITM artifact |
| `tcp.dstport` | 23,188 | 62.6% | About 7 rows per value; ambiguous |
| `tcp.payload` | 27,369 | 52.5% | About 6 rows per value; ambiguous |
| `ip.src_host` | 19,090 | 42.4% | Identifier-like |
| `http.request.full_uri` | 4,073 | 38.8% | About 39 rows per value |
| `ip.dst_host` | 8,084 | 32.8% | Identifier-like |
| `tcp.seq` | 18,199 | 30.4% | MITM artifact |
| `http.file_data` | 496 | 25.8% | |
| `http.referer` | 4 | 19.4% | Few values, not a shortcut |
| `http.request.uri.query` | 1,665 | 12.9% | |
| `icmp.seq_le` | 13,824 | 9.9% | Sequence counter; see 7.2 |
| `icmp.checksum` | 13,187 | 9.3% | Checksum |
| `udp.stream` | 14,492 | 9.2% | Connection counter |
| `mqtt.msgtype` | 5 | 3.2% | Not a shortcut |
| `dns.qry.name` | 1,430 | 1.0% | Not a shortcut |
| `mqtt.topic_len` | 2 | 0.8% | Not a shortcut |
| `udp.port`, `udp.time_delta` | 32; 39 | 0.3% | Not a shortcut |
| `icmp.transmit_timestamp` | 84 | 0.1% | Not a shortcut |
| `frame.time`, `tcp.ack_raw`, `tcp.checksum` | 155,186; 94,716; 55,513 | not computed (more than 50,000 values) | Identifier-like: nearly one value per row |

The cell 7 screenshot ends at `mbtcp.trans_id`. Any lines below it were not captured.

## 6. How many distinct rows survive? **[observed]**

Notebook cell 8. Distinct rows within each attack type after dropping the provisional columns of section 7, using numeric columns only, or numeric plus text columns as raw strings.

| Attack_type | Raw | Numeric only | Numeric + text |
|---|---|---|---|
| Backdoor | 10,195 | 4,598 | 9,506 |
| DDoS_HTTP | 10,561 | 1,399 | 9,412 |
| DDoS_ICMP | 14,090 | 12,694 | 12,694 |
| DDoS_TCP | 10,247 | 6,010 | 6,010 |
| DDoS_UDP | 14,498 | 1,403 | 1,403 |
| Fingerprinting | 1,001 | 6 | 6 |
| MITM | 1,214 | 116 | 154 |
| Normal | 24,301 | 4,042 | 4,284 |
| Password | 9,989 | 42 | 9,933 |
| Port_Scanning | 10,071 | 4,398 | 4,398 |
| Ransomware | 10,925 | 4,169 | 9,121 |
| SQL_injection | 10,311 | 698 | 10,096 |
| Uploading | 10,269 | 125 | 8,478 |
| Vulnerability_scanner | 10,076 | 7,140 | 10,023 |
| XSS | 10,052 | 132 | 9,144 |
| **Total** | **157,800** | **46,972** | **104,662** |

- With numeric columns only, 110,828 rows (70%) are repeats of another row, and 46,972 distinct rows remain. This matches an earlier split run exactly.
- Normal keeps only 4,042 distinct rows out of 24,301 (17%).
- Classes that collapse with numeric columns only: Fingerprinting (6), Password (42), Uploading (125), XSS (132), MITM (116), SQL_injection (698), DDoS_HTTP (1,399), DDoS_UDP (1,403).
- **[inferred]** The web attacks recover their distinct rows when text columns are added because their content (URIs, payloads, file data) lives in those columns.
- DDoS_ICMP, DDoS_TCP, DDoS_UDP, Port_Scanning and Fingerprinting do not change when text is added. **[inferred]** The text columns hold nothing distinguishing for them. Fingerprinting stays at 6 distinct rows, so its distinguishing information may sit in the dropped columns.
- Caveat: text columns can hold near-unique strings (payloads, URIs), which make every row distinct without adding usable information. A jump in the last column is a question to investigate, not proof of signal.
- The preview counts distinct rows within each type. The split script removes rows that are identical in kept features plus label, which removes slightly more.

## 7. Column decisions (provisional)

### 7.1 Proposed drop list

| Column(s) | Group | Evidence | Strength |
|---|---|---|---|
| `frame.time` | MITM artifact | 5.3; 155,186 distinct | Strong |
| `ip.src_host`, `ip.dst_host` | Address; MITM-odd | 5.3, 5.4 | Moderate |
| `tcp.srcport` | MITM artifact | 5.3, 5.4 | Strong |
| `tcp.seq` | MITM artifact | 5.3; decimals in MITM only | Strong |
| `arp.src.proto_ipv4`, `arp.dst.proto_ipv4` | Address | Spread 0.08 to 0.10; 8 values | Weak: dropped on principle |
| `icmp.transmit_timestamp` | Time | 84 values; 0.1% | Weak: dropped on principle |
| `tcp.ack_raw`, `tcp.checksum` | ID-like | 94,716 and 55,513 distinct | Strong |
| `icmp.checksum`, `udp.stream` | ID-like | 13,187 and 14,492 distinct; about 9% | Moderate: general reasoning (checksums and stream counters identify packets) |
| `tcp.dstport`, `udp.port` | Ports | 62.6% and 0.3% | **A judgment call**: port scans touch many ports, so these may be real signal. Dropped in the main run, added back later as a control |
| The 8 constant columns | No information | 5.1 | Strong |
| The 19 text columns | Numeric-only rule | See 6 and 8.1 | **Under review** (8.1) |
| `Attack_type` | Label leak | Determines the label | Never a feature; used for splitting and per-type reporting |

### 7.2 Numeric columns not on the drop list, still undecided **[pending]**
- `icmp.seq_le`: sequence counter, 13,824 distinct, 9.9%. Flagged by name; likely identifier-like.
- `dns.qry.name`: stored as numbers, 1,430 distinct; meaning unknown.
- `udp.time_delta` (39 distinct), `mqtt.msgtype` (5), `mqtt.topic_len` (2): low single-label shares; keep unless a control shows otherwise.

## 8. Findings that need attention

### 8.1 The numeric-only rule is expensive **[observed]**
It leaves 46,972 of 157,800 rows, and several classes are too small to evaluate individually (section 6). Options in section 9.

### 8.2 MITM is recorded differently from the other types **[observed, cause inferred]**
Five columns behave differently in MITM only: `frame.time`, `ip.dst_host`, `ip.src_host`, `tcp.srcport` and `tcp.seq`. All 814 duplicate rows are also MITM. **[inferred]** MITM rows may have been captured or converted differently. Treat MITM results as less reliable, and report results with and without MITM. Verify against the Edge-IIoTset paper if possible.

### 8.3 MQTT and DNS text columns separate the labels perfectly **[observed]**
`mqtt.protoname`, `mqtt.topic`, `mqtt.msg` and `dns.qry.name.len` each have a 100% only-one-class share. Real MQTT text appears only in Normal rows (spread 0.05, highest type Normal). **[inferred]** The attack traffic carries no MQTT application content, so "MQTT present" would mark a flow as normal. This is a protocol-presence shortcut. The four columns are text, so the numeric-only rule already removes them. The **numeric** MQTT columns that remain may carry the same signal. Check in the Step 5 controls and in SHAP.

### 8.4 Fingerprinting cannot be evaluated per type **[observed]**
Only 6 distinct patterns in the columns we keep, with or without text. Per-type results will be reported only where the test set has enough rows (the split script warns below 100).

### 8.5 Few distinct Normal rows **[observed]**
4,042 distinct Normal rows (numeric only). A 30% test set holds about 1,200 of them, so the false-positive rate moves by roughly 0.08 points per false alarm. Report counts, not only percentages.

## 9. Open decisions

| # | Decision | Options | Status |
|---|---|---|---|
| 1 | Feature set | **A:** numeric only. **B:** A plus numeric features derived from the text columns (lengths, presence flags, method type). Each set needs its own de-duplication and split so identical rows never cross train and test. | **[pending]**. Suggestion: finish the whole pipeline on A, then run B as a documented extension |
| 2 | Ports | Drop in the main run, add back as a control | [provisional] |
| 3 | Undecided numeric columns (7.2) | Keep or drop | [pending] |
| 4 | Split | 70/30, stratified by `Attack_type`, seed 42; duplicates removed on kept features plus `Attack_label`, random copy kept | [provisional] |
| 5 | MITM | Report with and without | [provisional] |
| 6 | Target false-positive rate | Value to agree with supervisor | [pending] |
| 7 | DNN file | Ignore, or examine later | [pending] |

Rules that stay fixed: decide before looking at model results; every reported number comes from a saved run; the test set is used once per finished model.

## 10. Not verified

- Column meanings have not been checked against the Edge-IIoTset paper's feature descriptions (only the abstract has been read).
- Whether rows are packets or flows.
- Why MITM is recorded differently, and how the ML file was sampled from the full data.
- The DNN file's contents.
- The single-label shares in 5.4 are measured by label. An earlier audit measured them by attack type, which is stricter, so the two sets of numbers differ.
- The data is a laboratory testbed, so results may not carry over to real plants.

## 11. Next steps

1. Decide the open items in section 9, at least 1 to 4.
2. Run `src/02_split.py` (version 2), read its output, and only then push the split files (`results/split_*.npy`, `results/kept_columns.json`).
3. Step 5 controls: shuffled labels should score near the majority baseline, and dropped columns added back should reveal any shortcut.
4. Hand over the split to teammates B and C.

## Change log

- 2026-11-07: Rewritten after audit notebook cells 2 to 8. Added column review, sample-size table, findings and open decisions.

---

## 12. Split results: numeric-only feature set (Option A)

Source: notebook `split.ipynb` (Cells 3 to 9), rerun by `src/02_split.py` (version 3). Run date: [fill in].
Tags as above: **[observed]**, **[inferred]**, **[decision]**, **[pending]**.

This section supersedes: the baseline in section 4 (0.846 applies to the raw file; the de-duplicated split below is 0.879), the stratification in section 9 row 4 (now by label), and section 8.4 (Fingerprinting now has no rows left).

### 12.1 Settings
- **[decision]** Seed 42, test size 30%, set name `numeric`.
- **[decision]** Duplicates removed on kept features plus `Attack_label` (a random copy stays, chosen with the seed). Reason: the task is binary, so an identical vector with the same label must not appear in both train and test.
- **[decision]** Split is stratified by `Attack_label`, not `Attack_type`. Stratifying by type failed with a `ValueError` because `DDoS_ICMP` had only 1 row left after de-duplication, and `Fingerprinting` had none. `Attack_type` stays in the table for per-type reporting.
- **[decision]** `icmp.seq_le` is dropped as an ID-like counter. It is tested again in the add-back control (Step 5).

### 12.2 Columns
**[observed]** 25 of 61 feature columns kept:
`arp.opcode`, `arp.hw.size`, `http.content_length`, `http.response`, `tcp.ack`, `tcp.connection.fin`, `tcp.connection.rst`, `tcp.connection.syn`, `tcp.connection.synack`, `tcp.flags`, `tcp.flags.ack`, `tcp.len`, `udp.time_delta`, `dns.qry.name`, `dns.qry.qu`, `dns.retransmission`, `dns.retransmit_request`, `mqtt.conflag.cleansess`, `mqtt.conflags`, `mqtt.hdrflags`, `mqtt.len`, `mqtt.msgtype`, `mqtt.proto_len`, `mqtt.topic_len`, `mqtt.ver`.

36 dropped: artifacts 3 (`frame.time`, `tcp.seq`, `tcp.srcport`), addresses and time 5, ID-like 5 (`icmp.checksum`, `icmp.seq_le`, `tcp.ack_raw`, `tcp.checksum`, `udp.stream`), ports 2, constants 8, text 13.

### 12.3 De-duplication and split
- **[observed]** 124,281 rows removed as identical to another row in the kept columns plus label. 33,519 rows remain.
- **[observed]** 18 feature patterns (36 rows) still appear with both labels. They are kept and cap the achievable score.
- **[observed]** Train 23,463 rows, test 10,056 rows.
- **[observed]** Attack share is 0.879 in both train and test. Normal rows in test: 1,213, so one false alarm moves the false-positive rate by about 0.08 points.
- **[observed]** Baseline: always answering "attack" scores 0.879 accuracy on this split.

| Attack_type | Raw | Removed | Kept | Train | Test |
|---|---|---|---|---|---|
| Backdoor | 10,195 | 5,675 | 4,520 | 3,188 | 1,332 |
| DDoS_HTTP | 10,561 | 9,423 | 1,138 | 779 | 359 |
| DDoS_ICMP | 14,090 | 14,089 | 1 | 0 | 1 |
| DDoS_TCP | 10,247 | 4,237 | 6,010 | 4,253 | 1,757 |
| DDoS_UDP | 14,498 | 13,096 | 1,402 | 997 | 405 |
| Fingerprinting | 1,001 | 1,001 | 0 | 0 | 0 |
| MITM | 1,214 | 1,099 | 115 | 78 | 37 |
| Normal | 24,301 | 20,259 | 4,042 | 2,829 | 1,213 |
| Password | 9,989 | 9,953 | 36 | 23 | 13 |
| Port_Scanning | 10,071 | 5,675 | 4,396 | 3,072 | 1,324 |
| Ransomware | 10,925 | 6,849 | 4,076 | 2,829 | 1,247 |
| SQL_injection | 10,311 | 9,726 | 585 | 402 | 183 |
| Uploading | 10,269 | 10,154 | 115 | 80 | 35 |
| Vulnerability_scanner | 10,076 | 3,113 | 6,963 | 4,859 | 2,104 |
| XSS | 10,052 | 9,932 | 120 | 74 | 46 |
| **Total** | **157,800** | **124,281** | **33,519** | **23,463** | **10,056** |

### 12.4 What this means
- **[observed]** Types with fewer than 2 rows left (cannot be reported per type): `DDoS_ICMP`, `Fingerprinting`.
- **[observed]** Types with fewer than 100 test rows (per-type results unreliable): `DDoS_ICMP`, `Fingerprinting`, `MITM` (37), `Password` (13), `Uploading` (35), `XSS` (46). Per-type results are reported only for the other nine types.
- **[observed]** The single `DDoS_ICMP` row is in the test set, so no `DDoS_ICMP` row is in training.
- **[inferred]** `DDoS_ICMP` collapsed because `icmp.seq_le` was the only thing making its rows distinct: it had 12,694 distinct numeric rows in the section 6 preview, before `icmp.seq_le` was dropped. Every ICMP column in the file (`icmp.checksum`, `icmp.seq_le`, `icmp.transmit_timestamp`, `icmp.unused`) is now dropped or constant, so these rows carry no ICMP information.
- **[inferred]** To the model, ICMP-flood rows probably look like zeros in every kept column. A model could learn "no TCP, UDP, HTTP, DNS or MQTT fields means attack", and ordinary ICMP traffic (such as a ping) might be flagged. Unverified; check in the Step 5 controls and in SHAP. State it as a limitation.
- **[inferred]** `Fingerprinting` rows are identical in the kept columns to rows of other attack types, so they were merged away. In these features it cannot be told apart from other attacks.
- **[inferred]** Each remaining pattern appears once, so every test pattern is new to the model. The test measures generalisation to unseen patterns. The scores will not be inflated by repeats.
- Per-type counts are distinct patterns attributed to a type by a random choice, not true class sizes.

### 12.5 Files (all in `results/`)
`train_split_numeric.npy`, `test_split_numeric.npy` (row positions in the original CSV), `kept_columns_numeric.json`, `split_numeric.json`, `split_summary_numeric.txt`.
Load them like this:

```python
tr = np.load("results/train_split_numeric.npy")
te = np.load("results/test_split_numeric.npy")
cols = json.load(open("results/kept_columns_numeric.json"))["kept"]
X_train, y_train = df.iloc[tr][cols], df.iloc[tr]["Attack_label"]
```

A later feature set B gets its own name (for example `derived`) and its own split, so identical rows never cross train and test for either set.

### 12.6 Still open
- Step 5 controls (shuffled labels, add-back of dropped groups, integrity checks), run on the training data with cross-validation.
- Target false-positive rate (section 9 row 6).
- Option B, derived text features.

## Change log (continued)

- [fill in date]: Added section 12 (numeric-only split results). Stratification changed from type to label after `DDoS_ICMP` was left with 1 row. Split files are named `train_split_numeric.npy`, `test_split_numeric.npy` and so on.
