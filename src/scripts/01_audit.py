"""01_audit.py - Step 3: READ-ONLY audit of the Edge-IIoTset CSV. It changes no data.

Run from the repo root:
    python src/01_audit.py                    # uses the ML file
    python src/01_audit.py data/raw/<other>.csv

It prints a report and saves the same text to results/audit.txt.
It lists CANDIDATES (columns that may leak or mislead). You decide after reading it.
"""
import os
import re
import sys

import pandas as pd

PATH = sys.argv[1] if len(sys.argv) > 1 else "data/raw/ML-EdgeIIoT-dataset.csv"
LABEL, TYPE = "Attack_label", "Attack_type"
SPREAD = 0.05  # flag a column if its format differs by more than this between attack types
NAME_PATTERN = (r"(ip\.|host|time|checksum|seq|ack_raw|stream|trans_id|timestamp|"
                r"payload|msg|name|uri|query|file_data|port|referer|topic)")
# Columns we expect to drop (from earlier analysis of this dataset). Used ONLY for the
# sample-size preview in section 6. The sections before it re-derive the evidence.
PROPOSED_DROP = ["frame.time", "tcp.srcport", "tcp.seq", "ip.src_host", "ip.dst_host",
                 "arp.src.proto_ipv4", "arp.dst.proto_ipv4", "icmp.transmit_timestamp",
                 "tcp.ack_raw", "tcp.checksum", "icmp.checksum", "udp.stream",
                 "tcp.dstport", "udp.port"]

lines = []


def say(text=""):
    print(text)
    lines.append(str(text))


df = pd.read_csv(PATH, low_memory=False)
n = len(df)
types = df[TYPE]
features = [c for c in df.columns if c not in (LABEL, TYPE)]
say(f"File: {PATH}")
say(f"Rows: {n}   Columns: {df.shape[1]}   Features: {len(features)}")

# ---- 1. Labels ----
say("\n== 1. LABELS ==")
say(df[LABEL].value_counts(dropna=False).to_string())
say(df[TYPE].value_counts(dropna=False).to_string())
say(f"Attack_label == 1 exactly when Attack_type != 'Normal': "
    f"{bool(((df[LABEL] == 1) == (df[TYPE] != 'Normal')).all())}")
majority = df[LABEL].value_counts(normalize=True).max()
say(f"Majority-class share: {majority:.1%}  (accuracy of always guessing the bigger class)")
blocks = int((types != types.shift()).sum())
say(f"Attack_type blocks along the file: {blocks} (types present: {types.nunique()})")
say("-> If blocks == types, the file is sorted by type: shuffle before any split.")

# ---- 2. Missing, constant and text columns ----
say("\n== 2. MISSING VALUES, CONSTANT AND TEXT COLUMNS ==")
miss = df.isna().sum()
say("Columns with missing values: " + (", ".join(miss[miss > 0].index) or "none"))
nunique = df.nunique(dropna=False)
constant = [c for c in features if nunique[c] <= 1]
say("Constant columns (one value only): " + (", ".join(constant) or "none"))
text_cols = [c for c in features if not pd.api.types.is_numeric_dtype(df[c])]
say("Text (non-numeric) columns: " + (", ".join(text_cols) or "none"))

# ---- 3. Duplicates in the original columns ----
say("\n== 3. DUPLICATES (all original columns) ==")
h = pd.util.hash_pandas_object(df[features], index=False)
dups = h.duplicated()
say(f"Rows whose features repeat an earlier row: {int(dups.sum())}")
say("By attack type: " + (str(df.loc[dups, TYPE].value_counts().to_dict()) if dups.any() else "none"))
conflict = int((df.groupby(h.values)[LABEL].nunique() > 1).sum())
say(f"Feature patterns that appear with BOTH labels: {conflict}")

# ---- 4. Format scan: columns recorded differently in some attack types ----
say(f"\n== 4. FORMAT SCAN: share of odd-format values differs by more than {SPREAD:.0%} between types ==")
rows = []
for c in features:
    if pd.api.types.is_numeric_dtype(df[c]):
        bad, kind = df[c].notna() & (df[c] % 1 != 0), "non-integer"
    else:
        bad, kind = pd.to_numeric(df[c], errors="coerce").isna(), "non-numeric"
    share = bad.groupby(types).mean()
    spread = share.max() - share.min()
    if spread > SPREAD:
        rows.append((c, kind, round(spread, 3), share.idxmax(), round(share.max(), 3),
                     share.idxmin(), round(share.min(), 3)))
if rows:
    out = pd.DataFrame(rows, columns=["column", "kind", "spread", "highest_type", "share_hi",
                                      "lowest_type", "share_lo"]).sort_values("spread", ascending=False)
    say(out.to_string(index=False))
else:
    say("none")
say("A listed column is recorded differently in some attack types: a CANDIDATE artifact, not proof.")
say("Protocol columns (http.*, mqtt.*, dns.*, udp.*) can differ for a natural reason: traffic that")
say("does not use the protocol has 0 there. Ask whether the attack itself explains the difference.")

# ---- 5. Identifier / shortcut candidates ----
say("\n== 5. IDENTIFIER CANDIDATES (candidates, not decisions) ==")
for c in features:
    if re.search(NAME_PATTERN, c) or nunique[c] > 0.5 * n:
        nu = int(nunique[c])
        msg = f"{c:30s} unique={nu}"
        if 1 < nu <= 50000:
            g = df.groupby(c, dropna=False)[LABEL].nunique()
            share = df[c].isin(g.index[g == 1]).mean()
            msg += f"  rows/value={n / nu:.1f}  rows whose value occurs in only one class: {share:.1%}"
        say(msg)
say("Nearly one value per row = an identifier. High share with FEW values = a shortcut.")

# ---- 6. How many distinct rows survive? (effective sample size preview) ----
say("\n== 6. SAMPLE-SIZE PREVIEW: distinct rows per attack type after dropping the proposed columns ==")
drop = [c for c in PROPOSED_DROP if c in df.columns]
rest = [c for c in features if c not in drop and c not in constant]
num_cols = [c for c in rest if pd.api.types.is_numeric_dtype(df[c])]
txt_cols = [c for c in rest if c not in num_cols]


def distinct_by_type(cols):
    k = pd.util.hash_pandas_object(df[cols + [TYPE]], index=False)
    return (~k.duplicated()).groupby(types).sum()


prev = pd.DataFrame({"raw": types.value_counts(),
                     f"numeric only ({len(num_cols)} cols)": distinct_by_type(num_cols),
                     f"numeric + text ({len(num_cols) + len(txt_cols)} cols)": distinct_by_type(num_cols + txt_cols)})
say(prev.to_string())
say("Total".ljust(12) + "  ".join(f"{c}: {int(prev[c].sum())}" for c in prev.columns))
say("Identical rows add no information and, split across train and test, inflate scores.")
say("A class with only a few dozen distinct rows cannot be evaluated reliably.")

os.makedirs("results", exist_ok=True)
with open("results/audit.txt", "w") as f:
    f.write("\n".join(lines) + "\n")
print("\nSaved report to results/audit.txt")
