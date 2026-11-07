"""02_split.py (v3) - Step 4: preprocess, deduplicate, shuffle and split.

Run from the repo root:   python src/02_split.py
It READS data/raw/ML-EdgeIIoT-dataset.csv and never modifies it.

Writes into results/ (names end with SET_NAME, so a second feature set cannot overwrite them):
    train_split_<SET_NAME>.npy, test_split_<SET_NAME>.npy   row positions in the ORIGINAL csv
    kept_columns_<SET_NAME>.json                            feature columns the models may use
    split_<SET_NAME>.json, split_summary_<SET_NAME>.txt     what happened, in numbers

Teammates load the split like this (SET_NAME = "numeric"):
    df = pd.read_csv(PATH, low_memory=False)
    tr = np.load("results/train_split_numeric.npy")
    te = np.load("results/test_split_numeric.npy")
    cols = json.load(open("results/kept_columns_numeric.json"))["kept"]
    X_train, y_train = df.iloc[tr][cols], df.iloc[tr]["Attack_label"]

v2 change: duplicates are removed on (kept features + Attack_label), not (features + type).
v3 change: the split is stratified by Attack_label, not Attack_type. After de-duplication some
types keep only 0 or 1 rows (their rows equal rows of other attack types), and scikit-learn
cannot stratify on a class with fewer than 2 rows. Attack_type stays in the table for
per-type reporting.
The task is binary, so an identical feature vector with the same label must not appear in
both train and test, even if the original rows had different attack types. A random order
(seed 42) decides which copy of a duplicate stays, so no attack type is favoured by file order.
"""
import json
import os

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

PATH = "data/raw/ML-EdgeIIoT-dataset.csv"
SEED = 42
SET_NAME = "numeric"  # feature set A; a later set B gets its own name and its own split
TEST_SIZE = 0.30  # fixed BEFORE any model results exist; do not change after seeing scores
MIN_TEST_PER_TYPE = 100  # per-type results are unreliable below this
LABEL, TYPE = "Attack_label", "Attack_type"

# Columns dropped on purpose, with the reason (from DATA_NOTES.md).
DROP = {
    "artifact (MITM-only quirk)": ["frame.time", "tcp.srcport", "tcp.seq"],
    "address / time": ["ip.src_host", "ip.dst_host", "arp.src.proto_ipv4",
                       "arp.dst.proto_ipv4", "icmp.transmit_timestamp"],
    "ID-like": ["tcp.ack_raw", "tcp.checksum", "icmp.checksum", "udp.stream",
                "icmp.seq_le"],  # counter; to be tested in the add-back control
    "ports (added back later as a control)": ["tcp.dstport", "udp.port"],
}

lines = []


def say(text=""):
    print(text)
    lines.append(str(text))


df = pd.read_csv(PATH, low_memory=False)
say(f"Rows read: {len(df)}   Columns: {df.shape[1]}")
assert ((df[LABEL] == 1) == (df[TYPE] != "Normal")).all(), "label and type disagree"

# ---- 1. Decide which columns the models may use ----
feature_cols = [c for c in df.columns if c not in (LABEL, TYPE)]
reason = {}
for why, cols in DROP.items():
    for c in cols:
        if c in df.columns:
            reason[c] = why
        else:
            say(f"WARNING: {c} is not in the file")
for c in feature_cols:
    if c not in reason and df[c].nunique(dropna=False) <= 1:
        reason[c] = "constant"
for c in feature_cols:
    if c not in reason and not pd.api.types.is_numeric_dtype(df[c]):
        reason[c] = "text (numeric-only rule)"
kept = [c for c in feature_cols if c not in reason]
assert LABEL not in kept and TYPE not in kept
assert not any(c in kept for cols in DROP.values() for c in cols)
X = df[kept].astype("float64")
assert np.isfinite(X.to_numpy()).all(), "NaN or inf in kept columns"

say(f"\nKept {len(kept)} of {len(feature_cols)} feature columns:")
say("  " + ", ".join(kept))
say("Dropped, by reason:")
for why in sorted(set(reason.values())):
    say(f"  {why}: " + ", ".join(c for c in feature_cols if reason.get(c) == why))

# ---- 2. Duplicates (kept features + label), random copy stays ----
raw_dups = int(pd.util.hash_pandas_object(df[feature_cols + [TYPE]], index=False).duplicated().sum())
key = pd.util.hash_pandas_object(df[kept + [LABEL]], index=False).to_numpy()
order = np.random.default_rng(SEED).permutation(len(df))
later_copy = pd.Series(key[order]).duplicated().to_numpy()
dup = np.zeros(len(df), dtype=bool)
dup[order[later_copy]] = True
say(f"\nDuplicate rows in the ORIGINAL columns: {raw_dups}")
say(f"Rows identical to another row in the columns the model SEES (kept features + label): {int(dup.sum())}")
say("Removed per type:")
say(df.loc[dup, TYPE].value_counts().to_string() if dup.any() else "  none")

pos = np.flatnonzero(~dup)
sub = df.iloc[pos]
fkey = pd.util.hash_pandas_object(sub[kept], index=False).to_numpy()
nlab = pd.Series(sub[LABEL].to_numpy()).groupby(fkey).transform("nunique").to_numpy()
say(f"After de-duplication: {len(pos)} rows remain.")
say(f"Feature patterns that still appear with BOTH labels: {len(set(fkey[nlab > 1]))} "
    f"({int((nlab > 1).sum())} rows). Normal and attack look identical there; "
    f"kept, but they cap achievable accuracy.")

# ---- 3. Shuffle and split the de-duplicated rows (stratified by label) ----
tr, te = train_test_split(pos, test_size=TEST_SIZE, random_state=SEED, shuffle=True,
                          stratify=df[LABEL].to_numpy()[pos])
tr, te = np.sort(tr), np.sort(te)

# ---- 4. Checks that can fail ----
assert not (set(tr) & set(te)), "a row is in both sets"
assert len(tr) + len(te) == len(pos)
assert not (set(key[tr]) & set(key[te])), "identical vector AND label in both train and test"
assert abs(df.iloc[tr][LABEL].mean() - df.iloc[te][LABEL].mean()) < 0.01, "attack share differs between train and test"
vec = pd.util.hash_pandas_object(df[kept], index=False).to_numpy()
cross = len(set(vec[tr]) & set(vec[te]))
say(f"Identical feature vectors in both train and test (only possible with conflicting labels): {cross}")

tab = pd.DataFrame({
    "raw": df[TYPE].value_counts(),
    "dups_removed": df.loc[dup, TYPE].value_counts(),
    "kept": df.iloc[pos][TYPE].value_counts(),
    "train": df.iloc[tr][TYPE].value_counts(),
    "test": df.iloc[te][TYPE].value_counts(),
}).fillna(0).astype(int)
say("\nRows per attack type:")
say(tab.to_string())
gone = tab.index[tab["kept"] < 2].tolist()
say("\nWARNING: fewer than 2 rows left after de-duplication (cannot be reported per type): "
    + (", ".join(gone) or "none"))
small = tab.index[tab["test"] < MIN_TEST_PER_TYPE].tolist()
say(f"WARNING: fewer than {MIN_TEST_PER_TYPE} test rows, per-type results unreliable: "
    + (", ".join(small) or "none"))
share_tr, share_te = df.iloc[tr][LABEL].mean(), df.iloc[te][LABEL].mean()
say(f"\nTrain rows: {len(tr)}  Test rows: {len(te)}  (test share {TEST_SIZE:.0%}, seed {SEED})")
say(f"Attack share  train: {share_tr:.1%}   test: {share_te:.1%}   "
    f"(= accuracy of always guessing 'attack')")
say(f"Normal rows in test: {int((df.iloc[te][LABEL] == 0).sum())}  "
    f"(false-positive rate resolution is 1 / this number)")

# ---- 5. Save ----
os.makedirs("results", exist_ok=True)
f_train = f"results/train_split_{SET_NAME}.npy"
f_test = f"results/test_split_{SET_NAME}.npy"
f_kept = f"results/kept_columns_{SET_NAME}.json"
f_info = f"results/split_{SET_NAME}.json"
f_summary = f"results/split_summary_{SET_NAME}.txt"
np.save(f_train, tr)
np.save(f_test, te)
with open(f_kept, "w") as f:
    json.dump({"kept": kept, "dropped": reason}, f, indent=2)
with open(f_info, "w") as f:
    json.dump({"version": 3, "set": SET_NAME, "stratified_by": "Attack_label",
               "dedupe_key": "kept features + Attack_label", "seed": SEED,
               "test_size": TEST_SIZE, "rows_read": len(df), "dups_removed": int(dup.sum()),
               "train": len(tr), "test": len(te),
               "attack_share_train": round(float(share_tr), 4),
               "attack_share_test": round(float(share_te), 4),
               "n_kept_columns": len(kept)}, f, indent=2)
say("\nSaved to results/: " + ", ".join(x.split("/")[-1] for x in (f_train, f_test, f_kept, f_info, f_summary)))
with open(f_summary, "w") as f:
    f.write("\n".join(lines) + "\n")
