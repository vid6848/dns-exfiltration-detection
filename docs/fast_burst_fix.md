# Fast-burst blind spot: diagnosis and fix

## The flaw

A DNS tunnel that sends its next query as soon as the previous answer returns
produces queries a few milliseconds apart. The `aws_benign_expansion_v0.1`
forest scored such traffic as benign: on fast-burst campaigns against unseen
domains it caught **4.2%** of queries, and at fixed gaps of 1–35 ms only
**0.2%**. The same campaigns spaced 100 ms apart were caught 85% of the time.

## Root cause

The training data never contained a fast attack. In
`data/generate_synthetic_exfiltration.py` the "burst" timing mode drew gaps
from 50–1500 ms. Measured on `cleaned_unified_v0.1.csv` per
`(src_ip, apex_domain)` group:

| Class | Smallest gap | 1st percentile | Gaps under 50 ms |
|---|---|---|---|
| Synthetic attack | 33 ms | 78 ms | 0.0% |
| Real benign | 1 ms | 3 ms | 3.5% |

Real resolvers do produce millisecond gaps (an `A` and an `AAAA` lookup for the same
host fire together; a page load fans out to several hosts of one domain). So in
the training data, a very short `time_interval` was perfect evidence of benign
traffic, and the forest learned exactly that. This is a dataset coverage gap,
not a feature bug: the behavioral feature was computed correctly.

## Fix

Everything except the development data is held fixed, so the result is
comparable with the previous model:

- Same input (`cleaned_unified_v0.1.csv`, hash-checked) and the same frozen
  v0.2 outer fold 5 (45,240 queries, 308 apex domains) as the evaluation population.
- Same public benign capture (85,604 queries) as the AWS experiment.
- Same eight RF configurations, three domain-disjoint inner folds, and FPR
  policy (pooled ≤1%, large-domain ≤5%). No evaluation score enters selection.
- **Added:** 3,000 synthetic attack queries from a new opt-in `fast_burst` timing
  mode (2–50 ms gaps; 97.9% of their in-group gaps are under 50 ms), on eight new
  attacker domains that appear nowhere in the evaluation fold. The default
  generator output is byte-identical to before (checked against the original
  script; the committed v0.1 CSV differs only by Windows line endings).

```bash
python data/generate_synthetic_exfiltration.py --num-records 3000 --seed 20261022 --timing-modes fast_burst \
  --base-domains "sync-cache-node.net,metrics-upload.org,telemetry-gw.io,update-mirror.biz,beacon-relay.xyz,cdn-edge-sync.co,status-ping.cc,log-shipper.live" \
  --source-tag "CyberTrace Synthetic DNS Exfiltration v0.2 fast-burst (training)" --output data/processed/synthetic_fast_burst_train_v0.2.csv
python data/generate_synthetic_exfiltration.py --num-records 1000 --seed 77001 --timing-modes fast_burst \
  --base-domains "quick-relay.net,fastlane-dns.org,rapid-sync.io,burst-gateway.biz,swift-update.xyz,nimble-cdn.co,express-ping.cc,turbo-logs.live" \
  --source-tag "CyberTrace Synthetic DNS Exfiltration v0.2 fast-burst (stress test)" --output data/processed/synthetic_fast_burst_stress_v0.2.csv
python -m scripts.restore_public_benign --output .public-data-research/university_restored.csv
python -m src.ml.fast_burst --benign .public-data-research/university_restored.csv --output-dir artifacts/fast_burst_repeat --n-jobs 8
```

Inner CV selected `max_depth=12, min_samples_leaf=5, class_weight=None` with
threshold **0.90** (previously 0.89).

## Results

Frozen diagnostic population, 45,240 queries (43,340 benign, 1,900 attacks):

| | Previous (`aws_benign_expansion_v0.1`) | Fixed (`fast_burst_v0.1`) |
|---|---|---|
| F1 | 95.03% | **95.40%** |
| Recall | 90.53% (1,720) | **91.21% (1,733)** |
| Precision / false alarms | 100% / 0 | 100% / 0 |
| AWS false alarms (36,255 queries) | 0 | 0 |
| False alarms on benign queries < 50 ms after the previous one (2,446) | 0 | **0** |
| ROC-AUC | 0.9978 | 0.9973 |

Fast-burst stress test: 1,000 separately generated queries (different seed) on
eight attacker domains used neither in development nor evaluation.

| | Previous | Fixed |
|---|---|---|
| Recall at natural 2–50 ms gaps | **4.2%** | **88.4%** |

Timing sweep: the same stress queries re-timed to a fixed gap within each
client/domain group (`timing_sweep.csv`).

| Gap | 1 ms | 5 ms | 10 ms | 20 ms | 35 ms | 50 ms | 100 ms | 250 ms | 1 s |
|---|---|---|---|---|---|---|---|---|---|
| Previous recall | 0.2% | 0.2% | 0.2% | 0.2% | 0.2% | 75.0% | 85.4% | 86.3% | 87.3% |
| Fixed recall | 0.9% | 80.9% | 81.6% | 81.9% | 81.9% | 81.7% | 81.8% | 81.8% | 85.5% |

`time_interval` importance fell from 1.46% to 0.77%: the forest now relies less
on timing, which is why the cliff at 50 ms is gone.

Demo stream (`make replay-fast`): the office capture with the tunnel at 5–30 ms.
Previous model 1/50 tunnel queries caught, fixed model 50/50, 0 false alarms each.

## Remaining limits

- **Gaps of about 1 ms or less are still missed.** They are below the 2 ms
  floor of the training campaigns, and that range is crowded with normal
  paired lookups. A tool that sends each query only after the previous
  answer returns cannot go below the round trip to the attacker's
  authoritative server, which is normally well above 1 ms. A tool that pipelines
  many queries without waiting could.
- At 100 ms–1 s the stress recall is a few points lower than before (≈82–86%
  vs 85–87%). The frozen evaluation set, where most attacks live, improved.
- The stress campaigns come from the same generator family as the training
  campaigns (different seed and domains). This shows the timing shortcut is
  gone; it is not evidence about real tunnelling tools.
- Fold 5 had been inspected before; these remain diagnostic development
  results, not a fresh final test.
