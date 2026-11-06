# Evaluation protocol

No performance or anomaly-detection results are claimed by this MVP. To evaluate the storage design, compare (A) browser encryption and object storage without chain lookup, (B) object-store checksum, and (C) browser AES-GCM plus SHA-256 and chain lookup before decryption. The first two are performance baselines, not equivalent integrity guarantees.

Use generated files at 1, 10, and 100 MiB; run at least 20 repetitions per size and record browser/device, network, chain/compiler, configuration, and raw timings. Report median, p95, spread/confidence interval, encryption/decryption throughput, browser memory where measurable, upload/download/API latency, transaction confirmation time and gas. For integrity, alter one byte in controlled ciphertext and require zero false accepts in the test set. Local EVM results do not predict public-chain costs/latency. Keep generated fixtures and scripts free of user content and credentials.

Multi-cloud and anomaly detection are not part of this release. Do not claim AI detection or provider-independent recovery without a separately implemented baseline, labeled synthetic or consented data, false-positive evaluation, failure simulation, and reproducible results.
