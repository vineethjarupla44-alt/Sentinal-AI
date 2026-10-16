# Sentinel AI: System Limitations & Engineering Constraints

## 1. Scope & Ethical Boundaries
- **Offline Processing Only:** Sentinel AI is designed strictly for offline network flow log telemetry analysis. It does **not** engage in active network packet sniffing, live socket capturing (pcap), packet injection, or network scanning.
- **Probabilistic vs Confirmed Maliciousness:** In adherence to strict SOC standards, Sentinel AI classifies events as **anomalous behavioral indicators** ranked by mathematical prioritization score (0–100). The system never claims that an unverified event is "confirmed malicious" without authoritative threat intelligence (e.g., hash matching, sandbox detonation, or endpoint telemetry).
- **Zero Silent Pruning:** Unlike legacy IDS engines that discard suppressed alerts, Sentinel AI demotes benign lookalikes to an `INFORMATIONAL` compliance tier while preserving 100% of underlying flow records and timestamps.

---

## 2. Technical Limitations

### A. Synthetic Telemetry Validation
- Empirical benchmarks (Precision: 79.5%–100%, Recall: 100%, FP Reduction: 60%–100%) were measured against annotated synthetic datasets with known ground truth labels.
- In production enterprise environments, real-world flow logs frequently exhibit noisy metadata, truncated session durations, and ambiguous non-standard port reuse that may produce lower initial baseline precision before site-specific tuning.

### B. Sliding Window Memory & Scale
- The sliding-window correlation algorithm operates in-memory over the loaded batch of records.
- For high-throughput enterprise networks (e.g., $>100,000$ flows/second), stateful sliding windows require a distributed streaming architecture (such as Apache Flink, Kafka Streams, or Redis sliding time-series sets) to maintain state across cluster nodes.

### C. Static Context vs Dynamic Behavioral Baselines
- Contextual baselines (approved scanners, maintenance hours, WSUS patch servers) are externalized in JSON configuration files.
- While this guarantees 100% explainability, it requires organizational maintenance to keep scanner IP lists and backup windows up to date. Future work could introduce unsupervised dynamic baselining (e.g., Exponential Smoothing or Seasonal Decomposition) to learn normal operating windows automatically.

### D. Single-Hop Lateral Movement Ingress Correlation
- The lateral movement rule correlates preceding inbound administrative traffic within 5 minutes prior to outbound fanout. In sophisticated advanced persistent threats (APTs), dwell time between initial compromise and lateral movement may span hours or days, requiring persistent graph database tracking (e.g. Neo4j).
