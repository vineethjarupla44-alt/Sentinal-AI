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

### E. Attack-Stage Hypotheses vs Forensic Ground-Truth
- Attack stage classifications displayed in the chronological incident timeline (`Reconnaissance`, `Lateral Movement`, `Command and Control (C2)`, `Unusual Outbound Transfer`) are **analytical hypotheses** inferred from observable traffic characteristics (port distributions, fan-out ratios, directionality, and timing regularity).
- These hypotheses are designed to accelerate SOC analyst triage, alert clustering, and initial scoping. They do **not** constitute forensically proven ground-truth or attribution, which requires endpoint memory analysis, disk forensics, malware reverse engineering, or decrypted payload inspection.

### F. Host Baseline Statistical History Requirements
- Statistical host traffic baselining calculates expected means and standard deviations across observed telemetry windows.
- To prevent false alarms on newly provisioned machines or sparse network segments, the engine enforces a strict minimum threshold of 3 observation windows ($N \ge 3$).
- Hosts with insufficient observations are explicitly assigned the status `INSUFFICIENT_HISTORY` with zero score penalty or deviation trigger, avoiding premature anomaly declarations until a valid statistical profile is established.

### G. Candidate Beaconing Detection & Jitter Sensitivity
- The candidate beaconing detector analyzes inter-arrival intervals ($\Delta t$) and Coefficient of Variation ($CV = \sigma / \mu$) across repetitive connections.
- Advanced C2 frameworks (e.g., Cobalt Strike, Mythic) can be configured with aggressive sleep jitter exceeding 70%–90% or multi-hour callback intervals. Detecting such highly irregular or ultra-low frequency beaconing requires aggregating multi-day or multi-week historical NetFlow archives, which exceeds the memory footprint of single-batch in-memory processing.

### H. Network Topology Graph Scalability
- The interactive directed communication graph is optimized for incident-scoped topologies (up to 150 communicating hosts and channels per incident).
- Rendering network-wide enterprise graphs containing tens of thousands of active nodes simultaneously requires WebGL canvas acceleration or hierarchical community clustering (e.g., Louvain modularity) to prevent DOM overhead.

