# Adaptive Detection Performance & False-Positive Reduction

## Executive Summary
This empirical validation measures the effectiveness of the **TraceGuard Adaptive Detection & Behaviour Analysis Engine** on normalized network flow datasets. The engine compares naive volumetric detection rules against context-aware adaptive baselining (incorporating approved scanners, maintenance windows, patch servers, and scheduled backups).

---

## Dataset Ground Truth Composition
- **Total Processed Flows:** 56
- **Malicious Attack Flows (Ground Truth TP):** 31
- **Benign Lookalike Flows (Scanners, Backups, Patching):** 22
- **Standard Baseline Benign Flows:** 3

---

## Empirical Comparison: Before vs After Adaptive Context Baselining

| Metric | Stage 1: Naive Volumetric IDS | Stage 2: Context-Aware TraceGuard | Improvement / Delta |
| :--- | :--- | :--- | :--- |
| **True Positives (TP)** | 31 | 31 | Maintained (31/31) |
| **False Positives (FP)** | 20 | 8 | **-12 FPs (60% reduction)** |
| **True Negatives (TN)** | 5 | 17 | +12 flows correctly classified |
| **False Negatives (FN)** | 0 | 0 | Zero missed attacks |
| **Precision** | 60.78% | **79.49%** | **+18.7%** |
| **Recall (Sensitivity)** | 100.00% | **100.00%** | **100% detection preserved** |
| **False Positive Rate (FPR)** | 80.00% | **32.00%** | **-48%** |
| **F1-Score** | 75.61% | **88.57%** | Significant confidence boost |

---

## Core Technical Findings
1. **Evidence-Preserving Deprioritization:** Rather than permanently dropping or silently hiding lookalike events, all raw flows are indexed with complete audit integrity. Benign lookalikes are safely deprioritized to low-risk compliance tiers while maintaining 100% of underlying evidence.
2. **Precision Enhancement:** By matching verified external schedules and approved profiles, analyst alert fatigue drops substantially (60% false-alarm reduction) without compromising genuine threat visibility.
3. **Unexplained Evidence Retention:** If an approved host initiates activity not permitted by its profile (e.g. unauthorized ports or unexpected target subnets), the system refuses to suppress the alert and escalates the deviation to analysts.
