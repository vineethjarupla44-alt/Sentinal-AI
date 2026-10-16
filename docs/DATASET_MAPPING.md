# TraceGuard: Dataset Column Mapping Specification

## 1. Overview
TraceGuard uses an externalized JSON mapping configuration ([`config/dataset_mapping.json`](file:///c:/Users/sonal/OneDrive/Desktop/Sentinal%20AI/config/dataset_mapping.json)) that enables any telemetry schema to be normalized into a single canonical internal schema: **`FlowRecord`**.

Adding or updating schemas requires **zero modifications to detection engine code**.

---

## 2. Canonical `FlowRecord` Schema

| Canonical Field | Type | Description | Safe Fallback Default |
| :--- | :--- | :--- | :--- |
| `record_id` | String | Unique flow identifier / session ID | Auto-generated UUID (`flow_xxxxxxx`) |
| `timestamp` | String | ISO-8601 formatted UTC timestamp | Current system time (`new Date().toISOString()`) |
| `epoch_ms` | Number | Unix timestamp in milliseconds for windowing | Current epoch time (`Date.now()`) |
| `src_ip` | String | Source IP address (IPv4/IPv6) | Required (row skipped if missing) |
| `src_port` | Number | Source ephemeral port | `0` |
| `dst_ip` | String | Destination IP address (IPv4/IPv6) | Required (row skipped if missing) |
| `dst_port` | Number | Destination service port | `0` |
| `protocol` | String | Layer 4 transport protocol (`TCP`, `UDP`, `ICMP`) | `'TCP'` |
| `bytes_out` | Number | Bytes transferred from source to destination | `0` |
| `bytes_in` | Number | Bytes transferred from destination to source | `0` |
| `total_bytes` | Number | Combined bidirectional volume (`bytes_out + bytes_in`) | `0` |
| `duration` | Number | Connection elapsed time in seconds | `0` |
| `conn_state` | String | Connection termination status (`SF`, `REJ`, `S0`, etc.) | `'UNKNOWN'` / `'ESTABLISHED'` |
| `action` | String | Firewall enforcement decision (`ALLOW`, `DENY`, `DROP`) | `'ALLOW'` |
| `label` | String | Ground truth annotation for evaluation (optional) | `'unlabeled'` |
| `raw_metadata` | Object | Preserved original raw headers and line numbers | `{}` |

---

## 3. Schema 1: Zeek / Bro Connection Log (`zeek_conn_log`)

Mapping definition from Zeek's default `conn.log` TSV/CSV format:

```json
{
  "mapping": {
    "record_id": "uid",
    "timestamp": "ts",
    "src_ip": "id.orig_h",
    "src_port": "id.orig_p",
    "dst_ip": "id.resp_h",
    "dst_port": "id.resp_p",
    "protocol": "proto",
    "bytes_out": "orig_bytes",
    "bytes_in": "resp_bytes",
    "duration": "duration",
    "conn_state": "conn_state",
    "label": "label"
  },
  "defaults": {
    "action": "ALLOW",
    "bytes_out": 0,
    "bytes_in": 0,
    "duration": 0,
    "protocol": "TCP"
  }
}
```

---

## 4. Schema 2: Enterprise NGFW / Cloud VPC Flow Log (`enterprise_firewall_vpc`)

Mapping definition for Palo Alto, AWS VPC Flow, and Azure NSG exports:

```json
{
  "mapping": {
    "record_id": "session_id",
    "timestamp": "timestamp",
    "src_ip": "src_ip",
    "src_port": "src_port",
    "dst_ip": "dst_ip",
    "dst_port": "dst_port",
    "protocol": "protocol",
    "bytes_out": "bytes_sent",
    "bytes_in": "bytes_received",
    "action": "action",
    "duration": "elapsed_time",
    "label": "ground_truth_label"
  },
  "defaults": {
    "conn_state": "ESTABLISHED",
    "bytes_out": 0,
    "bytes_in": 0,
    "duration": 0,
    "protocol": "TCP",
    "action": "ALLOW"
  }
}
```

---

## 5. Adding a New Schema
To add a 3rd schema (e.g. Cisco NetFlow or Suricata EVE JSON exported to CSV):
1. Open [`config/dataset_mapping.json`](file:///c:/Users/sonal/OneDrive/Desktop/Sentinal%20AI/config/dataset_mapping.json).
2. Add a new key under `"schemas"` with `"mapping"` pointing your CSV column names to the canonical fields.
3. Supply safe fallback defaults in `"defaults"`.
4. Run the analysis or upload via the web dashboard. The auto-detector will automatically match headers and route flows through the same detection pipeline.
