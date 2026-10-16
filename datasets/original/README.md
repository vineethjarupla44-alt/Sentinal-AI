# Original Dataset Schemas

This directory contains the original schema specifications and headers expected from enterprise telemetry sources:

1. **Schema 1: Zeek / Bro `conn.log` CSV**
   - Header: `ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,proto,service,duration,orig_bytes,resp_bytes,conn_state,history,label`
   - Source: Zeek Network Security Monitor connection logs exported to CSV.

2. **Schema 2: Enterprise NGFW / Cloud VPC Flow Log**
   - Header: `timestamp,session_id,src_ip,src_port,dst_ip,dst_port,protocol,action,bytes_sent,bytes_received,packets,rule_name,ground_truth_label`
   - Source: Palo Alto Networks, AWS VPC Flow, or Azure NSG flow exports.

Synthetic, annotated datasets with known ground truth for validation and testing are located in `datasets/synthetic/`.
