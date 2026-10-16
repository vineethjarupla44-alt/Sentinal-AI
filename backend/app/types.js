/**
 * Sentinel AI - Core Type Definitions & Schemas
 * Standardized representations for Flow Records, Detections, Mitigations, and Incidents.
 */

export const SeverityLevel = {
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
  INFORMATIONAL: 'INFORMATIONAL'
};

export const RuleId = {
  PORT_SCAN: 'RULE-PORT-SCAN-001',
  NETWORK_SWEEP: 'RULE-NET-SWEEP-002',
  LATERAL_MOVEMENT: 'RULE-LAT-MOVE-003'
};

export const MitigationTag = {
  AUTH_SEC_SCANNER: 'AUTH_SEC_SCANNER',
  AUTH_NIGHTLY_BACKUP: 'AUTH_NIGHTLY_BACKUP',
  AUTH_PATCH_DISTRIBUTION: 'AUTH_PATCH_DISTRIBUTION',
  MAINTENANCE_WINDOW: 'MAINTENANCE_WINDOW',
  TRUSTED_INFRASTRUCTURE: 'TRUSTED_INFRASTRUCTURE'
};

/**
 * Normalizes a raw flow record into the canonical FlowRecord shape
 */
export function createFlowRecord(data = {}) {
  const bytesOut = Number(data.bytes_out) || 0;
  const bytesIn = Number(data.bytes_in) || 0;
  
  return {
    record_id: String(data.record_id || `flow_${Math.random().toString(36).substring(2, 9)}`),
    timestamp: data.timestamp ? new Date(data.timestamp).toISOString() : new Date().toISOString(),
    epoch_ms: data.timestamp ? new Date(data.timestamp).getTime() : Date.now(),
    src_ip: String(data.src_ip || '').trim(),
    src_port: Number(data.src_port) || 0,
    dst_ip: String(data.dst_ip || '').trim(),
    dst_port: Number(data.dst_port) || 0,
    protocol: String(data.protocol || 'TCP').toUpperCase(),
    bytes_out: bytesOut,
    bytes_in: bytesIn,
    total_bytes: Number(data.total_bytes) || (bytesOut + bytesIn),
    duration: Number(data.duration) || 0,
    conn_state: String(data.conn_state || 'UNKNOWN').toUpperCase(),
    action: String(data.action || 'ALLOW').toUpperCase(),
    label: data.label ? String(data.label) : 'unlabeled',
    raw_metadata: data.raw_metadata || {}
  };
}
