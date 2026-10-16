/**
 * Sentinel AI - Frontend Type Definitions & Constants
 */

export const SeverityLevel = {
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
  INFORMATIONAL: 'INFORMATIONAL'
};

export const DatasetSchemas = {
  ZEEK: {
    key: 'zeek',
    name: 'Schema 1: Zeek conn.log (Bro Sensor)',
    format: 'Network Flow CSV'
  },
  FIREWALL: {
    key: 'firewall',
    name: 'Schema 2: Enterprise NGFW / Cloud VPC Flow',
    format: 'Firewall Session CSV'
  },
  EDGE: {
    key: 'edge',
    name: 'Edge Cases (Duplicates & Corrupted Fields)',
    format: 'Malformed / Boundary CSV'
  }
};
