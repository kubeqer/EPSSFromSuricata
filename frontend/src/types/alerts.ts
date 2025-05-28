export enum AlertStatus {
  NEW = 'new',
  ACKNOWLEDGED = 'acknowledged',
  IN_PROGRESS = 'in_progress',
  RESOLVED = 'resolved',
  FALSE_POSITIVE = 'false_positive',
}

export enum AlertPriority {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical',
}

export interface SuricataEvent {
  id: number;
  event_id: string;
  timestamp: string;
  src_ip: string;
  src_port: number;
  dest_ip: string;
  dest_port: number;
  proto: string;
  alert_signature: string;
  alert_category: string;
  alert_severity: number;
  raw_event?: Record<string, any>;
}

export interface Alert {
  id: number;
  event_id: number;
  cve_id: string;
  epss_score: number;
  epss_percentile: number;
  priority: AlertPriority;
  status: AlertStatus;
  notes: string | null;
  email_sent: boolean;
  created_at: string;
  updated_at: string;
  event?: SuricataEvent;
  is_synthetic: boolean;
  detection_type: string;
}

export interface AlertUpdate {
  status?: AlertStatus;
  priority?: AlertPriority;
  notes?: string;
  email_sent?: boolean;
}

export interface AlertFilter {
  status?: AlertStatus[];
  priority?: AlertPriority[];
  cve_id?: string;
  start_date?: string;
  end_date?: string;
  is_synthetic?: boolean;
}

export interface AlertStats {
  total: number;
  by_status: Record<AlertStatus, number>;
  by_priority: Record<AlertPriority, number>;
  recent_alerts: number;
  synthetic_alerts: number;
  cve_alerts: number;
}

export interface PaginationParams {
  page: number;
  limit: number;
}

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  limit: number;
  pages: number;
}

export interface WebSocketMessage {
  topic: 'new_alert' | 'alert_update';
  timestamp: string;
  data: {
    alert_id: number;
    data: Alert;
  };
}
