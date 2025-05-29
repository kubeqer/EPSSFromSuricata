import axios from './axios';
import { Alert, AlertFilter, AlertStats, AlertUpdate, Page } from '../types/alerts';

interface AlertsApiParams extends Partial<AlertFilter> {
  page?: number;
  limit?: number;
}

export const alertsApi = {
  // Get alerts with pagination and filters
  getAlerts: async (params: AlertsApiParams = {}): Promise<Page<Alert>> => {
    const response = await axios.get<Page<Alert>>('/alerts/', { params });
    return response.data;
  },

  // Get single alert by ID
  getAlert: async (alertId: number): Promise<Alert> => {
    const response = await axios.get<Alert>(`/alerts/${alertId}`);
    return response.data;
  },

  // Update alert status, priority, or notes
  updateAlert: async (alertId: number, data: AlertUpdate): Promise<Alert> => {
    const response = await axios.patch<Alert>(`/alerts/${alertId}`, data);
    return response.data;
  },

  // Get alert statistics
  getAlertStats: async (): Promise<AlertStats> => {
    const response = await axios.get<AlertStats>('/alerts/stats/summary');
    return response.data;
  },

  // Manually trigger alert processing
  processNewAlerts: async (): Promise<Alert[]> => {
    const response = await axios.post<Alert[]>('/alerts/process');
    return response.data;
  },
};