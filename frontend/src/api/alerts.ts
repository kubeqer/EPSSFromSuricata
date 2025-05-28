import axios from './axios';
import { Alert, AlertFilter, AlertStats, AlertUpdate, Page, WebSocketMessage } from '../types/alerts';

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

// WebSocket connection for real-time updates
export const createWebSocketConnection = (
  onMessage: (data: WebSocketMessage) => void,
  onError?: (error: Event) => void
): WebSocket => {
  const wsUrl = process.env.REACT_APP_WS_URL || 'ws://localhost:8000/api/v1/alerts/ws';
  const ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    console.log('WebSocket connected');
  };

  ws.onmessage = (event: MessageEvent) => {
    try {
      const data: WebSocketMessage = JSON.parse(event.data);
      onMessage(data);
    } catch (error) {
      console.error('Error parsing WebSocket message:', error);
    }
  };

  ws.onerror = (error: Event) => {
    console.error('WebSocket error:', error);
    if (onError) onError(error);
  };

  ws.onclose = () => {
    console.log('WebSocket disconnected');
    // Attempt to reconnect after 5 seconds
    setTimeout(() => createWebSocketConnection(onMessage, onError), 5000);
  };

  return ws;
};