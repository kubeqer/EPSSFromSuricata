import React, { useState, useEffect } from 'react';
import {
  Box,
  List,
  ListItem,
  ListItemText,
  Chip,
  Typography,
  Alert as MuiAlert,
  CircularProgress,
} from '@mui/material';
import { createWebSocketConnection } from '../../api/alerts';
import { Alert, AlertPriority, WebSocketMessage } from '../../types/alerts';

const RealtimeAlerts: React.FC = () => {
  const [realtimeAlerts, setRealtimeAlerts] = useState<Alert[]>([]);
  const [wsConnected, setWsConnected] = useState<boolean>(false);
  const [wsError, setWsError] = useState<string | null>(null);

  useEffect(() => {
    let ws: WebSocket | null = null;

    const handleMessage = (data: WebSocketMessage): void => {
      if (data.topic === 'new_alert') {
        setRealtimeAlerts((prev) => [data.data.data, ...prev].slice(0, 5));
      } else if (data.topic === 'alert_update') {
        setRealtimeAlerts((prev) =>
          prev.map((alert) =>
            alert.id === data.data.alert_id ? data.data.data : alert
          )
        );
      }
    };

    const handleError = (error: Event): void => {
      setWsError('WebSocket connection error');
      setWsConnected(false);
    };

    try {
      ws = createWebSocketConnection(handleMessage, handleError);
      setWsConnected(true);
      setWsError(null);
    } catch (error) {
      setWsError('Failed to connect to WebSocket');
    }

    return () => {
      if (ws) {
        ws.close();
      }
    };
  }, []);

  const getPriorityColor = (priority: AlertPriority): 'error' | 'warning' | 'default' => {
    if (priority === AlertPriority.CRITICAL) return 'error';
    if (priority === AlertPriority.HIGH) return 'warning';
    return 'default';
  };

  if (!wsConnected && !wsError) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" p={2}>
        <CircularProgress size={20} />
        <Typography variant="body2" ml={2}>
          Connecting to real-time updates...
        </Typography>
      </Box>
    );
  }

  if (wsError) {
    return (
      <MuiAlert severity="warning" sx={{ mb: 2 }}>
        {wsError}
      </MuiAlert>
    );
  }

  if (realtimeAlerts.length === 0) {
    return (
      <Typography variant="body2" color="text.secondary" sx={{ p: 2 }}>
        No real-time alerts yet. Alerts will appear here as they are created.
      </Typography>
    );
  }

  return (
    <List>
      {realtimeAlerts.map((alert) => (
        <ListItem key={alert.id} divider>
          <ListItemText
            primary={
              <Box display="flex" alignItems="center" gap={1}>
                <Chip
                  label={alert.priority.toUpperCase()}
                  size="small"
                  color={getPriorityColor(alert.priority)}
                />
                <Typography variant="body1">
                  {alert.event?.alert_signature || 'Unknown Alert'}
                </Typography>
              </Box>
            }
            secondary={
              <Box>
                <Typography variant="caption" color="text.secondary">
                  {alert.cve_id !== 'N/A' && alert.cve_id} •{' '}
                  {alert.event?.src_ip} → {alert.event?.dest_ip} •{' '}
                  {new Date(alert.created_at).toLocaleTimeString()}
                </Typography>
              </Box>
            }
          />
        </ListItem>
      ))}
    </List>
  );
};

export default RealtimeAlerts;