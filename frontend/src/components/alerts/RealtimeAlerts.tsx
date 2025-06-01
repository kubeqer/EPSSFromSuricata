import React, { useState, useEffect, useCallback } from 'react';
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
import { alertsApi } from '../../api/alerts';
import { Alert, AlertPriority } from '../../types/alerts';

const RealtimeAlerts: React.FC = () => {
  const [recentAlerts, setRecentAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date());

  const fetchRecentAlerts = useCallback(async () => {
    try {
      setError(null);
      const response = await alertsApi.getAlerts({
        page: 1,
        limit: 5,
      });
      const newAlerts = response.items;
      if (JSON.stringify(newAlerts) !== JSON.stringify(recentAlerts)) {
        setRecentAlerts(newAlerts);
      }

      setLastUpdate(new Date());
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to fetch alerts';
      setError(errorMessage);
      console.error('Error fetching recent alerts:', err);
    } finally {
      setLoading(false);
    }
  }, [recentAlerts]);

  useEffect(() => {
    fetchRecentAlerts();
    const interval = setInterval(fetchRecentAlerts, 5000);
    return () => clearInterval(interval);
  }, [fetchRecentAlerts]);

  const getPriorityColor = (priority: AlertPriority): 'error' | 'warning' | 'default' => {
    if (priority === AlertPriority.CRITICAL) return 'error';
    if (priority === AlertPriority.HIGH) return 'warning';
    return 'default';
  };

  if (loading && recentAlerts.length === 0) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" p={2}>
        <CircularProgress size={20} />
        <Typography variant="body2" ml={2}>
          Loading recent alerts...
        </Typography>
      </Box>
    );
  }

  if (error) {
    return (
      <MuiAlert severity="warning" sx={{ mb: 2 }}>
        {error}
      </MuiAlert>
    );
  }

  if (recentAlerts.length === 0) {
    return (
      <Box sx={{ p: 2 }}>
        <Typography variant="body2" color="text.secondary">
          No recent alerts found.
        </Typography>
        <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
          Last updated: {lastUpdate.toLocaleTimeString()}
        </Typography>
      </Box>
    );
  }

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
        <Typography variant="caption" color="text.secondary">
          Last updated: {lastUpdate.toLocaleTimeString()}
        </Typography>
        {loading && (
          <CircularProgress size={16} />
        )}
      </Box>

      <List>
        {recentAlerts.map((alert) => (
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
                    {alert.cve_id !== 'N/A' && `${alert.cve_id} • `}
                    {alert.event?.src_ip} → {alert.event?.dest_ip} •
                    {' '}{new Date(alert.created_at).toLocaleTimeString()}
                  </Typography>
                </Box>
              }
            />
          </ListItem>
        ))}
      </List>
    </Box>
  );
};

export default RealtimeAlerts;