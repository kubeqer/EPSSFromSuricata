import React, { useState, useEffect } from 'react';
import {
  Card,
  CardContent,
  Typography,
  Box,
  CircularProgress,
  Chip,
} from '@mui/material';
import Grid from '@mui/material/Unstable_Grid2';
import {
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
} from '@mui/icons-material';
import { alertsApi } from '../../api/alerts';
import { AlertStats as AlertStatsType, AlertStatus, AlertPriority } from '../../types/alerts';

const AlertStats: React.FC = () => {
  const [stats, setStats] = useState<AlertStatsType | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const data = await alertsApi.getAlertStats();
        setStats(data);
        setError(null);
      } catch (err) {
        const errorMessage = err instanceof Error ? err.message : 'An error occurred';
        setError(errorMessage);
      } finally {
        setLoading(false);
      }
    };

    fetchStats();
    const interval = setInterval(fetchStats, 30000); // Refresh every 30 seconds

    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" height={200}>
        <CircularProgress />
      </Box>
    );
  }

  if (error || !stats) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" height={200}>
        <Typography color="error">Error loading statistics: {error}</Typography>
      </Box>
    );
  }

  interface PriorityConfig {
    color: 'error' | 'warning' | 'info' | 'success';
    icon: React.ReactElement;
  }

  const priorityColors: Record<AlertPriority, PriorityConfig> = {
    [AlertPriority.CRITICAL]: { color: 'error', icon: <ErrorIcon /> },
    [AlertPriority.HIGH]: { color: 'warning', icon: <WarningIcon /> },
    [AlertPriority.MEDIUM]: { color: 'info', icon: <InfoIcon /> },
    [AlertPriority.LOW]: { color: 'success', icon: <CheckCircleIcon /> },
  };

  return (
    <Grid container spacing={3}>
      <Grid item xs={12} sm={6} md={3}>
        <Card>
          <CardContent>
            <Typography color="textSecondary" gutterBottom>
              Total Alerts
            </Typography>
            <Typography variant="h3">{stats.total}</Typography>
            <Typography variant="body2" color="textSecondary">
              All time
            </Typography>
          </CardContent>
        </Card>
      </Grid>

      <Grid item xs={12} sm={6} md={3}>
        <Card>
          <CardContent>
            <Typography color="textSecondary" gutterBottom>
              Recent Alerts
            </Typography>
            <Typography variant="h3">{stats.recent_alerts}</Typography>
            <Typography variant="body2" color="textSecondary">
              Last 24 hours
            </Typography>
          </CardContent>
        </Card>
      </Grid>

      <Grid item xs={12} sm={6} md={3}>
        <Card>
          <CardContent>
            <Typography color="textSecondary" gutterBottom>
              CVE Alerts
            </Typography>
            <Typography variant="h3">{stats.cve_alerts}</Typography>
            <Typography variant="body2" color="textSecondary">
              With CVE IDs
            </Typography>
          </CardContent>
        </Card>
      </Grid>

      <Grid item xs={12} sm={6} md={3}>
        <Card>
          <CardContent>
            <Typography color="textSecondary" gutterBottom>
              Synthetic Alerts
            </Typography>
            <Typography variant="h3">{stats.synthetic_alerts}</Typography>
            <Typography variant="body2" color="textSecondary">
              HTTP suspicious
            </Typography>
          </CardContent>
        </Card>
      </Grid>

      <Grid item xs={12} md={6}>
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Alerts by Status
            </Typography>
            <Box display="flex" flexWrap="wrap" gap={1}>
              {Object.entries(stats.by_status).map(([status, count]) => (
                <Chip
                  key={status}
                  label={`${status.replace('_', ' ').toUpperCase()}: ${count}`}
                  size="small"
                  variant="outlined"
                />
              ))}
            </Box>
          </CardContent>
        </Card>
      </Grid>

      <Grid item xs={12} md={6}>
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Alerts by Priority
            </Typography>
            <Grid container spacing={2}>
              {Object.entries(stats.by_priority).map(([priority, count]) => {
                const config = priorityColors[priority as AlertPriority];
                return (
                  <Grid item xs={6} key={priority}>
                    <Box display="flex" alignItems="center" gap={1}>
                      <Box color={`${config.color}.main`}>
                        {config.icon}
                      </Box>
                      <Typography variant="body1">
                        {priority.toUpperCase()}: {count}
                      </Typography>
                    </Box>
                  </Grid>
                );
              })}
            </Grid>
          </CardContent>
        </Card>
      </Grid>
    </Grid>
  );
};

export default AlertStats;