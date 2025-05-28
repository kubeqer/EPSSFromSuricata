import React, { useState } from 'react';
import {
  Container,
  Typography,
  Box,
  Paper,
  Button,
  Snackbar,
  Alert,
} from '@mui/material';
import { Refresh as RefreshIcon } from '@mui/icons-material';
import AlertStats from './AlertStats';
import AlertsTable from '../alerts/AlertsTable';
import RealtimeAlerts from '../alerts/RealtimeAlerts';
import { alertsApi } from '../../api/alerts';

interface SnackbarState {
  open: boolean;
  message: string;
  severity: 'success' | 'error' | 'info' | 'warning';
}

const Dashboard: React.FC = () => {
  const [processing, setProcessing] = useState<boolean>(false);
  const [snackbar, setSnackbar] = useState<SnackbarState>({
    open: false,
    message: '',
    severity: 'info'
  });

  const handleProcessAlerts = async (): Promise<void> => {
    setProcessing(true);
    try {
      const newAlerts = await alertsApi.processNewAlerts();
      setSnackbar({
        open: true,
        message: `Processed ${newAlerts.length} new alerts`,
        severity: 'success',
      });
    } catch (error) {
      setSnackbar({
        open: true,
        message: 'Error processing alerts',
        severity: 'error',
      });
    } finally {
      setProcessing(false);
    }
  };

  const handleSnackbarClose = (): void => {
    setSnackbar({ ...snackbar, open: false });
  };

  return (
    <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4" component="h1">
          Suricata Alert Dashboard
        </Typography>
        <Button
          variant="contained"
          startIcon={<RefreshIcon />}
          onClick={handleProcessAlerts}
          disabled={processing}
        >
          {processing ? 'Processing...' : 'Process New Alerts'}
        </Button>
      </Box>

      <Box mb={3}>
        <AlertStats />
      </Box>

      <Box mb={3}>
        <Paper sx={{ p: 2 }}>
          <Typography variant="h6" gutterBottom>
            Real-time Alerts
          </Typography>
          <RealtimeAlerts />
        </Paper>
      </Box>

      <Paper sx={{ p: 2 }}>
        <Typography variant="h6" gutterBottom>
          All Alerts
        </Typography>
        <AlertsTable />
      </Paper>

      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={handleSnackbarClose}
      >
        <Alert severity={snackbar.severity} onClose={handleSnackbarClose}>
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Container>
  );
};

export default Dashboard;