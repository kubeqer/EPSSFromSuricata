import React from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Typography,
  Box,
  Chip,
  Divider,
  Grid,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableRow,
} from '@mui/material';
import { Alert, AlertPriority, AlertStatus } from '../../types/alerts';

interface AlertDetailsDialogProps {
  open: boolean;
  onClose: () => void;
  alert: Alert | null;
}

const AlertDetailsDialog: React.FC<AlertDetailsDialogProps> = ({ open, onClose, alert }) => {
  if (!alert) return null;

  const getPriorityColor = (priority: AlertPriority): 'error' | 'warning' | 'info' | 'success' => {
    const colors: Record<AlertPriority, 'error' | 'warning' | 'info' | 'success'> = {
      [AlertPriority.CRITICAL]: 'error',
      [AlertPriority.HIGH]: 'warning',
      [AlertPriority.MEDIUM]: 'info',
      [AlertPriority.LOW]: 'success',
    };
    return colors[priority];
  };

  const getStatusColor = (status: AlertStatus): 'error' | 'warning' | 'info' | 'success' => {
    const colors: Record<AlertStatus, 'error' | 'warning' | 'info' | 'success'> = {
      [AlertStatus.NEW]: 'error',
      [AlertStatus.ACKNOWLEDGED]: 'warning',
      [AlertStatus.IN_PROGRESS]: 'info',
      [AlertStatus.RESOLVED]: 'success',
      [AlertStatus.FALSE_POSITIVE]: 'success',
    };
    return colors[status];
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="lg" fullWidth>
      <DialogTitle>Alert Details - ID: {alert.id}</DialogTitle>
      <DialogContent>
        <Box sx={{ mt: 2 }}>
          <Grid container spacing={2}>
            <Grid size={{xs: 6}}>
              <Typography variant="subtitle2" color="text.secondary">
                Priority
              </Typography>
              <Chip
                label={alert.priority.toUpperCase()}
                color={getPriorityColor(alert.priority)}
                size="small"
              />
            </Grid>
            <Grid size={{xs: 6}}>
              <Typography variant="subtitle2" color="text.secondary">
                Status
              </Typography>
              <Chip
                label={alert.status.replace('_', ' ').toUpperCase()}
                color={getStatusColor(alert.status)}
                size="small"
              />
            </Grid>
          </Grid>

          <Divider sx={{ my: 2 }} />

          <Typography variant="h6" gutterBottom>
            Alert Information
          </Typography>
          <Grid container spacing={2}>
            <Grid size={{xs: 12}}>
              <Typography variant="subtitle2" color="text.secondary">
                Signature
              </Typography>
              <Typography variant="body1">
                {alert.event?.alert_signature || 'N/A'}
              </Typography>
            </Grid>
            <Grid size={{xs: 6}}>
              <Typography variant="subtitle2" color="text.secondary">
                CVE ID
              </Typography>
              <Typography variant="body1">
                {alert.cve_id !== 'N/A' ? (
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${alert.cve_id}`}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    {alert.cve_id}
                  </a>
                ) : (
                  'N/A'
                )}
              </Typography>
            </Grid>
            <Grid size={{xs: 6}}>
              <Typography variant="subtitle2" color="text.secondary">
                EPSS Score
              </Typography>
              <Typography variant="body1">
                {alert.epss_score > 0
                  ? `${alert.epss_score.toFixed(4)}`
                  : 'N/A'}
              </Typography>
            </Grid>
          </Grid>

          <Divider sx={{ my: 2 }} />

          <Typography variant="h6" gutterBottom>
            Network Information
          </Typography>
          <Grid container spacing={2}>
            <Grid size={{xs: 6}}>
              <Typography variant="subtitle2" color="text.secondary">
                Source
              </Typography>
              <Typography variant="body1">
                {alert.event?.src_ip || 'N/A'}:{alert.event?.src_port || 'N/A'}
              </Typography>
            </Grid>
            <Grid size={{xs: 6}}>
              <Typography variant="subtitle2" color="text.secondary">
                Destination
              </Typography>
              <Typography variant="body1">
                {alert.event?.dest_ip || 'N/A'}:{alert.event?.dest_port || 'N/A'}
              </Typography>
            </Grid>
            <Grid size={{xs: 6}}>
              <Typography variant="subtitle2" color="text.secondary">
                Protocol
              </Typography>
              <Typography variant="body1">
                {alert.event?.proto || 'N/A'}
              </Typography>
            </Grid>
            <Grid size={{xs: 6}}>
              <Typography variant="subtitle2" color="text.secondary">
                Detection Type
              </Typography>
              <Typography variant="body1">{alert.detection_type}</Typography>
            </Grid>
          </Grid>
          {alert.http_details && (
            <>
              <Divider sx={{ my: 2 }} />
              <Typography variant="h6" gutterBottom>
                HTTP Details
              </Typography>
              <TableContainer component={Paper} variant="outlined">
                <Table size="small">
                  <TableBody>
                    {alert.http_details.url && (
                      <TableRow>
                        <TableCell component="th" scope="row" sx={{ fontWeight: 'medium' }}>
                          URL
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                            {alert.http_details.url}
                          </Typography>
                        </TableCell>
                      </TableRow>
                    )}
                    {alert.http_details.method && (
                      <TableRow>
                        <TableCell component="th" scope="row" sx={{ fontWeight: 'medium' }}>
                          Method
                        </TableCell>
                        <TableCell>{alert.http_details.method}</TableCell>
                      </TableRow>
                    )}
                    {alert.http_details.status !== undefined && (
                      <TableRow>
                        <TableCell component="th" scope="row" sx={{ fontWeight: 'medium' }}>
                          Status Code
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={alert.http_details.status}
                            size="small"
                            color={alert.http_details.status >= 400 ? 'error' : 'success'}
                          />
                        </TableCell>
                      </TableRow>
                    )}
                    {alert.http_details.hostname && (
                      <TableRow>
                        <TableCell component="th" scope="row" sx={{ fontWeight: 'medium' }}>
                          Hostname
                        </TableCell>
                        <TableCell>{alert.http_details.hostname}</TableCell>
                      </TableRow>
                    )}
                    {alert.http_details.user_agent && (
                      <TableRow>
                        <TableCell component="th" scope="row" sx={{ fontWeight: 'medium' }}>
                          User Agent
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" sx={{ wordBreak: 'break-all' }}>
                            {alert.http_details.user_agent}
                          </Typography>
                        </TableCell>
                      </TableRow>
                    )}
                    {alert.http_details.referrer && (
                      <TableRow>
                        <TableCell component="th" scope="row" sx={{ fontWeight: 'medium' }}>
                          Referrer
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" sx={{ wordBreak: 'break-all' }}>
                            {alert.http_details.referrer}
                          </Typography>
                        </TableCell>
                      </TableRow>
                    )}
                    {alert.http_details.content_type && (
                      <TableRow>
                        <TableCell component="th" scope="row" sx={{ fontWeight: 'medium' }}>
                          Content Type
                        </TableCell>
                        <TableCell>{alert.http_details.content_type}</TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </TableContainer>
            </>
          )}

          <Divider sx={{ my: 2 }} />

          <Typography variant="h6" gutterBottom>
            Timestamps
          </Typography>
          <Grid container spacing={2}>
            <Grid size={{xs: 6}}>
              <Typography variant="subtitle2" color="text.secondary">
                Event Time
              </Typography>
              <Typography variant="body1">
                {alert.event?.timestamp
                  ? new Date(alert.event.timestamp).toLocaleString()
                  : 'N/A'}
              </Typography>
            </Grid>
            <Grid size={{xs: 6}}>
              <Typography variant="subtitle2" color="text.secondary">
                Alert Created
              </Typography>
              <Typography variant="body1">
                {new Date(alert.created_at).toLocaleString()}
              </Typography>
            </Grid>
          </Grid>

          {alert.notes && (
            <>
              <Divider sx={{ my: 2 }} />
              <Typography variant="h6" gutterBottom>
                Notes
              </Typography>
              <Typography variant="body1" sx={{ whiteSpace: 'pre-wrap' }}>
                {alert.notes}
              </Typography>
            </>
          )}
        </Box>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Close</Button>
      </DialogActions>
    </Dialog>
  );
};

export default AlertDetailsDialog;