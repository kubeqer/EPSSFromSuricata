import React, { useState, useEffect, useCallback } from 'react';
import {
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  IconButton,
  Tooltip,
  TablePagination,
  Box,
  Typography,
  CircularProgress,
  TextField,
  MenuItem,
  Button,
  SelectChangeEvent,
  Grid,
} from '@mui/material';
import {
  Visibility as ViewIcon,
  Edit as EditIcon,
  Refresh as RefreshIcon,
  Clear as ClearIcon,
} from '@mui/icons-material';
import { alertsApi } from '../../api/alerts';
import { Alert, AlertStatus, AlertPriority, AlertFilter } from '../../types/alerts';
import AlertDetailsDialog from './AlertDetailsDialog';
import AlertUpdateDialog from './AlertUpdateDialog';

interface FilterState {
  status: string;
  priority: string;
  cve_id: string;
  is_synthetic: string;
  start_date: string;
  end_date: string;
}

const AlertsTable: React.FC = () => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState<number>(0);
  const [rowsPerPage, setRowsPerPage] = useState<number>(50);
  const [totalCount, setTotalCount] = useState<number>(0);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [detailsOpen, setDetailsOpen] = useState<boolean>(false);
  const [updateOpen, setUpdateOpen] = useState<boolean>(false);

  // Filters
  const [filters, setFilters] = useState<FilterState>({
    status: '',
    priority: '',
    cve_id: '',
    is_synthetic: '',
    start_date: '',
    end_date: '',
  });

  const fetchAlerts = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const params: any = {
        page: page + 1,
        limit: rowsPerPage,
      };

      // Add filters to params
      if (filters.status) params.status = [filters.status as AlertStatus];
      if (filters.priority) params.priority = [filters.priority as AlertPriority];
      if (filters.cve_id) params.cve_id = filters.cve_id;
      if (filters.is_synthetic !== '') params.is_synthetic = filters.is_synthetic === 'true';
      if (filters.start_date) params.start_date = filters.start_date;
      if (filters.end_date) params.end_date = filters.end_date;

      const data = await alertsApi.getAlerts(params);
      setAlerts(data.items);
      setTotalCount(data.total);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'An error occurred';
      setError(errorMessage);
      console.error('Error fetching alerts:', err);
    } finally {
      setLoading(false);
    }
  }, [page, rowsPerPage, filters]);

  useEffect(() => {
    fetchAlerts();
  }, [fetchAlerts]);

  const handleChangePage = (event: unknown, newPage: number): void => {
    setPage(newPage);
  };

  const handleChangeRowsPerPage = (event: React.ChangeEvent<HTMLInputElement>): void => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  const handleFilterChange = (field: keyof FilterState) => (
    event: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement> | SelectChangeEvent
  ): void => {
    setFilters({ ...filters, [field]: event.target.value });
    setPage(0);
  };

  const handleClearFilters = (): void => {
    setFilters({
      status: '',
      priority: '',
      cve_id: '',
      is_synthetic: '',
      start_date: '',
      end_date: '',
    });
    setPage(0);
  };

  const handleViewDetails = (alert: Alert): void => {
    setSelectedAlert(alert);
    setDetailsOpen(true);
  };

  const handleEditAlert = (alert: Alert): void => {
    setSelectedAlert(alert);
    setUpdateOpen(true);
  };

  const handleAlertUpdated = (updatedAlert: Alert): void => {
    setAlerts(alerts.map(a => a.id === updatedAlert.id ? updatedAlert : a));
    setUpdateOpen(false);
  };

  const getPriorityColor = (priority: AlertPriority): 'error' | 'warning' | 'info' | 'success' | 'default' => {
    const colors: Record<AlertPriority, 'error' | 'warning' | 'info' | 'success'> = {
      [AlertPriority.CRITICAL]: 'error',
      [AlertPriority.HIGH]: 'warning',
      [AlertPriority.MEDIUM]: 'info',
      [AlertPriority.LOW]: 'success',
    };
    return colors[priority] || 'default';
  };

  const getStatusColor = (status: AlertStatus): 'error' | 'warning' | 'info' | 'success' | 'default' => {
    const colors: Record<AlertStatus, 'error' | 'warning' | 'info' | 'success' | 'default'> = {
      [AlertStatus.NEW]: 'error',
      [AlertStatus.ACKNOWLEDGED]: 'warning',
      [AlertStatus.IN_PROGRESS]: 'info',
      [AlertStatus.RESOLVED]: 'success',
      [AlertStatus.FALSE_POSITIVE]: 'default',
    };
    return colors[status] || 'default';
  };

  if (loading && alerts.length === 0) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" height={400}>
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" height={400}>
        <Typography color="error">Error loading alerts: {error}</Typography>
      </Box>
    );
  }

  return (
    <Box>
      {/* Filters */}
      <Paper sx={{ p: 2, mb: 2 }}>
        <Grid container spacing={2} alignItems="center">
          <Grid size={{ xs: 12, sm: 6, md: 2}}>
            <TextField
              select
              fullWidth
              label="Status"
              value={filters.status}
              onChange={handleFilterChange('status')}
              size="small"
            >
              <MenuItem value="">All</MenuItem>
              <MenuItem value={AlertStatus.NEW}>New</MenuItem>
              <MenuItem value={AlertStatus.ACKNOWLEDGED}>Acknowledged</MenuItem>
              <MenuItem value={AlertStatus.IN_PROGRESS}>In Progress</MenuItem>
              <MenuItem value={AlertStatus.RESOLVED}>Resolved</MenuItem>
              <MenuItem value={AlertStatus.FALSE_POSITIVE}>False Positive</MenuItem>
            </TextField>
          </Grid>
          <Grid size={{ xs: 12, sm: 6, md: 2}}>
            <TextField
              select
              fullWidth
              label="Priority"
              value={filters.priority}
              onChange={handleFilterChange('priority')}
              size="small"
            >
              <MenuItem value="">All</MenuItem>
              <MenuItem value={AlertPriority.CRITICAL}>Critical</MenuItem>
              <MenuItem value={AlertPriority.HIGH}>High</MenuItem>
              <MenuItem value={AlertPriority.MEDIUM}>Medium</MenuItem>
              <MenuItem value={AlertPriority.LOW}>Low</MenuItem>
            </TextField>
          </Grid>
          <Grid size={{ xs: 12, sm: 6, md: 2}}>
            <TextField
              fullWidth
              label="CVE ID"
              value={filters.cve_id}
              onChange={handleFilterChange('cve_id')}
              size="small"
              placeholder="CVE-YYYY-NNNN"
            />
          </Grid>
          <Grid size={{ xs: 12, sm: 6, md: 2}}>
            <TextField
              select
              fullWidth
              label="Alert Type"
              value={filters.is_synthetic}
              onChange={handleFilterChange('is_synthetic')}
              size="small"
            >
              <MenuItem value="">All</MenuItem>
              <MenuItem value="true">Synthetic</MenuItem>
              <MenuItem value="false">Suricata</MenuItem>
            </TextField>
          </Grid>
          <Grid size={{ xs: 12, sm: 6, md: 2}}>
            <TextField
              fullWidth
              label="Start Date"
              type="datetime-local"
              value={filters.start_date}
              onChange={handleFilterChange('start_date')}
              size="small"
              InputLabelProps={{
                shrink: true,
              }}
            />
          </Grid>
          <Grid size={{ xs: 12, sm: 6, md: 2}}>
            <TextField
              fullWidth
              label="End Date"
              type="datetime-local"
              value={filters.end_date}
              onChange={handleFilterChange('end_date')}
              size="small"
              InputLabelProps={{
                shrink: true,
              }}
            />
          </Grid>
          <Grid size={{ xs: 12, sm: 6, md: 1}}>
            <Button
              variant="outlined"
              startIcon={<RefreshIcon />}
              onClick={fetchAlerts}
              disabled={loading}
              fullWidth
            >
              Refresh
            </Button>
          </Grid>
          <Grid size={{ xs: 12, sm: 6, md: 1}}>
            <Button
              variant="outlined"
              startIcon={<ClearIcon />}
              onClick={handleClearFilters}
              fullWidth
            >
              Clear
            </Button>
          </Grid>
        </Grid>
      </Paper>

      {/* Table */}
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>ID</TableCell>
              <TableCell>Priority</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Alert Signature</TableCell>
              <TableCell>CVE</TableCell>
              <TableCell>EPSS Score</TableCell>
              <TableCell>Source IP</TableCell>
              <TableCell>Destination IP</TableCell>
              <TableCell>Type</TableCell>
              <TableCell>Created</TableCell>
              <TableCell>Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {alerts.map((alert) => (
              <TableRow key={alert.id}>
                <TableCell>{alert.id}</TableCell>
                <TableCell>
                  <Chip
                    label={alert.priority.toUpperCase()}
                    color={getPriorityColor(alert.priority)}
                    size="small"
                  />
                </TableCell>
                <TableCell>
                  <Chip
                    label={alert.status.replace('_', ' ').toUpperCase()}
                    color={getStatusColor(alert.status)}
                    size="small"
                  />
                </TableCell>
                <TableCell>
                  <Typography variant="body2" noWrap sx={{ maxWidth: 300 }}>
                    {alert.event?.alert_signature || 'N/A'}
                  </Typography>
                </TableCell>
                <TableCell>
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
                </TableCell>
                <TableCell>
                  {alert.epss_score > 0 ? alert.epss_score.toFixed(4) : 'N/A'}
                </TableCell>
                <TableCell>{alert.event?.src_ip || 'N/A'}</TableCell>
                <TableCell>{alert.event?.dest_ip || 'N/A'}</TableCell>
                <TableCell>
                  <Chip
                    label={alert.detection_type}
                    size="small"
                    variant={alert.is_synthetic ? 'outlined' : 'filled'}
                  />
                </TableCell>
                <TableCell>
                  {new Date(alert.created_at).toLocaleString()}
                </TableCell>
                <TableCell>
                  <Tooltip title="View Details">
                    <IconButton size="small" onClick={() => handleViewDetails(alert)}>
                      <ViewIcon />
                    </IconButton>
                  </Tooltip>
                  <Tooltip title="Edit">
                    <IconButton size="small" onClick={() => handleEditAlert(alert)}>
                      <EditIcon />
                    </IconButton>
                  </Tooltip>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        <TablePagination
          rowsPerPageOptions={[25, 50, 100]}
          component="div"
          count={totalCount}
          rowsPerPage={rowsPerPage}
          page={page}
          onPageChange={handleChangePage}
          onRowsPerPageChange={handleChangeRowsPerPage}
        />
      </TableContainer>

      {/* Dialogs */}
      <AlertDetailsDialog
        open={detailsOpen}
        onClose={() => setDetailsOpen(false)}
        alert={selectedAlert}
      />
      <AlertUpdateDialog
        open={updateOpen}
        onClose={() => setUpdateOpen(false)}
        alert={selectedAlert}
        onUpdate={handleAlertUpdated}
      />
    </Box>
  );
};

export default AlertsTable;