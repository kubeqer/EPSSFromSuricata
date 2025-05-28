import React, { useState, useEffect } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  TextField,
  MenuItem,
  Box,
  Alert as MuiAlert,
} from '@mui/material';
import { alertsApi } from '../../api/alerts';
import { Alert, AlertStatus, AlertPriority, AlertUpdate } from '../../types/alerts';

interface AlertUpdateDialogProps {
  open: boolean;
  onClose: () => void;
  alert: Alert | null;
  onUpdate: (alert: Alert) => void;
}

const AlertUpdateDialog: React.FC<AlertUpdateDialogProps> = ({ open, onClose, alert, onUpdate }) => {
  const [formData, setFormData] = useState<{
    status: AlertStatus | '';
    priority: AlertPriority | '';
    notes: string;
  }>({
    status: '',
    priority: '',
    notes: '',
  });
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (alert) {
      setFormData({
        status: alert.status,
        priority: alert.priority,
        notes: alert.notes || '',
      });
    }
  }, [alert]);

  const handleChange = (field: keyof typeof formData) => (
    event: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>
  ): void => {
    setFormData({ ...formData, [field]: event.target.value });
  };

  const handleSubmit = async (): Promise<void> => {
    if (!alert) return;

    setLoading(true);
    setError(null);

    try {
      const updateData: AlertUpdate = {};
      if (formData.status && formData.status !== alert.status) updateData.status = formData.status;
      if (formData.priority && formData.priority !== alert.priority) updateData.priority = formData.priority;
      if (formData.notes !== alert.notes) updateData.notes = formData.notes;

      if (Object.keys(updateData).length === 0) {
        onClose();
        return;
      }

      const updatedAlert = await alertsApi.updateAlert(alert.id, updateData);
      onUpdate(updatedAlert);
      onClose();
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'An error occurred';
      setError(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  if (!alert) return null;

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>Update Alert - ID: {alert.id}</DialogTitle>
      <DialogContent>
        <Box sx={{ mt: 2 }}>
          {error && (
            <MuiAlert severity="error" sx={{ mb: 2 }}>
              {error}
            </MuiAlert>
          )}

          <TextField
            select
            fullWidth
            label="Status"
            value={formData.status}
            onChange={handleChange('status')}
            margin="normal"
          >
            <MenuItem value={AlertStatus.NEW}>New</MenuItem>
            <MenuItem value={AlertStatus.ACKNOWLEDGED}>Acknowledged</MenuItem>
            <MenuItem value={AlertStatus.IN_PROGRESS}>In Progress</MenuItem>
            <MenuItem value={AlertStatus.RESOLVED}>Resolved</MenuItem>
            <MenuItem value={AlertStatus.FALSE_POSITIVE}>False Positive</MenuItem>
          </TextField>

          <TextField
            select
            fullWidth
            label="Priority"
            value={formData.priority}
            onChange={handleChange('priority')}
            margin="normal"
          >
            <MenuItem value={AlertPriority.CRITICAL}>Critical</MenuItem>
            <MenuItem value={AlertPriority.HIGH}>High</MenuItem>
            <MenuItem value={AlertPriority.MEDIUM}>Medium</MenuItem>
            <MenuItem value={AlertPriority.LOW}>Low</MenuItem>
          </TextField>

          <TextField
            fullWidth
            label="Notes"
            value={formData.notes}
            onChange={handleChange('notes')}
            margin="normal"
            multiline
            rows={4}
            placeholder="Add notes about this alert..."
          />
        </Box>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={loading}>
          Cancel
        </Button>
        <Button onClick={handleSubmit} variant="contained" disabled={loading}>
          {loading ? 'Updating...' : 'Update'}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default AlertUpdateDialog;