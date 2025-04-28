import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
  Box, Typography, CircularProgress, Alert, Paper, Chip,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  Button, Dialog, DialogActions, DialogContent, DialogTitle,
  Accordion, AccordionSummary, AccordionDetails, Grid,
  Card, CardContent, CardHeader, Divider
} from '@mui/material';
import { 
  ExpandMore as ExpandMoreIcon, 
  Warning as WarningIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  CheckCircle as CheckCircleIcon,
  Delete as DeleteIcon
} from '@mui/icons-material';

const API_URL = 'http://localhost:5000';

const AlertList = () => {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false);

  const fetchAlerts = async () => {
    setLoading(true);
    try {
      const response = await axios.get(`${API_URL}/get_alerts`);
      setAlerts(response.data.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)));
      setError(null);
    } catch (err) {
      console.error('Error fetching alerts:', err);
      setError('Failed to load alerts. Please try again later.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, []);

  const handleViewDetails = (alert) => {
    setSelectedAlert(alert);
    setDialogOpen(true);
  };

  const handleCloseDialog = () => {
    setDialogOpen(false);
  };

  const handleDeleteAllAlerts = async () => {
    try {
      await axios.delete(`${API_URL}/delete_alerts`);
      setAlerts([]);
      setDeleteConfirmOpen(false);
    } catch (err) {
      console.error('Error deleting alerts:', err);
      setError('Failed to delete alerts. Please try again later.');
    }
  };

  const getSeverityIcon = (severity) => {
    switch(severity) {
      case 'Critical':
        return <ErrorIcon color="error" />;
      case 'High':
        return <WarningIcon color="warning" />;
      case 'Medium':
        return <InfoIcon color="info" />;
      case 'Low':
        return <CheckCircleIcon color="success" />;
      default:
        return <InfoIcon color="action" />;
    }
  };

  const getSeverityChip = (severity) => {
    let color;
    switch(severity) {
      case 'Critical': color = 'error'; break;
      case 'High': color = 'warning'; break;
      case 'Medium': color = 'info'; break;
      case 'Low': color = 'success'; break;
      default: color = 'default';
    }
    
    return (
      <Chip 
        icon={getSeverityIcon(severity)} 
        label={severity} 
        color={color} 
        size="small" 
        variant="filled"
      />
    );
  };

  const formatDate = (dateStr) => {
    const date = new Date(dateStr);
    return date.toLocaleString();
  };

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', my: 4 }}>
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Alert severity="error" sx={{ my: 2 }}>
        {error}
      </Alert>
    );
  }

  return (
    <Box sx={{ maxWidth: 1200, mx: 'auto', p: 2 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" component="h1">
          Security Alerts ({alerts.length})
        </Typography>
        <Button 
          variant="outlined" 
          color="error" 
          startIcon={<DeleteIcon />}
          onClick={() => setDeleteConfirmOpen(true)}
          disabled={alerts.length === 0}
        >
          Delete All
        </Button>
      </Box>

      {alerts.length === 0 ? (
        <Paper sx={{ p: 4, textAlign: 'center' }}>
          <Typography variant="h6" color="text.secondary">
            No alerts found
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mt: 1 }}>
            New alerts will appear here when they are processed.
          </Typography>
        </Paper>
      ) : (
        <TableContainer component={Paper} sx={{ mb: 4 }}>
          <Table sx={{ minWidth: 650 }}>
            <TableHead>
              <TableRow>
                <TableCell>Severity</TableCell>
                <TableCell>Message</TableCell>
                <TableCell>Time</TableCell>
                <TableCell>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {alerts.map((alert) => (
                <TableRow key={alert.id} hover>
                  <TableCell>{getSeverityChip(alert.severity)}</TableCell>
                  <TableCell>
                    <Typography noWrap sx={{ maxWidth: 400 }}>
                      {alert.message}
                    </Typography>
                  </TableCell>
                  <TableCell>{formatDate(alert.timestamp)}</TableCell>
                  <TableCell>
                    <Button 
                      variant="outlined" 
                      size="small"
                      onClick={() => handleViewDetails(alert)}
                    >
                      Details
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      {/* Alert Details Dialog */}
      <Dialog 
        open={dialogOpen} 
        onClose={handleCloseDialog}
        maxWidth="md"
        fullWidth
      >
        {selectedAlert && (
          <>
            <DialogTitle>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                {getSeverityIcon(selectedAlert.severity)}
                <Typography variant="h6">
                  Alert Details {selectedAlert.jira_ticket_id && `(Ticket: ${selectedAlert.jira_ticket_id})`}
                </Typography>
              </Box>
            </DialogTitle>
            <DialogContent dividers>
              <Grid container spacing={3}>
                <Grid item xs={12}>
                  <Card variant="outlined">
                    <CardHeader title="Alert Information" />
                    <Divider />
                    <CardContent>
                      <Typography variant="body1" gutterBottom>
                        <strong>Message:</strong> {selectedAlert.message}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        <strong>Time:</strong> {formatDate(selectedAlert.timestamp)}
                      </Typography>
                      <Box sx={{ mt: 1 }}>
                        <strong>Severity:</strong> {getSeverityChip(selectedAlert.severity)}
                      </Box>
                      
                      {selectedAlert.additional_data?.impact && (
                        <Typography variant="body1" sx={{ mt: 2 }}>
                          <strong>Impact:</strong> {selectedAlert.additional_data.impact}
                        </Typography>
                      )}
                      
                      {selectedAlert.additional_data?.reasoning && (
                        <Typography variant="body1" sx={{ mt: 2 }}>
                          <strong>Reasoning:</strong> {selectedAlert.additional_data.reasoning}
                        </Typography>
                      )}
                    </CardContent>
                  </Card>
                </Grid>
                
                <Grid item xs={12}>
                  <Accordion defaultExpanded>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Typography variant="h6">Recommended Actions</Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="subtitle1" gutterBottom>Immediate Actions:</Typography>
                      {selectedAlert.recommendations?.immediate?.length > 0 ? (
                        <ul>
                          {selectedAlert.recommendations.immediate.map((action, index) => (
                            <li key={index}>
                              <Typography variant="body1">{action}</Typography>
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <Typography variant="body2" color="text.secondary">No immediate actions specified</Typography>
                      )}
                      
                      <Typography variant="subtitle1" gutterBottom sx={{ mt: 2 }}>Long-term Actions:</Typography>
                      {selectedAlert.recommendations?.long_term?.length > 0 ? (
                        <ul>
                          {selectedAlert.recommendations.long_term.map((action, index) => (
                            <li key={index}>
                              <Typography variant="body1">{action}</Typography>
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <Typography variant="body2" color="text.secondary">No long-term actions specified</Typography>
                      )}
                    </AccordionDetails>
                  </Accordion>
                </Grid>

                <Grid item xs={12}>
                  <Accordion>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Typography variant="h6">Notifications</Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="body1">
                        <strong>Jira Ticket:</strong> {selectedAlert.jira_ticket_id || 'Not created'}
                      </Typography>
                      <Typography variant="body1" sx={{ mt: 1 }}>
                        <strong>Slack Notification:</strong> {selectedAlert.slack_notification_sent ? 'Sent successfully' : 'Not sent'}
                      </Typography>
                    </AccordionDetails>
                  </Accordion>
                </Grid>
              </Grid>
            </DialogContent>
            <DialogActions>
              <Button onClick={handleCloseDialog}>Close</Button>
            </DialogActions>
          </>
        )}
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <Dialog
        open={deleteConfirmOpen}
        onClose={() => setDeleteConfirmOpen(false)}
      >
        <DialogTitle>Confirm Delete</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to delete all alerts? This action cannot be undone.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteConfirmOpen(false)}>Cancel</Button>
          <Button onClick={handleDeleteAllAlerts} color="error" variant="contained">
            Delete All
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default AlertList;
