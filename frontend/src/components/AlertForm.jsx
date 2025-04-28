import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
  Box, Button, TextField, CircularProgress, 
  Alert, Typography, Paper, Grid, 
  Select, MenuItem, FormControl, InputLabel, Card, CardContent
} from '@mui/material';
import { Send as SendIcon, Security as SecurityIcon } from '@mui/icons-material';

const API_URL = 'http://localhost:5000';

const AlertForm = () => {
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const [response, setResponse] = useState(null);
  const [error, setError] = useState(null);
  const [classificationMethods, setClassificationMethods] = useState([]);
  const [selectedMethod, setSelectedMethod] = useState('model');

  useEffect(() => {
    // Fetch available classification methods
    const fetchClassificationMethods = async () => {
      try {
        const response = await axios.get(`${API_URL}/api/classification-methods`);
        setClassificationMethods(response.data);
      } catch (err) {
        console.error('Error fetching classification methods:', err);
        setClassificationMethods([
          {id: 'model', name: 'Local ML Model', description: 'Uses the trained machine learning model'},
          {id: 'gemini', name: 'Gemini AI', description: 'Uses Google\'s Gemini AI for intelligent classification'}
        ]);
      }
    };

    fetchClassificationMethods();
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setResponse(null);

    try {
      const response = await axios.post(`${API_URL}/process_alert`, {
        message,
        classification_method: selectedMethod
      });
      
      setResponse(response.data);
      setMessage(''); // Clear the form
    } catch (err) {
      console.error('Error submitting alert:', err);
      setError(err.response?.data?.error || 'Error processing alert. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box sx={{ maxWidth: 800, mx: 'auto', p: 2 }}>
      <Paper elevation={3} sx={{ p: 3, mb: 4 }}>
        <Typography variant="h4" component="h1" gutterBottom sx={{ display: 'flex', alignItems: 'center' }}>
          <SecurityIcon sx={{ mr: 1, fontSize: 35 }} />
          Security Alert Processing
        </Typography>
        
        <form onSubmit={handleSubmit}>
          <Grid container spacing={3}>
            <Grid item xs={12}>
              <TextField
                fullWidth
                multiline
                rows={4}
                label="Security Alert Message"
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                placeholder="Enter the security alert message here..."
                required
                variant="outlined"
                disabled={loading}
              />
            </Grid>
            
            <Grid item xs={12}>
              <FormControl fullWidth variant="outlined">
                <InputLabel id="classification-method-label">Classification Method</InputLabel>
                <Select
                  labelId="classification-method-label"
                  value={selectedMethod}
                  onChange={(e) => setSelectedMethod(e.target.value)}
                  label="Classification Method"
                  disabled={loading}
                >
                  {classificationMethods.map((method) => (
                    <MenuItem key={method.id} value={method.id}>
                      <Box>
                        <Typography variant="subtitle1">{method.name}</Typography>
                        <Typography variant="body2" color="text.secondary">
                          {method.description}
                        </Typography>
                      </Box>
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
            
            <Grid item xs={12}>
              <Button
                type="submit"
                variant="contained"
                color="primary"
                disabled={loading || !message.trim()}
                startIcon={loading ? <CircularProgress size={20} color="inherit" /> : <SendIcon />}
                sx={{ py: 1.2 }}
                fullWidth
              >
                {loading ? 'Processing...' : 'Process Alert'}
              </Button>
            </Grid>
          </Grid>
        </form>
      </Paper>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {response && (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Alert Processed Successfully
            </Typography>
            
            <Grid container spacing={2}>
              <Grid item xs={12} sm={6}>
                <Typography variant="subtitle1" color="text.secondary">Severity</Typography>
                <Typography variant="body1" sx={{ 
                  fontWeight: 'bold',
                  color: response.severity === 'Critical' ? 'error.main' : 
                          response.severity === 'High' ? 'warning.main' :
                          response.severity === 'Medium' ? 'info.main' : 'success.main'
                }}>
                  {response.severity}
                </Typography>
              </Grid>
              
              {response.impact && (
                <Grid item xs={12}>
                  <Typography variant="subtitle1" color="text.secondary">Impact</Typography>
                  <Typography variant="body1">{response.impact}</Typography>
                </Grid>
              )}
              
              {response.reasoning && (
                <Grid item xs={12}>
                  <Typography variant="subtitle1" color="text.secondary">Reasoning</Typography>
                  <Typography variant="body1">{response.reasoning}</Typography>
                </Grid>
              )}
              
              <Grid item xs={12} sm={6}>
                <Typography variant="subtitle1" color="text.secondary">Jira Ticket</Typography>
                <Typography variant="body1">{response.jira_ticket || 'Not created'}</Typography>
              </Grid>
              
              <Grid item xs={12} sm={6}>
                <Typography variant="subtitle1" color="text.secondary">Slack Notification</Typography>
                <Typography variant="body1">
                  {response.slack_notification_sent ? 'Sent successfully' : 'Not sent'}
                </Typography>
              </Grid>
              
              <Grid item xs={12}>
                <Typography variant="subtitle1" color="text.secondary">Immediate Actions</Typography>
                <ul>
                  {response.recommendations?.immediate.map((rec, index) => (
                    <li key={index}><Typography variant="body1">{rec}</Typography></li>
                  ))}
                </ul>
              </Grid>
              
              <Grid item xs={12}>
                <Typography variant="subtitle1" color="text.secondary">Long-term Actions</Typography>
                <ul>
                  {response.recommendations?.long_term.map((rec, index) => (
                    <li key={index}><Typography variant="body1">{rec}</Typography></li>
                  ))}
                </ul>
              </Grid>
            </Grid>
          </CardContent>
        </Card>
      )}
    </Box>
  );
};

export default AlertForm;
