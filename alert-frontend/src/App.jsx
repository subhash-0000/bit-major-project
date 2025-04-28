import { useState, useEffect } from 'react'
import 'bootstrap/dist/css/bootstrap.min.css'
import './App.css'

function App() {
  // Define all state variables
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [message, setMessage] = useState('')
  // New state variables for recommendations and ticket info
  const [submissionResult, setSubmissionResult] = useState(null)
  const [showResult, setShowResult] = useState(false)
  // Add state for classification method
  const [classificationMethod, setClassificationMethod] = useState('model')
  
  // Load alerts when component mounts
  useEffect(() => {
    fetchAlerts()
  }, [])

  const fetchAlerts = async () => {
    try {
      setLoading(true)
      console.log('Fetching alerts from API...')
      const response = await fetch('http://localhost:5000/get_alerts')
      
      if (!response.ok) {
        throw new Error(`Server responded with ${response.status}`)
      }
      
      const data = await response.json()
      console.log('Received alerts:', data)
      setAlerts(data)
      setError(null)
    } catch (err) {
      console.error('Error fetching alerts:', err)
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const fetchAlertsBySeverity = async (severity) => {
    try {
      setLoading(true)
      const response = await fetch(`http://localhost:5000/get_alerts?severity=${severity}`)
      
      if (!response.ok) {
        throw new Error(`Server responded with ${response.status}`)
      }
      
      const data = await response.json()
      setAlerts(data)
      setError(null)
    } catch (err) {
      console.error('Error fetching alerts by severity:', err)
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const deleteAllAlerts = async () => {
    if (!window.confirm('Are you sure you want to delete ALL alerts? This cannot be undone.')) {
      return
    }
    
    try {
      const response = await fetch('http://localhost:5000/delete_alerts', {
        method: 'DELETE'
      })
      
      if (!response.ok) {
        throw new Error(`Server responded with ${response.status}`)
      }
      
      fetchAlerts()
      setError(null)
    } catch (err) {
      console.error('Error deleting alerts:', err)
      setError(err.message)
    }
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!message.trim()) return
    
    try {
      console.log('Submitting alert:', message)
      console.log('Using classification method:', classificationMethod)
      const response = await fetch('http://localhost:5000/process_alert', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ 
          message, 
          classification_method: classificationMethod 
        })
      })
      
      const result = await response.json()
      console.log('Full API response:', result)
      console.log('Status:', result.status)
      console.log('Jira ticket value:', result.jira_ticket, typeof result.jira_ticket)
      console.log('Slack notification value:', result.slack_notification_sent, typeof result.slack_notification_sent)
      console.log('Has recommendations:', !!result.recommendations)
      
      if (response.ok) {
        // Store the result for display - THIS IS THE IMPORTANT PART
        setSubmissionResult(result)
        setShowResult(true)
        setMessage('')
        fetchAlerts()
        setError(null)
      } else {
        setError(result.error || 'Error processing alert')
        setSubmissionResult(null)
        setShowResult(false)
      }
    } catch (err) {
      console.error('Error submitting alert:', err)
      setError(err.message)
      setSubmissionResult(null)
      setShowResult(false)
    }
  }

  // Function to close the result modal
  const closeResultModal = () => {
    setShowResult(false)
    setSubmissionResult(null)
  }

  return (
    <div className="container mt-4">
      {/* Header Section */}
      <div className="app-header">
        <div className="d-flex justify-content-between align-items-center">
          <div>
            <h1>Security Alert System</h1>
            <p>Monitor, classify, and respond to security incidents</p>
          </div>
          <div className="d-none d-md-block">
            <i className="bi bi-shield-lock fs-1"></i>
          </div>
        </div>
      </div>
      
      {error && (
        <div className="alert alert-danger">
          <i className="bi bi-exclamation-triangle-fill me-2"></i>
          {error}
        </div>
      )}
      
      <div className="row mb-4">
        <div className="col-lg-6 mb-4 mb-lg-0">
          <div className="card">
            <div className="card-header">
              <h3><i className="bi bi-bell me-2"></i>Create New Alert</h3>
            </div>
            <div className="card-body">
              <form onSubmit={handleSubmit}>
                <div className="mb-3">
                  <label htmlFor="message" className="form-label">Alert Message</label>
                  <textarea 
                    className="form-control" 
                    id="message" 
                    rows="3"
                    placeholder="Describe the security incident or alert..."
                    value={message}
                    onChange={(e) => setMessage(e.target.value)}
                    required
                  ></textarea>
                </div>
                
                <div className="mb-3 classification-method">
                  <label className="form-label">Classification Method</label>
                  <div className="d-flex gap-4">
                    <div className="form-check">
                      <input
                        className="form-check-input"
                        type="radio"
                        name="classificationMethod"
                        id="modelMethod"
                        value="model"
                        checked={classificationMethod === 'model'}
                        onChange={(e) => setClassificationMethod(e.target.value)}
                      />
                      <label className="form-check-label" htmlFor="modelMethod">
                        <i className="bi bi-cpu me-2"></i>Local ML Model
                      </label>
                    </div>
                    <div className="form-check">
                      <input
                        className="form-check-input"
                        type="radio"
                        name="classificationMethod"
                        id="geminiMethod"
                        value="gemini"
                        checked={classificationMethod === 'gemini'}
                        onChange={(e) => setClassificationMethod(e.target.value)}
                      />
                      <label className="form-check-label" htmlFor="geminiMethod">
                        <i className="bi bi-stars me-2"></i>Gemini AI
                      </label>
                    </div>
                  </div>
                  <div className="mt-2 text-muted small">
                    {classificationMethod === 'model' ? 
                      <span><i className="bi bi-info-circle me-1"></i>Uses a trained machine learning model to classify alerts based on local data.</span> : 
                      <span><i className="bi bi-info-circle me-1"></i>Uses Google's Gemini AI to provide intelligent classification with impact analysis.</span>}
                  </div>
                </div>
                
                <div className="mb-3">
                  <button type="submit" className="btn btn-primary me-2">
                    <i className="bi bi-send me-2"></i>Submit Alert
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      
        {/* Status Card - Shows when idle */}
        {!showResult && (
          <div className="col-lg-6">
            <div className="card h-100">
              <div className="card-header">
                <h3><i className="bi bi-info-circle me-2"></i>System Status</h3>
              </div>
              <div className="card-body d-flex flex-column justify-content-center align-items-center">
                <div className="text-center mb-4">
                  <i className="bi bi-shield-check text-success" style={{ fontSize: '4rem' }}></i>
                  <h4 className="mt-3">Security Monitoring Active</h4>
                  <p className="text-muted">Submit a security alert to see classification results, or browse existing alerts below.</p>
                </div>
                
                <div className="d-flex gap-3">
                  <div className="text-center p-3 border rounded">
                    <div className="fs-4 fw-bold text-primary">{alerts.length}</div>
                    <div className="small text-muted">Total Alerts</div>
                  </div>
                  <div className="text-center p-3 border rounded">
                    <div className="fs-4 fw-bold text-danger">
                      {alerts.filter(a => a.severity === 'Critical' || a.severity === 'High').length}
                    </div>
                    <div className="small text-muted">High/Critical</div>
                  </div>
                  <div className="text-center p-3 border rounded">
                    <div className="fs-4 fw-bold text-success">
                      {alerts.filter(a => a.jira_ticket_id).length}
                    </div>
                    <div className="small text-muted">Ticketed</div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
      
      {/* Results Modal - shown after processing an alert */}
      {showResult && submissionResult && (
        <div className="row mb-4">
          <div className="col">
            <div className="card result-card">
              <div className="card-header bg-success text-white d-flex justify-content-between">
                <h3 className="mb-0"><i className="bi bi-check-circle me-2"></i>Alert Processed Successfully</h3>
                <button 
                  type="button" 
                  className="btn-close btn-close-white" 
                  onClick={closeResultModal}
                ></button>
              </div>
              <div className="card-body">
                <div className="alert alert-info">
                  <div className="d-flex justify-content-between align-items-center">
                    <h4 className="mb-0">
                      Alert Severity: 
                      <span className={`badge ms-2 severity-${submissionResult.severity}`}>
                        {submissionResult.severity === 'Critical' && <i className="bi bi-exclamation-triangle-fill me-1"></i>}
                        {submissionResult.severity === 'High' && <i className="bi bi-exclamation-circle-fill me-1"></i>}
                        {submissionResult.severity === 'Medium' && <i className="bi bi-exclamation me-1"></i>}
                        {submissionResult.severity === 'Low' && <i className="bi bi-info-circle-fill me-1"></i>}
                        {submissionResult.severity}
                      </span>
                    </h4>
                    <span className="badge bg-secondary">
                      <i className="bi bi-clock me-1"></i>
                      {new Date(submissionResult.timestamp).toLocaleString()}
                    </span>
                  </div>
                  
                  {/* Display classification method */}
                  <p className="mt-2 mb-0">
                    <strong>Classification by:</strong> {submissionResult.classification_method === 'gemini' ? 
                      <span><i className="bi bi-stars me-1"></i>Gemini AI</span> : 
                      <span><i className="bi bi-cpu me-1"></i>Local ML Model</span>}
                  </p>
                </div>
                
                {/* Show Impact Analysis (for Gemini) */}
                {submissionResult.impact && (
                  <div className="impact-analysis mb-3">
                    <h5 className="mb-2"><i className="bi bi-graph-up me-2"></i>Impact Analysis:</h5>
                    <p className="mb-0">{submissionResult.impact}</p>
                    
                    {submissionResult.reasoning && (
                      <div className="mt-2">
                        <strong><i className="bi bi-lightning me-1"></i>Reasoning:</strong> {submissionResult.reasoning}
                      </div>
                    )}
                  </div>
                )}
                
                <div className="row mt-4">
                  <div className="col-md-6 mb-3">
                    {/* Jira Ticket Info */}
                    <div className="card h-100">
                      <div className="card-header">
                        <h5 className="mb-0"><i className="bi bi-kanban me-2"></i>Jira Status</h5>
                      </div>
                      <div className="card-body">
                        {submissionResult.jira_ticket ? (
                          <div>
                            <h5 className="text-success"><i className="bi bi-check-circle me-2"></i>Jira Ticket Created</h5>
                            <p className="mb-0">Ticket ID: <strong>{submissionResult.jira_ticket}</strong></p>
                            <p className="mb-0">
                              <a 
                                href={`https://subhashsrinivas36.atlassian.net/browse/${submissionResult.jira_ticket}`} 
                                target="_blank" 
                                rel="noopener noreferrer" 
                                className="btn btn-sm btn-outline-primary mt-2"
                              >
                                View in Jira <i className="bi bi-box-arrow-up-right ms-1"></i>
                              </a>
                            </p>
                          </div>
                        ) : (
                          <div>
                            <h5 className="text-warning"><i className="bi bi-exclamation-circle me-2"></i>No Ticket Created</h5>
                            <p className="mb-0 text-muted">No Jira ticket was created. This could be due to configuration issues.</p>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                  
                  <div className="col-md-6 mb-3">
                    {/* Slack Notification Info */}
                    <div className="card h-100">
                      <div className="card-header">
                        <h5 className="mb-0"><i className="bi bi-chat me-2"></i>Notification Status</h5>
                      </div>
                      <div className="card-body">
                        {submissionResult.slack_notification_sent === true ? (
                          <div>
                            <h5 className="text-success"><i className="bi bi-check-circle me-2"></i>Slack Notification Sent</h5>
                            <p className="mb-0">Security team has been notified via Slack</p>
                            <small className="text-muted">
                              <i className="bi bi-info-circle me-1"></i>
                              A notification was sent to the security channel with alert details
                            </small>
                          </div>
                        ) : (
                          <div>
                            <h5 className="text-warning"><i className="bi bi-exclamation-circle me-2"></i>Notification Not Sent</h5>
                            <p className="mb-0 text-muted">Slack notification could not be sent. This could be due to configuration issues.</p>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
                
                {/* Recommendations */}
                {submissionResult.recommendations && (
                  <div className="mt-3">
                    <h5><i className="bi bi-list-check me-2"></i>Recommended Actions:</h5>
                    <div className="row">
                      <div className="col-md-6 mb-3">
                        <div className="card">
                          <div className="card-header bg-primary text-white">
                            <i className="bi bi-lightning me-2"></i>Immediate Actions
                          </div>
                          <div className="card-body">
                            <ul className="list-group list-group-flush">
                              {submissionResult.recommendations.immediate.map((rec, index) => (
                                <li key={index} className="list-group-item d-flex align-items-start">
                                  <i className="bi bi-check-circle-fill text-success me-2 mt-1"></i>
                                  <span>{rec}</span>
                                </li>
                              ))}
                            </ul>
                          </div>
                        </div>
                      </div>
                      
                      {submissionResult.recommendations.long_term && 
                        submissionResult.recommendations.long_term.length > 0 && (
                        <div className="col-md-6 mb-3">
                          <div className="card">
                            <div className="card-header bg-secondary text-white">
                              <i className="bi bi-clock-history me-2"></i>Long-term Actions
                            </div>
                            <div className="card-body">
                              <ul className="list-group list-group-flush">
                                {submissionResult.recommendations.long_term.map((rec, index) => (
                                  <li key={index} className="list-group-item d-flex align-items-start">
                                    <i className="bi bi-calendar-check text-primary me-2 mt-1"></i>
                                    <span>{rec}</span>
                                  </li>
                                ))}
                              </ul>
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}
                
                {/* Response Details */}
                <div className="mt-4 pt-3 border-top">
                  <h5>
                    <a 
                      className="text-decoration-none" 
                      data-bs-toggle="collapse" 
                      href="#responseDetails" 
                      role="button" 
                      aria-expanded="false" 
                      aria-controls="responseDetails"
                    >
                      <i className="bi bi-code-slash me-2"></i>
                      Technical Details <i className="bi bi-chevron-down ms-1 small"></i>
                    </a>
                  </h5>
                  <div className="collapse" id="responseDetails">
                    <div className="card card-body bg-light">
                      <pre className="mb-0" style={{fontSize: '0.85rem'}}>
                        {JSON.stringify(submissionResult, null, 2)}
                      </pre>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
      
      <div className="row">
        <div className="col">
          <div className="card">
            <div className="card-header d-flex justify-content-between align-items-center">
              <h3><i className="bi bi-shield-exclamation me-2"></i>Security Alerts</h3>
              <div className="btn-group">
                <button onClick={fetchAlerts} className="btn btn-outline-primary">
                  <i className="bi bi-arrow-clockwise me-1"></i>Refresh
                </button>
                <button onClick={deleteAllAlerts} className="btn btn-outline-danger">
                  <i className="bi bi-trash me-1"></i>Delete All
                </button>
              </div>
            </div>
            
            <div className="card-body">
              <div className="mb-3 d-flex justify-content-between align-items-center flex-wrap">
                <div className="btn-group mb-2" role="group">
                  <button 
                    type="button" 
                    className="btn btn-outline-secondary" 
                    onClick={() => fetchAlerts()}
                  >
                    All
                  </button>
                  <button 
                    type="button" 
                    className="btn btn-outline-success" 
                    onClick={() => fetchAlertsBySeverity('Low')}
                  >
                    <i className="bi bi-circle-fill text-success me-1" style={{fontSize: '0.6rem'}}></i>
                    Low
                  </button>
                  <button 
                    type="button" 
                    className="btn btn-outline-info" 
                    onClick={() => fetchAlertsBySeverity('Medium')}
                  >
                    <i className="bi bi-circle-fill text-info me-1" style={{fontSize: '0.6rem'}}></i>
                    Medium
                  </button>
                  <button 
                    type="button" 
                    className="btn btn-outline-warning" 
                    onClick={() => fetchAlertsBySeverity('High')}
                  >
                    <i className="bi bi-circle-fill text-warning me-1" style={{fontSize: '0.6rem'}}></i>
                    High
                  </button>
                  <button 
                    type="button" 
                    className="btn btn-outline-danger" 
                    onClick={() => fetchAlertsBySeverity('Critical')}
                  >
                    <i className="bi bi-circle-fill text-danger me-1" style={{fontSize: '0.6rem'}}></i>
                    Critical
                  </button>
                </div>
              </div>
              
              {loading ? (
                <div className="text-center p-5">
                  <div className="spinner-border text-primary" role="status">
                    <span className="visually-hidden">Loading...</span>
                  </div>
                  <p className="mt-3">Loading alerts...</p>
                </div>
              ) : alerts.length === 0 ? (
                <div className="text-center p-5">
                  <i className="bi bi-inbox text-muted" style={{fontSize: '3rem'}}></i>
                  <p className="mt-3">No alerts found</p>
                </div>
              ) : (
                <div className="table-responsive">
                  <table className="table table-hover">
                    <thead>
                      <tr>
                        <th>Time</th>
                        <th>Message</th>
                        <th>Severity</th>
                        <th>Jira Ticket</th>
                        <th>Slack</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {alerts.map(alert => (
                        <tr key={alert.id} className={alert.id === submissionResult?.alert_id ? 'highlight-new' : ''}>
                          <td>{new Date(alert.timestamp).toLocaleString()}</td>
                          <td>{alert.message.length > 50 ? `${alert.message.substring(0, 50)}...` : alert.message}</td>
                          <td>
                            <span className={`badge severity-${alert.severity}`}>
                              {alert.severity === 'Critical' && <i className="bi bi-exclamation-triangle-fill me-1"></i>}
                              {alert.severity === 'High' && <i className="bi bi-exclamation-circle-fill me-1"></i>}
                              {alert.severity === 'Medium' && <i className="bi bi-exclamation me-1"></i>}
                              {alert.severity === 'Low' && <i className="bi bi-info-circle-fill me-1"></i>}
                              {alert.severity}
                            </span>
                          </td>
                          <td>
                            {alert.jira_ticket_id ? (
                              <a 
                                href={`https://subhashsrinivas36.atlassian.net/browse/${alert.jira_ticket_id}`}
                                target="_blank" 
                                rel="noopener noreferrer"
                                className="text-decoration-none"
                              >
                                <span className="badge bg-primary">
                                  <i className="bi bi-link-45deg me-1"></i>{alert.jira_ticket_id}
                                </span>
                              </a>
                            ) : (
                              <span className="badge bg-secondary">None</span>
                            )}
                          </td>
                          <td>
                            {alert.slack_notification_sent ? (
                              <span className="badge bg-success">
                                <i className="bi bi-check-circle me-1"></i>Sent
                              </span>
                            ) : (
                              <span className="badge bg-secondary">Not sent</span>
                            )}
                          </td>
                          <td>
                            <button 
                              className="btn btn-sm btn-outline-primary"
                              onClick={() => {
                                // Fix the property name mismatch between API response and display
                                setSubmissionResult({
                                  severity: alert.severity,
                                  recommendations: alert.recommendations,
                                  message: alert.message,
                                  // Change from alert.jira_ticket_id to jira_ticket to match what your display expects
                                  jira_ticket: alert.jira_ticket_id, 
                                  // Ensure this is a boolean as your display component expects
                                  slack_notification_sent: Boolean(alert.slack_notification_sent),
                                  alert_id: alert.id,
                                  timestamp: alert.timestamp,
                                  // Include impact and reasoning if available
                                  impact: alert.additional_data?.impact,
                                  reasoning: alert.additional_data?.reasoning,
                                  // Default to 'model' if no classification method is stored
                                  classification_method: alert.additional_data?.impact ? 'gemini' : 'model'
                                });
                                setShowResult(true);
                              }}
                            >
                              <i className="bi bi-eye me-1"></i>View Details
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default App
