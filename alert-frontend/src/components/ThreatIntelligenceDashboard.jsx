import React, { useState, useEffect, useRef } from 'react';
import 'bootstrap/dist/css/bootstrap.min.css';
import CyberEducation from './CyberEducation';

const ThreatIntelligenceDashboard = () => {
    const [threats, setThreats] = useState([]);
    const [geoThreats, setGeoThreats] = useState([]);
    const [stats, setStats] = useState({});
    const [simulationStatus, setSimulationStatus] = useState('stopped');
    const [loading, setLoading] = useState(false);
    const [autoRefresh, setAutoRefresh] = useState(true);
    const [activeTab, setActiveTab] = useState('dashboard');
    const intervalRef = useRef(null);

    // Fetch threat intelligence data
    const fetchThreatData = async () => {
        try {
            const response = await fetch('http://localhost:5000/api/threat-intelligence');
            const data = await response.json();
            
            if (data.status === 'success') {
                setThreats(data.data);
                setSimulationStatus(data.simulation_status);
            }
        } catch (error) {
            console.error('Error fetching threat data:', error);
        }
    };

    // Fetch geographic threats
    const fetchGeoThreats = async () => {
        try {
            const response = await fetch('http://localhost:5000/api/geographic-threats');
            const data = await response.json();
            
            if (data.status === 'success') {
                setGeoThreats(data.data);
            }
        } catch (error) {
            console.error('Error fetching geo threats:', error);
        }
    };

    // Fetch threat statistics
    const fetchThreatStats = async () => {
        try {
            const response = await fetch('http://localhost:5000/api/threat-stats');
            const data = await response.json();
            
            if (data.status === 'success') {
                setStats(data.data);
            }
        } catch (error) {
            console.error('Error fetching threat stats:', error);
        }
    };

    // Control simulation
    const controlSimulation = async (action) => {
        setLoading(true);
        try {
            const response = await fetch('http://localhost:5000/api/attack-simulation', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ action })
            });
            
            const data = await response.json();
            if (data.status === 'success') {
                setSimulationStatus(data.simulation_status);
                if (action === 'start') {
                    startAutoRefresh();
                } else {
                    stopAutoRefresh();
                }
            }
        } catch (error) {
            console.error('Error controlling simulation:', error);
        } finally {
            setLoading(false);
        }
    };

    // Auto refresh functions
    const startAutoRefresh = () => {
        if (intervalRef.current) clearInterval(intervalRef.current);
        intervalRef.current = setInterval(() => {
            fetchThreatData();
            fetchGeoThreats();
            fetchThreatStats();
        }, 3000); // Refresh every 3 seconds
    };

    const stopAutoRefresh = () => {
        if (intervalRef.current) {
            clearInterval(intervalRef.current);
            intervalRef.current = null;
        }
    };

    // Get severity badge color
    const getSeverityColor = (severity) => {
        switch (severity) {
            case 'Critical': return 'danger';
            case 'High': return 'warning';
            case 'Medium': return 'info';
            case 'Low': return 'success';
            default: return 'secondary';
        }
    };

    // Component lifecycle
    useEffect(() => {
        fetchThreatData();
        fetchGeoThreats();
        fetchThreatStats();

        return () => {
            stopAutoRefresh();
        };
    }, []);

    useEffect(() => {
        if (autoRefresh && simulationStatus === 'running') {
            startAutoRefresh();
        } else {
            stopAutoRefresh();
        }
    }, [autoRefresh, simulationStatus]);

    return (
        <div className="container-fluid mt-4">
            <div className="row">
                <div className="col-12">
                    <div className="d-flex justify-content-between align-items-center mb-4">
                        <h1 className="h3 mb-0">
                            <i className="fas fa-shield-alt text-primary me-2"></i>
                            AI-Powered Threat Intelligence Dashboard
                        </h1>
                        <div className="d-flex gap-2">
                            <button
                                className={`btn btn-${simulationStatus === 'running' ? 'danger' : 'success'}`}
                                onClick={() => controlSimulation(simulationStatus === 'running' ? 'stop' : 'start')}
                                disabled={loading}
                            >
                                {loading ? (
                                    <span className="spinner-border spinner-border-sm me-2"></span>
                                ) : (
                                    <i className={`fas fa-${simulationStatus === 'running' ? 'stop' : 'play'} me-2`}></i>
                                )}
                                {simulationStatus === 'running' ? 'Stop Simulation' : 'Start Simulation'}
                            </button>
                            <div className="form-check form-switch d-flex align-items-center">
                                <input
                                    className="form-check-input me-2"
                                    type="checkbox"
                                    checked={autoRefresh}
                                    onChange={(e) => setAutoRefresh(e.target.checked)}
                                />
                                <label className="form-check-label">Auto Refresh</label>
                            </div>
                        </div>
                    </div>
                    
                    {/* Navigation Tabs */}
                    <ul className="nav nav-tabs mb-4">
                        <li className="nav-item">
                            <button 
                                className={`nav-link ${activeTab === 'dashboard' ? 'active' : ''}`}
                                onClick={() => setActiveTab('dashboard')}
                            >
                                <i className="fas fa-chart-line me-2"></i>Live Dashboard
                            </button>
                        </li>
                        <li className="nav-item">
                            <button 
                                className={`nav-link ${activeTab === 'education' ? 'active' : ''}`}
                                onClick={() => setActiveTab('education')}
                            >
                                <i className="fas fa-graduation-cap me-2"></i>Cyber Education
                            </button>
                        </li>
                    </ul>
                </div>
            </div>

            {/* Tab Content */}
            {activeTab === 'dashboard' && (
                <>
                    {/* Status Cards */}
                    <div className="row mb-4">
                        <div className="col-md-3">
                            <div className="card bg-primary text-white">
                                <div className="card-body">
                                    <div className="d-flex justify-content-between">
                                        <div>
                                            <h4 className="card-title">{stats.total_threats || 0}</h4>
                                            <p className="card-text">Total Threats</p>
                                        </div>
                                        <i className="fas fa-exclamation-triangle fa-2x"></i>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div className="col-md-3">
                            <div className="card bg-danger text-white">
                                <div className="card-body">
                                    <div className="d-flex justify-content-between">
                                        <div>
                                            <h4 className="card-title">{stats.severity_breakdown?.Critical || 0}</h4>
                                            <p className="card-text">Critical Threats</p>
                                        </div>
                                        <i className="fas fa-fire fa-2x"></i>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div className="col-md-3">
                            <div className="card bg-warning text-white">
                                <div className="card-body">
                                    <div className="d-flex justify-content-between">
                                        <div>
                                            <h4 className="card-title">{geoThreats.length}</h4>
                                            <p className="card-text">Active Locations</p>
                                        </div>
                                        <i className="fas fa-globe fa-2x"></i>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div className="col-md-3">
                            <div className={`card ${simulationStatus === 'running' ? 'bg-success' : 'bg-secondary'} text-white`}>
                                <div className="card-body">
                                    <div className="d-flex justify-content-between">
                                        <div>
                                            <h4 className="card-title">
                                                {simulationStatus === 'running' ? 'LIVE' : 'STOPPED'}
                                            </h4>
                                            <p className="card-text">Simulation Status</p>
                                        </div>
                                        <i className={`fas fa-${simulationStatus === 'running' ? 'broadcast-tower' : 'pause'} fa-2x`}></i>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div className="row">
                {/* Real-time Threat Feed */}
                <div className="col-lg-8">
                    <div className="card">
                        <div className="card-header d-flex justify-content-between align-items-center">
                            <h5 className="mb-0">
                                <i className="fas fa-stream me-2"></i>
                                Live Threat Intelligence Feed
                            </h5>
                            {simulationStatus === 'running' && (
                                <span className="badge bg-success">
                                    <i className="fas fa-circle me-1 blink"></i>
                                    LIVE
                                </span>
                            )}
                        </div>
                        <div className="card-body p-0">
                            <div style={{ maxHeight: '500px', overflowY: 'auto' }}>
                                {threats.length === 0 ? (
                                    <div className="text-center p-4">
                                        <i className="fas fa-info-circle text-muted fa-2x mb-2"></i>
                                        <p className="text-muted">No threat data available. Start simulation to see live threats.</p>
                                    </div>
                                ) : (
                                    <div className="list-group list-group-flush">
                                        {threats.map((threat, index) => (
                                            <div key={threat.id} className="list-group-item">
                                                <div className="d-flex justify-content-between align-items-start">
                                                    <div className="flex-grow-1">
                                                        <div className="d-flex align-items-center mb-1">
                                                            <span className={`badge bg-${getSeverityColor(threat.severity)} me-2`}>
                                                                {threat.severity}
                                                            </span>
                                                            <strong className="text-dark">{threat.threat_type}</strong>
                                                            <small className="text-muted ms-2">
                                                                {new Date(threat.timestamp).toLocaleTimeString()}
                                                            </small>
                                                        </div>
                                                        <p className="mb-1 text-muted small">{threat.description}</p>
                                                        <div className="row">
                                                            <div className="col-md-6">
                                                                <small className="text-muted">
                                                                    <i className="fas fa-map-marker-alt me-1"></i>
                                                                    Source: {threat.country}
                                                                </small>
                                                            </div>
                                                            <div className="col-md-6">
                                                                <small className="text-muted">
                                                                    <i className="fas fa-network-wired me-1"></i>
                                                                    {threat.source_ip} → {threat.target_ip}
                                                                </small>
                                                            </div>
                                                        </div>
                                                    </div>
                                                    <div className="text-end">
                                                        <div className="progress" style={{ width: '60px', height: '8px' }}>
                                                            <div 
                                                                className="progress-bar bg-info" 
                                                                style={{ width: `${threat.confidence}%` }}
                                                            ></div>
                                                        </div>
                                                        <small className="text-muted">{threat.confidence}%</small>
                                                    </div>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>
                        </div>
                    </div>
                </div>

                {/* Statistics Panel */}
                <div className="col-lg-4">
                    <div className="card mb-3">
                        <div className="card-header">
                            <h5 className="mb-0">
                                <i className="fas fa-chart-pie me-2"></i>
                                Threat Analytics
                            </h5>
                        </div>
                        <div className="card-body">
                            {/* Severity Breakdown */}
                            {stats.severity_breakdown && (
                                <div className="mb-3">
                                    <h6>Severity Distribution</h6>
                                    {Object.entries(stats.severity_breakdown).map(([severity, count]) => (
                                        <div key={severity} className="d-flex justify-content-between align-items-center mb-1">
                                            <span className={`badge bg-${getSeverityColor(severity)}`}>
                                                {severity}
                                            </span>
                                            <span>{count}</span>
                                        </div>
                                    ))}
                                </div>
                            )}

                            {/* Top Countries */}
                            {stats.top_countries && stats.top_countries.length > 0 && (
                                <div className="mb-3">
                                    <h6>Top Threat Sources</h6>
                                    {stats.top_countries.map((item, index) => (
                                        <div key={index} className="d-flex justify-content-between align-items-center mb-1">
                                            <span>
                                                <i className="fas fa-flag me-1"></i>
                                                {item.country}
                                            </span>
                                            <span className="badge bg-primary">{item.count}</span>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </div>
                    </div>

                    {/* Geographic Threats */}
                    <div className="card">
                        <div className="card-header">
                            <h5 className="mb-0">
                                <i className="fas fa-globe-americas me-2"></i>
                                Geographic Threats
                            </h5>
                        </div>
                        <div className="card-body p-0">
                            <div style={{ maxHeight: '300px', overflowY: 'auto' }}>
                                {geoThreats.length === 0 ? (
                                    <div className="text-center p-3">
                                        <i className="fas fa-map text-muted fa-2x mb-2"></i>
                                        <p className="text-muted small">No geographic data available</p>
                                    </div>
                                ) : (
                                    <div className="list-group list-group-flush">
                                        {geoThreats.slice(-10).map((threat, index) => (
                                            <div key={threat.id} className="list-group-item py-2">
                                                <div className="d-flex justify-content-between align-items-center">
                                                    <div>
                                                        <div className="d-flex align-items-center">
                                                            <i className="fas fa-map-pin text-danger me-2"></i>
                                                            <strong className="small">{threat.country}</strong>
                                                        </div>
                                                        <small className="text-muted">{threat.attack_type}</small>
                                                    </div>
                                                    <div className="text-end">
                                                        <span className={`badge bg-${getSeverityColor(threat.severity)} small`}>
                                                            {threat.threat_count} threats
                                                        </span>
                                                    </div>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            </>
            )}

            {/* Education Tab */}
            {activeTab === 'education' && (
                <CyberEducation />
            )}

            <style jsx>{`
                @keyframes blink {
                    0%, 50% { opacity: 1; }
                    51%, 100% { opacity: 0.3; }
                }
                
                .blink {
                    animation: blink 2s infinite;
                }
                
                .card {
                    box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
                    border: 1px solid rgba(0, 0, 0, 0.125);
                }
                
                .list-group-item:hover {
                    background-color: #f8f9fa;
                }
                
                .progress {
                    border-radius: 0.25rem;
                }
            `}</style>
        </div>
    );
};

export default ThreatIntelligenceDashboard;
