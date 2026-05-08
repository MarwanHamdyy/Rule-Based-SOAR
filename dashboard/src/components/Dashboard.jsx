import React, { useContext } from 'react';
import { SOARContext } from '../context/SOARContext';
import { Activity, ShieldAlert, CheckCircle, Clock } from 'lucide-react';
import './Dashboard.css';

// We'll mock the import of these components until we write them
import KPIOverview from './KPIOverview';
import LiveIncidentFeed from './LiveIncidentFeed';
import ActionAuditLog from './ActionAuditLog';
import AssetHealthMap from './AssetHealthMap';
import ThreatTimeline from './ThreatTimeline';

function Navbar() {
  const { state } = useContext(SOARContext);
  
  return (
    <header className="navbar glass flex-between" style={{ padding: '15px 24px', marginBottom: '24px' }}>
      <div className="flex-center" style={{ gap: '12px' }}>
        <ShieldAlert size={28} color="var(--primary)" />
        <h1 style={{ fontSize: '1.5rem', margin: 0 }}>Ruled-SOAR</h1>
      </div>
      <div className="flex-center" style={{ gap: '8px' }}>
        <div 
          style={{ 
            width: '10px', height: '10px', borderRadius: '50%', 
            background: state.wsStatus === 'connected' ? 'var(--success)' : 'var(--critical)' 
          }} 
        />
        <span className="text-muted" style={{ fontSize: '0.875rem' }}>
          {state.wsStatus === 'connected' ? 'Live Telemetry Active' : 'Disconnected'}
        </span>
      </div>
    </header>
  );
}

export default function Dashboard() {
  return (
    <div className="dashboard">
      <Navbar />
      
      <div className="dashboard-grid">
        <div className="grid-kpi">
          <KPIOverview />
        </div>
        
        <div className="grid-timeline glass">
          <ThreatTimeline />
        </div>
        
        <div className="grid-feed glass">
          <LiveIncidentFeed />
        </div>
        
        <div className="grid-assets glass">
          <AssetHealthMap />
        </div>
        
        <div className="grid-audit glass">
          <ActionAuditLog />
        </div>
      </div>
    </div>
  );
}
