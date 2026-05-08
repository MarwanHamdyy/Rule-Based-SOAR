import React, { useContext } from 'react';
import { SOARContext } from '../context/SOARContext';
import { ListFilter } from 'lucide-react';

const SeverityBadge = ({ severity }) => {
  const colorMap = {
    critical: 'bg-critical',
    high: 'bg-high',
    medium: 'bg-medium',
    low: 'bg-low'
  };
  
  return (
    <span style={{ 
      padding: '4px 8px', borderRadius: '4px', fontSize: '0.75rem', 
      fontWeight: 600, textTransform: 'uppercase' 
    }} className={colorMap[severity] || 'bg-low'}>
      {severity}
    </span>
  );
};

export default function LiveIncidentFeed() {
  const { state } = useContext(SOARContext);
  const { incidents } = state;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div className="flex-between panel-title">
        <div className="flex-center" style={{ gap: '8px' }}>
          <ListFilter size={20} className="text-primary" />
          <h2>Live Incident Feed</h2>
        </div>
        <span className="text-muted" style={{ fontSize: '0.875rem' }}>{incidents.length} events</span>
      </div>
      
      <div style={{ flex: 1, overflowY: 'auto', paddingRight: '4px' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border-light)', color: 'var(--text-muted)' }}>
              <th style={{ padding: '12px', fontWeight: 500 }}>Time</th>
              <th style={{ padding: '12px', fontWeight: 500 }}>Severity</th>
              <th style={{ padding: '12px', fontWeight: 500 }}>Attack Type</th>
              <th style={{ padding: '12px', fontWeight: 500 }}>Target</th>
              <th style={{ padding: '12px', fontWeight: 500 }}>Source</th>
            </tr>
          </thead>
          <tbody>
            {incidents.map((inc, i) => (
              <tr 
                key={inc.id} 
                className={i === 0 ? 'animate-slide-down' : ''}
                style={{ 
                  borderBottom: '1px solid var(--border-light)',
                  background: inc.status === 'active' ? 'rgba(255,255,255,0.02)' : 'transparent',
                  transition: 'background 0.2s'
                }}
              >
                <td style={{ padding: '16px 12px', fontSize: '0.875rem', color: 'var(--text-muted)' }}>
                  {new Date(inc.timestamp).toLocaleTimeString()}
                </td>
                <td style={{ padding: '16px 12px' }}>
                  <SeverityBadge severity={inc.severity} />
                </td>
                <td style={{ padding: '16px 12px', fontWeight: 500 }}>{inc.attack_type}</td>
                <td style={{ padding: '16px 12px', fontFamily: 'var(--font-mono)', fontSize: '0.875rem' }}>
                  {inc.target}
                </td>
                <td style={{ padding: '16px 12px', fontFamily: 'var(--font-mono)', fontSize: '0.875rem', color: 'var(--text-muted)' }}>
                  {inc.source_ip}
                </td>
              </tr>
            ))}
            {incidents.length === 0 && (
              <tr>
                <td colSpan="5" style={{ padding: '32px', textAlign: 'center', color: 'var(--text-muted)' }}>
                  Waiting for telemetry...
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
