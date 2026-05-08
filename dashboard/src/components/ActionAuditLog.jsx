import React, { useContext } from 'react';
import { SOARContext } from '../context/SOARContext';
import { Terminal, CheckCircle2, XCircle, Clock } from 'lucide-react';

const StatusIcon = ({ status }) => {
  if (status === 'success') return <CheckCircle2 size={16} className="text-success" />;
  if (status === 'failure') return <XCircle size={16} className="text-critical" />;
  if (status === 'timeout') return <Clock size={16} className="text-medium" />;
  return <div style={{ width: 16, height: 16, borderRadius: '50%', background: 'gray' }} />;
};

export default function ActionAuditLog() {
  const { state } = useContext(SOARContext);
  const { actions } = state;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div className="panel-title">
        <Terminal size={20} className="text-primary" />
        <h2>Action Audit Log</h2>
      </div>
      
      <div style={{ flex: 1, overflowY: 'auto' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {actions.map((act, i) => (
            <div 
              key={`${act.action_id}-${i}`}
              className={i === 0 ? 'animate-slide-down' : ''}
              style={{ 
                display: 'flex', alignItems: 'center', gap: '16px',
                padding: '12px 16px', background: 'rgba(255,255,255,0.02)',
                borderRadius: '8px', borderLeft: `3px solid ${act.status === 'success' ? 'var(--success)' : 'var(--critical)'}`
              }}
            >
              <StatusIcon status={act.status} />
              
              <div style={{ width: '80px', fontFamily: 'var(--font-mono)', fontSize: '0.875rem', color: 'var(--text-muted)' }}>
                {new Date(act.timestamp).toLocaleTimeString()}
              </div>
              
              <div style={{ width: '100px', fontWeight: 600, color: 'var(--primary)' }}>
                {act.action_id}
              </div>
              
              <div style={{ flex: 1, fontWeight: 500 }}>
                {act.action_name}
              </div>
              
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.875rem', color: 'var(--text-muted)' }}>
                Target: {act.target}
              </div>
              
              <div style={{ width: '80px', textAlign: 'right', fontSize: '0.875rem', color: 'var(--text-muted)' }}>
                {act.duration_ms}ms
              </div>
            </div>
          ))}
          {actions.length === 0 && (
            <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-muted)' }}>
              No automated actions recorded yet.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
