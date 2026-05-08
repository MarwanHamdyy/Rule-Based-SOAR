import React, { useContext } from 'react';
import { SOARContext } from '../context/SOARContext';
import { AlertTriangle, ShieldCheck, Activity, Zap } from 'lucide-react';

function KPICard({ title, value, icon: Icon, color, trend }) {
  return (
    <div className="glass" style={{ padding: '24px', position: 'relative', overflow: 'hidden' }}>
      {/* Decorative background glow */}
      <div 
        style={{ 
          position: 'absolute', top: '-20px', right: '-20px', 
          width: '100px', height: '100px', borderRadius: '50%',
          background: color, filter: 'blur(50px)', opacity: 0.1 
        }} 
      />
      
      <div className="flex-between" style={{ marginBottom: '16px' }}>
        <h3 className="text-muted" style={{ fontSize: '0.875rem', fontWeight: 500, margin: 0 }}>{title}</h3>
        <div style={{ padding: '8px', borderRadius: '8px', background: `${color}15`, color }}>
          <Icon size={20} />
        </div>
      </div>
      
      <div className="flex-between" style={{ alignItems: 'flex-end' }}>
        <div style={{ fontSize: '2.5rem', fontWeight: 700, lineHeight: 1 }}>{value}</div>
        {trend && (
          <div style={{ color: trend > 0 ? 'var(--critical)' : 'var(--success)', fontSize: '0.875rem', fontWeight: 500 }}>
            {trend > 0 ? '+' : ''}{trend}% (24h)
          </div>
        )}
      </div>
    </div>
  );
}

export default function KPIOverview() {
  const { state } = useContext(SOARContext);
  const { kpis } = state;

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '20px' }}>
      <KPICard 
        title="Total Alerts Processed" 
        value={kpis.totalAlerts} 
        icon={Activity} 
        color="var(--primary)" 
        trend={12}
      />
      <KPICard 
        title="Active Threats" 
        value={kpis.activeThreats} 
        icon={AlertTriangle} 
        color={kpis.activeThreats > 0 ? "var(--critical)" : "var(--success)"} 
        trend={-5}
      />
      <KPICard 
        title="Automated Mitigations" 
        value={kpis.mitigated} 
        icon={ShieldCheck} 
        color="var(--success)" 
      />
      <KPICard 
        title="Mean Time To Respond" 
        value={kpis.mttr} 
        icon={Zap} 
        color="var(--medium)" 
      />
    </div>
  );
}
