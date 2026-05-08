import React, { useContext } from 'react';
import { SOARContext } from '../context/SOARContext';
import { Network, Server, Shield, ShieldAlert } from 'lucide-react';

const AssetCard = ({ asset }) => {
  const isCompromised = asset.status === 'compromised';
  const isIsolated = asset.status === 'isolated';
  
  let borderColor = 'var(--border-light)';
  let bgClass = 'glass';
  let Icon = Server;
  
  if (isCompromised) {
    borderColor = 'var(--critical)';
    bgClass = 'glass-strong animate-pulse-critical';
    Icon = ShieldAlert;
  } else if (isIsolated) {
    borderColor = 'var(--medium)';
    Icon = Shield;
  }

  return (
    <div 
      className={bgClass} 
      style={{ 
        padding: '16px', 
        border: `1px solid ${borderColor}`,
        display: 'flex',
        flexDirection: 'column',
        gap: '12px'
      }}
    >
      <div className="flex-between">
        <div className="flex-center" style={{ gap: '8px' }}>
          <Icon size={18} className={isCompromised ? "text-critical" : isIsolated ? "text-medium" : "text-success"} />
          <span style={{ fontWeight: 600, fontSize: '0.9rem' }}>{asset.id}</span>
        </div>
        <span style={{ 
          fontSize: '0.75rem', padding: '2px 6px', borderRadius: '12px',
          background: isCompromised ? 'var(--critical-bg)' : isIsolated ? 'var(--medium-bg)' : 'var(--success-bg)',
          color: isCompromised ? 'var(--critical)' : isIsolated ? 'var(--medium)' : 'var(--success)',
          textTransform: 'uppercase', fontWeight: 600
        }}>
          {asset.status}
        </span>
      </div>
      
      <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
        {asset.name}
      </div>
      
      <div className="flex-between" style={{ fontSize: '0.8rem', marginTop: 'auto' }}>
        <span style={{ color: 'var(--text-muted)' }}>Net: {asset.network}</span>
        {asset.last_alert && (
          <span className="text-critical" style={{ fontWeight: 500 }}>{asset.last_alert}</span>
        )}
      </div>
    </div>
  );
};

export default function AssetHealthMap() {
  const { state } = useContext(SOARContext);
  const { assets } = state;

  const dockerAssets = assets.filter(a => a.type === 'docker');
  const eveAssets = assets.filter(a => a.type === 'eve-ng');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div className="panel-title">
        <Network size={20} className="text-primary" />
        <h2>Asset Health Topology</h2>
      </div>
      
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '24px', overflowY: 'auto' }}>
        
        <div>
          <h3 style={{ fontSize: '0.875rem', color: 'var(--text-muted)', marginBottom: '12px', textTransform: 'uppercase', letterSpacing: '1px' }}>
            IoT Devices (Docker)
          </h3>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px' }}>
            {dockerAssets.map(asset => (
              <AssetCard key={asset.id} asset={asset} />
            ))}
          </div>
        </div>
        
        {eveAssets.length > 0 && (
          <div>
            <h3 style={{ fontSize: '0.875rem', color: 'var(--text-muted)', marginBottom: '12px', textTransform: 'uppercase', letterSpacing: '1px' }}>
              Network Infrastructure (EVE-NG)
            </h3>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px' }}>
              {eveAssets.map(asset => (
                <AssetCard key={asset.id} asset={asset} />
              ))}
            </div>
          </div>
        )}
        
      </div>
    </div>
  );
}
