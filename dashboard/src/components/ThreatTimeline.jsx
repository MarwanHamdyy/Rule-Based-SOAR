import React, { useContext } from 'react';
import { SOARContext } from '../context/SOARContext';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Area, AreaChart } from 'recharts';
import { BarChart3 } from 'lucide-react';

const CustomTooltip = ({ active, payload, label }) => {
  if (active && payload && payload.length) {
    return (
      <div className="glass-strong" style={{ padding: '12px', fontSize: '0.875rem' }}>
        <p style={{ margin: '0 0 8px 0', fontWeight: 600 }}>{new Date(label).toLocaleTimeString()}</p>
        {payload.map((entry, index) => (
          <div key={index} style={{ color: entry.color, display: 'flex', justifyContent: 'space-between', width: '120px' }}>
            <span style={{ textTransform: 'capitalize' }}>{entry.name}:</span>
            <span style={{ fontWeight: 600 }}>{entry.value}</span>
          </div>
        ))}
      </div>
    );
  }
  return null;
};

export default function ThreatTimeline() {
  const { state } = useContext(SOARContext);
  const { timeline } = state;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div className="panel-title">
        <BarChart3 size={20} className="text-primary" />
        <h2>Threat Timeline (24h)</h2>
      </div>
      
      <div style={{ flex: 1, width: '100%', minHeight: 0 }}>
        {timeline.length > 0 ? (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={timeline} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="colorCritical" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="var(--critical)" stopOpacity={0.3}/>
                  <stop offset="95%" stopColor="var(--critical)" stopOpacity={0}/>
                </linearGradient>
                <linearGradient id="colorHigh" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="var(--high)" stopOpacity={0.3}/>
                  <stop offset="95%" stopColor="var(--high)" stopOpacity={0}/>
                </linearGradient>
                <linearGradient id="colorMedium" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="var(--medium)" stopOpacity={0.3}/>
                  <stop offset="95%" stopColor="var(--medium)" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
              <XAxis 
                dataKey="time" 
                tickFormatter={(time) => new Date(time).getHours() + ':00'} 
                stroke="var(--text-muted)" 
                fontSize={12} 
                tickLine={false}
                axisLine={false}
                dy={10}
              />
              <YAxis 
                stroke="var(--text-muted)" 
                fontSize={12}
                tickLine={false}
                axisLine={false}
              />
              <Tooltip content={<CustomTooltip />} />
              <Area type="monotone" dataKey="critical" stackId="1" stroke="var(--critical)" fill="url(#colorCritical)" strokeWidth={2} />
              <Area type="monotone" dataKey="high" stackId="1" stroke="var(--high)" fill="url(#colorHigh)" strokeWidth={2} />
              <Area type="monotone" dataKey="medium" stackId="1" stroke="var(--medium)" fill="url(#colorMedium)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        ) : (
          <div className="flex-center" style={{ height: '100%', color: 'var(--text-muted)' }}>
            Loading timeline data...
          </div>
        )}
      </div>
    </div>
  );
}
