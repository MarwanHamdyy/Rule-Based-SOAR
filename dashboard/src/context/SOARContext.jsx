import React, { createContext, useReducer, useEffect } from 'react';
import { useWebSocket } from '../hooks/useWebSocket';
import { useSOARApi } from '../hooks/useSOARApi';

export const SOARContext = createContext();

const initialState = {
  incidents: [],
  actions: [],
  assets: [],
  timeline: [],
  kpis: {
    totalAlerts: 0,
    mitigated: 0,
    mttr: "0m 0s",
    activeThreats: 0,
  },
  wsStatus: 'disconnected'
};

function reducer(state, action) {
  switch (action.type) {
    case 'INIT_DATA':
      return {
        ...state,
        incidents: action.payload.incidents || state.incidents,
        actions: action.payload.actions || state.actions,
        assets: action.payload.assets || state.assets,
        timeline: action.payload.timeline || state.timeline,
        kpis: action.payload.kpis || state.kpis,
      };
    case 'NEW_INCIDENT':
      return {
        ...state,
        incidents: [action.payload, ...state.incidents].slice(0, 100), // Keep last 100
      };
    case 'NEW_ACTION':
      return {
        ...state,
        actions: [action.payload, ...state.actions].slice(0, 100),
      };
    case 'UPDATE_KPIS':
      return {
        ...state,
        kpis: { ...state.kpis, ...action.payload }
      };
    case 'SET_WS_STATUS':
      return { ...state, wsStatus: action.payload };
    default:
      return state;
  }
}

export function SOARProvider({ children }) {
  const [state, dispatch] = useReducer(reducer, initialState);
  
  // Fetch initial data
  const { data: kpiData } = useSOARApi('/kpis');
  const { data: incidentData } = useSOARApi('/incidents');
  const { data: actionData } = useSOARApi('/actions');
  const { data: assetData } = useSOARApi('/assets');
  const { data: timelineData } = useSOARApi('/timeline');

  // Load initial data
  useEffect(() => {
    if (kpiData && incidentData && actionData && assetData && timelineData) {
      dispatch({
        type: 'INIT_DATA',
        payload: {
          kpis: kpiData,
          incidents: incidentData.incidents,
          actions: actionData.actions,
          assets: assetData.assets,
          timeline: timelineData.timeline
        }
      });
    }
  }, [kpiData, incidentData, actionData, assetData, timelineData]);

  // Connect WebSocket
  const { status, lastMessage } = useWebSocket('ws://localhost:8080/ws/telemetry');

  // Handle WS status
  useEffect(() => {
    dispatch({ type: 'SET_WS_STATUS', payload: status });
  }, [status]);

  // Handle incoming WS messages
  useEffect(() => {
    if (!lastMessage) return;

    if (lastMessage.type === 'new_incident') {
      dispatch({ type: 'NEW_INCIDENT', payload: lastMessage.data });
    } else if (lastMessage.type === 'action_result') {
      dispatch({ type: 'NEW_ACTION', payload: lastMessage.data });
    } else if (lastMessage.type === 'kpi_update') {
      dispatch({ type: 'UPDATE_KPIS', payload: lastMessage.data });
    }
  }, [lastMessage]);

  return (
    <SOARContext.Provider value={{ state, dispatch }}>
      {children}
    </SOARContext.Provider>
  );
}
