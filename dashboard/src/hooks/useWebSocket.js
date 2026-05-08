import { useState, useEffect, useCallback, useRef } from 'react';

export function useWebSocket(url) {
  const [status, setStatus] = useState('connecting');
  const [lastMessage, setLastMessage] = useState(null);
  const ws = useRef(null);
  const reconnectAttempts = useRef(0);
  const maxReconnectDelay = 16000;

  const connect = useCallback(() => {
    try {
      ws.current = new WebSocket(url);

      ws.current.onopen = () => {
        setStatus('connected');
        reconnectAttempts.current = 0;
      };

      ws.current.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          setLastMessage(data);
        } catch (e) {
          console.error("Failed to parse WS message", e);
        }
      };

      ws.current.onclose = () => {
        setStatus('disconnected');
        const delay = Math.min(1000 * Math.pow(2, reconnectAttempts.current), maxReconnectDelay);
        reconnectAttempts.current += 1;
        setTimeout(connect, delay);
      };

      ws.current.onerror = () => {
        ws.current.close();
      };
    } catch (e) {
      console.error("WS connection error", e);
    }
  }, [url]);

  useEffect(() => {
    connect();
    return () => {
      if (ws.current) {
        ws.current.close();
      }
    };
  }, [connect]);

  return { status, lastMessage };
}
