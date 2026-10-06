/**
 * WebSocket hook with automatic reconnection, heartbeat ping,
 * and batched event handling.
 */

import { useEffect, useRef, useState, useCallback } from 'react';
import { WebSocketEvent } from '../types/api';

export interface UseWebSocketOptions {
  onEvents?: (events: WebSocketEvent[]) => void;
  reconnectInterval?: number;
}

export function useWebSocket(options: UseWebSocketOptions = {}) {
  const [isConnected, setIsConnected] = useState(false);
  const [lastError, setLastError] = useState<string | null>(null);
  const socketRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<any>(null);
  const pingIntervalRef = useRef<any>(null);
  const onEventsRef = useRef(options.onEvents);

  useEffect(() => {
    onEventsRef.current = options.onEvents;
  }, [options.onEvents]);

  const connect = useCallback(() => {
    try {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      // In dev proxy or direct connection
      const wsUrl = `${protocol}//${window.location.hostname}:8000/api/stream`;

      const ws = new WebSocket(wsUrl);
      socketRef.current = ws;

      ws.onopen = () => {
        setIsConnected(true);
        setLastError(null);

        // Periodic ping
        pingIntervalRef.current = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'ping' }));
          }
        }, 15000);
      };

      ws.onmessage = (event) => {
        try {
          const parsed = JSON.parse(event.data);
          if (parsed.type === 'batch' && Array.isArray(parsed.events)) {
            onEventsRef.current?.(parsed.events);
          } else if (parsed.type === 'pong' || parsed.type === 'connection_established') {
            // Heartbeat / init
          } else {
            onEventsRef.current?.([parsed]);
          }
        } catch (e) {
          console.error('Failed to parse WebSocket message:', e);
        }
      };

      ws.onerror = () => {
        setLastError('WebSocket connection error');
      };

      ws.onclose = () => {
        setIsConnected(false);
        if (pingIntervalRef.current) clearInterval(pingIntervalRef.current);
        // Attempt reconnection
        reconnectTimeoutRef.current = setTimeout(() => {
          connect();
        }, options.reconnectInterval || 3000);
      };
    } catch (e: any) {
      setLastError(e.message || 'Connection failed');
    }
  }, [options.reconnectInterval]);

  useEffect(() => {
    connect();

    return () => {
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
      if (pingIntervalRef.current) clearInterval(pingIntervalRef.current);
      if (socketRef.current) {
        socketRef.current.close();
      }
    };
  }, [connect]);

  const send = useCallback((message: any) => {
    if (socketRef.current && socketRef.current.readyState === WebSocket.OPEN) {
      socketRef.current.send(JSON.stringify(message));
    }
  }, []);

  return { isConnected, lastError, send };
}
