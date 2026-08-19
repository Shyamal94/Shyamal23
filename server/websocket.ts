import { WebSocketServer, WebSocket } from 'ws';
import { Server } from 'http';

let wss: WebSocketServer | null = null;
const clients = new Set<WebSocket>();

export function initWebSocketServer(server: Server) {
  wss = new WebSocketServer({ server, path: '/ws' });

  wss.on('connection', (ws: WebSocket, req) => {
    clients.add(ws);

    // Send initial welcome & connection confirmation
    try {
      ws.send(
        JSON.stringify({
          type: 'WS_CONNECTED',
          payload: {
            message: 'Connected to SentinelX Real-Time SecOps Telemetry Stream',
            timestamp: new Date().toISOString(),
            clientCount: clients.size,
          },
        })
      );
    } catch {
      // ignore
    }

    ws.on('message', (data) => {
      try {
        const msg = JSON.parse(data.toString());
        if (msg.type === 'PING') {
          ws.send(JSON.stringify({ type: 'PONG', timestamp: Date.now() }));
        }
      } catch {
        // ignore
      }
    });

    ws.on('close', () => {
      clients.delete(ws);
    });

    ws.on('error', () => {
      clients.delete(ws);
    });
  });

  console.log('SentinelX WebSocket server initialized on path /ws');
  return wss;
}

export function broadcast(type: string, payload: any) {
  if (!wss || clients.size === 0) return;

  const data = JSON.stringify({
    type,
    payload,
    timestamp: new Date().toISOString(),
  });

  for (const client of clients) {
    if (client.readyState === WebSocket.OPEN) {
      try {
        client.send(data);
      } catch (err) {
        console.error('Failed to send WS message to client:', err);
      }
    }
  }
}
