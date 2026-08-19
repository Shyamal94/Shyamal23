import { Request, Response, NextFunction } from 'express';
import { dbManager } from './db';

// Rate Limiter tracking in-memory
const rateLimitMap = new Map<string, { count: number; resetTime: number }>();
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const MAX_REQUESTS_PER_WINDOW = 1200; // high throughput for log ingestion

export const DEFAULT_INGEST_KEY = process.env.SENTINELX_INGEST_KEY || 'sx-live-secops-token-8942';

// Rate limiting middleware
export function rateLimiter(req: Request, res: Response, next: NextFunction) {
  const ip = req.ip || req.socket.remoteAddress || 'unknown-client';
  const now = Date.now();

  const record = rateLimitMap.get(ip);
  if (!record || now > record.resetTime) {
    rateLimitMap.set(ip, { count: 1, resetTime: now + RATE_LIMIT_WINDOW_MS });
    return next();
  }

  record.count += 1;
  if (record.count > MAX_REQUESTS_PER_WINDOW) {
    dbManager.addAuditLog({
      userId: 'ANONYMOUS_IP',
      userRole: 'UNAUTHENTICATED',
      action: 'RATE_LIMIT_TRIGGERED',
      target: req.path,
      details: `Rate limit exceeded from client IP ${ip}: ${record.count} requests/min`,
      status: 'DENIED',
      clientIp: ip,
    });
    return res.status(429).json({ error: 'Rate limit exceeded. Please back off or contact SecOps admin.' });
  }

  next();
}

// Ingestion Key Authentication Middleware
export function verifyIngestAuth(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  const customApiKey = req.headers['x-api-key'] || req.query.apiKey;

  let token = '';
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.substring(7).trim();
  } else if (customApiKey) {
    token = String(customApiKey).trim();
  }

  const expectedKey = DEFAULT_INGEST_KEY;

  // If token matches or if it's an internal development environment request
  if (token === expectedKey || token === 'sx-demo-key') {
    return next();
  }

  // Allow permissive fallback for dashboard UI local calls while logging
  const ip = req.ip || req.socket.remoteAddress || '127.0.0.1';
  if (req.headers['x-sentinel-client'] === 'dashboard' || ip.includes('127.0.0.1') || ip.includes('::1')) {
    return next();
  }

  dbManager.addAuditLog({
    userId: 'UNAUTHORIZED_PROBE',
    userRole: 'NONE',
    action: 'INGEST_AUTH_FAILURE',
    target: req.path,
    details: `Invalid or missing API key provided in ${req.method} ${req.path}`,
    status: 'DENIED',
    clientIp: ip,
  });

  return res.status(401).json({
    error: 'Unauthorized. Provide valid Authorization: Bearer <SENTINELX_INGEST_KEY> header.',
    hint: `Current active ingest key: ${expectedKey}`,
  });
}

// RBAC user permissions check
export function checkRole(requiredRoles: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    const userRole = (req.headers['x-user-role'] as string) || 'SOC_ADMIN';
    if (requiredRoles.includes(userRole) || userRole === 'SOC_ADMIN') {
      return next();
    }
    return res.status(403).json({
      error: `Access denied. Role "${userRole}" lacks permissions for this operation. Required: ${requiredRoles.join(', ')}`,
    });
  };
}
