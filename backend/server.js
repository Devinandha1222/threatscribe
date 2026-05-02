/**
 * ThreatScribe AI Backend Server
 * Express API for CVE triage with IBM Bob QA engine
 */

import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

// Import routes
import ingestRouter from './routes/ingest.js';
import triageRouter from './routes/triage.js';
import qaRouter from './routes/qa.js';
import actionsRouter from './routes/actions.js';
import reportRouter from './routes/report.js';

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors({
  origin: ['http://localhost:5173', 'http://localhost:5174'], // Vite frontend
  credentials: true
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request logging middleware
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${req.method} ${req.path}`);
  next();
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'ThreatScribe AI Backend',
    version: '1.0.0',
    demo_mode: process.env.DEMO_MODE === 'true',
    timestamp: new Date().toISOString()
  });
});

// API routes
app.use('/api/ingest', ingestRouter);
app.use('/api/triage', triageRouter);
app.use('/api/qa', qaRouter);
app.use('/api/actions', actionsRouter);
app.use('/api/report', reportRouter);

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Not Found',
    message: `Route ${req.method} ${req.path} not found`,
    available_routes: [
      'POST /api/ingest',
      'POST /api/triage',
      'POST /api/qa',
      'POST /api/actions',
      'POST /api/report',
      'GET /health'
    ]
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Error:', err);

  const statusCode = err.statusCode || 500;
  const response = {
    error: err.name || 'InternalServerError',
    message: err.message || 'An unexpected error occurred',
    qa_required: true,
    timestamp: new Date().toISOString()
  };

  // Include stack trace in development
  if (process.env.NODE_ENV === 'development') {
    response.stack = err.stack;
  }

  res.status(statusCode).json(response);
});

// Start server
app.listen(PORT, () => {
  console.log('╔════════════════════════════════════════════════════════════╗');
  console.log('║                                                            ║');
  console.log('║              🛡️  ThreatScribe AI Backend 🛡️                ║');
  console.log('║                                                            ║');
  console.log('║  Intelligent CVE Triage + IBM Bob QA Engine               ║');
  console.log('║  Powered by IBM watsonx.ai                                 ║');
  console.log('║                                                            ║');
  console.log('╚════════════════════════════════════════════════════════════╝');
  console.log('');
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`📊 Demo Mode: ${process.env.DEMO_MODE === 'true' ? 'ENABLED' : 'DISABLED'}`);
  console.log(`🤖 IBM Bob Strict Mode: ${process.env.IBM_BOB_STRICT_MODE === 'true' ? 'ENABLED' : 'DISABLED'}`);
  console.log('');
  console.log('Available endpoints:');
  console.log('  POST /api/ingest   - Ingest raw CVE text');
  console.log('  GET  /api/triage   - Get all CVE records');
  console.log('  POST /api/triage   - Run watsonx.ai triage');
  console.log('  POST /api/qa       - Run IBM Bob QA checks');
  console.log('  POST /api/actions  - Execute action chain');
  console.log('  POST /api/report   - Generate deliverables');
  console.log('  GET  /health       - Health check');
  console.log('');
  console.log('Ready to detect threats! 🔍');
  console.log('');
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('\nSIGINT received, shutting down gracefully...');
  process.exit(0);
});

export default app;

// Made with Bob
