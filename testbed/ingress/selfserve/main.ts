import express from "express";
import cors from "cors";
import helmet from "helmet";
import compression from "compression";
import { createLogger, format, transports } from "winston";
import { register, collectDefaultMetrics } from "prom-client";
import rateLimit from "express-rate-limit";
import { ValidationMiddleware } from "./middleware/validation";

// Initialize logger
const logger = createLogger({
  format: format.combine(format.timestamp(), format.errors({ stack: true }), format.json()),
  transports: [
    new transports.Console({
      format: format.combine(format.colorize(), format.simple()),
    }),
  ],
});

// Initialize Prometheus metrics
collectDefaultMetrics();
register.setDefaultLabels({ app: "pf-testbed-ingress" });

// Initialize Express app
const app = express();
const port = process.env.INGRESS_PORT || 3001;

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: "Too many requests from this IP, please try again later.",
});

// Initialize validation middleware
const signatureSecret = process.env.PF_SIGNATURE_SECRET;
if (!signatureSecret && process.env.NODE_ENV !== "test") {
  throw new Error("PF_SIGNATURE_SECRET must be set for non-test environments");
}
const validationMiddleware = new ValidationMiddleware(signatureSecret || "test-signature-secret");

// Middleware
app.use(helmet());
app.use(cors());
app.use(compression());
app.use(express.json());
app.use(limiter);

// Apply validation middleware to all routes
app.use(validationMiddleware.validateRequest);

// Health check endpoint
app.get("/health", (req, res) => {
  res.json({
    status: "healthy",
    timestamp: new Date().toISOString(),
    service: "pf-testbed-ingress",
  });
});

// Metrics endpoint
app.get("/metrics", async (req, res) => {
  try {
    res.set("Content-Type", register.contentType);
    res.end(await register.metrics());
  } catch (err) {
    res.status(500).end(err);
  }
});

// Test endpoint for validation
app.post("/api/test", (req, res) => {
  res.json({
    message: "Request validated successfully",
    timestamp: new Date().toISOString(),
    headers: req.headers,
  });
});

// Proxy endpoint to gateway
app.all("/api/*", (req, res) => {
  // This would proxy to the gateway service
  // For now, just return a placeholder response
  res.json({
    message: "Request would be proxied to gateway",
    method: req.method,
    path: req.path,
    timestamp: new Date().toISOString(),
  });
});

// Error handling middleware
app.use((err: any, req: express.Request, res: express.Response, _next: express.NextFunction) => {
  logger.error("Unhandled error", { error: err });
  res.status(500).json({ error: "Internal server error" });
});

// Start server
app.listen(port, () => {
  logger.info(`PF Testbed Ingress service started on port ${port}`);
  logger.info(`Health check: http://localhost:${port}/health`);
  logger.info(`Metrics: http://localhost:${port}/metrics`);
});
