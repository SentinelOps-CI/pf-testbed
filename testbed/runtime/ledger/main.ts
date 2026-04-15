import express from "express";
import cors from "cors";
import helmet from "helmet";
import compression from "compression";
import { createLogger, format, transports } from "winston";
import { register, collectDefaultMetrics } from "prom-client";
import { SafetyCaseManager } from "./safety_case";

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
register.setDefaultLabels({ app: "pf-testbed-ledger" });

// Initialize Express app
const app = express();
const port = process.env.LEDGER_PORT || 3002;

// Initialize safety case manager
const safetyCaseManager = new SafetyCaseManager();

// Middleware
app.use(helmet());
app.use(cors());
app.use(compression());
app.use(express.json());

// Health check endpoint
app.get("/health", (req, res) => {
  res.json({
    status: "healthy",
    timestamp: new Date().toISOString(),
    service: "pf-testbed-ledger",
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

// Safety case endpoints
app.post("/api/safety-case", (req, res) => {
  try {
    const { session_id, tenant, journey, plan, receipts, traces, theorems } = req.body;

    if (!session_id || !tenant || !journey || !plan) {
      return res.status(400).json({
        error: "Missing required fields: session_id, tenant, journey, plan",
      });
    }

    const bundle = safetyCaseManager.createBundle(
      session_id,
      tenant,
      journey,
      plan,
      receipts || [],
      traces || [],
      theorems || [],
    );

    logger.info("Safety case bundle created", {
      bundle_id: bundle.id,
      session_id,
      tenant,
    });

    res.status(201).json(bundle);
  } catch (error) {
    logger.error("Error creating safety case bundle", { error });
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/api/safety-case/:id", (req, res) => {
  try {
    const { id } = req.params;
    const bundle = safetyCaseManager.getBundle(id);

    if (!bundle) {
      return res.status(404).json({ error: "Safety case bundle not found" });
    }

    res.json(bundle);
  } catch (error) {
    logger.error("Error retrieving safety case bundle", { error });
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/api/safety-case/tenant/:tenant", (req, res) => {
  try {
    const { tenant } = req.params;
    const bundles = safetyCaseManager.getBundlesByTenant(tenant);
    res.json(bundles);
  } catch (error) {
    logger.error("Error retrieving safety case bundles by tenant", { error });
    res.status(500).json({ error: "Internal server error" });
  }
});

// Error handling middleware
app.use((err: any, req: express.Request, res: express.Response, _next: express.NextFunction) => {
  logger.error("Unhandled error", { error: err });
  res.status(500).json({ error: "Internal server error" });
});

// Start server
app.listen(port, () => {
  logger.info(`PF Testbed Ledger service started on port ${port}`);
  logger.info(`Health check: http://localhost:${port}/health`);
  logger.info(`Metrics: http://localhost:${port}/metrics`);
});
