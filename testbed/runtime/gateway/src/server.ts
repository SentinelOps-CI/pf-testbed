import express from "express";
import { HealthResponse, ABACRequest, ABACResponse } from "./types";
import { ABACEngine } from "./abac-engine";

const app = express();
const port = process.env.GATEWAY_PORT || 3000;

// Initialize ABAC engine
const abacEngine = new ABACEngine();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Health check endpoint
app.get("/health", (req, res) => {
  const healthResponse: HealthResponse = {
    status: "healthy",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  };
  res.json(healthResponse);
});

// ABAC Query endpoint
app.post("/api/v1/query", async (req, res) => {
  try {
    const request: ABACRequest = req.body;

    // Validate required fields
    if (!request.tenant || !request.subject_id || !request.subject_roles || !request.query) {
      return res.status(400).json({
        error: "Missing required fields",
        required: ["tenant", "subject_id", "subject_roles", "query"],
      });
    }

    // Evaluate access using ABAC engine
    const response: ABACResponse = await abacEngine.evaluateAccess(request);

    res.status(200).json(response);
  } catch (error) {
    console.error("ABAC query error:", error);
    res.status(403).json({
      error: "Access denied",
      message: error instanceof Error ? error.message : "Unknown error",
      timestamp: new Date().toISOString(),
    });
  }
});

// Root endpoint
app.get("/", (req, res) => {
  res.json({
    service: "pf-testbed-gateway",
    version: "1.0.0",
    endpoints: {
      health: "/health",
      query: "/api/v1/query",
    },
    timestamp: new Date().toISOString(),
  });
});

// 404 handler
app.use("*", (req, res) => {
  res.status(404).json({
    error: "Endpoint not found",
    path: req.originalUrl,
    timestamp: new Date().toISOString(),
  });
});

// Error handler
app.use((error: any, req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error("Unhandled error:", error);
  res.status(500).json({
    error: "Internal server error",
    message: "An unexpected error occurred",
    timestamp: new Date().toISOString(),
  });
});

export { app, port };
