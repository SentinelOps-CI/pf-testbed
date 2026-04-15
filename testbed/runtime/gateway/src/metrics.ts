import { register, Counter, Histogram, Gauge } from "prom-client";

// Prometheus metrics for testbed observability
export class TestbedMetrics {
  // SLO and violation metrics
  private sloViolationsTotal = new Counter({
    name: "testbed_slo_violations_total",
    help: "Total number of SLO violations",
    labelNames: ["tenant", "journey", "slo_type", "severity"],
  });

  // Latency metrics
  private requestDurationSeconds = new Histogram({
    name: "testbed_request_duration_seconds",
    help: "Request duration in seconds",
    labelNames: ["tenant", "journey", "endpoint", "method"],
    buckets: [0.1, 0.25, 0.5, 1, 2, 5, 10],
  });

  // Theorem verification metrics
  private theoremVerificationRate = new Gauge({
    name: "testbed_theorem_verification_rate",
    help: "Rate of theorem verification success",
    labelNames: ["tenant", "journey"],
  });

  // Trace metrics
  private activeTracesTotal = new Gauge({
    name: "testbed_active_traces_total",
    help: "Total number of active traces",
    labelNames: ["tenant", "journey", "status"],
  });

  private tracesCreatedTotal = new Counter({
    name: "testbed_traces_created_total",
    help: "Total number of traces created",
    labelNames: ["tenant", "journey"],
  });

  // Honeytoken metrics
  private honeytokenAlertsTotal = new Counter({
    name: "testbed_honeytoken_alerts_total",
    help: "Total number of honeytoken alerts",
    labelNames: ["tenant", "type", "severity"],
  });

  // Access receipt metrics
  private accessReceiptsTotal = new Counter({
    name: "testbed_access_receipts_total",
    help: "Total number of access receipts",
    labelNames: ["tenant", "journey", "status"],
  });

  // Certificate metrics
  private certificateStatusTotal = new Gauge({
    name: "testbed_certificate_status_total",
    help: "Total certificates by status",
    labelNames: ["tenant", "status", "type"],
  });

  // Plan execution metrics
  private planExecutionsTotal = new Counter({
    name: "testbed_plan_executions_total",
    help: "Total number of plan executions",
    labelNames: ["tenant", "journey", "status"],
  });

  private planExecutionDurationSeconds = new Histogram({
    name: "testbed_plan_execution_duration_seconds",
    help: "Plan execution duration in seconds",
    labelNames: ["tenant", "journey"],
    buckets: [1, 5, 10, 30, 60, 120, 300],
  });

  // Error metrics
  private errorsTotal = new Counter({
    name: "testbed_errors_total",
    help: "Total number of errors",
    labelNames: ["tenant", "journey", "error_type", "severity"],
  });

  // Throughput metrics
  private requestsTotal = new Counter({
    name: "testbed_requests_total",
    help: "Total number of requests",
    labelNames: ["tenant", "journey", "method", "status"],
  });

  // Constructor - register all metrics
  constructor() {
    // Register all metrics with Prometheus
    register.registerMetric(this.sloViolationsTotal);
    register.registerMetric(this.requestDurationSeconds);
    register.registerMetric(this.theoremVerificationRate);
    register.registerMetric(this.activeTracesTotal);
    register.registerMetric(this.tracesCreatedTotal);
    register.registerMetric(this.honeytokenAlertsTotal);
    register.registerMetric(this.accessReceiptsTotal);
    register.registerMetric(this.certificateStatusTotal);
    register.registerMetric(this.planExecutionsTotal);
    register.registerMetric(this.planExecutionDurationSeconds);
    register.registerMetric(this.errorsTotal);
    register.registerMetric(this.requestsTotal);
  }

  // SLO violation tracking
  recordSloViolation(tenant: string, journey: string, sloType: string, severity: string): void {
    this.sloViolationsTotal.inc({
      tenant,
      journey,
      slo_type: sloType,
      severity,
    });
  }

  // Request duration tracking
  startRequestTimer(tenant: string, journey: string, endpoint: string, method: string): () => void {
    const timer = this.requestDurationSeconds.startTimer({
      tenant,
      journey,
      endpoint,
      method,
    });
    return () => timer();
  }

  // Theorem verification tracking
  updateTheoremVerificationRate(tenant: string, journey: string, rate: number): void {
    this.theoremVerificationRate.set({ tenant, journey }, rate);
  }

  // Trace tracking
  incrementActiveTraces(tenant: string, journey: string, status: string): void {
    this.activeTracesTotal.inc({ tenant, journey, status });
  }

  decrementActiveTraces(tenant: string, journey: string, status: string): void {
    this.activeTracesTotal.dec({ tenant, journey, status });
  }

  recordTraceCreated(tenant: string, journey: string): void {
    this.tracesCreatedTotal.inc({ tenant, journey });
  }

  // Honeytoken tracking
  recordHoneytokenAlert(tenant: string, type: string, severity: string): void {
    this.honeytokenAlertsTotal.inc({ tenant, type, severity });
  }

  // Access receipt tracking
  recordAccessReceipt(tenant: string, journey: string, status: string): void {
    this.accessReceiptsTotal.inc({ tenant, journey, status });
  }

  // Certificate tracking
  updateCertificateStatus(tenant: string, status: string, type: string, count: number): void {
    this.certificateStatusTotal.set({ tenant, status, type }, count);
  }

  // Plan execution tracking
  recordPlanExecution(tenant: string, journey: string, status: string): void {
    this.planExecutionsTotal.inc({ tenant, journey, status });
  }

  startPlanExecutionTimer(tenant: string, journey: string): () => void {
    const timer = this.planExecutionDurationSeconds.startTimer({
      tenant,
      journey,
    });
    return () => timer();
  }

  // Error tracking
  recordError(tenant: string, journey: string, errorType: string, severity: string): void {
    this.errorsTotal.inc({ tenant, journey, error_type: errorType, severity });
  }

  // Request tracking
  recordRequest(tenant: string, journey: string, method: string, status: string): void {
    this.requestsTotal.inc({ tenant, journey, method, status });
  }

  // Get metrics for Prometheus endpoint
  getMetrics(): Promise<string> {
    return register.metrics();
  }

  // Reset all metrics (useful for testing)
  reset(): void {
    register.clear();
  }
}

// Export singleton instance
export const testbedMetrics = new TestbedMetrics();
