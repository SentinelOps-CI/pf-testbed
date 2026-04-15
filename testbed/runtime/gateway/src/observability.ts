import { Plan } from "./types";

// Enhanced trace linking for Lean theorem integration
export interface LeanTheoremMapping {
  theorem_id: string;
  theorem_name: string;
  spec_file: string;
  spec_line: number;
  confidence: number;
  verification_status: "verified" | "pending" | "failed";
  last_verified: string;
}

export interface TraceContext {
  trace_id: string;
  plan_id: string;
  tenant: string;
  journey: string;
  user_id?: string;
  session_id: string;
  request_id: string;
  timestamp: string;
  lean_theorems: LeanTheoremMapping[];
  spec_lines: string[];
  metadata: Record<string, any>;
}

export interface ObservabilityMetrics {
  latency_p95: number;
  latency_p99: number;
  throughput: number;
  error_rate: number;
  success_rate: number;
  active_traces: number;
  theorem_verification_rate: number;
  // Paper-faithful metrics
  decision_path_phases: {
    observe: DecisionPathPhaseMetrics;
    retrieve: DecisionPathPhaseMetrics;
    plan: DecisionPathPhaseMetrics;
    kernel: DecisionPathPhaseMetrics;
    tool_broker: DecisionPathPhaseMetrics;
    egress: DecisionPathPhaseMetrics;
    safety_case: DecisionPathPhaseMetrics;
  };
  non_interference: {
    total_checks: number;
    passed: number;
    failed: number;
    success_rate: number;
  };
  certificates: {
    total_generated: number;
    pii_detected: number;
    secrets_detected: number;
    near_dup_detected: number;
    avg_processing_time: number;
  };
  receipts: {
    total_generated: number;
    valid_signatures: number;
    expired_count: number;
    avg_lifetime_hours: number;
  };
}

export interface SavedView {
  id: string;
  name: string;
  tenant: string;
  journey: string;
  filters: ViewFilters;
  layout: ViewLayout;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface ViewFilters {
  time_range: {
    start: string;
    end: string;
  };
  tenants: string[];
  journeys: string[];
  risk_levels: string[];
  status: string[];
  lean_theorems: string[];
  decision_path_phases: string[];
  non_interference_status: string[];
}

export interface ViewLayout {
  panels: PanelConfig[];
  refresh_interval: number;
  auto_refresh: boolean;
}

export interface PanelConfig {
  id: string;
  type:
    | "metrics"
    | "traces"
    | "theorems"
    | "alerts"
    | "decision_path"
    | "certificates"
    | "receipts";
  position: {
    x: number;
    y: number;
    width: number;
    height: number;
  };
  config: Record<string, any>;
}

// Paper-faithful alert types
export interface SecurityAlert {
  id: string;
  severity: "low" | "medium" | "high" | "critical";
  type:
    | "policy_violation"
    | "non_interference_failure"
    | "receipt_forgery"
    | "certificate_tampering"
    | "decision_path_failure";
  message: string;
  trace_id?: string;
  plan_id?: string;
  tenant: string;
  proof_hash?: string;
  timestamp: string;
  acknowledged: boolean;
  acknowledged_by?: string;
  acknowledged_at?: string;
}

export interface DecisionPathPhaseMetrics {
  count: number;
  avg_duration: number;
  success_rate: number;
  receipt_count?: number;
  policy_violations?: number;
  tools_executed?: number;
  certs_generated?: number;
  pii_blocked?: number;
  cases_generated?: number;
}

// Core observability service
export class ObservabilityService {
  private traceContexts: Map<string, TraceContext> = new Map();
  private savedViews: Map<string, SavedView> = new Map();
  private securityAlerts: Map<string, SecurityAlert> = new Map();
  private metrics: ObservabilityMetrics = {
    latency_p95: 0,
    latency_p99: 0,
    throughput: 0,
    error_rate: 0,
    success_rate: 0,
    active_traces: 0,
    theorem_verification_rate: 0,
    decision_path_phases: {
      observe: { count: 0, avg_duration: 0, success_rate: 0 },
      retrieve: { count: 0, avg_duration: 0, success_rate: 0, receipt_count: 0 },
      plan: { count: 0, avg_duration: 0, success_rate: 0 },
      kernel: { count: 0, avg_duration: 0, success_rate: 0, policy_violations: 0 },
      tool_broker: { count: 0, avg_duration: 0, success_rate: 0, tools_executed: 0 },
      egress: { count: 0, avg_duration: 0, success_rate: 0, certs_generated: 0, pii_blocked: 0 },
      safety_case: { count: 0, avg_duration: 0, success_rate: 0, cases_generated: 0 },
    },
    non_interference: {
      total_checks: 0,
      passed: 0,
      failed: 0,
      success_rate: 0,
    },
    certificates: {
      total_generated: 0,
      pii_detected: 0,
      secrets_detected: 0,
      near_dup_detected: 0,
      avg_processing_time: 0,
    },
    receipts: {
      total_generated: 0,
      valid_signatures: 0,
      expired_count: 0,
      avg_lifetime_hours: 0,
    },
  };

  // Create new trace context with Lean theorem linking
  createTraceContext(
    plan: Plan,
    request_id: string,
    session_id: string,
    user_id?: string,
  ): TraceContext {
    const trace_id = this.generateTraceId();

    const context: TraceContext = {
      trace_id,
      plan_id: plan.id,
      tenant: plan.tenant,
      journey: plan.journey,
      user_id,
      session_id,
      request_id,
      timestamp: new Date().toISOString(),
      lean_theorems: [],
      spec_lines: [],
      metadata: {
        agent: plan.metadata.agent,
        model: plan.metadata.model,
        confidence: plan.metadata.confidence,
        risk_level: plan.metadata.risk_level,
      },
    };

    this.traceContexts.set(trace_id, context);
    this.updateMetrics();

    return context;
  }

  // Link trace to Lean theorem and spec lines
  linkLeanTheorem(trace_id: string, theorem: LeanTheoremMapping, spec_lines: string[]): void {
    const context = this.traceContexts.get(trace_id);
    if (!context) {
      throw new Error(`Trace context not found: ${trace_id}`);
    }

    context.lean_theorems.push(theorem);
    context.spec_lines.push(...spec_lines);

    // Update verification status
    this.updateTheoremVerificationStatus(trace_id, theorem.theorem_id);
  }

  // Update theorem verification status
  private updateTheoremVerificationStatus(trace_id: string, theorem_id: string): void {
    const context = this.traceContexts.get(trace_id);
    if (!context) return;

    const theorem = context.lean_theorems.find((t) => t.theorem_id === theorem_id);
    if (theorem) {
      theorem.verification_status = "verified";
      theorem.last_verified = new Date().toISOString();
    }
  }

  // Get complete trace context for UI calls drawer
  getTraceContext(trace_id: string): TraceContext | null {
    return this.traceContexts.get(trace_id) || null;
  }

  // Get trace chain: Trace → Plan → Theorem → Cert
  getTraceChain(trace_id: string): {
    trace: TraceContext;
    plan: Plan;
    theorems: LeanTheoremMapping[];
    certificates: any[];
  } | null {
    const context = this.traceContexts.get(trace_id);
    if (!context) return null;

    // In a real implementation, you would fetch these from your data stores
    return {
      trace: context,
      plan: {} as Plan, // Would be fetched from plan store
      theorems: context.lean_theorems,
      certificates: [], // Would be fetched from cert store
    };
  }

  // Save view for specific journey and tenant
  saveView(view: Omit<SavedView, "id" | "created_at" | "updated_at">): SavedView {
    const id = this.generateViewId();
    const now = new Date().toISOString();

    const savedView: SavedView = {
      ...view,
      id,
      created_at: now,
      updated_at: now,
    };

    this.savedViews.set(id, savedView);
    return savedView;
  }

  // Get saved views for tenant and journey
  getSavedViews(tenant: string, journey: string): SavedView[] {
    return Array.from(this.savedViews.values()).filter(
      (view) => view.tenant === tenant && view.journey === journey,
    );
  }

  // Paper-faithful: Record decision path phase execution
  recordDecisionPathPhase(
    phase: keyof ObservabilityMetrics["decision_path_phases"],
    duration: number,
    success: boolean,
    metadata?: Record<string, any>,
  ): void {
    const phaseMetrics = this.metrics.decision_path_phases[phase];

    // Update counts
    phaseMetrics.count++;

    // Update average duration
    const totalDuration = phaseMetrics.avg_duration * (phaseMetrics.count - 1) + duration;
    phaseMetrics.avg_duration = totalDuration / phaseMetrics.count;

    // Update success rate
    const totalSuccesses = phaseMetrics.success_rate * (phaseMetrics.count - 1) + (success ? 1 : 0);
    phaseMetrics.success_rate = totalSuccesses / phaseMetrics.count;

    // Update phase-specific metrics
    switch (phase) {
      case "retrieve":
        if (metadata?.receipt_count) {
          phaseMetrics.receipt_count = (phaseMetrics.receipt_count || 0) + metadata.receipt_count;
        }
        break;
      case "kernel":
        if (!success && metadata?.policy_violation) {
          phaseMetrics.policy_violations = (phaseMetrics.policy_violations || 0) + 1;
        }
        break;
      case "tool_broker":
        if (metadata?.tools_executed) {
          phaseMetrics.tools_executed =
            (phaseMetrics.tools_executed || 0) + metadata.tools_executed;
        }
        break;
      case "egress":
        if (metadata?.certs_generated) {
          phaseMetrics.certs_generated =
            (phaseMetrics.certs_generated || 0) + metadata.certs_generated;
        }
        if (metadata?.pii_blocked) {
          phaseMetrics.pii_blocked = (phaseMetrics.pii_blocked || 0) + metadata.pii_blocked;
        }
        break;
      case "safety_case":
        if (metadata?.cases_generated) {
          phaseMetrics.cases_generated =
            (phaseMetrics.cases_generated || 0) + metadata.cases_generated;
        }
        break;
    }
  }

  // Paper-faithful: Record non-interference check result
  recordNonInterferenceCheck(passed: boolean, level: string, proof_hash: string): void {
    this.metrics.non_interference.total_checks++;

    if (passed) {
      this.metrics.non_interference.passed++;
    } else {
      this.metrics.non_interference.failed++;

      // Create security alert for NI failure
      this.createSecurityAlert({
        severity: "high",
        type: "non_interference_failure",
        message: `Non-interference check failed for level ${level}`,
        tenant: "system",
        proof_hash,
      });
    }

    this.metrics.non_interference.success_rate =
      this.metrics.non_interference.passed / this.metrics.non_interference.total_checks;
  }

  // Paper-faithful: Record certificate generation
  recordCertificateGeneration(
    pii_detected: number,
    secrets_detected: number,
    near_dup_detected: number,
    processing_time: number,
  ): void {
    this.metrics.certificates.total_generated++;
    this.metrics.certificates.pii_detected += pii_detected;
    this.metrics.certificates.secrets_detected += secrets_detected;
    this.metrics.certificates.near_dup_detected += near_dup_detected;

    // Update average processing time
    const totalTime =
      this.metrics.certificates.avg_processing_time *
        (this.metrics.certificates.total_generated - 1) +
      processing_time;
    this.metrics.certificates.avg_processing_time =
      totalTime / this.metrics.certificates.total_generated;
  }

  // Paper-faithful: Record receipt generation
  recordReceiptGeneration(valid_signature: boolean, lifetime_hours: number): void {
    this.metrics.receipts.total_generated++;

    if (valid_signature) {
      this.metrics.receipts.valid_signatures++;
    }

    // Update average lifetime
    const totalLifetime =
      this.metrics.receipts.avg_lifetime_hours * (this.metrics.receipts.total_generated - 1) +
      lifetime_hours;
    this.metrics.receipts.avg_lifetime_hours =
      totalLifetime / this.metrics.receipts.total_generated;
  }

  // Paper-faithful: Create security alert
  createSecurityAlert(
    alert: Omit<SecurityAlert, "id" | "timestamp" | "acknowledged">,
  ): SecurityAlert {
    const id = this.generateAlertId();
    const timestamp = new Date().toISOString();

    const securityAlert: SecurityAlert = {
      ...alert,
      id,
      timestamp,
      acknowledged: false,
    };

    this.securityAlerts.set(id, securityAlert);
    return securityAlert;
  }

  // Paper-faithful: Acknowledge security alert
  acknowledgeAlert(alert_id: string, acknowledged_by: string): void {
    const alert = this.securityAlerts.get(alert_id);
    if (alert) {
      alert.acknowledged = true;
      alert.acknowledged_by = acknowledged_by;
      alert.acknowledged_at = new Date().toISOString();
    }
  }

  // Paper-faithful: Get security alerts
  getSecurityAlerts(
    severity?: SecurityAlert["severity"],
    type?: SecurityAlert["type"],
    tenant?: string,
    acknowledged?: boolean,
  ): SecurityAlert[] {
    let alerts = Array.from(this.securityAlerts.values());

    if (severity) {
      alerts = alerts.filter((a) => a.severity === severity);
    }

    if (type) {
      alerts = alerts.filter((a) => a.type === type);
    }

    if (tenant) {
      alerts = alerts.filter((a) => a.tenant === tenant);
    }

    if (acknowledged !== undefined) {
      alerts = alerts.filter((a) => a.acknowledged === acknowledged);
    }

    return alerts.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  }

  // Paper-faithful: Get decision path analytics
  getDecisionPathAnalytics(): {
    phase_performance: Record<string, any>;
    bottlenecks: string[];
    recommendations: string[];
  } {
    const phases = this.metrics.decision_path_phases;
    const bottlenecks: string[] = [];
    const recommendations: string[] = [];

    // Identify bottlenecks (phases with high duration or low success rate)
    for (const [phase, metrics] of Object.entries(phases)) {
      if (metrics.avg_duration > 1000) {
        // > 1 second
        bottlenecks.push(`${phase}: high latency (${metrics.avg_duration.toFixed(2)}ms)`);
        recommendations.push(`Optimize ${phase} phase performance`);
      }

      if (metrics.success_rate < 0.95) {
        // < 95% success rate
        bottlenecks.push(
          `${phase}: low success rate (${(metrics.success_rate * 100).toFixed(1)}%)`,
        );
        recommendations.push(`Investigate ${phase} phase failures`);
      }
    }

    return {
      phase_performance: phases,
      bottlenecks,
      recommendations,
    };
  }

  // Update metrics
  private updateMetrics(): void {
    this.metrics.active_traces = this.traceContexts.size;

    // Calculate other metrics based on trace data
    const traces = Array.from(this.traceContexts.values());
    const verifiedTheorems = traces.reduce(
      (count, trace) =>
        count + trace.lean_theorems.filter((t) => t.verification_status === "verified").length,
      0,
    );
    const totalTheorems = traces.reduce((count, trace) => count + trace.lean_theorems.length, 0);

    this.metrics.theorem_verification_rate =
      totalTheorems > 0 ? verifiedTheorems / totalTheorems : 0;
  }

  // Get current metrics
  getMetrics(): ObservabilityMetrics {
    return { ...this.metrics };
  }

  // Clean up old traces (retention policy)
  cleanupOldTraces(retentionDays: number = 90): void {
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - retentionDays);

    for (const [trace_id, context] of this.traceContexts.entries()) {
      if (new Date(context.timestamp) < cutoff) {
        this.traceContexts.delete(trace_id);
      }
    }

    this.updateMetrics();
  }

  // Generate unique IDs
  private generateTraceId(): string {
    return `trace_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private generateViewId(): string {
    return `view_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private generateAlertId(): string {
    return `alert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}

// Export singleton instance
export const observabilityService = new ObservabilityService();
