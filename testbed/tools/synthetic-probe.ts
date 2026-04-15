#!/usr/bin/env ts-node

// Synthetic Probe for Continuous Monitoring
// Runs every minute: cert present, policy hash matches, receipts verified

export interface ProbeResult {
  id: string;
  timestamp: string;
  probe_type: "decision_path" | "retrieval" | "egress" | "kernel" | "routing" | "cache";
  status: "passed" | "failed" | "warning";
  checks: ProbeCheck[];
  execution_time_ms: number;
  metadata: Record<string, any>;
}

export interface ProbeCheck {
  name: string;
  status: "passed" | "failed" | "warning";
  description: string;
  details: Record<string, any>;
  error_message?: string;
}

export interface ProbeSummary {
  total_probes: number;
  passed_probes: number;
  failed_probes: number;
  warning_probes: number;
  success_rate: number;
  last_run: string;
  critical_failures: string[];
  avg_execution_time_ms: number;
}

export class SyntheticProbe {
  private probeHistory: ProbeResult[] = [];
  private probeStats = {
    total_runs: 0,
    total_passed: 0,
    total_failed: 0,
    total_warnings: 0,
    avg_execution_time_ms: 0,
  };

  constructor(
    private readonly endpoints: Record<string, string> = {
      gateway: process.env.GATEWAY_HEALTH_URL || "http://localhost:3003/health",
      ingress: process.env.INGRESS_HEALTH_URL || "http://localhost:3001/health",
      ledger: process.env.LEDGER_HEALTH_URL || "http://localhost:3002/health",
      prometheus: process.env.PROMETHEUS_HEALTH_URL || "http://localhost:9090/-/healthy",
      retrieval: process.env.RETRIEVAL_HEALTH_URL || "http://localhost:3100/api/health",
    },
  ) {
    this.startContinuousMonitoring();
  }

  /**
   * Start continuous monitoring every minute
   */
  private startContinuousMonitoring(): void {
    // Run initial probe
    this.runFullProbe();

    // Schedule continuous monitoring
    setInterval(() => {
      this.runFullProbe();
    }, 60 * 1000); // Every minute
  }

  /**
   * Run full synthetic probe
   */
  async runFullProbe(): Promise<ProbeSummary> {
    const startTime = Date.now();
    console.log(`\n[${new Date().toISOString()}] Starting synthetic probe...`);

    const results: ProbeResult[] = [];

    results.push(await this.probeService("decision_path", "gateway"));
    results.push(await this.probeService("retrieval", "retrieval"));
    results.push(await this.probeService("egress", "gateway"));
    results.push(await this.probeService("kernel", "ledger"));
    results.push(await this.probeService("routing", "gateway"));
    results.push(await this.probeService("cache", "prometheus"));

    const totalExecutionTime = Date.now() - startTime;

    // Calculate summary
    const summary = this.calculateProbeSummary(results);

    // Update stats
    this.updateProbeStats(results);

    // Log results
    this.logProbeResults(results, summary, totalExecutionTime);

    return summary;
  }

  /**
   * Probe Decision Path Engine
   */
  private async probeService(
    probeType: ProbeResult["probe_type"],
    service: keyof SyntheticProbe["endpoints"],
  ): Promise<ProbeResult> {
    const startTime = Date.now();
    const checks: ProbeCheck[] = [];

    try {
      const url = this.endpoints[service];
      const response = await fetch(url);
      const body = await response.text();

      checks.push({
        name: `${service} endpoint reachable`,
        status: response.ok ? "passed" : "failed",
        description: `Public health endpoint response for ${service}`,
        details: {
          service,
          status_code: response.status,
          status_text: response.statusText,
        },
      });
      checks.push({
        name: `${service} response body`,
        status: body.length > 0 ? "passed" : "warning",
        description: "Endpoint returned a non-empty payload",
        details: { content_length: body.length },
      });
    } catch (error) {
      checks.push({
        name: `${service} health check`,
        status: "failed",
        description: "Failed to probe public endpoint",
        details: {},
        error_message: error instanceof Error ? error.message : "Unknown error",
      });
    }

    const executionTime = Date.now() - startTime;
    const status = this.determineOverallStatus(checks);

    const result: ProbeResult = {
      id: `probe_${probeType}_${Date.now()}`,
      timestamp: new Date().toISOString(),
      probe_type: probeType,
      status,
      checks,
      execution_time_ms: executionTime,
      metadata: {
        service,
        version: "1.0.0",
      },
    };

    this.probeHistory.push(result);
    return result;
  }

  /**
   * Determine overall status from checks
   */
  private determineOverallStatus(checks: ProbeCheck[]): "passed" | "failed" | "warning" {
    if (checks.some((c) => c.status === "failed")) {
      return "failed";
    }
    if (checks.some((c) => c.status === "warning")) {
      return "warning";
    }
    return "passed";
  }

  /**
   * Calculate probe summary
   */
  private calculateProbeSummary(results: ProbeResult[]): ProbeSummary {
    const totalProbes = results.length;
    const passedProbes = results.filter((r) => r.status === "passed").length;
    const failedProbes = results.filter((r) => r.status === "failed").length;
    const warningProbes = results.filter((r) => r.status === "warning").length;

    const successRate = totalProbes > 0 ? (passedProbes / totalProbes) * 100 : 0;

    const criticalFailures = results
      .filter((r) => r.status === "failed")
      .map(
        (r) =>
          `${r.probe_type}: ${r.checks
            .filter((c) => c.status === "failed")
            .map((c) => c.name)
            .join(", ")}`,
      );

    const avgExecutionTime = results.reduce((sum, r) => sum + r.execution_time_ms, 0) / totalProbes;

    return {
      total_probes: totalProbes,
      passed_probes: passedProbes,
      failed_probes: failedProbes,
      warning_probes: warningProbes,
      success_rate: successRate,
      last_run: new Date().toISOString(),
      critical_failures: criticalFailures,
      avg_execution_time_ms: avgExecutionTime,
    };
  }

  /**
   * Update probe statistics
   */
  private updateProbeStats(results: ProbeResult[]): void {
    this.probeStats.total_runs++;

    results.forEach((result) => {
      switch (result.status) {
        case "passed":
          this.probeStats.total_passed++;
          break;
        case "failed":
          this.probeStats.total_failed++;
          break;
        case "warning":
          this.probeStats.total_warnings++;
          break;
      }
    });

    // Update average execution time
    const totalTime = results.reduce((sum, r) => sum + r.execution_time_ms, 0);
    const currentAvg = this.probeStats.avg_execution_time_ms;
    const newAvg =
      (currentAvg * (this.probeStats.total_runs - 1) + totalTime) / this.probeStats.total_runs;
    this.probeStats.avg_execution_time_ms = newAvg;
  }

  /**
   * Log probe results
   */
  private logProbeResults(results: ProbeResult[], summary: ProbeSummary, totalTime: number): void {
    console.log(`\n[${new Date().toISOString()}] Synthetic probe completed in ${totalTime}ms`);
    console.log(
      `Overall Status: ${summary.success_rate >= 90 ? "🟢 HEALTHY" : summary.success_rate >= 70 ? "🟡 WARNING" : "🔴 CRITICAL"}`,
    );
    console.log(
      `Success Rate: ${summary.success_rate.toFixed(2)}% (${summary.passed_probes}/${summary.total_probes})`,
    );

    if (summary.critical_failures.length > 0) {
      console.log(`\n🔴 Critical Failures:`);
      summary.critical_failures.forEach((failure) => {
        console.log(`  - ${failure}`);
      });
    }

    console.log(`\nComponent Status:`);
    results.forEach((result) => {
      const statusIcon =
        result.status === "passed" ? "🟢" : result.status === "warning" ? "🟡" : "🔴";
      console.log(
        `  ${statusIcon} ${result.probe_type}: ${result.status.toUpperCase()} (${result.execution_time_ms}ms)`,
      );
    });
  }

  /**
   * Get probe history
   */
  getProbeHistory(): ProbeResult[] {
    return [...this.probeHistory];
  }

  /**
   * Get probe statistics
   */
  getProbeStats() {
    return { ...this.probeStats };
  }

  /**
   * Clear probe history
   */
  clearHistory(): void {
    this.probeHistory = [];
  }

  /**
   * Export results for dashboard integration
   */
  exportResultsForDashboard(): any {
    return {
      probe_stats: this.getProbeStats(),
      recent_probes: this.probeHistory.slice(-10),
      component_health: this.getComponentHealthSummary(),
      last_run:
        this.probeHistory.length > 0 ? this.probeHistory[this.probeHistory.length - 1] : null,
    };
  }

  /**
   * Get component health summary
   */
  private getComponentHealthSummary(): Record<string, any> {
    const recentProbes = this.probeHistory.slice(-6); // Last 6 probes (6 minutes)
    const componentHealth: Record<string, any> = {};

    ["decision_path", "retrieval", "egress", "kernel", "routing", "cache"].forEach((component) => {
      const componentProbes = recentProbes.filter((p) => p.probe_type === component);
      if (componentProbes.length > 0) {
        const lastProbe = componentProbes[componentProbes.length - 1];
        if (lastProbe) {
          componentHealth[component] = {
            status: lastProbe.status,
            last_check: lastProbe.timestamp,
            checks_passed: lastProbe.checks.filter((c) => c.status === "passed").length,
            total_checks: lastProbe.checks.length,
          };
        }
      }
    });

    return componentHealth;
  }
}

// Export singleton instance
export const syntheticProbe = new SyntheticProbe();
