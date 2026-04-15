import { randomBytes } from "crypto";

// Types for metering and billing
export interface UsageMetrics {
  tenant_id: string;
  session_id: string;
  timestamp: string;
  cpu_ms: number;
  network_bytes: number;
  api_calls: number;
  tool_executions: number;
  data_retrievals: number;
  egress_scans: number;
  policy_checks: number;
  violations: number;
  risk_score: number;
}

export interface BillingTier {
  name: string;
  base_price_usd: number;
  cpu_price_per_ms: number;
  network_price_per_mb: number;
  api_call_price: number;
  tool_execution_price: number;
  data_retrieval_price: number;
  egress_scan_price: number;
  policy_check_price: number;
  violation_price: number;
  risk_multiplier: number;
  monthly_quota: {
    cpu_ms: number;
    network_mb: number;
    api_calls: number;
    tool_executions: number;
    data_retrievals: number;
  };
}

export interface CostBreakdown {
  base_cost: number;
  cpu_cost: number;
  network_cost: number;
  api_cost: number;
  tool_cost: number;
  data_cost: number;
  egress_cost: number;
  policy_cost: number;
  violation_cost: number;
  risk_adjustment: number;
  total_cost: number;
}

export interface InvoiceData {
  invoice_id: string;
  tenant_id: string;
  period_start: string;
  period_end: string;
  usage_metrics: UsageMetrics[];
  cost_breakdown: CostBreakdown;
  stripe_invoice_id?: string;
  status: "draft" | "sent" | "paid" | "overdue";
  created_at: string;
  due_date: string;
}

export interface StripeConfig {
  secret_key: string;
  webhook_secret: string;
  price_ids: {
    [tier: string]: string;
  };
  enabled: boolean;
}

export class MeteringService {
  private billingTiers: Map<string, BillingTier>;
  private stripeConfig: StripeConfig;
  private usageStore: Map<string, UsageMetrics[]>;
  private invoiceStore: Map<string, InvoiceData[]>;

  constructor(stripeConfig: StripeConfig) {
    this.stripeConfig = stripeConfig;
    this.usageStore = new Map();
    this.invoiceStore = new Map();

    // Initialize billing tiers
    this.billingTiers = new Map([
      [
        "basic",
        {
          name: "Basic",
          base_price_usd: 50.0,
          cpu_price_per_ms: 0.0000001, // $0.36 per hour
          network_price_per_mb: 0.05,
          api_call_price: 0.001,
          tool_execution_price: 0.01,
          data_retrieval_price: 0.005,
          egress_scan_price: 0.002,
          policy_check_price: 0.001,
          violation_price: 1.0,
          risk_multiplier: 1.0,
          monthly_quota: {
            cpu_ms: 3600000, // 1 hour
            network_mb: 1000,
            api_calls: 10000,
            tool_executions: 1000,
            data_retrievals: 500,
          },
        },
      ],
      [
        "professional",
        {
          name: "Professional",
          base_price_usd: 200.0,
          cpu_price_per_ms: 0.00000008, // $0.288 per hour
          network_price_per_mb: 0.04,
          api_call_price: 0.0008,
          tool_execution_price: 0.008,
          data_retrieval_price: 0.004,
          egress_scan_price: 0.0015,
          policy_check_price: 0.0008,
          violation_price: 0.8,
          risk_multiplier: 0.9,
          monthly_quota: {
            cpu_ms: 7200000, // 2 hours
            network_mb: 5000,
            api_calls: 50000,
            tool_executions: 5000,
            data_retrievals: 2500,
          },
        },
      ],
      [
        "enterprise",
        {
          name: "Enterprise",
          base_price_usd: 500.0,
          cpu_price_per_ms: 0.00000006, // $0.216 per hour
          network_price_per_mb: 0.03,
          api_call_price: 0.0005,
          tool_execution_price: 0.005,
          data_retrieval_price: 0.003,
          egress_scan_price: 0.001,
          policy_check_price: 0.0005,
          violation_price: 0.5,
          risk_multiplier: 0.8,
          monthly_quota: {
            cpu_ms: 18000000, // 5 hours
            network_mb: 20000,
            api_calls: 200000,
            tool_executions: 20000,
            data_retrievals: 10000,
          },
        },
      ],
    ]);
  }

  /**
   * Record usage metrics for a session
   */
  recordUsage(metrics: UsageMetrics): void {
    const tenantKey = `${metrics.tenant_id}_${this.getCurrentPeriod()}`;

    if (!this.usageStore.has(tenantKey)) {
      this.usageStore.set(tenantKey, []);
    }

    this.usageStore.get(tenantKey)!.push(metrics);
  }

  /**
   * Get current billing period (YYYY-MM format)
   */
  private getCurrentPeriod(): string {
    const now = new Date();
    return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}`;
  }

  /**
   * Calculate cost for usage metrics
   */
  calculateCost(tenantId: string, period: string): CostBreakdown {
    const tenantKey = `${tenantId}_${period}`;
    const usageMetrics = this.usageStore.get(tenantKey) || [];

    if (usageMetrics.length === 0) {
      return this.getEmptyCostBreakdown();
    }

    // Aggregate metrics
    const aggregated = this.aggregateMetrics(usageMetrics);

    // Get tenant's billing tier (default to basic)
    const tier = this.billingTiers.get("basic")!;

    // Calculate costs
    const cpu_cost = aggregated.cpu_ms * tier.cpu_price_per_ms;
    const network_cost = (aggregated.network_bytes / (1024 * 1024)) * tier.network_price_per_mb;
    const api_cost = aggregated.api_calls * tier.api_call_price;
    const tool_cost = aggregated.tool_executions * tier.tool_execution_price;
    const data_cost = aggregated.data_retrievals * tier.data_retrieval_price;
    const egress_cost = aggregated.egress_scans * tier.egress_scan_price;
    const policy_cost = aggregated.policy_checks * tier.policy_check_price;
    const violation_cost = aggregated.violations * tier.violation_price;

    const total_base_cost =
      tier.base_price_usd +
      cpu_cost +
      network_cost +
      api_cost +
      tool_cost +
      data_cost +
      egress_cost +
      policy_cost +
      violation_cost;

    // Apply risk multiplier
    const risk_adjustment = total_base_cost * (tier.risk_multiplier - 1);
    const total_cost = total_base_cost + risk_adjustment;

    return {
      base_cost: tier.base_price_usd,
      cpu_cost,
      network_cost,
      api_cost,
      tool_cost,
      data_cost,
      egress_cost,
      policy_cost,
      violation_cost,
      risk_adjustment,
      total_cost,
    };
  }

  /**
   * Aggregate usage metrics for a period
   */
  private aggregateMetrics(metrics: UsageMetrics[]): {
    cpu_ms: number;
    network_bytes: number;
    api_calls: number;
    tool_executions: number;
    data_retrievals: number;
    egress_scans: number;
    policy_checks: number;
    violations: number;
    avg_risk_score: number;
  } {
    return {
      cpu_ms: metrics.reduce((sum, m) => sum + m.cpu_ms, 0),
      network_bytes: metrics.reduce((sum, m) => sum + m.network_bytes, 0),
      api_calls: metrics.reduce((sum, m) => sum + m.api_calls, 0),
      tool_executions: metrics.reduce((sum, m) => sum + m.tool_executions, 0),
      data_retrievals: metrics.reduce((sum, m) => sum + m.data_retrievals, 0),
      egress_scans: metrics.reduce((sum, m) => sum + m.egress_scans, 0),
      policy_checks: metrics.reduce((sum, m) => sum + m.policy_checks, 0),
      violations: metrics.reduce((sum, m) => sum + m.violations, 0),
      avg_risk_score: metrics.reduce((sum, m) => sum + m.risk_score, 0) / metrics.length,
    };
  }

  /**
   * Get empty cost breakdown
   */
  private getEmptyCostBreakdown(): CostBreakdown {
    return {
      base_cost: 0,
      cpu_cost: 0,
      network_cost: 0,
      api_cost: 0,
      tool_cost: 0,
      data_cost: 0,
      egress_cost: 0,
      policy_cost: 0,
      violation_cost: 0,
      risk_adjustment: 0,
      total_cost: 0,
    };
  }

  /**
   * Generate invoice for a tenant and period
   */
  async generateInvoice(tenantId: string, period: string): Promise<InvoiceData> {
    const costBreakdown = this.calculateCost(tenantId, period);
    const tenantKey = `${tenantId}_${period}`;
    const usageMetrics = this.usageStore.get(tenantKey) || [];

    const parts = period.split("-");
    const year = parts[0];
    const month = parts[1];
    if (year === undefined || month === undefined) {
      throw new Error(`Invalid billing period (expected YYYY-MM): ${period}`);
    }
    const periodStart = new Date(parseInt(year, 10), parseInt(month, 10) - 1, 1);
    const periodEnd = new Date(parseInt(year, 10), parseInt(month, 10), 0);

    const invoice: InvoiceData = {
      invoice_id: this.generateInvoiceId(),
      tenant_id: tenantId,
      period_start: periodStart.toISOString(),
      period_end: periodEnd.toISOString(),
      usage_metrics: usageMetrics,
      cost_breakdown: costBreakdown,
      status: "draft",
      created_at: new Date().toISOString(),
      due_date: new Date(periodEnd.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString(), // 30 days after period end
    };

    // Store invoice
    if (!this.invoiceStore.has(tenantId)) {
      this.invoiceStore.set(tenantId, []);
    }
    this.invoiceStore.get(tenantId)!.push(invoice);

    // Create Stripe invoice if enabled
    if (this.stripeConfig.enabled) {
      try {
        const stripeInvoiceId = await this.createStripeInvoice(invoice);
        invoice.stripe_invoice_id = stripeInvoiceId;
      } catch (error) {
        console.error("Failed to create Stripe invoice:", error);
      }
    }

    return invoice;
  }

  /**
   * Generate unique invoice ID
   */
  private generateInvoiceId(): string {
    return `INV-${Date.now()}-${randomBytes(4).toString("hex")}`;
  }

  /**
   * Create Stripe invoice (placeholder for real integration)
   */
  private async createStripeInvoice(invoice: InvoiceData): Promise<string> {
    // This would integrate with Stripe API
    // For now, return a mock ID
    return `stripe_${invoice.invoice_id}`;
  }

  /**
   * Get usage metrics for a tenant and period
   */
  getUsageMetrics(tenantId: string, period: string): UsageMetrics[] {
    const tenantKey = `${tenantId}_${period}`;
    return this.usageStore.get(tenantKey) || [];
  }

  /**
   * Get invoices for a tenant
   */
  getInvoices(tenantId: string): InvoiceData[] {
    return this.invoiceStore.get(tenantId) || [];
  }

  /**
   * Export usage data to Prometheus metrics format
   */
  exportPrometheusMetrics(): string {
    const metrics: string[] = [];

    for (const [tenantKey, usageList] of this.usageStore) {
      const [tenantId] = tenantKey.split("_");

      for (const usage of usageList) {
        metrics.push(`# HELP pf_usage_cpu_ms CPU usage in milliseconds`);
        metrics.push(`# TYPE pf_usage_cpu_ms counter`);
        metrics.push(
          `pf_usage_cpu_ms{tenant="${tenantId}",session="${usage.session_id}"} ${usage.cpu_ms}`,
        );

        metrics.push(`# HELP pf_usage_network_bytes Network usage in bytes`);
        metrics.push(`# TYPE pf_usage_network_bytes counter`);
        metrics.push(
          `pf_usage_network_bytes{tenant="${tenantId}",session="${usage.session_id}"} ${usage.network_bytes}`,
        );

        metrics.push(`# HELP pf_usage_api_calls API calls count`);
        metrics.push(`# TYPE pf_usage_api_calls counter`);
        metrics.push(
          `pf_usage_api_calls{tenant="${tenantId}",session="${usage.session_id}"} ${usage.api_calls}`,
        );

        metrics.push(`# HELP pf_usage_tool_executions Tool executions count`);
        metrics.push(`# TYPE pf_usage_tool_executions counter`);
        metrics.push(
          `pf_usage_tool_executions{tenant="${tenantId}",session="${usage.session_id}"} ${usage.tool_executions}`,
        );

        metrics.push(`# HELP pf_usage_data_retrievals Data retrievals count`);
        metrics.push(`# TYPE pf_usage_data_retrievals counter`);
        metrics.push(
          `pf_usage_data_retrievals{tenant="${tenantId}",session="${usage.session_id}"} ${usage.data_retrievals}`,
        );

        metrics.push(`# HELP pf_usage_egress_scans Egress scans count`);
        metrics.push(`# TYPE pf_usage_egress_scans counter`);
        metrics.push(
          `pf_usage_egress_scans{tenant="${tenantId}",session="${usage.session_id}"} ${usage.egress_scans}`,
        );

        metrics.push(`# HELP pf_usage_policy_checks Policy checks count`);
        metrics.push(`# TYPE pf_usage_policy_checks counter`);
        metrics.push(
          `pf_usage_policy_checks{tenant="${tenantId}",session="${usage.session_id}"} ${usage.policy_checks}`,
        );

        metrics.push(`# HELP pf_usage_violations Violations count`);
        metrics.push(`# TYPE pf_usage_violations counter`);
        metrics.push(
          `pf_usage_violations{tenant="${tenantId}",session="${usage.session_id}"} ${usage.violations}`,
        );

        metrics.push(`# HELP pf_usage_risk_score Risk score (0-1)`);
        metrics.push(`# TYPE pf_usage_risk_score gauge`);
        metrics.push(
          `pf_usage_risk_score{tenant="${tenantId}",session="${usage.session_id}"} ${usage.risk_score}`,
        );
      }
    }

    return metrics.join("\n");
  }

  /**
   * Get billing tier information
   */
  getBillingTier(tierName: string): BillingTier | undefined {
    return this.billingTiers.get(tierName);
  }

  /**
   * List all billing tiers
   */
  listBillingTiers(): BillingTier[] {
    return Array.from(this.billingTiers.values());
  }

  /**
   * Update billing tier for a tenant (placeholder for real implementation)
   */
  updateTenantBillingTier(_tenantId: string, tierName: string): boolean {
    // This would update tenant billing tier in database
    // For now, just validate the tier exists
    return this.billingTiers.has(tierName);
  }
}
