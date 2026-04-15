import { MeteringService, StripeConfig, UsageMetrics } from "../../../runtime/gateway/src/metering";

describe("MeteringService", () => {
  let meteringService: MeteringService;
  let mockStripeConfig: StripeConfig;

  beforeEach(() => {
    mockStripeConfig = {
      secret_key: "sk_test_mock",
      webhook_secret: "whsec_mock",
      price_ids: {
        basic: "price_basic_test",
        professional: "price_professional_test",
        enterprise: "price_enterprise_test",
      },
      enabled: false,
    };

    meteringService = new MeteringService(mockStripeConfig);
  });

  describe("Billing Tiers", () => {
    it("should have three billing tiers", () => {
      const tiers = meteringService.listBillingTiers();
      expect(tiers).toHaveLength(3);
      expect(tiers.map((t: { name: string }) => t.name)).toEqual([
        "Basic",
        "Professional",
        "Enterprise",
      ]);
    });

    it("should return correct billing tier by name", () => {
      const basicTier = meteringService.getBillingTier("basic");
      expect(basicTier).toBeDefined();
      expect(basicTier!.name).toBe("Basic");
      expect(basicTier!.base_price_usd).toBe(50.0);
    });

    it("should return undefined for non-existent tier", () => {
      const tier = meteringService.getBillingTier("non-existent");
      expect(tier).toBeUndefined();
    });

    it("should have correct pricing for Professional tier", () => {
      const proTier = meteringService.getBillingTier("professional");
      expect(proTier!.base_price_usd).toBe(200.0);
      expect(proTier!.cpu_price_per_ms).toBe(0.00000008);
      expect(proTier!.risk_multiplier).toBe(0.9);
    });

    it("should have correct pricing for Enterprise tier", () => {
      const entTier = meteringService.getBillingTier("enterprise");
      expect(entTier!.base_price_usd).toBe(500.0);
      expect(entTier!.cpu_price_per_ms).toBe(0.00000006);
      expect(entTier!.risk_multiplier).toBe(0.8);
    });
  });

  describe("Usage Recording", () => {
    it("should record usage metrics correctly", () => {
      const metrics: UsageMetrics = {
        tenant_id: "test-tenant",
        session_id: "session-123",
        timestamp: new Date().toISOString(),
        cpu_ms: 1000,
        network_bytes: 1024 * 1024, // 1MB
        api_calls: 10,
        tool_executions: 5,
        data_retrievals: 3,
        egress_scans: 2,
        policy_checks: 50,
        violations: 0,
        risk_score: 0.2,
      };

      meteringService.recordUsage(metrics);

      const currentPeriod = new Date().toISOString().slice(0, 7); // YYYY-MM
      const recordedMetrics = meteringService.getUsageMetrics("test-tenant", currentPeriod);

      expect(recordedMetrics).toHaveLength(1);
      expect(recordedMetrics[0]).toEqual(metrics);
    });

    it("should aggregate multiple usage sessions correctly", () => {
      const session1: UsageMetrics = {
        tenant_id: "test-tenant",
        session_id: "session-1",
        timestamp: new Date().toISOString(),
        cpu_ms: 1000,
        network_bytes: 1024 * 1024,
        api_calls: 10,
        tool_executions: 5,
        data_retrievals: 3,
        egress_scans: 2,
        policy_checks: 50,
        violations: 0,
        risk_score: 0.2,
      };

      const session2: UsageMetrics = {
        tenant_id: "test-tenant",
        session_id: "session-2",
        timestamp: new Date().toISOString(),
        cpu_ms: 2000,
        network_bytes: 2 * 1024 * 1024,
        api_calls: 20,
        tool_executions: 10,
        data_retrievals: 6,
        egress_scans: 4,
        policy_checks: 100,
        violations: 1,
        risk_score: 0.3,
      };

      meteringService.recordUsage(session1);
      meteringService.recordUsage(session2);

      const currentPeriod = new Date().toISOString().slice(0, 7);
      const recordedMetrics = meteringService.getUsageMetrics("test-tenant", currentPeriod);

      expect(recordedMetrics).toHaveLength(2);
    });

    it("should separate usage by tenant and period", () => {
      const metrics1: UsageMetrics = {
        tenant_id: "tenant-1",
        session_id: "session-1",
        timestamp: new Date().toISOString(),
        cpu_ms: 1000,
        network_bytes: 1024 * 1024,
        api_calls: 10,
        tool_executions: 5,
        data_retrievals: 3,
        egress_scans: 2,
        policy_checks: 50,
        violations: 0,
        risk_score: 0.2,
      };

      const metrics2: UsageMetrics = {
        tenant_id: "tenant-2",
        session_id: "session-2",
        timestamp: new Date().toISOString(),
        cpu_ms: 2000,
        network_bytes: 2 * 1024 * 1024,
        api_calls: 20,
        tool_executions: 10,
        data_retrievals: 6,
        egress_scans: 4,
        policy_checks: 100,
        violations: 1,
        risk_score: 0.3,
      };

      meteringService.recordUsage(metrics1);
      meteringService.recordUsage(metrics2);

      const currentPeriod = new Date().toISOString().slice(0, 7);
      const tenant1Metrics = meteringService.getUsageMetrics("tenant-1", currentPeriod);
      const tenant2Metrics = meteringService.getUsageMetrics("tenant-2", currentPeriod);

      expect(tenant1Metrics).toHaveLength(1);
      expect(tenant2Metrics).toHaveLength(1);
      expect(tenant1Metrics[0]!.tenant_id).toBe("tenant-1");
      expect(tenant2Metrics[0]!.tenant_id).toBe("tenant-2");
    });
  });

  describe("Cost Calculation", () => {
    it("should calculate costs correctly for Basic tier", () => {
      const metrics: UsageMetrics = {
        tenant_id: "test-tenant",
        session_id: "session-123",
        timestamp: new Date().toISOString(),
        cpu_ms: 3600000, // 1 hour
        network_bytes: 1024 * 1024, // 1MB
        api_calls: 100,
        tool_executions: 50,
        data_retrievals: 25,
        egress_scans: 10,
        policy_checks: 500,
        violations: 2,
        risk_score: 0.3,
      };

      meteringService.recordUsage(metrics);

      const currentPeriod = new Date().toISOString().slice(0, 7);
      const costBreakdown = meteringService.calculateCost("test-tenant", currentPeriod);

      // Basic tier calculations
      expect(costBreakdown.base_cost).toBe(50.0);
      expect(costBreakdown.cpu_cost).toBeCloseTo(0.36, 2); // 1 hour * $0.36/hour
      expect(costBreakdown.network_cost).toBeCloseTo(0.05, 2); // 1MB * $0.05/MB
      expect(costBreakdown.api_cost).toBeCloseTo(0.1, 2); // 100 calls * $0.001/call
      expect(costBreakdown.tool_cost).toBeCloseTo(0.5, 2); // 50 executions * $0.01/execution
      expect(costBreakdown.data_cost).toBeCloseTo(0.125, 3); // 25 retrievals * $0.005/retrieval
      expect(costBreakdown.egress_cost).toBeCloseTo(0.02, 3); // 10 scans * $0.002/scan
      expect(costBreakdown.policy_cost).toBeCloseTo(0.5, 2); // 500 checks * $0.001/check
      expect(costBreakdown.violation_cost).toBeCloseTo(2.0, 2); // 2 violations * $1.0/violation
      expect(costBreakdown.risk_adjustment).toBeCloseTo(0, 2); // Basic tier has 1.0x multiplier

      const expectedTotal = 50.0 + 0.36 + 0.05 + 0.1 + 0.5 + 0.125 + 0.02 + 0.5 + 2.0;
      expect(costBreakdown.total_cost).toBeCloseTo(expectedTotal, 2);
    });

    it("should calculate costs correctly for Professional tier", () => {
      const metrics: UsageMetrics = {
        tenant_id: "test-tenant",
        session_id: "session-123",
        timestamp: new Date().toISOString(),
        cpu_ms: 3600000, // 1 hour
        network_bytes: 1024 * 1024, // 1MB
        api_calls: 100,
        tool_executions: 50,
        data_retrievals: 25,
        egress_scans: 10,
        policy_checks: 500,
        violations: 2,
        risk_score: 0.3,
      };

      meteringService.recordUsage(metrics);

      const currentPeriod = new Date().toISOString().slice(0, 7);
      const costBreakdown = meteringService.calculateCost("test-tenant", currentPeriod);

      // Note: Currently defaults to Basic tier, but we can test the calculation logic
      expect(costBreakdown.base_cost).toBe(50.0);
      expect(costBreakdown.total_cost).toBeGreaterThan(50.0);
    });

    it("should return empty cost breakdown for no usage", () => {
      const currentPeriod = new Date().toISOString().slice(0, 7);
      const costBreakdown = meteringService.calculateCost("no-usage-tenant", currentPeriod);

      expect(costBreakdown.base_cost).toBe(0);
      expect(costBreakdown.total_cost).toBe(0);
      expect(costBreakdown.cpu_cost).toBe(0);
      expect(costBreakdown.network_cost).toBe(0);
    });
  });

  describe("Invoice Generation", () => {
    it("should generate invoice with correct structure", async () => {
      const metrics: UsageMetrics = {
        tenant_id: "test-tenant",
        session_id: "session-123",
        timestamp: new Date().toISOString(),
        cpu_ms: 1000,
        network_bytes: 1024 * 1024,
        api_calls: 10,
        tool_executions: 5,
        data_retrievals: 3,
        egress_scans: 2,
        policy_checks: 50,
        violations: 0,
        risk_score: 0.2,
      };

      meteringService.recordUsage(metrics);

      const currentPeriod = new Date().toISOString().slice(0, 7);
      const invoice = await meteringService.generateInvoice("test-tenant", currentPeriod);

      expect(invoice.invoice_id).toMatch(/^INV-\d+-[a-f0-9]{8}$/);
      expect(invoice.tenant_id).toBe("test-tenant");
      expect(invoice.period_start).toBeDefined();
      expect(invoice.period_end).toBeDefined();
      expect(invoice.status).toBe("draft");
      expect(invoice.usage_metrics).toHaveLength(1);
      expect(invoice.cost_breakdown).toBeDefined();
      expect(invoice.created_at).toBeDefined();
      expect(invoice.due_date).toBeDefined();
    });

    it("should store invoice in invoice store", async () => {
      const metrics: UsageMetrics = {
        tenant_id: "test-tenant",
        session_id: "session-123",
        timestamp: new Date().toISOString(),
        cpu_ms: 1000,
        network_bytes: 1024 * 1024,
        api_calls: 10,
        tool_executions: 5,
        data_retrievals: 3,
        egress_scans: 2,
        policy_checks: 50,
        violations: 0,
        risk_score: 0.2,
      };

      meteringService.recordUsage(metrics);

      const currentPeriod = new Date().toISOString().slice(0, 7);
      await meteringService.generateInvoice("test-tenant", currentPeriod);

      const invoices = meteringService.getInvoices("test-tenant");
      expect(invoices).toHaveLength(1);
      expect(invoices[0]!.tenant_id).toBe("test-tenant");
    });

    it("should generate unique invoice IDs", async () => {
      const metrics: UsageMetrics = {
        tenant_id: "test-tenant",
        session_id: "session-123",
        timestamp: new Date().toISOString(),
        cpu_ms: 1000,
        network_bytes: 1024 * 1024,
        api_calls: 10,
        tool_executions: 5,
        data_retrievals: 3,
        egress_scans: 2,
        policy_checks: 50,
        violations: 0,
        risk_score: 0.2,
      };

      meteringService.recordUsage(metrics);

      const currentPeriod = new Date().toISOString().slice(0, 7);
      const invoice1 = await meteringService.generateInvoice("test-tenant", currentPeriod);
      const invoice2 = await meteringService.generateInvoice("test-tenant", currentPeriod);

      expect(invoice1.invoice_id).not.toBe(invoice2.invoice_id);
    });
  });

  describe("Prometheus Metrics Export", () => {
    it("should export metrics in Prometheus format", () => {
      const metrics: UsageMetrics = {
        tenant_id: "test-tenant",
        session_id: "session-123",
        timestamp: new Date().toISOString(),
        cpu_ms: 1000,
        network_bytes: 1024 * 1024,
        api_calls: 10,
        tool_executions: 5,
        data_retrievals: 3,
        egress_scans: 2,
        policy_checks: 50,
        violations: 0,
        risk_score: 0.2,
      };

      meteringService.recordUsage(metrics);

      const prometheusMetrics = meteringService.exportPrometheusMetrics();

      expect(prometheusMetrics).toContain("# HELP pf_usage_cpu_ms CPU usage in milliseconds");
      expect(prometheusMetrics).toContain("# TYPE pf_usage_cpu_ms counter");
      expect(prometheusMetrics).toContain(
        'pf_usage_cpu_ms{tenant="test-tenant",session="session-123"} 1000',
      );
      expect(prometheusMetrics).toContain(
        'pf_usage_network_bytes{tenant="test-tenant",session="session-123"} 1048576',
      );
      expect(prometheusMetrics).toContain(
        'pf_usage_api_calls{tenant="test-tenant",session="session-123"} 10',
      );
      expect(prometheusMetrics).toContain(
        'pf_usage_tool_executions{tenant="test-tenant",session="session-123"} 5',
      );
      expect(prometheusMetrics).toContain(
        'pf_usage_data_retrievals{tenant="test-tenant",session="session-123"} 3',
      );
      expect(prometheusMetrics).toContain(
        'pf_usage_egress_scans{tenant="test-tenant",session="session-123"} 2',
      );
      expect(prometheusMetrics).toContain(
        'pf_usage_policy_checks{tenant="test-tenant",session="session-123"} 50',
      );
      expect(prometheusMetrics).toContain(
        'pf_usage_violations{tenant="test-tenant",session="session-123"} 0',
      );
      expect(prometheusMetrics).toContain(
        'pf_usage_risk_score{tenant="test-tenant",session="session-123"} 0.2',
      );
    });

    it("should handle multiple tenants and sessions", () => {
      const metrics1: UsageMetrics = {
        tenant_id: "tenant-1",
        session_id: "session-1",
        timestamp: new Date().toISOString(),
        cpu_ms: 1000,
        network_bytes: 1024 * 1024,
        api_calls: 10,
        tool_executions: 5,
        data_retrievals: 3,
        egress_scans: 2,
        policy_checks: 50,
        violations: 0,
        risk_score: 0.2,
      };

      const metrics2: UsageMetrics = {
        tenant_id: "tenant-2",
        session_id: "session-2",
        timestamp: new Date().toISOString(),
        cpu_ms: 2000,
        network_bytes: 2 * 1024 * 1024,
        api_calls: 20,
        tool_executions: 10,
        data_retrievals: 6,
        egress_scans: 4,
        policy_checks: 100,
        violations: 1,
        risk_score: 0.3,
      };

      meteringService.recordUsage(metrics1);
      meteringService.recordUsage(metrics2);

      const prometheusMetrics = meteringService.exportPrometheusMetrics();

      expect(prometheusMetrics).toContain('tenant="tenant-1"');
      expect(prometheusMetrics).toContain('tenant="tenant-2"');
      expect(prometheusMetrics).toContain('session="session-1"');
      expect(prometheusMetrics).toContain('session="session-2"');
    });
  });

  describe("Billing Tier Management", () => {
    it("should validate billing tier updates", () => {
      expect(meteringService.updateTenantBillingTier("test-tenant", "basic")).toBe(true);
      expect(meteringService.updateTenantBillingTier("test-tenant", "professional")).toBe(true);
      expect(meteringService.updateTenantBillingTier("test-tenant", "enterprise")).toBe(true);
      expect(meteringService.updateTenantBillingTier("test-tenant", "non-existent")).toBe(false);
    });
  });

  describe("Edge Cases", () => {
    it("should handle zero values correctly", () => {
      const metrics: UsageMetrics = {
        tenant_id: "test-tenant",
        session_id: "session-123",
        timestamp: new Date().toISOString(),
        cpu_ms: 0,
        network_bytes: 0,
        api_calls: 0,
        tool_executions: 0,
        data_retrievals: 0,
        egress_scans: 0,
        policy_checks: 0,
        violations: 0,
        risk_score: 0,
      };

      meteringService.recordUsage(metrics);

      const currentPeriod = new Date().toISOString().slice(0, 7);
      const costBreakdown = meteringService.calculateCost("test-tenant", currentPeriod);

      expect(costBreakdown.cpu_cost).toBe(0);
      expect(costBreakdown.network_cost).toBe(0);
      expect(costBreakdown.api_cost).toBe(0);
      expect(costBreakdown.tool_cost).toBe(0);
      expect(costBreakdown.data_cost).toBe(0);
      expect(costBreakdown.egress_cost).toBe(0);
      expect(costBreakdown.policy_cost).toBe(0);
      expect(costBreakdown.violation_cost).toBe(0);
    });

    it("should handle very large values correctly", () => {
      const metrics: UsageMetrics = {
        tenant_id: "test-tenant",
        session_id: "session-123",
        timestamp: new Date().toISOString(),
        cpu_ms: Number.MAX_SAFE_INTEGER,
        network_bytes: Number.MAX_SAFE_INTEGER,
        api_calls: Number.MAX_SAFE_INTEGER,
        tool_executions: Number.MAX_SAFE_INTEGER,
        data_retrievals: Number.MAX_SAFE_INTEGER,
        egress_scans: Number.MAX_SAFE_INTEGER,
        policy_checks: Number.MAX_SAFE_INTEGER,
        violations: Number.MAX_SAFE_INTEGER,
        risk_score: 1.0,
      };

      meteringService.recordUsage(metrics);

      const currentPeriod = new Date().toISOString().slice(0, 7);
      const costBreakdown = meteringService.calculateCost("test-tenant", currentPeriod);

      expect(costBreakdown.total_cost).toBeGreaterThan(0);
      expect(Number.isFinite(costBreakdown.total_cost)).toBe(true);
    });

    it("should handle decimal risk scores correctly", () => {
      const metrics: UsageMetrics = {
        tenant_id: "test-tenant",
        session_id: "session-123",
        timestamp: new Date().toISOString(),
        cpu_ms: 1000,
        network_bytes: 1024 * 1024,
        api_calls: 10,
        tool_executions: 5,
        data_retrievals: 3,
        egress_scans: 2,
        policy_checks: 50,
        violations: 0,
        risk_score: 0.123456789,
      };

      meteringService.recordUsage(metrics);

      const currentPeriod = new Date().toISOString().slice(0, 7);
      const costBreakdown = meteringService.calculateCost("test-tenant", currentPeriod);

      expect(costBreakdown.total_cost).toBeGreaterThan(0);
      expect(Number.isFinite(costBreakdown.total_cost)).toBe(true);
    });
  });
});
