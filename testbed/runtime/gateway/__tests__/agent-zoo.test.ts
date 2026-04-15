import { UnifiedGateway } from "../src/unified-gateway";
import { GatewayConfig, Plan } from "../src/types";
import { OpenAIAssistantsRunner } from "../../../agents/openai_assistants/runner";
import { LangChainRunner } from "../../../agents/langchain/runner";
import { LangGraphRunner } from "../../../agents/langgraph/runner";
import { DSPyRunner } from "../../../agents/dspy/runner";

// Mock environment variables
process.env["PF_ENFORCE"] = "false";

describe("Agent-Zoo Connectors (TB-AGENTS)", () => {
  let gateway: UnifiedGateway;
  let config: GatewayConfig;

  beforeAll(async () => {
    // Setup test configuration
    config = {
      port: 3001,
      host: "localhost",
      cors_origins: ["http://localhost:3000"],
      rate_limit: {
        window_ms: 60000,
        max_requests: 1000,
      },
      auth: {
        enabled: false,
      },
      monitoring: {
        enabled: true,
        metrics_port: 9091,
        health_check_interval: 1000,
      },
    };

    gateway = new UnifiedGateway(config);
  });

  describe("Agent Registration", () => {
    it("should register all four agent stacks", async () => {
      // Register all agents
      const openaiRunner = new OpenAIAssistantsRunner();
      const langchainRunner = new LangChainRunner();
      const langgraphRunner = new LangGraphRunner();
      const dspyRunner = new DSPyRunner();

      gateway.registerAgent("openai-assistants", openaiRunner);
      gateway.registerAgent("langchain", langchainRunner);
      gateway.registerAgent("langgraph", langgraphRunner);
      gateway.registerAgent("dspy", dspyRunner);

      // Verify registration
      const metrics = await gateway.getStackMetrics();
      expect(Object.keys(metrics)).toHaveLength(4);
      expect(metrics).toHaveProperty("openai-assistants");
      expect(metrics).toHaveProperty("langchain");
      expect(metrics).toHaveProperty("langgraph");
      expect(metrics).toHaveProperty("dspy");
    });
  });

  describe("Journey Execution Across All Stacks", () => {
    const journeys = [
      "support_triage",
      "expense_approval",
      "sales_outreach",
      "hr_onboarding",
      "dev_triage",
    ];

    const stacks = ["openai-assistants", "langchain", "langgraph", "dspy"];

    const testCases = journeys.flatMap((journey) => stacks.map((stack) => ({ journey, stack })));

    test.each(testCases)(
      "should execute $journey journey on $stack stack",
      async ({ journey, stack }) => {
        const plan = {
          id: `test-${journey}-${stack}`,
          tenant: "acme",
          journey,
          steps: [
            {
              id: "step-1",
              type: "tool_call",
              tool: "slack",
              parameters: { channel: "general", message: "Test message" },
              capability: "read",
              status: "pending",
              timestamp: new Date().toISOString(),
            },
          ],
          metadata: {
            version: "1.0.0",
            agent: stack,
            model: "gpt-4",
            confidence: 0.8,
            risk_level: "low",
            tags: ["test"],
            context: { test: true },
          },
          timestamp: new Date().toISOString(),
          expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
        };

        const context = {
          tenant: "acme",
          session_id: "test-session",
          request_id: `req-${Date.now()}`,
          timestamp: new Date().toISOString(),
          metadata: { test: true },
        };

        const result = await gateway.executePlan(stack, plan as Plan, context);

        // Verify execution result
        expect(result.success).toBe(true);
        expect(result.plan_id).toBe(plan.id);
        expect(result.execution_time).toBeGreaterThan(0);
        expect(result.steps_completed).toBeGreaterThan(0);
        expect(result.traces).toHaveLength(1);

        // Verify normalized trace
        const trace = result.traces[0]!;
        expect(trace.plan_id).toBe(plan.id);
        expect(trace.agent_stack).toBe(stack);
        expect(trace.journey).toBe(journey);
        expect(trace.tenant).toBe("acme");
        expect(trace.cert_id).toBeDefined();
        expect(trace.timings).toBeDefined();
        expect(trace.metadata).toBeDefined();
        expect(trace.metadata.shadow_mode).toBe(true);
        expect(trace.metadata.enforce_policies).toBe(false);
      },
      30000, // 30 second timeout
    );
  });

  describe("Normalized Trace Export Schema", () => {
    it("should export consistent trace schema across all stacks", async () => {
      const journey = "support_triage";
      const tenant = "acme";

      const traces = await gateway.exportJourneyTraces(journey, tenant);

      // Verify trace structure
      if (traces.length > 0) {
        const trace = traces[0];
        expect(trace).toHaveProperty("plan_id");
        expect(trace).toHaveProperty("agent_stack");
        expect(trace).toHaveProperty("journey");
        expect(trace).toHaveProperty("tenant");
        expect(trace).toHaveProperty("steps");
        expect(trace).toHaveProperty("receipts");
        expect(trace).toHaveProperty("cert_id");
        expect(trace).toHaveProperty("timings");
        expect(trace).toHaveProperty("metadata");

        // Verify timings structure
        expect(trace.timings).toHaveProperty("plan_start");
        expect(trace.timings).toHaveProperty("plan_end");
        expect(trace.timings).toHaveProperty("total_duration_ms");
        expect(trace.timings).toHaveProperty("step_durations");

        // Verify metadata structure
        expect(trace.metadata).toHaveProperty("model");
        expect(trace.metadata).toHaveProperty("confidence");
        expect(trace.metadata).toHaveProperty("risk_level");
        expect(trace.metadata).toHaveProperty("capabilities_used");
        expect(trace.metadata).toHaveProperty("shadow_mode");
        expect(trace.metadata).toHaveProperty("enforce_policies");
      }
    });
  });

  describe("Toggle Shadow vs Enforce Mode", () => {
    it("should respect PF_ENFORCE environment variable", () => {
      // Test shadow mode (default)
      expect(gateway.isEnforceMode()).toBe(false);

      // Test enforce mode
      process.env["PF_ENFORCE"] = "true";
      const enforceGateway = new UnifiedGateway(config);
      expect(enforceGateway.isEnforceMode()).toBe(true);

      // Reset for other tests
      process.env["PF_ENFORCE"] = "false";
    });
  });

  describe("Comparable Metrics", () => {
    it("should provide comparable metrics across all stacks", async () => {
      const metrics = await gateway.getStackMetrics();

      // Verify all stacks have metrics
      for (const stack of Object.keys(metrics)) {
        expect(metrics[stack]).toHaveProperty("status");
        expect(metrics[stack]).toHaveProperty("metrics");
        expect(metrics[stack]).toHaveProperty("timestamp");

        // Verify status structure
        const status = metrics[stack].status;
        expect(status).toHaveProperty("healthy");
        expect(status).toHaveProperty("version");
        expect(status).toHaveProperty("uptime");
        expect(status).toHaveProperty("last_heartbeat");
        expect(status).toHaveProperty("active_plans");
        expect(status).toHaveProperty("total_executions");
        expect(status).toHaveProperty("error_rate");
      }
    });

    it("should track execution metrics consistently", async () => {
      // Execute a simple plan on each stack
      const plan = {
        id: "metrics-test",
        tenant: "acme",
        journey: "support_triage",
        steps: [],
        metadata: {
          version: "1.0.0",
          agent: "test",
          model: "gpt-4",
          confidence: 0.8,
          risk_level: "low",
          tags: [],
          context: {},
        },
        timestamp: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
      };

      const context = {
        tenant: "acme",
        session_id: "metrics-test-session",
        request_id: `metrics-req-${Date.now()}`,
        timestamp: new Date().toISOString(),
        metadata: {},
      };

      // Execute on all stacks
      for (const stack of ["openai-assistants", "langchain", "langgraph", "dspy"]) {
        const result = await gateway.executePlan(stack, plan as Plan, context);
        expect(result.success).toBe(true);
        expect(result.execution_time).toBeGreaterThan(0);
      }

      // Verify metrics are updated
      const updatedMetrics = await gateway.getStackMetrics();
      for (const stack of Object.keys(updatedMetrics)) {
        const status = updatedMetrics[stack].status;
        expect(status.total_executions).toBeGreaterThan(0);
        expect(status.uptime).toBeGreaterThan(0);
      }
    });
  });

  describe("Health Status", () => {
    it("should provide health status for all stacks", async () => {
      const health = await gateway.getHealthStatus();

      // Verify all stacks have health status
      expect(Object.keys(health)).toHaveLength(4);
      for (const stack of Object.keys(health)) {
        expect(typeof health[stack]).toBe("boolean");
      }
    });
  });

  describe("Configuration Management", () => {
    it("should provide gateway configuration", () => {
      const gatewayConfig = gateway.getConfig();
      expect(gatewayConfig).toEqual(config);
    });
  });

  describe("Error Handling", () => {
    it("should handle invalid stack gracefully", async () => {
      const plan = {
        id: "error-test",
        tenant: "acme",
        journey: "support_triage",
        steps: [],
        metadata: {
          version: "1.0.0",
          agent: "test",
          model: "gpt-4",
          confidence: 0.8,
          risk_level: "low",
          tags: [],
          context: {},
        },
        timestamp: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
      };

      const context = {
        tenant: "acme",
        session_id: "error-test-session",
        request_id: `error-req-${Date.now()}`,
        timestamp: new Date().toISOString(),
        metadata: {},
      };

      await expect(gateway.executePlan("invalid-stack", plan as Plan, context)).rejects.toThrow(
        "Unsupported agent stack: invalid-stack",
      );
    });

    it("should handle plan validation errors", async () => {
      const invalidPlan = {
        id: "invalid-plan",
        tenant: "invalid-tenant",
        journey: "invalid-journey",
        steps: [],
        metadata: {},
        timestamp: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
      };

      const context = {
        tenant: "acme",
        session_id: "error-test-session",
        request_id: `error-req-${Date.now()}`,
        timestamp: new Date().toISOString(),
        metadata: {},
      };

      // This should fail validation but not crash
      const result = await gateway.executePlan(
        "openai-assistants",
        invalidPlan as unknown as Plan,
        context,
      );
      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });
  });

  describe("Performance Requirements", () => {
    it("should meet performance requirements for journey execution", async () => {
      const plan = {
        id: "perf-test",
        tenant: "acme",
        journey: "support_triage",
        steps: [
          {
            id: "step-1",
            type: "tool_call",
            tool: "slack",
            parameters: { channel: "general", message: "Performance test" },
            capability: "read",
            status: "pending",
            timestamp: new Date().toISOString(),
          },
        ],
        metadata: {
          version: "1.0.0",
          agent: "test",
          model: "gpt-4",
          confidence: 0.8,
          risk_level: "low",
          tags: [],
          context: {},
        },
        timestamp: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
      };

      const context = {
        tenant: "acme",
        session_id: "perf-test-session",
        request_id: `perf-req-${Date.now()}`,
        timestamp: new Date().toISOString(),
        metadata: {},
      };

      // Test performance on all stacks
      const startTime = Date.now();
      const results = [];

      for (const stack of ["openai-assistants", "langchain", "langgraph", "dspy"]) {
        const result = await gateway.executePlan(stack, plan as Plan, context);
        results.push({ stack, result });
      }

      const totalTime = Date.now() - startTime;
      const avgTime = totalTime / results.length;

      // Performance requirements (adjust as needed)
      expect(avgTime).toBeLessThan(10000); // Average < 10 seconds
      expect(totalTime).toBeLessThan(60000); // Total < 60 seconds

      // Verify all executions succeeded
      for (const { stack, result } of results) {
        expect(result.success).toBe(true);
        expect(result.execution_time).toBeLessThan(15000); // Individual < 15 seconds
      }
    });
  });
});
