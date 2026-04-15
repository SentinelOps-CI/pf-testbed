import {
  AgentRunner,
  Plan,
  ToolCall,
  ToolResult,
  VerificationResult,
  AgentConfig,
  AgentStatus,
  PlanValidationError,
  CapabilityError,
  ReceiptError,
  SUPPORTED_JOURNEYS,
  SUPPORTED_TOOLS,
  AccessReceipt,
} from "./types";

/**
 * Base agent runner implementation that provides common functionality
 * for all agent runners in the testbed
 */
export abstract class BaseAgentRunner implements AgentRunner {
  public name: string;
  public version: string;
  public capabilities: string[];

  protected config: AgentConfig;
  protected startTime: number;
  protected activePlans: Set<string>;
  protected executionCount: number;
  protected errorCount: number;
  protected lastHeartbeat: number;

  constructor(name: string, version: string, capabilities: string[]) {
    this.name = name;
    this.version = version;
    this.capabilities = capabilities;
    this.startTime = Date.now();
    this.activePlans = new Set();
    this.executionCount = 0;
    this.errorCount = 0;
    this.lastHeartbeat = Date.now();
  }

  /**
   * Abstract methods that must be implemented by specific agent runners
   */
  abstract plan(json: any): Promise<Plan>;
  abstract executeTool(call: ToolCall): Promise<ToolResult>;

  /**
   * Default plan verification implementation
   */
  async verifyPlan(plan: Plan): Promise<VerificationResult> {
    const errors: string[] = [];
    const warnings: string[] = [];
    const receipts: AccessReceipt[] = [];

    try {
      // Validate journey
      if (!SUPPORTED_JOURNEYS.includes(plan.journey as any)) {
        errors.push(`Unsupported journey: ${plan.journey}`);
      }

      // Validate tenant
      if (!plan.tenant || !["acme", "globex"].includes(plan.tenant)) {
        errors.push(`Invalid tenant: ${plan.tenant}`);
      }

      // Validate plan structure
      if (!plan.id || !plan.steps || !Array.isArray(plan.steps)) {
        errors.push("Invalid plan structure: missing id or steps");
      }

      // Validate steps
      for (const step of plan.steps) {
        if (!step.id || !step.type || !step.timestamp) {
          errors.push(`Invalid step structure in step ${step.id}`);
          continue;
        }

        // Validate tool calls
        if (step.type === "tool_call") {
          if (!step.tool || !SUPPORTED_TOOLS.includes(step.tool as any)) {
            errors.push(`Unsupported tool in step ${step.id}: ${step.tool}`);
          }

          if (!step.capability) {
            errors.push(`Missing capability in step ${step.id}`);
          }
        }

        // Validate receipts for retrieval steps
        if (step.type === "retrieval" && !step.receipt) {
          errors.push(`Missing receipt in retrieval step ${step.id}`);
        }
      }

      // Validate metadata
      if (!plan.metadata || !plan.metadata.agent || !plan.metadata.model) {
        errors.push("Invalid metadata: missing agent or model information");
      }

      // Validate confidence and risk level
      if (
        plan.metadata?.confidence &&
        (plan.metadata.confidence < 0 || plan.metadata.confidence > 1)
      ) {
        errors.push("Invalid confidence: must be between 0 and 1");
      }

      if (
        plan.metadata?.risk_level &&
        !["low", "medium", "high", "critical"].includes(plan.metadata.risk_level)
      ) {
        errors.push("Invalid risk level");
      }

      // Validate expiration
      if (plan.expiresAt && new Date(plan.expiresAt) <= new Date()) {
        errors.push("Plan has expired");
      }
    } catch (error) {
      errors.push(
        `Verification error: ${error instanceof Error ? error.message : "Unknown error"}`,
      );
    }

    return {
      plan_id: plan.id,
      valid: errors.length === 0,
      errors,
      warnings,
      receipts,
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Default plan execution implementation
   */
  async executePlan(plan: Plan): Promise<Plan> {
    const startTime = Date.now();

    try {
      // Verify plan first
      const verification = await this.verifyPlan(plan);
      if (!verification.valid) {
        throw new PlanValidationError("Plan validation failed", verification.errors);
      }

      // Track active plan
      this.activePlans.add(plan.id);
      this.executionCount++;

      // Execute steps sequentially
      for (const step of plan.steps) {
        step.status = "executing";
        step.timestamp = new Date().toISOString();

        try {
          if (step.type === "tool_call") {
            const toolCall: ToolCall = {
              id: step.id,
              tool: step.tool!,
              parameters: step.parameters || {},
              capability: step.capability!,
              timestamp: step.timestamp,
              tenant: plan.tenant,
            };

            const result = await this.executeTool(toolCall);
            step.result = result.result;
            step.status = "completed";
            step.duration = Date.now() - startTime;
          } else if (step.type === "decision") {
            // Handle decision steps (agent-specific logic)
            step.status = "completed";
            step.duration = Date.now() - startTime;
          } else if (step.type === "retrieval") {
            // Validate receipt
            if (!step.receipt) {
              throw new ReceiptError("Missing receipt for retrieval step", step.id);
            }
            step.status = "completed";
            step.duration = Date.now() - startTime;
          } else if (step.type === "verification") {
            // Handle verification steps
            step.status = "completed";
            step.duration = Date.now() - startTime;
          }
        } catch (error) {
          step.status = "failed";
          step.error = error instanceof Error ? error.message : "Unknown error";
          step.duration = Date.now() - startTime;

          // Log error but continue with other steps
          console.error(`Step ${step.id} failed:`, error);
        }
      }

      // Update last heartbeat
      this.lastHeartbeat = Date.now();

      return plan;
    } catch (error) {
      this.errorCount++;
      throw error;
    } finally {
      // Remove from active plans
      this.activePlans.delete(plan.id);
    }
  }

  /**
   * Default trace export implementation
   */
  async exportTrace(plan_id: string): Promise<any> {
    // This is a basic implementation - specific runners can override
    return {
      plan_id,
      agent: this.name,
      version: this.version,
      timestamp: new Date().toISOString(),
      metadata: {
        runner: this.name,
        capabilities: this.capabilities,
        config: this.config,
      },
    };
  }

  /**
   * Default configuration method
   */
  async configure(config: AgentConfig): Promise<void> {
    this.config = config;

    // Validate configuration
    if (config.timeout <= 0) {
      throw new Error("Timeout must be positive");
    }

    if (config.max_retries < 0) {
      throw new Error("Max retries must be non-negative");
    }
  }

  /**
   * Default status method
   */
  async getStatus(): Promise<AgentStatus> {
    const now = Date.now();
    const uptime = now - this.startTime;

    return {
      healthy: this.activePlans.size < 100, // Simple health check
      version: this.version,
      uptime,
      last_heartbeat: new Date(this.lastHeartbeat).toISOString(),
      active_plans: this.activePlans.size,
      total_executions: this.executionCount,
      error_rate: this.executionCount > 0 ? this.errorCount / this.executionCount : 0,
    };
  }

  /**
   * Utility method to validate capabilities
   */
  protected validateCapability(required: string, available: string[]): void {
    if (!available.includes(required)) {
      throw new CapabilityError(`Required capability not available: ${required}`, required);
    }
  }

  /**
   * Utility method to generate unique IDs
   */
  protected generateId(): string {
    return `${this.name}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Utility method to check if plan is expired
   */
  protected isPlanExpired(plan: Plan): boolean {
    if (!plan.expiresAt) return false;
    return new Date(plan.expiresAt) <= new Date();
  }

  /**
   * Utility method to log execution metrics
   */
  protected logMetrics(plan: Plan, executionTime: number): void {
    console.log(`Plan ${plan.id} executed in ${executionTime}ms`, {
      journey: plan.journey,
      tenant: plan.tenant,
      steps: plan.steps.length,
      agent: this.name,
      timestamp: new Date().toISOString(),
    });
  }
}
