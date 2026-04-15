import { ToolCall, ToolResult } from "../../contracts/types";
import { ToolEmulator } from "../base/emulator";

export interface CapabilityCheck {
  required: string[];
  provided: string[];
  valid: boolean;
  missing: string[];
  excess: string[];
}

export interface CapabilityLog {
  timestamp: string;
  tool_call_id: string;
  tenant: string;
  user: string;
  tool: string;
  required_capabilities: string[];
  provided_capabilities: string[];
  result: "ALLOW" | "DENY_CAP_MISS" | "DENY_QUOTA" | "DENY_RATE_LIMIT";
  metadata: Record<string, any>;
}

export interface QuotaConfig {
  daily_limit: number;
  monthly_limit: number;
  burst_limit: number;
  reset_time: string; // HH:MM format
}

export class CapabilityBroker {
  private emulators: Map<string, ToolEmulator> = new Map();
  private capabilityLogs: CapabilityLog[] = [];
  private quotas: Map<string, QuotaConfig> = new Map();
  private usage: Map<string, { daily: number; monthly: number; burst: number; lastReset: number }> =
    new Map();
  private rateLimitWindows: Map<string, { start: number; count: number }> = new Map();

  constructor() {
    this.initializeDefaultQuotas();
  }

  private initializeDefaultQuotas(): void {
    // Default quotas for common tools
    const defaultQuotas: Record<string, QuotaConfig> = {
      slack: {
        daily_limit: 1000,
        monthly_limit: 30000,
        burst_limit: 100,
        reset_time: "00:00",
      },
      stripe: {
        daily_limit: 100,
        monthly_limit: 3000,
        burst_limit: 20,
        reset_time: "00:00",
      },
      email: {
        daily_limit: 500,
        monthly_limit: 15000,
        burst_limit: 50,
        reset_time: "00:00",
      },
    };

    Object.entries(defaultQuotas).forEach(([tool, quota]) => {
      this.quotas.set(tool, quota);
    });
  }

  /**
   * Register a tool emulator with the broker
   */
  registerEmulator(emulator: ToolEmulator): void {
    this.emulators.set(emulator.name, emulator);

    // Initialize usage tracking for this emulator
    this.usage.set(emulator.name, {
      daily: 0,
      monthly: 0,
      burst: 0,
      lastReset: Date.now(),
    });

    this.rateLimitWindows.set(emulator.name, {
      start: Date.now(),
      count: 0,
    });
  }

  /**
   * Check if a tool call has the required capabilities
   */
  checkCapability(call: ToolCall): CapabilityCheck {
    const emulator = this.emulators.get(call.tool.split(".")[0]);
    if (!emulator) {
      return {
        required: [],
        provided: call.capability ? [call.capability] : [],
        valid: false,
        missing: [],
        excess: [],
      };
    }

    const requiredCapabilities = emulator.capabilities;
    const providedCapabilities = call.capability ? [call.capability] : [];

    const missing = requiredCapabilities.filter((cap) => !providedCapabilities.includes(cap));
    const excess = providedCapabilities.filter((cap) => !requiredCapabilities.includes(cap));

    return {
      required: requiredCapabilities,
      provided: providedCapabilities,
      valid: missing.length === 0,
      missing,
      excess,
    };
  }

  /**
   * Check if a tool call is within quota limits
   */
  checkQuota(call: ToolCall): { allowed: boolean; reason?: string } {
    const toolName = call.tool.split(".")[0];
    const quota = this.quotas.get(toolName);

    if (!quota) {
      return { allowed: true }; // No quota configured
    }

    const usage = this.usage.get(toolName);
    if (!usage) {
      return { allowed: false, reason: "Usage tracking not initialized" };
    }

    // Check if we need to reset counters
    this.checkAndResetCounters(toolName, quota);

    // Check daily limit
    if (usage.daily >= quota.daily_limit) {
      return { allowed: false, reason: "Daily quota exceeded" };
    }

    // Check monthly limit
    if (usage.monthly >= quota.monthly_limit) {
      return { allowed: false, reason: "Monthly quota exceeded" };
    }

    // Check burst limit
    if (usage.burst >= quota.burst_limit) {
      return { allowed: false, reason: "Burst quota exceeded" };
    }

    return { allowed: true };
  }

  /**
   * Check rate limiting
   */
  checkRateLimit(call: ToolCall): { allowed: boolean; reason?: string } {
    const toolName = call.tool.split(".")[0];
    const quota = this.quotas.get(toolName);

    if (!quota) {
      return { allowed: true }; // No rate limiting configured
    }

    const window = this.rateLimitWindows.get(toolName);
    if (!window) {
      return { allowed: false, reason: "Rate limit window not initialized" };
    }

    const now = Date.now();
    const windowStart = Math.floor(now / 60000) * 60000; // 1-minute windows

    if (windowStart !== window.start) {
      // New window, reset counter
      window.start = windowStart;
      window.count = 1;
      return { allowed: true };
    }

    if (window.count >= quota.burst_limit) {
      return { allowed: false, reason: "Rate limit exceeded" };
    }

    window.count++;
    return { allowed: true };
  }

  /**
   * Execute a tool call with capability and quota enforcement
   */
  async execute(call: ToolCall): Promise<ToolResult> {
    const startTime = Date.now();

    // Check capabilities
    const capabilityCheck = this.checkCapability(call);
    if (!capabilityCheck.valid) {
      const log = this.createCapabilityLog(call, "DENY_CAP_MISS", {
        missing_capabilities: capabilityCheck.missing,
        required_capabilities: capabilityCheck.required,
      });
      this.capabilityLogs.push(log);

      return {
        id: this.generateId(),
        success: false,
        error: `Missing required capabilities: ${capabilityCheck.missing.join(", ")}`,
        capability_consumed: call.capability,
        timestamp: new Date().toISOString(),
      };
    }

    // Check quota
    const quotaCheck = this.checkQuota(call);
    if (!quotaCheck.allowed) {
      const log = this.createCapabilityLog(call, "DENY_QUOTA", {
        quota_reason: quotaCheck.reason,
      });
      this.capabilityLogs.push(log);

      return {
        id: this.generateId(),
        success: false,
        error: `Quota exceeded: ${quotaCheck.reason}`,
        capability_consumed: call.capability,
        timestamp: new Date().toISOString(),
      };
    }

    // Check rate limiting
    const rateLimitCheck = this.checkRateLimit(call);
    if (!rateLimitCheck.allowed) {
      const log = this.createCapabilityLog(call, "DENY_RATE_LIMIT", {
        rate_limit_reason: rateLimitCheck.reason,
      });
      this.capabilityLogs.push(log);

      return {
        id: this.generateId(),
        success: false,
        error: `Rate limit exceeded: ${rateLimitCheck.reason}`,
        capability_consumed: call.capability,
        timestamp: new Date().toISOString(),
      };
    }

    // Execute the tool call
    try {
      const emulator = this.emulators.get(call.tool.split(".")[0]);
      if (!emulator) {
        throw new Error(`Tool emulator not found: ${call.tool}`);
      }

      // Update usage counters
      this.updateUsage(call.tool.split(".")[0]);

      const result = await emulator.execute(call);

      // Log successful execution
      const log = this.createCapabilityLog(call, "ALLOW", {
        execution_time: Date.now() - startTime,
        result_id: result.id,
      });
      this.capabilityLogs.push(log);

      return result;
    } catch (error) {
      const log = this.createCapabilityLog(call, "ALLOW", {
        execution_time: Date.now() - startTime,
        error: error instanceof Error ? error.message : "Unknown error",
      });
      this.capabilityLogs.push(log);

      throw error;
    }
  }

  /**
   * Get capability logs
   */
  getCapabilityLogs(filter?: {
    tenant?: string;
    tool?: string;
    result?: string;
    startTime?: Date;
    endTime?: Date;
  }): CapabilityLog[] {
    let logs = [...this.capabilityLogs];

    if (filter?.tenant) {
      logs = logs.filter((log) => log.tenant === filter.tenant);
    }

    if (filter?.tool) {
      logs = logs.filter((log) => log.tool === filter.tool);
    }

    if (filter?.result) {
      logs = logs.filter((log) => log.result === filter.result);
    }

    if (filter?.startTime) {
      logs = logs.filter((log) => new Date(log.timestamp) >= filter.startTime!);
    }

    if (filter?.endTime) {
      logs = logs.filter((log) => new Date(log.timestamp) <= filter.endTime!);
    }

    return logs;
  }

  /**
   * Get usage statistics
   */
  getUsageStats(toolName?: string): Record<string, any> {
    if (toolName) {
      const usage = this.usage.get(toolName);
      const quota = this.quotas.get(toolName);

      if (!usage || !quota) {
        return {};
      }

      return {
        tool: toolName,
        daily_usage: usage.daily,
        daily_limit: quota.daily_limit,
        daily_remaining: quota.daily_limit - usage.daily,
        monthly_usage: usage.monthly,
        monthly_limit: quota.monthly_limit,
        monthly_remaining: quota.monthly_limit - usage.monthly,
        burst_usage: usage.burst,
        burst_limit: quota.burst_limit,
        burst_remaining: quota.burst_limit - usage.burst,
      };
    }

    const stats: Record<string, any> = {};
    this.usage.forEach((usage, tool) => {
      stats[tool] = this.getUsageStats(tool);
    });

    return stats;
  }

  /**
   * Set quota configuration for a tool
   */
  setQuota(toolName: string, quota: QuotaConfig): void {
    this.quotas.set(toolName, quota);

    // Initialize usage tracking if not exists
    if (!this.usage.has(toolName)) {
      this.usage.set(toolName, {
        daily: 0,
        monthly: 0,
        burst: 0,
        lastReset: Date.now(),
      });
    }
  }

  private createCapabilityLog(
    call: ToolCall,
    result: CapabilityLog["result"],
    metadata: Record<string, any> = {},
  ): CapabilityLog {
    return {
      timestamp: new Date().toISOString(),
      tool_call_id: call.id,
      tenant: call.tenant,
      user: call.parameters.user || "unknown",
      tool: call.tool,
      required_capabilities: this.emulators.get(call.tool.split(".")[0])?.capabilities || [],
      provided_capabilities: call.capability ? [call.capability] : [],
      result,
      metadata,
    };
  }

  private checkAndResetCounters(toolName: string, quota: QuotaConfig): void {
    const usage = this.usage.get(toolName);
    if (!usage) return;

    const now = Date.now();
    const resetTime = this.parseResetTime(quota.reset_time);

    // Check daily reset
    if (this.isNewDay(usage.lastReset, now)) {
      usage.daily = 0;
      usage.lastReset = now;
    }

    // Check monthly reset (simplified - assumes 30 days)
    if (this.isNewMonth(usage.lastReset, now)) {
      usage.monthly = 0;
    }

    // Reset burst counter every minute
    const window = this.rateLimitWindows.get(toolName);
    if (window) {
      const windowStart = Math.floor(now / 60000) * 60000;
      if (windowStart !== window.start) {
        window.start = windowStart;
        window.count = 0;
        usage.burst = 0;
      }
    }
  }

  private updateUsage(toolName: string): void {
    const usage = this.usage.get(toolName);
    if (usage) {
      usage.daily++;
      usage.monthly++;
      usage.burst++;
    }
  }

  private parseResetTime(timeStr: string): { hour: number; minute: number } {
    const [hour, minute] = timeStr.split(":").map(Number);
    return { hour, minute };
  }

  private isNewDay(lastReset: number, now: number): boolean {
    const lastDate = new Date(lastReset);
    const currentDate = new Date(now);
    return (
      lastDate.getDate() !== currentDate.getDate() ||
      lastDate.getMonth() !== currentDate.getMonth() ||
      lastDate.getFullYear() !== currentDate.getFullYear()
    );
  }

  private isNewMonth(lastReset: number, now: number): boolean {
    const lastDate = new Date(lastReset);
    const currentDate = new Date(now);
    return (
      lastDate.getMonth() !== currentDate.getMonth() ||
      lastDate.getFullYear() !== currentDate.getFullYear()
    );
  }

  private generateId(): string {
    return `cap_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}
