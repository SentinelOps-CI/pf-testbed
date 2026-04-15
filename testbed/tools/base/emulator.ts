import { ToolCall, ToolResult, ToolTrace } from "../../contracts/types";

/**
 * Base interface for all tool emulators
 */
export interface ToolEmulator {
  name: string;
  version: string;
  capabilities: string[];

  // Core methods
  execute(call: ToolCall): Promise<ToolResult>;
  validateCapability(capability: string): boolean;
  getStatus(): ToolEmulatorStatus;

  // Configuration
  configure(config: ToolEmulatorConfig): Promise<void>;

  // Mock data management
  setMockData(data: any): void;
  getMockData(): any;
  clearMockData(): void;
}

/**
 * Configuration for tool emulators
 */
export interface ToolEmulatorConfig {
  mode: "mock" | "real" | "hybrid";
  rate_limit?: {
    requests_per_minute: number;
    burst_size: number;
  };
  timeout: number;
  max_retries: number;
  seed?: string; // For deterministic responses
  tenant: string;
}

/**
 * Status information for tool emulators
 */
export interface ToolEmulatorStatus {
  healthy: boolean;
  mode: string;
  uptime: number;
  total_calls: number;
  success_rate: number;
  last_call: string;
  rate_limit_remaining: number;
}

/**
 * Base implementation for tool emulators
 */
export abstract class BaseToolEmulator implements ToolEmulator {
  public name: string;
  public version: string;
  public capabilities: string[];

  protected config: ToolEmulatorConfig;
  protected startTime: number;
  protected totalCalls: number;
  protected successfulCalls: number;
  protected lastCallTime: number;
  protected mockData: any;
  protected rateLimitWindow: { start: number; count: number } = {
    start: 0,
    count: 0,
  };

  constructor(name: string, version: string, capabilities: string[]) {
    this.name = name;
    this.version = version;
    this.capabilities = capabilities;
    this.startTime = Date.now();
    this.totalCalls = 0;
    this.successfulCalls = 0;
    this.lastCallTime = 0;
    this.mockData = {};
  }

  /**
   * Execute a tool call
   */
  async execute(call: ToolCall): Promise<ToolResult> {
    const startTime = Date.now();

    try {
      // Validate capability
      if (!this.validateCapability(call.capability)) {
        throw new Error(`Insufficient capability: ${call.capability}`);
      }

      // Check rate limiting
      if (!this.checkRateLimit()) {
        throw new Error("Rate limit exceeded");
      }

      // Update call tracking
      this.totalCalls++;
      this.lastCallTime = startTime;

      // Execute based on mode
      let result: any;
      if (this.config.mode === "mock") {
        result = await this.executeMock(call);
      } else if (this.config.mode === "real") {
        result = await this.executeReal(call);
      } else if (this.config.mode === "hybrid") {
        // Use real for some operations, mock for others
        result = await this.executeHybrid(call);
      } else {
        throw new Error(`Unknown execution mode: ${this.config.mode}`);
      }

      // Create tool trace
      const trace: ToolTrace = {
        id: this.generateId(),
        tool_call_id: call.id,
        inputs: call.parameters,
        outputs: result,
        metadata: {
          tool: call.tool,
          capability: call.capability,
          tenant: call.tenant,
          mode: this.config.mode,
          execution_time: Date.now() - startTime,
          timestamp: call.timestamp,
        },
        replayable: this.config.mode === "mock",
      };

      // Update success tracking
      this.successfulCalls++;

      return {
        id: this.generateId(),
        success: true,
        result,
        capability_consumed: call.capability,
        trace,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      return {
        id: this.generateId(),
        success: false,
        error: error instanceof Error ? error.message : "Unknown error",
        capability_consumed: call.capability,
        trace: {
          id: this.generateId(),
          tool_call_id: call.id,
          inputs: call.parameters,
          outputs: {},
          metadata: {
            tool: call.tool,
            capability: call.capability,
            tenant: call.tenant,
            mode: this.config.mode,
            error: error instanceof Error ? error.message : "Unknown error",
            timestamp: call.timestamp,
          },
          replayable: false,
        },
        timestamp: new Date().toISOString(),
      };
    }
  }

  /**
   * Validate if the capability is sufficient for this tool
   */
  validateCapability(capability: string): boolean {
    return this.capabilities.includes(capability);
  }

  /**
   * Get emulator status
   */
  getStatus(): ToolEmulatorStatus {
    const now = Date.now();
    const uptime = now - this.startTime;

    // Calculate rate limit remaining
    let rateLimitRemaining = 0;
    if (this.config.rate_limit) {
      const windowStart = Math.floor(now / 60000) * 60000; // 1-minute windows
      if (windowStart === this.rateLimitWindow.start) {
        rateLimitRemaining = Math.max(
          0,
          this.config.rate_limit.requests_per_minute - this.rateLimitWindow.count,
        );
      } else {
        rateLimitRemaining = this.config.rate_limit.requests_per_minute;
      }
    }

    return {
      healthy: this.totalCalls < 10000, // Simple health check
      mode: this.config.mode,
      uptime,
      total_calls: this.totalCalls,
      success_rate: this.totalCalls > 0 ? this.successfulCalls / this.totalCalls : 1,
      last_call: new Date(this.lastCallTime).toISOString(),
      rate_limit_remaining: rateLimitRemaining,
    };
  }

  /**
   * Configure the emulator
   */
  async configure(config: ToolEmulatorConfig): Promise<void> {
    this.config = config;

    // Validate configuration
    if (config.timeout <= 0) {
      throw new Error("Timeout must be positive");
    }

    if (config.max_retries < 0) {
      throw new Error("Max retries must be non-negative");
    }

    if (config.rate_limit && config.rate_limit.requests_per_minute <= 0) {
      throw new Error("Rate limit must be positive");
    }
  }

  /**
   * Set mock data for deterministic responses
   */
  setMockData(data: any): void {
    this.mockData = { ...this.mockData, ...data };
  }

  /**
   * Get current mock data
   */
  getMockData(): any {
    return { ...this.mockData };
  }

  /**
   * Clear all mock data
   */
  clearMockData(): void {
    this.mockData = {};
  }

  /**
   * Check rate limiting
   */
  protected checkRateLimit(): boolean {
    if (!this.config.rate_limit) {
      return true;
    }

    const now = Date.now();
    const windowStart = Math.floor(now / 60000) * 60000; // 1-minute windows

    if (windowStart !== this.rateLimitWindow.start) {
      // New window, reset counter
      this.rateLimitWindow = { start: windowStart, count: 1 };
      return true;
    }

    if (this.rateLimitWindow.count >= this.config.rate_limit.requests_per_minute) {
      return false;
    }

    this.rateLimitWindow.count++;
    return true;
  }

  /**
   * Generate a unique ID
   */
  protected generateId(): string {
    return `${this.name}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Abstract methods that must be implemented by specific emulators
   */
  protected abstract executeMock(call: ToolCall): Promise<any>;
  protected abstract executeReal(call: ToolCall): Promise<any>;
  protected abstract executeHybrid(call: ToolCall): Promise<any>;

  /**
   * Utility method to get deterministic response based on seed
   */
  protected getDeterministicResponse(key: string, fallback: any): any {
    if (!this.config.seed) {
      return fallback;
    }

    // Simple deterministic hash based on seed and key
    const hash = this.simpleHash(this.config.seed + key);
    const mockData = this.mockData[key];

    if (Array.isArray(mockData)) {
      return mockData[hash % mockData.length];
    }

    return mockData || fallback;
  }

  /**
   * Simple hash function for deterministic responses
   */
  private simpleHash(str: string): number {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash);
  }

  /**
   * Utility method to simulate network delay
   */
  protected async simulateDelay(): Promise<void> {
    if (this.config.mode === "mock") {
      const delay = Math.random() * 100 + 50; // 50-150ms for mock mode
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }

  /**
   * Utility method to simulate errors based on configuration
   */
  protected shouldSimulateError(): boolean {
    if (!this.config.seed) {
      return false;
    }

    // Use seed to deterministically simulate errors
    const hash = this.simpleHash(this.config.seed + Date.now().toString());
    return hash % 100 < 5; // 5% error rate
  }
}
