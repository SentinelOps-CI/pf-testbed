import { createHash } from "crypto";
import { z } from "zod";

// Fetch emulator for TB-08
// Provides deterministic, seeded mocks with real mode capabilities

export const FetchRequestSchema = z.object({
  url: z.string().url(),
  method: z.enum(["GET", "POST", "PUT", "DELETE", "PATCH"]).default("GET"),
  headers: z.record(z.string()).optional(),
  body: z.any().optional(),
  tenant: z.string().min(1),
  capability_token: z.string().min(1),
  enforce: z.boolean().default(true),
  timeout_ms: z.number().min(100).max(30000).default(5000),
});

export const FetchResponseSchema = z.object({
  success: z.boolean(),
  status: z.number(),
  statusText: z.string(),
  headers: z.record(z.string()),
  body: z.unknown(),
  url: z.string(),
  method: z.string(),
  processing_time_ms: z.number(),
  metadata: z.object({
    tenant: z.string(),
    capability_token: z.string(),
    enforce_mode: z.boolean(),
    request_hash: z.string(),
  }),
  error: z.string().optional(),
});

export type FetchRequest = z.infer<typeof FetchRequestSchema>;
export type FetchResponse = z.infer<typeof FetchResponseSchema>;

// Mock endpoint interface
export interface MockEndpoint {
  url: string;
  method: string;
  tenant: string;
  response: {
    status: number;
    statusText: string;
    headers: Record<string, string>;
    body: any;
  };
  delay_ms: number;
  failure_rate: number;
}

// Mock fetch configuration
export interface MockFetchConfig {
  seed: string;
  base_delay_ms: number;
  failure_rate: number;
  max_timeout_ms: number;
  allowed_domains: string[];
  blocked_domains: string[];
  rate_limit_per_minute: number;
}

export class FetchEmulator {
  private readonly seed: string;
  private readonly enforceMode: boolean;
  private readonly capabilityToken: string;
  private readonly tenant: string;
  private readonly mockConfig: MockFetchConfig;
  private readonly mockEndpoints: Map<string, MockEndpoint> = new Map();
  private readonly requestHistory: Map<string, FetchRequest[]> = new Map(); // tenant -> requests
  private readonly rateLimitTracker: Map<string, { count: number; resetTime: number }> = new Map();

  constructor(
    seed: string = "default",
    enforceMode: boolean = true,
    capabilityToken: string = "",
    tenant: string = "default",
  ) {
    this.seed = seed;
    this.enforceMode = enforceMode;
    this.capabilityToken = capabilityToken;
    this.tenant = tenant;

    // Initialize mock configuration based on seed
    this.mockConfig = this.initializeMockConfig(seed);

    // Initialize with sample data
    this.initializeSampleData();
  }

  private initializeMockConfig(seed: string): MockFetchConfig {
    const hash = createHash("sha256").update(seed).digest("hex");

    return {
      seed,
      base_delay_ms: (parseInt(hash.slice(0, 8), 16) % 800) + 50, // 50-850ms
      failure_rate: (parseInt(hash.slice(8, 16), 16) % 100) / 1000, // 0-10%
      max_timeout_ms: (parseInt(hash.slice(16, 24), 16) % 20000) + 10000, // 10000-30000ms
      allowed_domains: ["api.acme.com", "api.globex.com", "docs.example.com", "data.test.org"],
      blocked_domains: ["malware.evil.com", "phishing.fake.org", "blocked.domain"],
      rate_limit_per_minute: (parseInt(hash.slice(24, 32), 16) % 200) + 50, // 50-250
    };
  }

  private initializeSampleData(): void {
    // Create sample mock endpoints for ACME
    const acmeEndpoints: MockEndpoint[] = [
      {
        url: "https://api.acme.com/users",
        method: "GET",
        tenant: "acme",
        response: {
          status: 200,
          statusText: "OK",
          headers: {
            "Content-Type": "application/json",
            "X-Rate-Limit-Remaining": "99",
          },
          body: {
            users: [
              { id: 1, name: "John Doe", email: "john@acme.com", role: "admin" },
              { id: 2, name: "Jane Smith", email: "jane@acme.com", role: "user" },
              { id: 3, name: "Bob Johnson", email: "bob@acme.com", role: "user" },
            ],
            total: 3,
            page: 1,
            per_page: 10,
          },
        },
        delay_ms: 150,
        failure_rate: 0.01,
      },
      {
        url: "https://api.acme.com/users",
        method: "POST",
        tenant: "acme",
        response: {
          status: 201,
          statusText: "Created",
          headers: {
            "Content-Type": "application/json",
            Location: "https://api.acme.com/users/4",
          },
          body: {
            id: 4,
            name: "New User",
            email: "newuser@acme.com",
            role: "user",
            created_at: new Date().toISOString(),
          },
        },
        delay_ms: 200,
        failure_rate: 0.02,
      },
      {
        url: "https://api.acme.com/health",
        method: "GET",
        tenant: "acme",
        response: {
          status: 200,
          statusText: "OK",
          headers: {
            "Content-Type": "application/json",
          },
          body: {
            status: "healthy",
            timestamp: new Date().toISOString(),
            version: "1.2.3",
            uptime: "7d 12h 34m 56s",
          },
        },
        delay_ms: 50,
        failure_rate: 0.001,
      },
    ];

    // Create sample mock endpoints for Globex
    const globexEndpoints: MockEndpoint[] = [
      {
        url: "https://api.globex.com/products",
        method: "GET",
        tenant: "globex",
        response: {
          status: 200,
          statusText: "OK",
          headers: {
            "Content-Type": "application/json",
            "X-Total-Count": "5",
          },
          body: {
            products: [
              { id: "prod_001", name: "Widget A", price: 29.99, category: "electronics" },
              { id: "prod_002", name: "Widget B", price: 49.99, category: "electronics" },
              { id: "prod_003", name: "Service X", price: 99.99, category: "services" },
            ],
            total: 3,
            page: 1,
            per_page: 10,
          },
        },
        delay_ms: 120,
        failure_rate: 0.015,
      },
      {
        url: "https://api.globex.com/orders",
        method: "POST",
        tenant: "globex",
        response: {
          status: 201,
          statusText: "Created",
          headers: {
            "Content-Type": "application/json",
            "X-Order-ID": "ord_12345",
          },
          body: {
            order_id: "ord_12345",
            status: "pending",
            total: 79.98,
            items: [
              { product_id: "prod_001", quantity: 1, price: 29.99 },
              { product_id: "prod_002", quantity: 1, price: 49.99 },
            ],
            created_at: new Date().toISOString(),
          },
        },
        delay_ms: 300,
        failure_rate: 0.025,
      },
    ];

    // Add all endpoints
    [...acmeEndpoints, ...globexEndpoints].forEach((endpoint) => {
      const key = `${endpoint.method}:${endpoint.url}`;
      this.mockEndpoints.set(key, endpoint);
    });
  }

  // Validate capability token
  private validateCapability(capabilityToken: string, operation: string): boolean {
    if (!this.enforceMode) {
      return true; // Skip validation in non-enforce mode
    }

    if (!capabilityToken) {
      return false;
    }

    // In a real implementation, this would validate against a capability broker
    // For now, we'll use a simple hash-based validation
    const expectedHash = createHash("sha256")
      .update(`${this.tenant}:fetch:${operation}`)
      .digest("hex");

    return capabilityToken === expectedHash;
  }

  // Check domain restrictions
  private isDomainAllowed(url: string): boolean {
    try {
      const domain = new URL(url).hostname;

      // Check blocked domains first
      if (this.mockConfig.blocked_domains.some((blocked) => domain.includes(blocked))) {
        return false;
      }

      // Check if domain is in allowed list
      return this.mockConfig.allowed_domains.some((allowed) => domain.includes(allowed));
    } catch {
      return false; // Invalid URL
    }
  }

  // Check rate limiting
  private checkRateLimit(tenant: string): boolean {
    const now = Date.now();
    const limit = this.rateLimitTracker.get(tenant);

    if (!limit || now > limit.resetTime) {
      // Reset or create new limit
      this.rateLimitTracker.set(tenant, {
        count: 1,
        resetTime: now + 60000, // 1 minute
      });
      return true;
    }

    if (limit.count >= this.mockConfig.rate_limit_per_minute) {
      return false;
    }

    limit.count++;
    return true;
  }

  // Perform fetch request
  async fetch(request: FetchRequest): Promise<FetchResponse> {
    const startTime = Date.now();

    try {
      // Validate request schema
      const validatedRequest = FetchRequestSchema.parse(request);

      // Validate capability if in enforce mode
      if (
        this.enforceMode &&
        !this.validateCapability(validatedRequest.capability_token, "fetch")
      ) {
        return {
          success: false,
          status: 403,
          statusText: "Forbidden",
          headers: {},
          body: { error: "CAP_MISS: Missing or invalid capability token for fetch operations" },
          url: validatedRequest.url,
          method: validatedRequest.method,
          processing_time_ms: Date.now() - startTime,
          metadata: {
            tenant: validatedRequest.tenant,
            capability_token: validatedRequest.capability_token,
            enforce_mode: this.enforceMode,
            request_hash: "",
          },
          error: "CAP_MISS: Missing or invalid capability token for fetch operations",
        };
      }

      // Check domain restrictions
      if (!this.isDomainAllowed(validatedRequest.url)) {
        return {
          success: false,
          status: 403,
          statusText: "Forbidden",
          headers: {},
          body: { error: "DOMAIN_BLOCKED: Domain not allowed for fetch operations" },
          url: validatedRequest.url,
          method: validatedRequest.method,
          processing_time_ms: Date.now() - startTime,
          metadata: {
            tenant: validatedRequest.tenant,
            capability_token: validatedRequest.capability_token,
            enforce_mode: this.enforceMode,
            request_hash: "",
          },
          error: "DOMAIN_BLOCKED: Domain not allowed for fetch operations",
        };
      }

      // Check rate limiting
      if (!this.checkRateLimit(validatedRequest.tenant)) {
        return {
          success: false,
          status: 429,
          statusText: "Too Many Requests",
          headers: {
            "Retry-After": "60",
            "X-Rate-Limit-Reset": new Date(Date.now() + 60000).toISOString(),
          },
          body: { error: "RATE_LIMIT_EXCEEDED: Too many fetch requests" },
          url: validatedRequest.url,
          method: validatedRequest.method,
          processing_time_ms: Date.now() - startTime,
          metadata: {
            tenant: validatedRequest.tenant,
            capability_token: validatedRequest.capability_token,
            enforce_mode: this.enforceMode,
            request_hash: "",
          },
          error: "RATE_LIMIT_EXCEEDED: Too many fetch requests",
        };
      }

      // Find matching mock endpoint
      const key = `${validatedRequest.method}:${validatedRequest.url}`;
      const mockEndpoint = this.mockEndpoints.get(key);

      if (!mockEndpoint) {
        // Return 404 for unmocked endpoints
        return {
          success: false,
          status: 404,
          statusText: "Not Found",
          headers: {},
          body: { error: "ENDPOINT_NOT_MOCKED: No mock endpoint found for this request" },
          url: validatedRequest.url,
          method: validatedRequest.method,
          processing_time_ms: Date.now() - startTime,
          metadata: {
            tenant: validatedRequest.tenant,
            capability_token: validatedRequest.capability_token,
            enforce_mode: this.enforceMode,
            request_hash: "",
          },
          error: "ENDPOINT_NOT_MOCKED: No mock endpoint found for this request",
        };
      }

      // Check tenant match
      if (mockEndpoint.tenant !== validatedRequest.tenant) {
        return {
          success: false,
          status: 403,
          statusText: "Forbidden",
          headers: {},
          body: { error: "TENANT_MISMATCH: Endpoint not accessible for this tenant" },
          url: validatedRequest.url,
          method: validatedRequest.method,
          processing_time_ms: Date.now() - startTime,
          metadata: {
            tenant: validatedRequest.tenant,
            capability_token: validatedRequest.capability_token,
            enforce_mode: this.enforceMode,
            request_hash: "",
          },
          error: "TENANT_MISMATCH: Endpoint not accessible for this tenant",
        };
      }

      // Simulate endpoint delay
      await this.simulateEndpointDelay(mockEndpoint.delay_ms);

      // Simulate potential failure
      if (Math.random() < mockEndpoint.failure_rate) {
        throw new Error("Simulated endpoint failure");
      }

      // Store request history
      if (!this.requestHistory.has(validatedRequest.tenant)) {
        this.requestHistory.set(validatedRequest.tenant, []);
      }
      this.requestHistory.get(validatedRequest.tenant)!.push(validatedRequest);

      // Generate request hash
      const requestHash = createHash("sha256")
        .update(
          validatedRequest.url + validatedRequest.method + validatedRequest.tenant + Date.now(),
        )
        .digest("hex");

      const response: FetchResponse = {
        success: true,
        status: mockEndpoint.response.status,
        statusText: mockEndpoint.response.statusText,
        headers: mockEndpoint.response.headers,
        body: mockEndpoint.response.body,
        url: validatedRequest.url,
        method: validatedRequest.method,
        processing_time_ms: Date.now() - startTime,
        metadata: {
          tenant: validatedRequest.tenant,
          capability_token: validatedRequest.capability_token,
          enforce_mode: this.enforceMode,
          request_hash: requestHash,
        },
      };

      return response;
    } catch (error) {
      return {
        success: false,
        status: 500,
        statusText: "Internal Server Error",
        headers: {},
        body: { error: "Internal emulator error" },
        url: request.url || "",
        method: request.method || "GET",
        processing_time_ms: Date.now() - startTime,
        metadata: {
          tenant: request.tenant || "unknown",
          capability_token: request.capability_token || "",
          enforce_mode: this.enforceMode,
          request_hash: "",
        },
        error: error instanceof Error ? error.message : "Unknown error",
      };
    }
  }

  // Simulate endpoint delay
  private async simulateEndpointDelay(delayMs: number): Promise<void> {
    return new Promise((resolve) => {
      setTimeout(resolve, delayMs);
    });
  }

  // Add custom mock endpoint
  async addMockEndpoint(endpoint: MockEndpoint, capabilityToken: string): Promise<boolean> {
    // Validate capability if in enforce mode
    if (this.enforceMode && !this.validateCapability(capabilityToken, "configure")) {
      throw new Error("CAP_MISS: Missing or invalid capability token for endpoint configuration");
    }

    const key = `${endpoint.method}:${endpoint.url}`;
    this.mockEndpoints.set(key, endpoint);
    return true;
  }

  // Remove mock endpoint
  async removeMockEndpoint(url: string, method: string, capabilityToken: string): Promise<boolean> {
    // Validate capability if in enforce mode
    if (this.enforceMode && !this.validateCapability(capabilityToken, "configure")) {
      throw new Error("CAP_MISS: Missing or invalid capability token for endpoint configuration");
    }

    const key = `${method}:${url}`;
    return this.mockEndpoints.delete(key);
  }

  // List mock endpoints for a tenant
  async listMockEndpoints(tenant: string, capabilityToken: string): Promise<MockEndpoint[]> {
    // Validate capability if in enforce mode
    if (this.enforceMode && !this.validateCapability(capabilityToken, "read")) {
      throw new Error("CAP_MISS: Missing or invalid capability token for endpoint listing");
    }

    return Array.from(this.mockEndpoints.values()).filter((endpoint) => endpoint.tenant === tenant);
  }

  // Get request history for a tenant
  async getRequestHistory(tenant: string, capabilityToken: string): Promise<FetchRequest[]> {
    // Validate capability if in enforce mode
    if (this.enforceMode && !this.validateCapability(capabilityToken, "read")) {
      throw new Error("CAP_MISS: Missing or invalid capability token for request history reading");
    }

    return this.requestHistory.get(tenant) || [];
  }

  // Get mock configuration
  getMockConfig(): MockFetchConfig {
    return { ...this.mockConfig };
  }

  // Reset emulator state
  reset(): void {
    this.mockEndpoints.clear();
    this.requestHistory.clear();
    this.rateLimitTracker.clear();
    this.initializeSampleData();
  }

  // Switch to real mode (placeholder for real fetch service integration)
  async switchToRealMode(apiKey: string, serviceConfig: any): Promise<void> {
    if (this.enforceMode) {
      throw new Error("Cannot switch to real mode while enforce mode is enabled");
    }

    // In a real implementation, this would initialize a real fetch service
    // For now, we'll just log the intention
    console.log("Switching to real fetch service mode");
    console.log("API Key:", apiKey ? "***" + apiKey.slice(-4) : "none");
    console.log("Service Config:", serviceConfig);
  }
}

// Export factory function for easy instantiation
export const createFetchEmulator = (
  seed: string = "default",
  enforceMode: boolean = true,
  capabilityToken: string = "",
  tenant: string = "default",
): FetchEmulator => {
  return new FetchEmulator(seed, enforceMode, capabilityToken, tenant);
};

// Export default instance
export const defaultFetchEmulator = createFetchEmulator();
