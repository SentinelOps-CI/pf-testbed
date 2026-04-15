import express from "express";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import cors from "cors";
import { randomBytes } from "crypto";
import { z } from "zod";
import {
  ValidationMiddleware,
  TenantRateLimiter,
  requestIdMiddleware,
} from "./middleware/validation";

// Self-serve ingress system for external partners
export class SelfServeIngress {
  private app: express.Application;
  private tenants: Map<string, Tenant> = new Map();
  private apiKeys: Map<string, ApiKey> = new Map();
  private rateLimiters: Map<string, any> = new Map();
  private validationMiddleware: ValidationMiddleware;
  private tenantRateLimiter: TenantRateLimiter;

  constructor() {
    this.app = express();

    // Initialize validation middleware with secret key
    const secretKey = this.resolveSignatureSecret();
    this.validationMiddleware = new ValidationMiddleware(secretKey);
    this.tenantRateLimiter = new TenantRateLimiter(15 * 60 * 1000, 100); // 15 min window, 100 requests

    this.setupMiddleware();
    this.setupRoutes();
  }

  private resolveSignatureSecret(): string {
    const secret = process.env.PF_SIGNATURE_SECRET;
    if (secret) return secret;
    if (process.env.NODE_ENV === "test") {
      return "test-signature-secret";
    }
    throw new Error("PF_SIGNATURE_SECRET must be set for non-test ingress environments");
  }

  private setupMiddleware(): void {
    // Security middleware
    this.app.use(helmet());
    this.app.use(
      cors({
        origin: process.env.ALLOWED_ORIGINS?.split(",") || ["http://localhost:3000"],
        credentials: true,
      }),
    );

    // Body parsing
    this.app.use(express.json({ limit: "10mb" }));
    this.app.use(express.urlencoded({ extended: true }));

    // Request ID middleware
    this.app.use(requestIdMiddleware);

    // Global rate limiting
    this.app.use(
      rateLimit({
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 100, // limit each IP to 100 requests per windowMs
        message: "Too many requests from this IP, please try again later.",
      }),
    );
  }

  private setupRoutes(): void {
    // Health check
    this.app.get("/health", (req, res) => {
      res.json({ status: "healthy", timestamp: new Date().toISOString() });
    });

    // Signup endpoint
    this.app.post("/signup", this.handleSignup.bind(this));

    // API key management
    this.app.post("/api-keys", this.handleCreateApiKey.bind(this));
    this.app.get("/api-keys/:keyId", this.handleGetApiKey.bind(this));
    this.app.delete("/api-keys/:keyId", this.handleRevokeApiKey.bind(this));

    // Tenant management
    this.app.get("/tenants/:tenantId", this.handleGetTenant.bind(this));
    this.app.put("/tenants/:tenantId", this.handleUpdateTenant.bind(this));

    // Example middleware download
    this.app.get("/middleware/:type", this.handleDownloadMiddleware.bind(this));

    // Documentation
    this.app.get("/docs", this.handleGetDocs.bind(this));
    this.app.get("/postman", this.handleGetPostmanCollection.bind(this));

    // Protected routes (require API key)
    this.app.use("/api/*", this.authenticateApiKey.bind(this));

    // Validation endpoints with PF-Sig and Access Receipt validation
    this.app.post("/api/validate-pf-sig", this.handleValidatePfSig.bind(this));
    this.app.post("/api/validate-receipt", this.handleValidateReceipt.bind(this));

    // New validation endpoints with enhanced middleware
    this.app.post(
      "/api/validate-request",
      this.validationMiddleware.validateRequest,
      this.tenantRateLimiter.limitByTenant,
      this.handleValidateRequest.bind(this),
    );

    // Test endpoints for generating signatures and receipts
    this.app.post("/api/test/generate-signature", this.handleGenerateSignature.bind(this));
    this.app.post("/api/test/generate-receipt", this.handleGenerateReceipt.bind(this));
  }

  // Signup handler
  private async handleSignup(req: express.Request, res: express.Response): Promise<void> {
    try {
      const signupData = SignupSchema.parse(req.body);

      // Check if email already exists
      if (this.emailExists(signupData.email)) {
        res.status(409).json({ error: "Email already registered" });
        return;
      }

      // Create tenant
      const tenant = this.createTenant(signupData);

      // Create API key
      const apiKey = this.createApiKey(tenant.id, "default");

      // Setup rate limiting for tenant
      this.setupTenantRateLimiting(tenant.id, tenant.plan);

      // Send welcome email (in real implementation)
      await this.sendWelcomeEmail(tenant, apiKey);

      res.status(201).json({
        message: "Signup successful",
        tenant: {
          id: tenant.id,
          name: tenant.name,
          plan: tenant.plan,
          status: tenant.status,
        },
        api_key: {
          id: apiKey.id,
          key: apiKey.key,
          created_at: apiKey.created_at,
        },
        next_steps: [
          "Download example middleware",
          "Review API documentation",
          "Start with guided demo",
        ],
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        res.status(400).json({ error: "Invalid signup data", details: error.errors });
      } else {
        res.status(500).json({ error: "Internal server error" });
      }
    }
  }

  // API key creation
  private async handleCreateApiKey(req: express.Request, res: express.Response): Promise<void> {
    try {
      const { tenant_id, name } = req.body;

      if (!this.tenants.has(tenant_id)) {
        res.status(404).json({ error: "Tenant not found" });
        return;
      }

      const apiKey = this.createApiKey(tenant_id, name);

      res.status(201).json({
        id: apiKey.id,
        name: apiKey.name,
        key: apiKey.key,
        created_at: apiKey.created_at,
        expires_at: apiKey.expires_at,
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to create API key" });
    }
  }

  // API key retrieval
  private async handleGetApiKey(req: express.Request, res: express.Response): Promise<void> {
    try {
      const { keyId } = req.params;
      const apiKey = this.apiKeys.get(keyId);

      if (!apiKey) {
        res.status(404).json({ error: "API key not found" });
        return;
      }

      res.json({
        id: apiKey.id,
        name: apiKey.name,
        tenant_id: apiKey.tenant_id,
        created_at: apiKey.created_at,
        expires_at: apiKey.expires_at,
        last_used: apiKey.last_used,
        status: apiKey.status,
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to retrieve API key" });
    }
  }

  // API key revocation
  private async handleRevokeApiKey(req: express.Request, res: express.Response): Promise<void> {
    try {
      const { keyId } = req.params;
      const apiKey = this.apiKeys.get(keyId);

      if (!apiKey) {
        res.status(404).json({ error: "API key not found" });
        return;
      }

      apiKey.status = "revoked";
      apiKey.revoked_at = new Date().toISOString();

      res.json({ message: "API key revoked successfully" });
    } catch (error) {
      res.status(500).json({ error: "Failed to revoke API key" });
    }
  }

  // Tenant retrieval
  private async handleGetTenant(req: express.Request, res: express.Response): Promise<void> {
    try {
      const { tenantId } = req.params;
      const tenant = this.tenants.get(tenantId);

      if (!tenant) {
        res.status(404).json({ error: "Tenant not found" });
        return;
      }

      res.json({
        id: tenant.id,
        name: tenant.name,
        email: tenant.email,
        plan: tenant.plan,
        status: tenant.status,
        created_at: tenant.created_at,
        api_keys_count: this.getApiKeysCount(tenant.id),
        usage_stats: tenant.usage_stats,
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to retrieve tenant" });
    }
  }

  // Tenant update
  private async handleUpdateTenant(req: express.Request, res: express.Response): Promise<void> {
    try {
      const { tenantId } = req.params;
      const updateData = TenantUpdateSchema.parse(req.body);

      const tenant = this.tenants.get(tenantId);
      if (!tenant) {
        res.status(404).json({ error: "Tenant not found" });
        return;
      }

      // Update allowed fields
      if (updateData.name) tenant.name = updateData.name;
      if (updateData.plan) {
        tenant.plan = updateData.plan;
        this.setupTenantRateLimiting(tenant.id, tenant.plan);
      }

      res.json({ message: "Tenant updated successfully" });
    } catch (error) {
      if (error instanceof z.ZodError) {
        res.status(400).json({ error: "Invalid update data", details: error.errors });
      } else {
        res.status(500).json({ error: "Failed to update tenant" });
      }
    }
  }

  // Middleware download
  private async handleDownloadMiddleware(
    req: express.Request,
    res: express.Response,
  ): Promise<void> {
    try {
      const { type } = req.params;
      const supportedTypes = ["nodejs", "python", "go", "rust"];

      if (!supportedTypes.includes(type)) {
        res.status(400).json({ error: "Unsupported middleware type" });
        return;
      }

      // In a real implementation, you would serve actual middleware files
      const middlewareContent = this.generateMiddlewareExample(type);

      res.setHeader("Content-Type", "application/zip");
      res.setHeader("Content-Disposition", `attachment; filename="${type}-middleware.zip"`);
      res.send(Buffer.from(middlewareContent, "utf-8"));
    } catch (error) {
      res.status(500).json({ error: "Failed to download middleware" });
    }
  }

  // Documentation
  private async handleGetDocs(req: express.Request, res: express.Response): Promise<void> {
    res.json({
      title: "Testbed API Documentation",
      version: "1.0.0",
      description: "Complete API reference for the Provability Fabric Testbed",
      sections: [
        "Authentication",
        "API Keys",
        "Rate Limiting",
        "Endpoints",
        "Examples",
        "Error Codes",
      ],
      quick_start: [
        "1. Sign up for an account",
        "2. Get your API key",
        "3. Download example middleware",
        "4. Make your first API call",
      ],
    });
  }

  // Postman collection
  private async handleGetPostmanCollection(
    req: express.Request,
    res: express.Response,
  ): Promise<void> {
    const collection = {
      info: {
        name: "Testbed API Collection",
        description: "Complete Postman collection for the Testbed API",
        version: "1.0.0",
      },
      item: [
        {
          name: "Authentication",
          item: [
            {
              name: "Create API Key",
              request: {
                method: "POST",
                url: "{{base_url}}/api-keys",
                body: {
                  mode: "raw",
                  raw: JSON.stringify({
                    tenant_id: "{{tenant_id}}",
                    name: "My API Key",
                  }),
                },
              },
            },
          ],
        },
        {
          name: "API Endpoints",
          item: [
            {
              name: "Validate PF-Sig",
              request: {
                method: "POST",
                url: "{{base_url}}/api/validate-pf-sig",
                headers: [{ key: "X-API-Key", value: "{{api_key}}" }],
                body: {
                  mode: "raw",
                  raw: JSON.stringify({ signature: "{{pf_signature}}" }),
                },
              },
            },
          ],
        },
      ],
      variable: [
        { key: "base_url", value: "https://testbed.example.com" },
        { key: "tenant_id", value: "your_tenant_id" },
        { key: "api_key", value: "your_api_key" },
      ],
    };

    res.setHeader("Content-Type", "application/json");
    res.json(collection);
  }

  // PF-Sig validation
  private async handleValidatePfSig(req: express.Request, res: express.Response): Promise<void> {
    try {
      const { signature, data } = req.body;

      if (!signature) {
        res.status(400).json({
          error: "Missing PF-Sig header",
          documentation: "https://docs.example.com/pf-signatures",
          code: "MISSING_PF_SIG",
        });
        return;
      }

      // Validate signature format
      if (!this.isValidPfSigFormat(signature)) {
        res.status(400).json({
          error: "Invalid PF-Sig format",
          documentation: "https://docs.example.com/pf-signatures",
          code: "INVALID_PF_SIG_FORMAT",
        });
        return;
      }

      // Validate signature (in real implementation, verify cryptographic signature)
      const isValid = await this.verifyPfSig(signature, data);

      if (!isValid) {
        res.status(403).json({
          error: "Invalid PF-Sig",
          documentation: "https://docs.example.com/pf-signatures",
          code: "INVALID_PF_SIG",
        });
        return;
      }

      res.json({
        valid: true,
        message: "PF-Sig validated successfully",
        signature_info: this.parseSignatureInfo(signature),
      });
    } catch (error) {
      res.status(500).json({ error: "Signature validation failed" });
    }
  }

  // Receipt validation
  private async handleValidateReceipt(req: express.Request, res: express.Response): Promise<void> {
    try {
      const { receipt } = req.body;

      if (!receipt) {
        res.status(400).json({ error: "Missing receipt data" });
        return;
      }

      // Validate receipt schema
      const validationResult = this.validateReceiptSchema(receipt);

      if (!validationResult.valid) {
        res.status(400).json({
          error: "Invalid receipt schema",
          details: validationResult.errors,
        });
        return;
      }

      res.json({
        valid: true,
        message: "Receipt schema validated successfully",
        receipt_info: {
          id: receipt.id,
          tenant: receipt.tenant,
          expires_at: receipt.expires_at,
        },
      });
    } catch (error) {
      res.status(500).json({ error: "Receipt validation failed" });
    }
  }

  // API key authentication middleware
  private authenticateApiKey(
    req: express.Request,
    res: express.Response,
    next: express.NextFunction,
  ): void {
    const apiKey = req.headers["x-api-key"] as string;

    if (!apiKey) {
      res.status(401).json({
        error: "Missing API key",
        documentation: "https://docs.example.com/authentication",
      });
      return;
    }

    const keyData = this.apiKeys.get(apiKey);
    if (!keyData || keyData.status !== "active") {
      res.status(401).json({
        error: "Invalid or revoked API key",
        documentation: "https://docs.example.com/authentication",
      });
      return;
    }

    // Check rate limiting
    const tenant = this.tenants.get(keyData.tenant_id);
    if (tenant && this.rateLimiters.has(tenant.id)) {
      const limiter = this.rateLimiters.get(tenant.id);
      limiter(req, res, next);
    } else {
      next();
    }
  }

  // Helper methods
  private emailExists(email: string): boolean {
    return Array.from(this.tenants.values()).some((tenant) => tenant.email === email);
  }

  private createTenant(signupData: SignupData): Tenant {
    const tenant: Tenant = {
      id: this.generateTenantId(),
      name: signupData.name,
      email: signupData.email,
      company: signupData.company,
      plan: "sandbox",
      status: "active",
      created_at: new Date().toISOString(),
      usage_stats: {
        api_calls: 0,
        data_processed: 0,
        last_activity: new Date().toISOString(),
      },
    };

    this.tenants.set(tenant.id, tenant);
    return tenant;
  }

  private createApiKey(tenantId: string, name: string): ApiKey {
    const apiKey: ApiKey = {
      id: this.generateApiKeyId(),
      tenant_id: tenantId,
      name,
      key: this.generateApiKey(),
      created_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(), // 1 year
      last_used: null,
      status: "active",
      revoked_at: null,
    };

    this.apiKeys.set(apiKey.key, apiKey);
    return apiKey;
  }

  private setupTenantRateLimiting(tenantId: string, plan: string): void {
    const limits = this.getPlanLimits(plan);

    const limiter = rateLimit({
      windowMs: limits.windowMs,
      max: limits.maxRequests,
      message: `Rate limit exceeded for ${plan} plan`,
      keyGenerator: (_req) => tenantId,
    });

    this.rateLimiters.set(tenantId, limiter);
  }

  private getPlanLimits(plan: string): {
    windowMs: number;
    maxRequests: number;
  } {
    switch (plan) {
      case "sandbox":
        return { windowMs: 15 * 60 * 1000, maxRequests: 100 }; // 100 req/15min
      case "starter":
        return { windowMs: 15 * 60 * 1000, maxRequests: 1000 }; // 1000 req/15min
      case "professional":
        return { windowMs: 15 * 60 * 1000, maxRequests: 10000 }; // 10000 req/15min
      default:
        return { windowMs: 15 * 60 * 1000, maxRequests: 100 };
    }
  }

  private generateTenantId(): string {
    return `tenant_${Date.now()}_${randomBytes(8).toString("hex")}`;
  }

  private generateApiKeyId(): string {
    return `key_${Date.now()}_${randomBytes(8).toString("hex")}`;
  }

  private generateApiKey(): string {
    return `pf_${randomBytes(32).toString("hex")}`;
  }

  private getApiKeysCount(tenantId: string): number {
    return Array.from(this.apiKeys.values()).filter((key) => key.tenant_id === tenantId).length;
  }

  private async sendWelcomeEmail(tenant: Tenant, _apiKey: ApiKey): Promise<void> {
    // In real implementation, send actual email
    console.log(`Welcome email sent to ${tenant.email} for tenant ${tenant.id}`);
  }

  private generateMiddlewareExample(type: string): string {
    const examples: Record<string, string> = {
      nodejs: 'console.log("Node.js middleware example");',
      python: 'print("Python middleware example")',
      go: 'fmt.Println("Go middleware example")',
      rust: 'println!("Rust middleware example");',
    };

    return examples[type] || examples.nodejs;
  }

  private isValidPfSigFormat(signature: string): boolean {
    // Basic format validation
    return /^pf_[a-f0-9]{64}$/.test(signature);
  }

  private async verifyPfSig(signature: string, _data: unknown): Promise<boolean> {
    // In real implementation, verify cryptographic signature
    return signature.startsWith("pf_") && signature.length === 67;
  }

  private parseSignatureInfo(signature: string): any {
    return {
      prefix: signature.substring(0, 3),
      hash: signature.substring(3),
      algorithm: "sha256",
    };
  }

  private validateReceiptSchema(receipt: any): {
    valid: boolean;
    errors: string[];
  } {
    const errors: string[] = [];

    if (!receipt.id) errors.push("Missing receipt ID");
    if (!receipt.tenant) errors.push("Missing tenant");
    if (!receipt.subject) errors.push("Missing subject");
    if (!receipt.signature) errors.push("Missing signature");
    if (!receipt.expires_at) errors.push("Missing expiration");

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  // Start the server
  start(port: number = 3001): void {
    this.app.listen(port, () => {
      console.log(`Self-serve ingress running on port ${port}`);
    });
  }

  // Get Express app for testing
  getApp(): express.Application {
    return this.app;
  }

  // New validation handler with enhanced middleware
  private async handleValidateRequest(req: express.Request, res: express.Response): Promise<void> {
    try {
      // At this point, validation middleware has already passed
      // and tenant rate limiting has been applied

      res.json({
        success: true,
        message: "Request validation successful",
        data: {
          tenant: req.tenant,
          user_id: req.userId,
          capabilities: req.capabilities,
          validation_timestamp: new Date().toISOString(),
          request_id: res.locals.requestId,
        },
      });
    } catch (error) {
      res.status(500).json({
        error: {
          code: "INTERNAL_ERROR",
          message: "Failed to process validation request",
        },
        timestamp: new Date().toISOString(),
        request_id: res.locals.requestId,
      });
    }
  }

  // Generate test PF signature
  private async handleGenerateSignature(
    req: express.Request,
    res: express.Response,
  ): Promise<void> {
    try {
      const { tenant, user_id, capabilities, expires_in } = req.body;

      if (!tenant || !user_id || !capabilities || !expires_in) {
        res.status(400).json({
          error: {
            code: "INVALID_REQUEST",
            message: "Missing required fields: tenant, user_id, capabilities, expires_in",
          },
        });
        return;
      }

      const signature = this.validationMiddleware.generateSignature({
        tenant,
        user_id,
        capabilities,
        expires_in,
      });

      res.json({
        success: true,
        signature,
        expires_at: new Date(Date.now() + expires_in * 1000).toISOString(),
      });
    } catch (error) {
      res.status(500).json({
        error: {
          code: "INTERNAL_ERROR",
          message: "Failed to generate signature",
        },
      });
    }
  }

  // Generate test access receipt
  private async handleGenerateReceipt(req: express.Request, res: express.Response): Promise<void> {
    try {
      const { tenant, subject, shard, query_hash, result_hash, expires_in } = req.body;

      if (!tenant || !subject || !shard || !query_hash || !result_hash || !expires_in) {
        res.status(400).json({
          error: {
            code: "INVALID_REQUEST",
            message:
              "Missing required fields: tenant, subject, shard, query_hash, result_hash, expires_in",
          },
        });
        return;
      }

      const receipt = this.validationMiddleware.generateAccessReceipt({
        tenant,
        subject,
        shard,
        query_hash,
        result_hash,
        expires_in,
      });

      res.json({
        success: true,
        receipt,
        expires_at: receipt.expires_at,
      });
    } catch (error) {
      res.status(500).json({
        error: {
          code: "INTERNAL_ERROR",
          message: "Failed to generate receipt",
        },
      });
    }
  }
}

// Data models
interface Tenant {
  id: string;
  name: string;
  email: string;
  company: string;
  plan: "sandbox" | "starter" | "professional";
  status: "active" | "suspended" | "cancelled";
  created_at: string;
  usage_stats: {
    api_calls: number;
    data_processed: number;
    last_activity: string;
  };
}

interface ApiKey {
  id: string;
  tenant_id: string;
  name: string;
  key: string;
  created_at: string;
  expires_at: string;
  last_used: string | null;
  status: "active" | "revoked";
  revoked_at: string | null;
}

// Add missing type definitions
type SignupData = z.infer<typeof SignupSchema>;

// Validation schemas
const SignupSchema = z.object({
  name: z.string().min(2).max(100),
  email: z.string().email(),
  company: z.string().min(2).max(100),
  use_case: z.string().optional(),
});

const TenantUpdateSchema = z.object({
  name: z.string().min(2).max(100).optional(),
  plan: z.enum(["sandbox", "starter", "professional"]).optional(),
});

// Export the class and create instance
export const selfServeIngress = new SelfServeIngress();
