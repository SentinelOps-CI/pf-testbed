import { createHash, randomBytes } from "crypto";
import { z } from "zod";

// Email emulator for TB-08
// Provides deterministic, seeded mocks with real mode capabilities

export const EmailRequestSchema = z.object({
  to: z.array(z.string().email()),
  cc: z.array(z.string().email()).optional(),
  bcc: z.array(z.string().email()).optional(),
  subject: z.string().min(1).max(200),
  body: z.string().min(1),
  from: z.string().email(),
  tenant: z.string().min(1),
  capability_token: z.string().min(1),
  enforce: z.boolean().default(true),
});

export const EmailResponseSchema = z.object({
  success: z.boolean(),
  message_id: z.string(),
  sent_at: z.string(),
  recipients: z.object({
    to: z.array(z.string()),
    cc: z.array(z.string()),
    bcc: z.array(z.string()),
  }),
  metadata: z.object({
    tenant: z.string(),
    capability_token: z.string(),
    enforce_mode: z.boolean(),
    processing_time_ms: z.number(),
  }),
  error: z.string().optional(),
});

export type EmailRequest = z.infer<typeof EmailRequestSchema>;
export type EmailResponse = z.infer<typeof EmailResponseSchema>;

// Email template interface
export interface EmailTemplate {
  id: string;
  name: string;
  subject: string;
  body: string;
  variables: string[];
  tenant: string;
}

// Mock email service configuration
export interface MockEmailConfig {
  seed: string;
  delivery_delay_ms: number;
  failure_rate: number;
  max_recipients: number;
  rate_limit_per_minute: number;
}

export class EmailEmulator {
  private readonly seed: string;
  private readonly enforceMode: boolean;
  private readonly capabilityToken: string;
  private readonly tenant: string;
  private readonly mockConfig: MockEmailConfig;
  private readonly templates: Map<string, EmailTemplate> = new Map();
  private readonly sentEmails: Map<string, EmailRequest> = new Map();
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

    // Initialize email templates
    this.initializeTemplates();
  }

  private initializeMockConfig(seed: string): MockEmailConfig {
    const hash = createHash("sha256").update(seed).digest("hex");

    return {
      seed,
      delivery_delay_ms: (parseInt(hash.slice(0, 8), 16) % 5000) + 100, // 100-5100ms
      failure_rate: (parseInt(hash.slice(8, 16), 16) % 100) / 1000, // 0-10%
      max_recipients: (parseInt(hash.slice(16, 24), 16) % 50) + 1, // 1-50
      rate_limit_per_minute: (parseInt(hash.slice(24, 32), 16) % 100) + 10, // 10-110
    };
  }

  private initializeTemplates(): void {
    const templates: EmailTemplate[] = [
      {
        id: "welcome",
        name: "Welcome Email",
        subject: "Welcome to {{company_name}}!",
        body: "Hi {{first_name}},\n\nWelcome to {{company_name}}! We're excited to have you on board.\n\nBest regards,\nThe {{company_name}} Team",
        variables: ["company_name", "first_name"],
        tenant: "acme",
      },
      {
        id: "notification",
        name: "System Notification",
        subject: "{{notification_type}} - {{title}}",
        body: "Hello {{user_name}},\n\n{{message}}\n\nThis is an automated notification from {{system_name}}.\n\nRegards,\n{{system_name}}",
        variables: ["notification_type", "title", "user_name", "message", "system_name"],
        tenant: "acme",
      },
      {
        id: "approval",
        name: "Approval Request",
        subject: "Approval Required: {{request_type}}",
        body: "Hi {{approver_name}},\n\n{{requester_name}} has requested approval for {{request_type}}.\n\nDetails:\n{{details}}\n\nPlease review and approve/reject at your earliest convenience.\n\nRegards,\n{{system_name}}",
        variables: ["request_type", "approver_name", "requester_name", "details", "system_name"],
        tenant: "globex",
      },
    ];

    templates.forEach((template) => {
      this.templates.set(template.id, template);
    });
  }

  // Validate capability token
  private validateCapability(capabilityToken: string): boolean {
    if (!this.enforceMode) {
      return true; // Skip validation in non-enforce mode
    }

    if (!capabilityToken) {
      return false;
    }

    // In a real implementation, this would validate against a capability broker
    // For now, we'll use a simple hash-based validation
    const expectedHash = createHash("sha256").update(`${this.tenant}:email:send`).digest("hex");

    return capabilityToken === expectedHash;
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

  // Send email (main method)
  async sendEmail(request: EmailRequest): Promise<EmailResponse> {
    const startTime = Date.now();

    try {
      // Validate request schema
      const validatedRequest = EmailRequestSchema.parse(request);

      // Validate capability if in enforce mode
      if (this.enforceMode && !this.validateCapability(validatedRequest.capability_token)) {
        return {
          success: false,
          message_id: "",
          sent_at: new Date().toISOString(),
          recipients: {
            to: [],
            cc: [],
            bcc: [],
          },
          metadata: {
            tenant: validatedRequest.tenant,
            capability_token: validatedRequest.capability_token,
            enforce_mode: this.enforceMode,
            processing_time_ms: Date.now() - startTime,
          },
          error: "CAP_MISS: Missing or invalid capability token for email sending",
        };
      }

      // Check rate limiting
      if (!this.checkRateLimit(validatedRequest.tenant)) {
        return {
          success: false,
          message_id: "",
          sent_at: new Date().toISOString(),
          recipients: {
            to: [],
            cc: [],
            bcc: [],
          },
          metadata: {
            tenant: validatedRequest.tenant,
            capability_token: validatedRequest.capability_token,
            enforce_mode: this.enforceMode,
            processing_time_ms: Date.now() - startTime,
          },
          error: "RATE_LIMIT_EXCEEDED: Email rate limit exceeded for tenant",
        };
      }

      // Validate recipient limits
      const totalRecipients =
        validatedRequest.to.length +
        (validatedRequest.cc?.length || 0) +
        (validatedRequest.bcc?.length || 0);

      if (totalRecipients > this.mockConfig.max_recipients) {
        return {
          success: false,
          message_id: "",
          sent_at: new Date().toISOString(),
          recipients: {
            to: [],
            cc: [],
            bcc: [],
          },
          metadata: {
            tenant: validatedRequest.tenant,
            capability_token: validatedRequest.capability_token,
            enforce_mode: this.enforceMode,
            processing_time_ms: Date.now() - startTime,
          },
          error: `RECIPIENT_LIMIT_EXCEEDED: Maximum ${this.mockConfig.max_recipients} recipients allowed`,
        };
      }

      // Simulate delivery delay
      await this.simulateDeliveryDelay();

      // Simulate potential failure
      if (Math.random() < this.mockConfig.failure_rate) {
        throw new Error("Simulated email delivery failure");
      }

      // Generate deterministic message ID based on seed
      const messageId = this.generateMessageId(validatedRequest);

      // Store sent email
      this.sentEmails.set(messageId, validatedRequest);

      const response: EmailResponse = {
        success: true,
        message_id: messageId,
        sent_at: new Date().toISOString(),
        recipients: {
          to: validatedRequest.to,
          cc: validatedRequest.cc || [],
          bcc: validatedRequest.bcc || [],
        },
        metadata: {
          tenant: validatedRequest.tenant,
          capability_token: validatedRequest.capability_token,
          enforce_mode: this.enforceMode,
          processing_time_ms: Date.now() - startTime,
        },
      };

      return response;
    } catch (error) {
      return {
        success: false,
        message_id: "",
        sent_at: new Date().toISOString(),
        recipients: {
          to: [],
          cc: [],
          bcc: [],
        },
        metadata: {
          tenant: request.tenant || "unknown",
          capability_token: request.capability_token || "",
          enforce_mode: this.enforceMode,
          processing_time_ms: Date.now() - startTime,
        },
        error: error instanceof Error ? error.message : "Unknown error",
      };
    }
  }

  // Generate deterministic message ID
  private generateMessageId(request: EmailRequest): string {
    const data = `${this.seed}:${request.from}:${request.to.join(",")}:${request.subject}:${Date.now()}`;
    return createHash("sha256").update(data).digest("hex").slice(0, 16);
  }

  // Simulate delivery delay
  private async simulateDeliveryDelay(): Promise<void> {
    return new Promise((resolve) => {
      setTimeout(resolve, this.mockConfig.delivery_delay_ms);
    });
  }

  // Get email template
  getTemplate(templateId: string): EmailTemplate | undefined {
    return this.templates.get(templateId);
  }

  // List available templates
  listTemplates(): EmailTemplate[] {
    return Array.from(this.templates.values());
  }

  // Get sent email by ID
  getSentEmail(messageId: string): EmailRequest | undefined {
    return this.sentEmails.get(messageId);
  }

  // List sent emails
  listSentEmails(): Map<string, EmailRequest> {
    return new Map(this.sentEmails);
  }

  // Get mock configuration
  getMockConfig(): MockEmailConfig {
    return { ...this.mockConfig };
  }

  // Reset emulator state
  reset(): void {
    this.sentEmails.clear();
    this.rateLimitTracker.clear();
  }

  // Switch to real mode (placeholder for real email service integration)
  async switchToRealMode(apiKey: string, serviceConfig: any): Promise<void> {
    if (this.enforceMode) {
      throw new Error("Cannot switch to real mode while enforce mode is enabled");
    }

    // In a real implementation, this would initialize a real email service
    // For now, we'll just log the intention
    console.log("Switching to real email service mode");
    console.log("API Key:", apiKey ? "***" + apiKey.slice(-4) : "none");
    console.log("Service Config:", serviceConfig);
  }
}

// Export factory function for easy instantiation
export const createEmailEmulator = (
  seed: string = "default",
  enforceMode: boolean = true,
  capabilityToken: string = "",
  tenant: string = "default",
): EmailEmulator => {
  return new EmailEmulator(seed, enforceMode, capabilityToken, tenant);
};

// Export default instance
export const defaultEmailEmulator = createEmailEmulator();
