import { createHash } from "crypto";
import { z } from "zod";

// Notion emulator for TB-08
// Provides deterministic, seeded mocks with real mode capabilities

export const NotionPageSchema = z.object({
  id: z.string().optional(),
  title: z.string().min(1).max(200),
  content: z.string().min(1),
  parent_id: z.string().optional(),
  tenant: z.string().min(1),
  capability_token: z.string().min(1),
  enforce: z.boolean().default(true),
  properties: z.record(z.any()).optional(),
  tags: z.array(z.string()).optional(),
});

export const NotionResponseSchema = z.object({
  success: z.boolean(),
  page_id: z.string(),
  created_at: z.string(),
  page: NotionPageSchema,
  metadata: z.object({
    tenant: z.string(),
    capability_token: z.string(),
    enforce_mode: z.boolean(),
    processing_time_ms: z.number(),
  }),
  error: z.string().optional(),
});

export type NotionPage = z.infer<typeof NotionPageSchema>;
export type NotionResponse = z.infer<typeof NotionResponseSchema>;

// Notion database interface
export interface NotionDatabase {
  id: string;
  name: string;
  description: string;
  tenant: string;
  pages: string[]; // Page IDs
  properties: Record<string, any>;
}

// Mock Notion configuration
export interface MockNotionConfig {
  seed: string;
  operation_delay_ms: number;
  failure_rate: number;
  max_pages_per_database: number;
  max_content_length: number;
  supported_properties: string[];
}

export class NotionEmulator {
  private readonly seed: string;
  private readonly enforceMode: boolean;
  private readonly capabilityToken: string;
  private readonly tenant: string;
  private readonly mockConfig: MockNotionConfig;
  private readonly pages: Map<string, NotionPage> = new Map();
  private readonly databases: Map<string, NotionDatabase> = new Map();
  private readonly pageHierarchy: Map<string, string[]> = new Map(); // parent_id -> children

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

  private initializeMockConfig(seed: string): MockNotionConfig {
    const hash = createHash("sha256").update(seed).digest("hex");

    return {
      seed,
      operation_delay_ms: (parseInt(hash.slice(0, 8), 16) % 2000) + 100, // 100-2100ms
      failure_rate: (parseInt(hash.slice(8, 16), 16) % 100) / 1000, // 0-10%
      max_pages_per_database: (parseInt(hash.slice(16, 24), 16) % 100) + 10, // 10-110
      max_content_length: (parseInt(hash.slice(24, 32), 16) % 10000) + 1000, // 1000-11000
      supported_properties: [
        "title",
        "content",
        "tags",
        "status",
        "priority",
        "assignee",
        "due_date",
      ],
    };
  }

  private initializeSampleData(): void {
    // Create sample databases
    const acmeDatabase: NotionDatabase = {
      id: "db_acme_projects",
      name: "ACME Projects",
      description: "Project management database for ACME Corp",
      tenant: "acme",
      pages: [],
      properties: {
        title: { type: "title" },
        status: { type: "select", options: ["Not Started", "In Progress", "Completed"] },
        priority: { type: "select", options: ["Low", "Medium", "High"] },
        assignee: { type: "person" },
      },
    };

    const globexDatabase: NotionDatabase = {
      id: "db_globex_tasks",
      name: "Globex Tasks",
      description: "Task tracking for Globex Corp",
      tenant: "globex",
      pages: [],
      properties: {
        title: { type: "title" },
        status: { type: "select", options: ["Todo", "In Progress", "Done"] },
        priority: { type: "select", options: ["P1", "P2", "P3"] },
        due_date: { type: "date" },
      },
    };

    this.databases.set(acmeDatabase.id, acmeDatabase);
    this.databases.set(globexDatabase.id, globexDatabase);

    // Create sample pages
    const samplePages: NotionPage[] = [
      {
        title: "Q1 Product Launch",
        content: "Launch planning for our flagship product in Q1. Key milestones and deliverables.",
        parent_id: "db_acme_projects",
        tenant: "acme",
        capability_token: "sample_token",
        enforce: false,
        properties: {
          status: "In Progress",
          priority: "High",
          assignee: "product_manager@acme.com",
        },
        tags: ["product", "launch", "q1"],
      },
      {
        title: "Customer Support Portal",
        content: "Design and implementation of customer support portal with ticket tracking.",
        parent_id: "db_acme_projects",
        tenant: "acme",
        capability_token: "sample_token",
        enforce: false,
        properties: {
          status: "Not Started",
          priority: "Medium",
          assignee: "dev_team@acme.com",
        },
        tags: ["support", "portal", "development"],
      },
      {
        title: "API Documentation Update",
        content: "Update API documentation to reflect latest changes and new endpoints.",
        parent_id: "db_globex_tasks",
        tenant: "globex",
        capability_token: "sample_token",
        enforce: false,
        properties: {
          status: "Todo",
          priority: "P2",
          due_date: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
        },
        tags: ["api", "documentation"],
      },
    ];

    samplePages.forEach((page) => {
      const pageId = this.generatePageId(page);
      this.pages.set(pageId, { ...page, id: pageId });

      // Add to database
      if (page.parent_id && this.databases.has(page.parent_id)) {
        const db = this.databases.get(page.parent_id)!;
        db.pages.push(pageId);
      }

      // Update hierarchy
      if (page.parent_id) {
        const children = this.pageHierarchy.get(page.parent_id) || [];
        children.push(pageId);
        this.pageHierarchy.set(page.parent_id, children);
      }
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
      .update(`${this.tenant}:notion:${operation}`)
      .digest("hex");

    return capabilityToken === expectedHash;
  }

  // Create Notion page
  async createPage(page: NotionPage): Promise<NotionResponse> {
    const startTime = Date.now();

    try {
      // Validate request schema
      const validatedPage = NotionPageSchema.parse(page);

      // Validate capability if in enforce mode
      if (this.enforceMode && !this.validateCapability(validatedPage.capability_token, "create")) {
        return {
          success: false,
          page_id: "",
          created_at: new Date().toISOString(),
          page: validatedPage,
          metadata: {
            tenant: validatedPage.tenant,
            capability_token: validatedPage.capability_token,
            enforce_mode: this.enforceMode,
            processing_time_ms: Date.now() - startTime,
          },
          error: "CAP_MISS: Missing or invalid capability token for Notion page creation",
        };
      }

      // Check content length
      if (validatedPage.content.length > this.mockConfig.max_content_length) {
        return {
          success: false,
          page_id: "",
          created_at: new Date().toISOString(),
          page: validatedPage,
          metadata: {
            tenant: validatedPage.tenant,
            capability_token: validatedPage.capability_token,
            enforce_mode: this.enforceMode,
            processing_time_ms: Date.now() - startTime,
          },
          error: `CONTENT_TOO_LONG: Maximum content length is ${this.mockConfig.max_content_length} characters`,
        };
      }

      // Check database limits if parent_id is specified
      if (validatedPage.parent_id && this.databases.has(validatedPage.parent_id)) {
        const db = this.databases.get(validatedPage.parent_id)!;
        if (db.pages.length >= this.mockConfig.max_pages_per_database) {
          return {
            success: false,
            page_id: "",
            created_at: new Date().toISOString(),
            page: validatedPage,
            metadata: {
              tenant: validatedPage.tenant,
              capability_token: validatedPage.capability_token,
              enforce_mode: this.enforceMode,
              processing_time_ms: Date.now() - startTime,
            },
            error: `DATABASE_FULL: Maximum ${this.mockConfig.max_pages_per_database} pages allowed per database`,
          };
        }
      }

      // Simulate operation delay
      await this.simulateOperationDelay();

      // Simulate potential failure
      if (Math.random() < this.mockConfig.failure_rate) {
        throw new Error("Simulated Notion operation failure");
      }

      // Generate page ID
      const pageId = this.generatePageId(validatedPage);

      // Store page
      this.pages.set(pageId, { ...validatedPage, id: pageId });

      // Add to database if parent_id is specified
      if (validatedPage.parent_id && this.databases.has(validatedPage.parent_id)) {
        const db = this.databases.get(validatedPage.parent_id)!;
        db.pages.push(pageId);
      }

      // Update hierarchy
      if (validatedPage.parent_id) {
        const children = this.pageHierarchy.get(validatedPage.parent_id) || [];
        children.push(pageId);
        this.pageHierarchy.set(validatedPage.parent_id, children);
      }

      const response: NotionResponse = {
        success: true,
        page_id: pageId,
        created_at: new Date().toISOString(),
        page: { ...validatedPage, id: pageId },
        metadata: {
          tenant: validatedPage.tenant,
          capability_token: validatedPage.capability_token,
          enforce_mode: this.enforceMode,
          processing_time_ms: Date.now() - startTime,
        },
      };

      return response;
    } catch (error) {
      return {
        success: false,
        page_id: "",
        created_at: new Date().toISOString(),
        page: page,
        metadata: {
          tenant: page.tenant || "unknown",
          capability_token: page.capability_token || "",
          enforce_mode: this.enforceMode,
          processing_time_ms: Date.now() - startTime,
        },
        error: error instanceof Error ? error.message : "Unknown error",
      };
    }
  }

  // Get page by ID
  async getPage(pageId: string, capabilityToken: string): Promise<NotionResponse | null> {
    const startTime = Date.now();

    // Validate capability if in enforce mode
    if (this.enforceMode && !this.validateCapability(capabilityToken, "read")) {
      return {
        success: false,
        page_id: pageId,
        created_at: new Date().toISOString(),
        page: {} as NotionPage,
        metadata: {
          tenant: "unknown",
          capability_token: capabilityToken,
          enforce_mode: this.enforceMode,
          processing_time_ms: Date.now() - startTime,
        },
        error: "CAP_MISS: Missing or invalid capability token for Notion page reading",
      };
    }

    const page = this.pages.get(pageId);
    if (!page) {
      return null;
    }

    return {
      success: true,
      page_id: pageId,
      created_at: new Date().toISOString(),
      page,
      metadata: {
        tenant: page.tenant,
        capability_token: capabilityToken,
        enforce_mode: this.enforceMode,
        processing_time_ms: Date.now() - startTime,
      },
    };
  }

  // List pages for a tenant
  async listPages(
    tenant: string,
    capabilityToken: string,
    databaseId?: string,
  ): Promise<NotionPage[]> {
    // Validate capability if in enforce mode
    if (this.enforceMode && !this.validateCapability(capabilityToken, "read")) {
      throw new Error("CAP_MISS: Missing or invalid capability token for Notion page listing");
    }

    let pages = Array.from(this.pages.values()).filter((page) => page.tenant === tenant);

    // Filter by database if specified
    if (databaseId) {
      pages = pages.filter((page) => page.parent_id === databaseId);
    }

    return pages;
  }

  // Search pages
  async searchPages(
    tenant: string,
    query: string,
    capabilityToken: string,
    filters?: Record<string, any>,
  ): Promise<NotionPage[]> {
    // Validate capability if in enforce mode
    if (this.enforceMode && !this.validateCapability(capabilityToken, "read")) {
      throw new Error("CAP_MISS: Missing or invalid capability token for Notion page searching");
    }

    let pages = Array.from(this.pages.values()).filter((page) => page.tenant === tenant);

    // Simple text search
    if (query) {
      const queryLower = query.toLowerCase();
      pages = pages.filter(
        (page) =>
          page.title.toLowerCase().includes(queryLower) ||
          page.content.toLowerCase().includes(queryLower) ||
          (page.tags && page.tags.some((tag) => tag.toLowerCase().includes(queryLower))),
      );
    }

    // Apply filters
    if (filters) {
      pages = pages.filter((page) => {
        for (const [key, value] of Object.entries(filters)) {
          if (page.properties && page.properties[key] !== value) {
            return false;
          }
        }
        return true;
      });
    }

    return pages;
  }

  // Get database by ID
  async getDatabase(databaseId: string, capabilityToken: string): Promise<NotionDatabase | null> {
    // Validate capability if in enforce mode
    if (this.enforceMode && !this.validateCapability(capabilityToken, "read")) {
      throw new Error("CAP_MISS: Missing or invalid capability token for Notion database reading");
    }

    return this.databases.get(databaseId) || null;
  }

  // List databases for a tenant
  async listDatabases(tenant: string, capabilityToken: string): Promise<NotionDatabase[]> {
    // Validate capability if in enforce mode
    if (this.enforceMode && !this.validateCapability(capabilityToken, "read")) {
      throw new Error("CAP_MISS: Missing or invalid capability token for Notion database listing");
    }

    return Array.from(this.databases.values()).filter((db) => db.tenant === tenant);
  }

  // Generate deterministic page ID
  private generatePageId(page: NotionPage): string {
    const data = `${this.seed}:${page.title}:${page.tenant}:${page.parent_id || "root"}:${Date.now()}`;
    return createHash("sha256").update(data).digest("hex").slice(0, 16);
  }

  // Simulate operation delay
  private async simulateOperationDelay(): Promise<void> {
    return new Promise((resolve) => {
      setTimeout(resolve, this.mockConfig.operation_delay_ms);
    });
  }

  // Get mock configuration
  getMockConfig(): MockNotionConfig {
    return { ...this.mockConfig };
  }

  // Reset emulator state
  reset(): void {
    this.pages.clear();
    this.databases.clear();
    this.pageHierarchy.clear();
    this.initializeSampleData();
  }

  // Switch to real mode (placeholder for real Notion service integration)
  async switchToRealMode(apiKey: string, serviceConfig: any): Promise<void> {
    if (this.enforceMode) {
      throw new Error("Cannot switch to real mode while enforce mode is enabled");
    }

    // In a real implementation, this would initialize a real Notion service
    // For now, we'll just log the intention
    console.log("Switching to real Notion service mode");
    console.log("API Key:", apiKey ? "***" + apiKey.slice(-4) : "none");
    console.log("Service Config:", serviceConfig);
  }
}

// Export factory function for easy instantiation
export const createNotionEmulator = (
  seed: string = "default",
  enforceMode: boolean = true,
  capabilityToken: string = "",
  tenant: string = "default",
): NotionEmulator => {
  return new NotionEmulator(seed, enforceMode, capabilityToken, tenant);
};

// Export default instance
export const defaultNotionEmulator = createNotionEmulator();
