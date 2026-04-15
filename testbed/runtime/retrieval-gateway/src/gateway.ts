import { randomBytes, createHash, createHmac } from "crypto";
import { z } from "zod";

// Schema for retrieval requests
export const RetrievalRequestSchema = z.object({
  tenant: z.string().min(1),
  subject: z.string().min(1),
  query: z.record(z.any()),
  user_id: z.string().min(1),
  capabilities: z.array(z.string()).min(1),
  nonce: z.string().min(16),
});

// Schema for access receipts
export const AccessReceiptSchema = z.object({
  tenant: z.string().min(1),
  subject: z.string().min(1),
  shard: z.string().min(1),
  query_hash: z.string().min(1),
  result_hash: z.string().min(1),
  nonce: z.string().min(16),
  exp: z.string().datetime(), // Changed from expires_at to exp for consistency
  sig: z.string().min(1), // Changed from signature to sig for consistency
});

// Schema for retrieval responses
export const RetrievalResponseSchema = z.object({
  success: z.boolean(),
  data: z.any().optional(),
  error: z.string().optional(),
  receipt: AccessReceiptSchema,
  metadata: z.object({
    tenant: z.string(),
    shard: z.string(),
    query_hash: z.string(),
    result_hash: z.string(),
    timestamp: z.string().datetime(),
    request_id: z.string(),
  }),
});

// Types
export type RetrievalRequest = z.infer<typeof RetrievalRequestSchema>;
export type AccessReceipt = z.infer<typeof AccessReceiptSchema>;
export type RetrievalResponse = z.infer<typeof RetrievalResponseSchema>;

// Honeytoken interface
export interface Honeytoken {
  id: string;
  tenant: string;
  subject: string;
  data: any;
  created_at: string;
  accessed_count: number;
  last_accessed?: string;
  alert_threshold: number;
}

// Sharded data store interface
export interface ShardedDataStore {
  get(tenant: string, subject: string, query: Record<string, any>): Promise<any>;
  set(tenant: string, subject: string, data: any): Promise<void>;
  delete(tenant: string, subject: string): Promise<void>;
  list(tenant: string, pattern?: string): Promise<string[]>;
  addHoneytoken(honeytoken: Honeytoken): Promise<void>;
  getHoneytoken(tenant: string, subject: string): Promise<Honeytoken | null>;
  updateHoneytokenAccess(honeytokenId: string): Promise<void>;
}

// In-memory sharded data store implementation
export class InMemoryShardedStore implements ShardedDataStore {
  private data: Map<string, Map<string, any>> = new Map();
  private honeytokens: Map<string, Honeytoken> = new Map();

  constructor() {
    // Initialize with some test data
    this.initializeTestData();
    this.initializeHoneytokens();
  }

  private initializeTestData(): void {
    // ACME tenant data
    const acmeData = new Map();
    acmeData.set("ticket_123", {
      id: "ticket_123",
      title: "Server down issue",
      priority: "high",
      status: "open",
      created_by: "user1",
      tenant: "acme",
    });
    acmeData.set("ticket_456", {
      id: "ticket_456",
      title: "Login problem",
      priority: "medium",
      status: "resolved",
      created_by: "user2",
      tenant: "acme",
    });
    this.data.set("acme", acmeData);

    // Globex tenant data
    const globexData = new Map();
    globexData.set("incident_789", {
      id: "incident_789",
      title: "Database connection timeout",
      severity: "critical",
      status: "investigating",
      assigned_to: "admin1",
      tenant: "globex",
    });
    globexData.set("incident_101", {
      id: "incident_101",
      title: "API rate limit exceeded",
      severity: "warning",
      status: "resolved",
      assigned_to: "admin2",
      tenant: "globex",
    });
    this.data.set("globex", globexData);
  }

  private initializeHoneytokens(): void {
    // Add honeytokens for each tenant to detect unauthorized access
    const acmeHoneytoken: Honeytoken = {
      id: "honeytoken_acme_001",
      tenant: "acme",
      subject: "honeytoken_001",
      data: {
        id: "honeytoken_001",
        title: "Sensitive internal document",
        content: "This is a honeytoken - unauthorized access detected",
        tenant: "acme",
        is_honeytoken: true,
      },
      created_at: new Date().toISOString(),
      accessed_count: 0,
      alert_threshold: 1,
    };

    const globexHoneytoken: Honeytoken = {
      id: "honeytoken_globex_001",
      tenant: "globex",
      subject: "honeytoken_001",
      data: {
        id: "honeytoken_001",
        title: "Confidential report",
        content: "This is a honeytoken - unauthorized access detected",
        tenant: "globex",
        is_honeytoken: true,
      },
      created_at: new Date().toISOString(),
      accessed_count: 0,
      alert_threshold: 1,
    };

    this.honeytokens.set(acmeHoneytoken.id, acmeHoneytoken);
    this.honeytokens.set(globexHoneytoken.id, globexHoneytoken);
  }

  async get(tenant: string, subject: string, query: Record<string, any>): Promise<any> {
    const tenantData = this.data.get(tenant);
    if (!tenantData) {
      throw new Error(`Tenant ${tenant} not found`);
    }

    let data = tenantData.get(subject);
    if (!data) {
      const honeytoken = await this.getHoneytoken(tenant, subject);
      if (honeytoken) {
        data = honeytoken.data;
      }
    }
    if (!data) {
      for (const [otherTenant, otherMap] of this.data) {
        if (otherTenant === tenant) {
          continue;
        }
        if (otherMap.has(subject)) {
          throw new Error("Cross-tenant access denied");
        }
      }
      for (const [, ht] of this.honeytokens) {
        if (ht.tenant !== tenant && ht.subject === subject) {
          throw new Error("Cross-tenant access denied");
        }
      }
      throw new Error(`Subject ${subject} not found in tenant ${tenant}`);
    }

    // Apply query filters (simple implementation)
    return this.applyQueryFilters(data, query);
  }

  async set(tenant: string, subject: string, data: any): Promise<void> {
    if (!this.data.has(tenant)) {
      this.data.set(tenant, new Map());
    }
    this.data.get(tenant)!.set(subject, { ...data, tenant });
  }

  async delete(tenant: string, subject: string): Promise<void> {
    const tenantData = this.data.get(tenant);
    if (tenantData) {
      tenantData.delete(subject);
    }
  }

  async list(tenant: string, pattern?: string): Promise<string[]> {
    const tenantData = this.data.get(tenant);
    if (!tenantData) {
      return [];
    }

    const subjects = Array.from(tenantData.keys());
    if (pattern) {
      return subjects.filter((subject) => subject.includes(pattern));
    }
    return subjects;
  }

  async addHoneytoken(honeytoken: Honeytoken): Promise<void> {
    this.honeytokens.set(honeytoken.id, honeytoken);
  }

  async getHoneytoken(tenant: string, subject: string): Promise<Honeytoken | null> {
    for (const [, honeytoken] of this.honeytokens) {
      if (honeytoken.tenant === tenant && honeytoken.subject === subject) {
        return honeytoken;
      }
    }
    return null;
  }

  async updateHoneytokenAccess(honeytokenId: string): Promise<void> {
    const honeytoken = this.honeytokens.get(honeytokenId);
    if (honeytoken) {
      honeytoken.accessed_count++;
      honeytoken.last_accessed = new Date().toISOString();

      // Alert if threshold exceeded
      if (honeytoken.accessed_count >= honeytoken.alert_threshold) {
        console.warn(
          `🚨 HONEYTOKEN ALERT: ${honeytokenId} accessed ${honeytoken.accessed_count} times!`,
        );
        // In production, this would trigger security alerts, logging, etc.
      }
    }
  }

  private applyQueryFilters(data: any, query: Record<string, any>): any {
    // Simple query filtering - in production, this would use a proper query engine
    let filteredData = data;

    for (const [key, value] of Object.entries(query)) {
      if (filteredData[key] !== value) {
        return null; // No match
      }
    }

    return filteredData;
  }

  // Get all data for a tenant (for testing purposes)
  getAllTenantData(tenant: string): any[] {
    const tenantData = this.data.get(tenant);
    if (!tenantData) {
      return [];
    }
    return Array.from(tenantData.values());
  }
}

// Retrieval Gateway class
export class RetrievalGateway {
  private dataStore: ShardedDataStore;
  private readonly signingSecret: string;
  private readonly receiptExpiryHours = 24;

  constructor(dataStore: ShardedDataStore, privateKeyHex: string) {
    this.dataStore = dataStore;
    this.signingSecret = privateKeyHex;
  }

  // Main retrieval method
  async retrieve(request: RetrievalRequest): Promise<RetrievalResponse> {
    try {
      // Validate request
      const validatedRequest = RetrievalRequestSchema.parse(request);

      // Generate shard path
      const shard = `tenants/${validatedRequest.tenant}`;

      // Generate query hash
      const queryHash = this.generateQueryHash(validatedRequest.query);

      // Retrieve data from sharded store
      const data = await this.dataStore.get(
        validatedRequest.tenant,
        validatedRequest.subject,
        validatedRequest.query,
      );

      if (!data) {
        throw new Error("No data found matching query");
      }

      // Check if this is a honeytoken access
      const honeytoken = await this.dataStore.getHoneytoken(
        validatedRequest.tenant,
        validatedRequest.subject,
      );
      if (honeytoken && data.is_honeytoken) {
        await this.dataStore.updateHoneytokenAccess(honeytoken.id);
      }

      // Generate result hash
      const resultHash = this.generateResultHash(data);

      // Generate access receipt
      const receipt = await this.generateAccessReceipt({
        tenant: validatedRequest.tenant,
        subject: validatedRequest.subject,
        shard,
        query_hash: queryHash,
        result_hash: resultHash,
        nonce: validatedRequest.nonce,
      });

      // Generate response
      const response: RetrievalResponse = {
        success: true,
        data,
        receipt,
        metadata: {
          tenant: validatedRequest.tenant,
          shard,
          query_hash: queryHash,
          result_hash: resultHash,
          timestamp: new Date().toISOString(),
          request_id: this.generateRequestId(),
        },
      };

      return response;
    } catch (error) {
      // Generate error receipt
      const receipt = await this.generateAccessReceipt({
        tenant: request.tenant || "unknown",
        subject: request.subject || "unknown",
        shard: `tenants/${request.tenant || "unknown"}`,
        query_hash: this.generateQueryHash(request.query || {}),
        result_hash: "error",
        nonce: request.nonce || randomBytes(16).toString("hex"),
      });

      return {
        success: false,
        error: error instanceof Error ? error.message : "Unknown error",
        receipt,
        metadata: {
          tenant: request.tenant || "unknown",
          shard: `tenants/${request.tenant || "unknown"}`,
          query_hash: this.generateQueryHash(request.query || {}),
          result_hash: "error",
          timestamp: new Date().toISOString(),
          request_id: this.generateRequestId(),
        },
      };
    }
  }

  // Generate access receipt with deterministic signature.
  private async generateAccessReceipt(data: {
    tenant: string;
    subject: string;
    shard: string;
    query_hash: string;
    result_hash: string;
    nonce: string;
  }): Promise<AccessReceipt> {
    const exp = new Date(Date.now() + this.receiptExpiryHours * 60 * 60 * 1000).toISOString();

    const receiptData = {
      ...data,
      exp,
    };

    const dataString = JSON.stringify(receiptData, Object.keys(receiptData).sort());
    const message = Buffer.from(dataString, "utf8");

    const sig = createHmac("sha256", this.signingSecret).update(message).digest("hex");

    return { ...receiptData, sig };
  }

  // Generate query hash
  private generateQueryHash(query: Record<string, any>): string {
    const queryString = JSON.stringify(query, Object.keys(query).sort());
    return createHash("sha256").update(queryString).digest("hex");
  }

  // Generate result hash
  private generateResultHash(data: any): string {
    const dataString = JSON.stringify(data, Object.keys(data).sort());
    return createHash("sha256").update(dataString).digest("hex");
  }

  // Generate request ID
  private generateRequestId(): string {
    return randomBytes(8).toString("hex");
  }

  // Verify access receipt signature
  async verifyReceipt(receipt: AccessReceipt): Promise<boolean> {
    try {
      const { sig, ...dataToSign } = receipt;
      const dataString = JSON.stringify(dataToSign, Object.keys(dataToSign).sort());
      const message = Buffer.from(dataString, "utf8");
      const expectedSig = createHmac("sha256", this.signingSecret).update(message).digest("hex");
      return sig === expectedSig;
    } catch (error) {
      return false;
    }
  }

  // Check if receipt is expired
  isReceiptExpired(receipt: AccessReceipt): boolean {
    const expiryDate = new Date(receipt.exp);
    const now = new Date();
    return now > expiryDate;
  }

  // Validate receipt for access
  async validateReceiptForAccess(
    receipt: AccessReceipt,
    tenant: string,
    subject: string,
  ): Promise<boolean> {
    // Check if receipt is valid
    if (!(await this.verifyReceipt(receipt))) {
      return false;
    }

    // Check if receipt is expired
    if (this.isReceiptExpired(receipt)) {
      return false;
    }

    // Check if receipt matches the requested access
    if (receipt.tenant !== tenant || receipt.subject !== subject) {
      return false;
    }

    return true;
  }

  // Get tenant data (for testing)
  getTenantData(tenant: string): any[] {
    if (this.dataStore instanceof InMemoryShardedStore) {
      return this.dataStore.getAllTenantData(tenant);
    }
    return [];
  }

  // List available tenants (for testing)
  getAvailableTenants(): string[] {
    if (this.dataStore instanceof InMemoryShardedStore) {
      return Array.from(this.dataStore["data"].keys());
    }
    return [];
  }

  // Get public key for verification
  getPublicKey(): string {
    return createHash("sha256").update(this.signingSecret).digest("hex");
  }
}

// Export instances for testing
export const createTestGateway = async (): Promise<RetrievalGateway> => {
  const dataStore = new InMemoryShardedStore();
  let privateKey = process.env["ACCESS_RECEIPT_PRIVATE_KEY"];
  if (!privateKey) {
    if (process.env["NODE_ENV"] !== "test") {
      throw new Error("ACCESS_RECEIPT_PRIVATE_KEY must be set outside test mode");
    }
    privateKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  }
  return new RetrievalGateway(dataStore, privateKey);
};
