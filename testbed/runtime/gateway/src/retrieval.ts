import { createHash, createHmac } from "crypto";
import { Plan, ExecutionContext } from "./types";

// Retrieval Gateway with Per-Tenant Partitions and Signed Access Receipts
// Implements physical partition per tenant/label and signed Access Receipts verified per plan node

export interface RetrievalPartition {
  id: string;
  tenant: string;
  labels: string[];
  shard_id: string;
  encryption_key: string;
  access_policy: string;
  created_at: string;
  last_accessed: string;
}

export interface RetrievalQuery {
  id: string;
  tenant: string;
  labels: string[];
  query_hash: string;
  parameters: Record<string, any>;
  timestamp: string;
  nonce: string;
}

export interface RetrievalResult {
  id: string;
  query_id: string;
  tenant: string;
  data_hash: string;
  metadata: Record<string, any>;
  timestamp: string;
  partition_id: string;
}

export interface SignedAccessReceipt {
  id: string;
  plan_id: string;
  plan_step_id: string;
  tenant: string;
  query_id: string;
  partition_id: string;
  access_timestamp: string;
  expires_at: string;
  capabilities: string[];
  labels: string[];
  query_hash: string;
  result_hash: string;
  signature: string;
  public_key: string;
}

export class RetrievalGateway {
  private partitions: Map<string, RetrievalPartition> = new Map();
  private accessReceipts: Map<string, SignedAccessReceipt> = new Map();
  private tenantShards: Map<string, Set<string>> = new Map();
  private encryptionKeys: Map<string, string> = new Map();

  constructor() {
    this.initializeDefaultPartitions();
  }

  /**
   * Initialize default partitions for system tenants
   */
  private initializeDefaultPartitions(): void {
    const defaultTenants = ["system", "admin", "public"];

    defaultTenants.forEach((tenant) => {
      const partition: RetrievalPartition = {
        id: `partition_${tenant}`,
        tenant,
        labels: ["system"],
        shard_id: `shard_${tenant}`,
        encryption_key: this.generateEncryptionKey(),
        access_policy: "strict",
        created_at: new Date().toISOString(),
        last_accessed: new Date().toISOString(),
      };

      this.partitions.set(partition.id, partition);
      this.tenantShards.set(tenant, new Set([partition.shard_id]));
      this.encryptionKeys.set(partition.id, partition.encryption_key);
    });
  }

  /**
   * Create a new partition for a tenant
   */
  async createPartition(tenant: string, labels: string[]): Promise<RetrievalPartition> {
    const partitionId = `partition_${tenant}_${Date.now()}`;
    const shardId = `shard_${tenant}_${Math.random().toString(36).substr(2, 9)}`;

    const partition: RetrievalPartition = {
      id: partitionId,
      tenant,
      labels,
      shard_id: shardId,
      encryption_key: this.generateEncryptionKey(),
      access_policy: "tenant_isolated",
      created_at: new Date().toISOString(),
      last_accessed: new Date().toISOString(),
    };

    this.partitions.set(partitionId, partition);

    if (!this.tenantShards.has(tenant)) {
      this.tenantShards.set(tenant, new Set());
    }
    this.tenantShards.get(tenant)!.add(shardId);
    this.encryptionKeys.set(partitionId, partition.encryption_key);

    return partition;
  }

  /**
   * Execute retrieval with strict tenant isolation
   */
  async executeRetrieval(
    query: RetrievalQuery,
    plan: Plan,
    context: ExecutionContext,
  ): Promise<{ result: RetrievalResult; receipt: SignedAccessReceipt }> {
    // Verify tenant isolation
    this.verifyTenantIsolation(query.tenant, context.tenant);

    // Find appropriate partition
    const partition = this.findPartition(query.tenant, query.labels);
    if (!partition) {
      throw new Error(
        `No partition found for tenant ${query.tenant} with labels ${query.labels.join(",")}`,
      );
    }

    // Execute query in isolated partition
    const result = await this.executeQueryInPartition(query, partition);

    // Generate signed access receipt
    const receipt = await this.generateAccessReceipt(query, result, plan, partition);

    // Store receipt
    this.accessReceipts.set(receipt.id, receipt);

    // Update partition access time
    partition.last_accessed = new Date().toISOString();

    return { result, receipt };
  }

  /**
   * Verify tenant isolation - prevent cross-tenant access
   */
  private verifyTenantIsolation(queryTenant: string, contextTenant: string): void {
    if (queryTenant !== contextTenant) {
      throw new Error(`Cross-tenant access denied: ${queryTenant} != ${contextTenant}`);
    }
  }

  /**
   * Find appropriate partition for tenant and labels
   */
  private findPartition(tenant: string, labels: string[]): RetrievalPartition | undefined {
    const tenantPartitions = Array.from(this.partitions.values()).filter(
      (p) => p.tenant === tenant,
    );

    // Find partition with matching labels
    return tenantPartitions.find((p) => labels.every((label) => p.labels.includes(label)));
  }

  /**
   * Execute query in isolated partition
   */
  private async executeQueryInPartition(
    query: RetrievalQuery,
    partition: RetrievalPartition,
  ): Promise<RetrievalResult> {
    // Simulate query execution in isolated partition
    const result: RetrievalResult = {
      id: `result_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      query_id: query.id,
      tenant: query.tenant,
      data_hash: this.hashData(query.parameters),
      metadata: {
        partition_id: partition.id,
        shard_id: partition.shard_id,
        labels: query.labels,
        encrypted: true,
      },
      timestamp: new Date().toISOString(),
      partition_id: partition.id,
    };

    return result;
  }

  /**
   * Generate signed access receipt for the retrieval
   */
  private async generateAccessReceipt(
    query: RetrievalQuery,
    result: RetrievalResult,
    plan: Plan,
    partition: RetrievalPartition,
  ): Promise<SignedAccessReceipt> {
    const receipt: SignedAccessReceipt = {
      id: `receipt_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      plan_id: plan.id,
      plan_step_id: query.id,
      tenant: query.tenant,
      query_id: query.id,
      partition_id: partition.id,
      access_timestamp: new Date().toISOString(),
      expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(), // 24 hours
      capabilities: ["read"],
      labels: query.labels,
      query_hash: query.query_hash,
      result_hash: result.data_hash,
      signature: "",
      public_key: this.getPublicKey(partition.id),
    };

    // Sign the receipt
    receipt.signature = await this.signReceipt(receipt, partition.id);

    return receipt;
  }

  /**
   * Verify access receipt signature and validity
   */
  async verifyAccessReceipt(receipt: SignedAccessReceipt): Promise<boolean> {
    try {
      // Check expiration
      if (new Date(receipt.expires_at) < new Date()) {
        return false;
      }

      // Verify signature
      const expectedSignature = await this.signReceipt(receipt, receipt.partition_id);
      if (receipt.signature !== expectedSignature) {
        return false;
      }

      // Verify partition exists and tenant matches
      const partition = this.partitions.get(receipt.partition_id);
      if (!partition || partition.tenant !== receipt.tenant) {
        return false;
      }

      return true;
    } catch (error) {
      console.error("Receipt verification failed:", error);
      return false;
    }
  }

  /**
   * Get all receipts for a plan
   */
  getPlanReceipts(planId: string): SignedAccessReceipt[] {
    return Array.from(this.accessReceipts.values()).filter((r) => r.plan_id === planId);
  }

  /**
   * Get all receipts for a tenant
   */
  getTenantReceipts(tenant: string): SignedAccessReceipt[] {
    return Array.from(this.accessReceipts.values()).filter((r) => r.tenant === tenant);
  }

  /**
   * Audit cross-tenant access attempts
   */
  auditCrossTenantAccess(): { attempts: number; blocked: number; allowed: number } {
    const receipts = Array.from(this.accessReceipts.values());
    const attempts = receipts.length;
    const blocked = receipts.filter((r) => !this.verifyAccessReceipt(r)).length;
    const allowed = attempts - blocked;

    return { attempts, blocked, allowed };
  }

  // Utility methods
  private generateEncryptionKey(): string {
    return createHash("sha256")
      .update(Math.random().toString() + Date.now().toString())
      .digest("hex");
  }

  private hashData(data: any): string {
    const dataStr = JSON.stringify(data);
    return createHash("sha256").update(dataStr).digest("hex");
  }

  private getPublicKey(partitionId: string): string {
    // In production, this would retrieve the actual public key
    return `public_key_${partitionId}`;
  }

  private async signReceipt(
    receipt: Omit<SignedAccessReceipt, "signature">,
    partitionId: string,
  ): Promise<string> {
    const key = this.encryptionKeys.get(partitionId);
    if (!key) {
      throw new Error(`No encryption key found for partition ${partitionId}`);
    }

    const receiptData = JSON.stringify({
      id: receipt.id,
      plan_id: receipt.plan_id,
      tenant: receipt.tenant,
      query_id: receipt.query_id,
      partition_id: receipt.partition_id,
      access_timestamp: receipt.access_timestamp,
      expires_at: receipt.expires_at,
      capabilities: receipt.capabilities,
      labels: receipt.labels,
      query_hash: receipt.query_hash,
      result_hash: receipt.result_hash,
    });

    return createHmac("sha256", key).update(receiptData).digest("hex");
  }

  // Public access methods
  getPartition(partitionId: string): RetrievalPartition | undefined {
    return this.partitions.get(partitionId);
  }

  getTenantPartitions(tenant: string): RetrievalPartition[] {
    return Array.from(this.partitions.values()).filter((p) => p.tenant === tenant);
  }

  getAccessReceipt(receiptId: string): SignedAccessReceipt | undefined {
    return this.accessReceipts.get(receiptId);
  }
}

// Export singleton instance
export const retrievalGateway = new RetrievalGateway();
