import { createHash, createHmac } from "crypto";
import { SignedAccessReceipt, RetrievalPartition } from "./retrieval";
import { Plan, PlanStep } from "./types";

// Receipt Verification Module
// Verifies signed access receipts per plan node with cryptographic validation

export interface ReceiptVerificationResult {
  valid: boolean;
  reason?: string;
  verification_timestamp: string;
  signature_valid: boolean;
  expiration_valid: boolean;
  tenant_match: boolean;
  partition_valid: boolean;
  plan_step_valid: boolean;
}

export interface ReceiptVerificationContext {
  plan: Plan;
  step: PlanStep;
  tenant: string;
  user_id: string;
  session_id: string;
  timestamp: string;
}

export interface ReceiptValidationError {
  code: string;
  message: string;
  details: Record<string, any>;
  timestamp: string;
}

export class ReceiptVerifier {
  private verificationCache: Map<string, ReceiptVerificationResult> = new Map();
  private errorLog: ReceiptValidationError[] = [];
  private verificationStats = {
    total_verifications: 0,
    successful_verifications: 0,
    failed_verifications: 0,
    cache_hits: 0,
    cache_misses: 0,
  };

  constructor() {}

  /**
   * Verify a signed access receipt for a specific plan step
   */
  async verifyReceipt(
    receipt: SignedAccessReceipt,
    context: ReceiptVerificationContext,
    partition: RetrievalPartition,
  ): Promise<ReceiptVerificationResult> {
    const cacheKey = this.generateCacheKey(receipt, context);

    // Check cache first
    if (this.verificationCache.has(cacheKey)) {
      this.verificationStats.cache_hits++;
      return this.verificationCache.get(cacheKey)!;
    }

    this.verificationStats.cache_misses++;
    this.verificationStats.total_verifications++;

    const result = await this.performVerification(receipt, context, partition);

    // Cache the result
    this.verificationCache.set(cacheKey, result);

    // Update stats
    if (result.valid) {
      this.verificationStats.successful_verifications++;
    } else {
      this.verificationStats.failed_verifications++;
      this.logValidationError(receipt, context, result);
    }

    return result;
  }

  /**
   * Perform comprehensive receipt verification
   */
  private async performVerification(
    receipt: SignedAccessReceipt,
    context: ReceiptVerificationContext,
    partition: RetrievalPartition,
  ): Promise<ReceiptVerificationResult> {
    const verification_timestamp = new Date().toISOString();

    // 1. Verify signature
    const signature_valid = await this.verifySignature(receipt, partition);

    // 2. Verify expiration
    const expiration_valid = this.verifyExpiration(receipt);

    // 3. Verify tenant match
    const tenant_match = this.verifyTenantMatch(receipt, context);

    // 4. Verify partition validity
    const partition_valid = this.verifyPartition(receipt, partition);

    // 5. Verify plan step consistency
    const plan_step_valid = this.verifyPlanStep(receipt, context);

    // Overall validity
    const valid =
      signature_valid && expiration_valid && tenant_match && partition_valid && plan_step_valid;

    const result: ReceiptVerificationResult = {
      valid,
      verification_timestamp,
      signature_valid,
      expiration_valid,
      tenant_match,
      partition_valid,
      plan_step_valid,
    };

    // Add reason for failure if any
    if (!valid) {
      result.reason = this.determineFailureReason(result);
    }

    return result;
  }

  /**
   * Verify cryptographic signature of the receipt
   */
  private async verifySignature(
    receipt: SignedAccessReceipt,
    partition: RetrievalPartition,
  ): Promise<boolean> {
    try {
      const expectedSignature = await this.generateExpectedSignature(receipt, partition);
      return receipt.signature === expectedSignature;
    } catch (error) {
      console.error("Signature verification failed:", error);
      return false;
    }
  }

  /**
   * Generate expected signature for comparison
   */
  private async generateExpectedSignature(
    receipt: SignedAccessReceipt,
    partition: RetrievalPartition,
  ): Promise<string> {
    // In production, this would use the actual private key from the partition
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

    // Use partition encryption key for signing
    const key = partition.encryption_key;
    return createHmac("sha256", key).update(receiptData).digest("hex");
  }

  /**
   * Verify receipt hasn't expired
   */
  private verifyExpiration(receipt: SignedAccessReceipt): boolean {
    const now = new Date();
    const expiration = new Date(receipt.expires_at);
    return now < expiration;
  }

  /**
   * Verify tenant matches between receipt and context
   */
  private verifyTenantMatch(
    receipt: SignedAccessReceipt,
    context: ReceiptVerificationContext,
  ): boolean {
    return receipt.tenant === context.tenant;
  }

  /**
   * Verify partition is valid and accessible
   */
  private verifyPartition(receipt: SignedAccessReceipt, partition: RetrievalPartition): boolean {
    return (
      partition.id === receipt.partition_id &&
      partition.tenant === receipt.tenant &&
      partition.access_policy !== "disabled"
    );
  }

  /**
   * Verify plan step consistency
   */
  private verifyPlanStep(
    receipt: SignedAccessReceipt,
    context: ReceiptVerificationContext,
  ): boolean {
    return receipt.plan_id === context.plan.id && receipt.plan_step_id === context.step.id;
  }

  /**
   * Determine the specific reason for verification failure
   */
  private determineFailureReason(result: ReceiptVerificationResult): string {
    if (!result.signature_valid) return "Invalid cryptographic signature";
    if (!result.expiration_valid) return "Receipt has expired";
    if (!result.tenant_match) return "Tenant mismatch between receipt and context";
    if (!result.partition_valid) return "Invalid or inaccessible partition";
    if (!result.plan_step_valid) return "Plan step inconsistency";
    return "Unknown verification failure";
  }

  /**
   * Log validation errors for audit purposes
   */
  private logValidationError(
    receipt: SignedAccessReceipt,
    context: ReceiptVerificationContext,
    result: ReceiptVerificationResult,
  ): void {
    const error: ReceiptValidationError = {
      code: "RECEIPT_VERIFICATION_FAILED",
      message: result.reason || "Receipt verification failed",
      details: {
        receipt_id: receipt.id,
        plan_id: receipt.plan_id,
        tenant: receipt.tenant,
        user_id: context.user_id,
        session_id: context.session_id,
        verification_result: result,
      },
      timestamp: new Date().toISOString(),
    };

    this.errorLog.push(error);

    // Keep only last 1000 errors to prevent memory issues
    if (this.errorLog.length > 1000) {
      this.errorLog = this.errorLog.slice(-1000);
    }
  }

  /**
   * Generate cache key for verification results
   */
  private generateCacheKey(
    receipt: SignedAccessReceipt,
    context: ReceiptVerificationContext,
  ): string {
    const keyData = {
      receipt_id: receipt.id,
      plan_id: context.plan.id,
      step_id: context.step.id,
      tenant: context.tenant,
      user_id: context.user_id,
    };

    return createHash("sha256").update(JSON.stringify(keyData)).digest("hex");
  }

  /**
   * Batch verify multiple receipts
   */
  async batchVerifyReceipts(
    receipts: SignedAccessReceipt[],
    context: ReceiptVerificationContext,
    partition: RetrievalPartition,
  ): Promise<ReceiptVerificationResult[]> {
    const results = await Promise.all(
      receipts.map((receipt) => this.verifyReceipt(receipt, context, partition)),
    );

    return results;
  }

  /**
   * Clear verification cache
   */
  clearCache(): void {
    this.verificationCache.clear();
  }

  /**
   * Get verification statistics
   */
  getVerificationStats() {
    return { ...this.verificationStats };
  }

  /**
   * Get recent validation errors
   */
  getRecentErrors(limit: number = 100): ReceiptValidationError[] {
    return this.errorLog.slice(-limit);
  }

  /**
   * Export verification audit log
   */
  exportAuditLog(): {
    stats: typeof this.verificationStats;
    recent_errors: ReceiptValidationError[];
    cache_size: number;
  } {
    return {
      stats: this.getVerificationStats(),
      recent_errors: this.getRecentErrors(),
      cache_size: this.verificationCache.size,
    };
  }
}

// Export singleton instance
export const receiptVerifier = new ReceiptVerifier();
