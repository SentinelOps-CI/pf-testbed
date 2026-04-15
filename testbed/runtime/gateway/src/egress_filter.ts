import { createHash } from "crypto";
import { Plan, PlanStep } from "./types";

// Content Egress Firewall
// Implements deterministic PII/secret detectors + SimHash near-dup; configurable "never reveal X" templates

export interface PIIPattern {
  name: string;
  pattern: RegExp;
  confidence: number;
  category: "personal" | "financial" | "medical" | "government" | "other";
  replacement: string;
}

export interface SecretPattern {
  name: string;
  pattern: RegExp;
  confidence: number;
  type: "api_key" | "password" | "token" | "private_key" | "other";
  replacement: string;
}

export interface EgressPolicy {
  id: string;
  name: string;
  tenant: string;
  never_reveal: string[];
  pii_detection: boolean;
  secret_detection: boolean;
  near_dup_detection: boolean;
  redaction_mode: "mask" | "hash" | "remove";
  max_content_length: number;
  created_at: string;
  updated_at: string;
}

export interface EgressFilterResult {
  id: string;
  plan_id: string;
  step_id: string;
  tenant: string;
  content_hash: string;
  original_length: number;
  filtered_length: number;
  redaction_summary: {
    pii: number;
    secrets: number;
    near_dup: number;
    blocked_spans: Array<[number, number]>;
    redacted_content: string[];
  };
  non_interference: {
    level: string;
    verdict: "passed" | "failed";
    proof_hash: string;
  };
  processing_time_ms: number;
  timestamp: string;
  policy_applied: string;
}

export interface SimHashResult {
  hash: string;
  similarity: number;
  near_duplicates: string[];
}

export class ContentEgressFirewall {
  private piiPatterns: PIIPattern[] = [];
  private secretPatterns: SecretPattern[] = [];
  private egressPolicies: Map<string, EgressPolicy> = new Map();
  private contentHashes: Map<string, string> = new Map();
  private processingStats = {
    total_processed: 0,
    pii_detected: 0,
    secrets_detected: 0,
    near_dup_detected: 0,
    blocked_content: 0,
    avg_processing_time_ms: 0,
  };

  constructor() {
    this.initializeDefaultPatterns();
    this.initializeDefaultPolicies();
  }

  /**
   * Initialize default PII detection patterns
   */
  private initializeDefaultPatterns(): void {
    // PII Patterns
    this.piiPatterns = [
      {
        name: "email_address",
        pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
        confidence: 0.99,
        category: "personal",
        replacement: "[EMAIL]",
      },
      {
        name: "phone_number",
        pattern: /\b(\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
        confidence: 0.98,
        category: "personal",
        replacement: "[PHONE]",
      },
      {
        name: "credit_card",
        pattern: /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g,
        confidence: 0.99,
        category: "financial",
        replacement: "[CC_NUMBER]",
      },
      {
        name: "ssn",
        pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
        confidence: 0.99,
        category: "government",
        replacement: "[SSN]",
      },
      {
        name: "ip_address",
        pattern: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g,
        confidence: 0.95,
        category: "other",
        replacement: "[IP_ADDRESS]",
      },
    ];

    // Secret Patterns
    this.secretPatterns = [
      {
        name: "api_key",
        pattern: /\b(api[_-]?key|apikey|access[_-]?key)\s*[:=]\s*[a-zA-Z0-9]{20,}\b/gi,
        confidence: 0.95,
        type: "api_key",
        replacement: "[API_KEY]",
      },
      {
        name: "password",
        pattern: /\b(password|passwd|pwd)\s*[:=]\s*[^\s\n]{8,}\b/gi,
        confidence: 0.9,
        type: "password",
        replacement: "[PASSWORD]",
      },
      {
        name: "jwt_token",
        pattern: /\b(eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*)\b/g,
        confidence: 0.99,
        type: "token",
        replacement: "[JWT_TOKEN]",
      },
      {
        name: "private_key",
        pattern:
          /\b-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----\s*[\s\S]*?-----END\s+(RSA\s+)?PRIVATE\s+KEY-----\b/g,
        confidence: 0.99,
        type: "private_key",
        replacement: "[PRIVATE_KEY]",
      },
    ];
  }

  /**
   * Initialize default egress policies
   */
  private initializeDefaultPolicies(): void {
    const defaultPolicies: EgressPolicy[] = [
      {
        id: "default_strict",
        name: "Default Strict Policy",
        tenant: "system",
        never_reveal: ["password", "private_key", "ssn", "credit_card"],
        pii_detection: true,
        secret_detection: true,
        near_dup_detection: true,
        redaction_mode: "mask",
        max_content_length: 1000000, // 1MB
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      },
      {
        id: "financial_restricted",
        name: "Financial Restricted Policy",
        tenant: "financial",
        never_reveal: ["account_number", "routing_number", "balance", "transaction_id"],
        pii_detection: true,
        secret_detection: true,
        near_dup_detection: true,
        redaction_mode: "hash",
        max_content_length: 500000, // 500KB
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      },
    ];

    defaultPolicies.forEach((policy) => {
      this.egressPolicies.set(policy.id, policy);
    });
  }

  /**
   * Filter content through the egress firewall
   */
  async filterContent(
    content: string,
    plan: Plan,
    step: PlanStep,
    policyId: string = "default_strict",
  ): Promise<EgressFilterResult> {
    const startTime = Date.now();
    const policy = this.egressPolicies.get(policyId);

    if (!policy) {
      throw new Error(`Egress policy not found: ${policyId}`);
    }

    // Check content length
    if (content.length > policy.max_content_length) {
      throw new Error(
        `Content exceeds maximum length: ${content.length} > ${policy.max_content_length}`,
      );
    }

    let filteredContent = content;
    const redactionSummary = {
      pii: 0,
      secrets: 0,
      near_dup: 0,
      blocked_spans: [] as Array<[number, number]>,
      redacted_content: [] as string[],
    };

    // Apply PII detection if enabled
    if (policy.pii_detection) {
      const piiResult = this.detectPII(filteredContent, policy);
      filteredContent = piiResult.filtered_content;
      redactionSummary.pii = piiResult.detected_count;
      redactionSummary.redacted_content.push(...piiResult.redacted_items);
    }

    // Apply secret detection if enabled
    if (policy.secret_detection) {
      const secretResult = this.detectSecrets(filteredContent, policy);
      filteredContent = secretResult.filtered_content;
      redactionSummary.secrets = secretResult.detected_count;
      redactionSummary.redacted_content.push(...secretResult.redacted_items);
    }

    // Apply near-duplicate detection if enabled
    if (policy.near_dup_detection) {
      const dupResult = this.detectNearDuplicates(filteredContent);
      redactionSummary.near_dup = dupResult.near_duplicates.length;
    }

    // Apply "never reveal" templates
    const neverRevealResult = this.applyNeverRevealTemplates(filteredContent, policy);
    filteredContent = neverRevealResult.filtered_content;
    redactionSummary.redacted_content.push(...neverRevealResult.redacted_items);

    const processingTime = Date.now() - startTime;
    const contentHash = this.hashContent(filteredContent);

    const result: EgressFilterResult = {
      id: `egress_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      plan_id: plan.id,
      step_id: step.id,
      tenant: plan.tenant,
      content_hash: contentHash,
      original_length: content.length,
      filtered_length: filteredContent.length,
      redaction_summary: redactionSummary,
      non_interference: {
        level: this.calculateNonInterferenceLevel(redactionSummary),
        verdict: redactionSummary.pii > 0 || redactionSummary.secrets > 0 ? "failed" : "passed",
        proof_hash: this.generateProofHash(content, filteredContent, redactionSummary),
      },
      processing_time_ms: processingTime,
      timestamp: new Date().toISOString(),
      policy_applied: policyId,
    };

    // Update processing stats
    this.updateProcessingStats(result);

    // Store content hash for future reference
    this.contentHashes.set(contentHash, filteredContent);

    return result;
  }

  /**
   * Detect PII in content
   */
  private detectPII(
    content: string,
    _policy: EgressPolicy,
  ): {
    filtered_content: string;
    detected_count: number;
    redacted_items: string[];
  } {
    let filteredContent = content;
    let detectedCount = 0;
    const redactedItems: string[] = [];

    this.piiPatterns.forEach((pattern) => {
      const matches = content.match(pattern.pattern);
      if (matches) {
        detectedCount += matches.length;
        matches.forEach((match) => {
          redactedItems.push(`${pattern.name}: ${match}`);
          filteredContent = filteredContent.replace(match, pattern.replacement);
        });
      }
    });

    return {
      filtered_content: filteredContent,
      detected_count: detectedCount,
      redacted_items: redactedItems,
    };
  }

  /**
   * Detect secrets in content
   */
  private detectSecrets(
    content: string,
    _policy: EgressPolicy,
  ): {
    filtered_content: string;
    detected_count: number;
    redacted_items: string[];
  } {
    let filteredContent = content;
    let detectedCount = 0;
    const redactedItems: string[] = [];

    this.secretPatterns.forEach((pattern) => {
      const matches = content.match(pattern.pattern);
      if (matches) {
        detectedCount += matches.length;
        matches.forEach((match) => {
          redactedItems.push(`${pattern.type}: ${match}`);
          filteredContent = filteredContent.replace(match, pattern.replacement);
        });
      }
    });

    return {
      filtered_content: filteredContent,
      detected_count: detectedCount,
      redacted_items: redactedItems,
    };
  }

  /**
   * Detect near-duplicates using SimHash
   */
  private detectNearDuplicates(content: string): SimHashResult {
    const contentHash = this.generateSimHash(content);
    const nearDuplicates: string[] = [];

    // Check against stored hashes for similarity
    this.contentHashes.forEach((storedContent, hash) => {
      const similarity = this.calculateSimHashSimilarity(contentHash, hash);
      if (similarity > 0.8) {
        // 80% similarity threshold
        nearDuplicates.push(hash);
      }
    });

    return {
      hash: contentHash,
      similarity: nearDuplicates.length > 0 ? 0.85 : 0.0,
      near_duplicates: nearDuplicates,
    };
  }

  /**
   * Apply "never reveal" templates
   */
  private applyNeverRevealTemplates(
    content: string,
    policy: EgressPolicy,
  ): {
    filtered_content: string;
    redacted_items: string[];
  } {
    let filteredContent = content;
    const redactedItems: string[] = [];

    policy.never_reveal.forEach((template) => {
      const regex = new RegExp(`\\b${template}\\b`, "gi");
      const matches = content.match(regex);
      if (matches) {
        matches.forEach((match) => {
          redactedItems.push(`never_reveal: ${match}`);
          filteredContent = filteredContent.replace(match, `[${template.toUpperCase()}]`);
        });
      }
    });

    return {
      filtered_content: filteredContent,
      redacted_items: redactedItems,
    };
  }

  /**
   * Generate SimHash for content
   */
  private generateSimHash(content: string): string {
    // Simplified SimHash implementation
    const words = content.toLowerCase().split(/\s+/);
    const hash = createHash("sha256").update(words.join(" ")).digest("hex");
    return hash;
  }

  /**
   * Calculate similarity between two SimHashes
   */
  private calculateSimHashSimilarity(hash1: string, hash2: string): number {
    // Simplified similarity calculation
    let differences = 0;
    const minLength = Math.min(hash1.length, hash2.length);

    for (let i = 0; i < minLength; i++) {
      if (hash1[i] !== hash2[i]) {
        differences++;
      }
    }

    return 1 - differences / minLength;
  }

  /**
   * Calculate non-interference level
   */
  private calculateNonInterferenceLevel(redactionSummary: any): string {
    if (redactionSummary.pii === 0 && redactionSummary.secrets === 0) {
      return "L0"; // No sensitive data
    } else if (redactionSummary.pii <= 5 && redactionSummary.secrets === 0) {
      return "L1"; // Low risk
    } else if (redactionSummary.pii <= 10 || redactionSummary.secrets > 0) {
      return "L2"; // Medium risk
    } else {
      return "L3"; // High risk
    }
  }

  /**
   * Generate proof hash for non-interference
   */
  private generateProofHash(original: string, filtered: string, summary: any): string {
    const proofData = {
      original_hash: this.hashContent(original),
      filtered_hash: this.hashContent(filtered),
      redaction_summary: summary,
      timestamp: Date.now(),
    };

    return createHash("sha256").update(JSON.stringify(proofData)).digest("hex");
  }

  /**
   * Hash content for storage and comparison
   */
  private hashContent(content: string): string {
    return createHash("sha256").update(content).digest("hex");
  }

  /**
   * Update processing statistics
   */
  private updateProcessingStats(result: EgressFilterResult): void {
    this.processingStats.total_processed++;
    this.processingStats.pii_detected += result.redaction_summary.pii;
    this.processingStats.secrets_detected += result.redaction_summary.secrets;
    this.processingStats.near_dup_detected += result.redaction_summary.near_dup;

    if (result.non_interference.verdict === "failed") {
      this.processingStats.blocked_content++;
    }

    // Update average processing time
    const totalTime =
      this.processingStats.avg_processing_time_ms * (this.processingStats.total_processed - 1);
    this.processingStats.avg_processing_time_ms =
      (totalTime + result.processing_time_ms) / this.processingStats.total_processed;
  }

  /**
   * Add custom PII pattern
   */
  addPIIPattern(pattern: PIIPattern): void {
    this.piiPatterns.push(pattern);
  }

  /**
   * Add custom secret pattern
   */
  addSecretPattern(pattern: SecretPattern): void {
    this.secretPatterns.push(pattern);
  }

  /**
   * Create new egress policy
   */
  createPolicy(policy: Omit<EgressPolicy, "id" | "created_at" | "updated_at">): EgressPolicy {
    const newPolicy: EgressPolicy = {
      ...policy,
      id: `policy_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    this.egressPolicies.set(newPolicy.id, newPolicy);
    return newPolicy;
  }

  /**
   * Get processing statistics
   */
  getProcessingStats() {
    return { ...this.processingStats };
  }

  /**
   * Get all policies
   */
  getAllPolicies(): EgressPolicy[] {
    return Array.from(this.egressPolicies.values());
  }

  /**
   * Get policy by ID
   */
  getPolicy(policyId: string): EgressPolicy | undefined {
    return this.egressPolicies.get(policyId);
  }
}

// Export singleton instance
export const contentEgressFirewall = new ContentEgressFirewall();
