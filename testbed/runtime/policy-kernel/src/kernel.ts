import { createHash } from "crypto";
import { z } from "zod";

// Schema definitions matching the Go implementation
export const SystemChannelSchema = z.object({
  hash: z.string().regex(/^[a-fA-F0-9]{64}$/),
  policy_hash: z.string().regex(/^[a-fA-F0-9]{64}$/),
});

export const UserChannelSchema = z.object({
  content_hash: z.string().regex(/^[a-fA-F0-9]{64}$/),
  quoted: z.literal(true), // Must be true for untrusted channels
});

export const RetrievedChannelSchema = z.object({
  receipt_id: z.string(),
  content_hash: z.string().regex(/^[a-fA-F0-9]{64}$/),
  quoted: z.literal(true), // Must be true for untrusted channels
  labels: z.array(z.string()),
});

export const FileChannelSchema = z.object({
  sha256: z.string().regex(/^[a-fA-F0-9]{64}$/),
  media_type: z.string(),
  quoted: z.literal(true), // Must be true for untrusted channels
});

export const InputChannelsSchema = z.object({
  system: SystemChannelSchema,
  user: UserChannelSchema,
  retrieved: z.array(RetrievedChannelSchema).optional(),
  file: z.array(FileChannelSchema).optional(),
});

export const AccessReceiptSchema = z.object({
  receipt_id: z.string(),
  tenant: z.string(),
  subject_id: z.string(),
  query_hash: z.string(),
  index_shard: z.string(),
  timestamp: z.number(),
  result_hash: z.string(),
  sign_alg: z.string(),
  sig: z.string(),
});

export const SubjectSchema = z.object({
  id: z.string(),
  caps: z.array(z.string()),
});

export const StepSchema = z.object({
  tool: z.string(),
  args: z.record(z.any()),
  caps_required: z.array(z.string()),
  labels_in: z.array(z.string()),
  labels_out: z.array(z.string()),
  receipts: z.array(AccessReceiptSchema).optional(),
});

export const ConstraintsSchema = z.object({
  budget: z.number().min(0).max(10000),
  pii: z.boolean(),
  dp_epsilon: z.number().min(0).max(10),
  dp_delta: z.number().min(0).max(1e-5).optional(),
  latency_max: z.number().min(0).max(300).optional(),
  max_tokens: z.number().int().min(0).max(100000).optional(),
  max_retrieval_results: z.number().int().min(0).max(1000).optional(),
});

export const PlanSchema = z.object({
  plan_id: z.string().regex(/^[a-zA-Z0-9_-]+$/),
  tenant: z.string().regex(/^[a-zA-Z0-9_-]+$/),
  subject: SubjectSchema,
  input_channels: InputChannelsSchema,
  steps: z.array(StepSchema),
  constraints: ConstraintsSchema,
  system_prompt_hash: z.string().regex(/^[a-fA-F0-9]{64}$/),
  allowed_operations: z.array(z.string()),
  created_at: z.string().datetime().optional(),
  expires_at: z.string().datetime().optional(),
  security_level: z.enum(["strict", "permissive"]).default("strict"),
});

// Types
export type SystemChannel = z.infer<typeof SystemChannelSchema>;
export type UserChannel = z.infer<typeof UserChannelSchema>;
export type RetrievedChannel = z.infer<typeof RetrievedChannelSchema>;
export type FileChannel = z.infer<typeof FileChannelSchema>;
export type InputChannels = z.infer<typeof InputChannelsSchema>;
export type AccessReceipt = z.infer<typeof AccessReceiptSchema>;
export type Subject = z.infer<typeof SubjectSchema>;
export type Step = z.infer<typeof StepSchema>;
export type Constraints = z.infer<typeof ConstraintsSchema>;
export type Plan = z.infer<typeof PlanSchema>;

// Policy Kernel Engine
export class PolicyKernel {
  private readonly injectionCorpus: Set<string> = new Set();
  private readonly blockedInjectionAttempts = new Map<string, number>();

  constructor() {
    this.initializeInjectionCorpus();
  }

  private initializeInjectionCorpus(): void {
    // Common injection patterns to block
    const patterns = [
      // SQL Injection
      "'; DROP TABLE users; --",
      "' OR '1'='1",
      "'; INSERT INTO users VALUES ('hacker', 'password'); --",

      // NoSQL Injection
      '{"$where": "function() { return true; }"}',
      '{"$ne": null}',

      // Command Injection
      "; rm -rf /",
      "| cat /etc/passwd",
      "&& echo 'hacked'",

      // XSS
      "<script>alert('xss')</script>",
      "javascript:alert('xss')",

      // Template Injection
      "{{7*7}}",
      "${7*7}",

      // Path Traversal
      "../../../etc/passwd",
      "..\\..\\..\\windows\\system32\\config\\sam",

      // LDAP Injection
      "*)(uid=*))(|(uid=*",
      "*))%00",

      // XML Injection
      "<!DOCTYPE test [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><test>&xxe;</test>",

      // JSON Injection
      '{"__proto__": {"isAdmin": true}}',
      '{"constructor": {"prototype": {"isAdmin": true}}}',
    ];

    patterns.forEach((pattern) => {
      this.injectionCorpus.add(pattern);
      this.blockedInjectionAttempts.set(pattern, 0);
    });
  }

  // Validate plan against schema and security policies
  validatePlan(plan: Plan): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    try {
      // Validate against schema
      PlanSchema.parse(plan);
    } catch (error) {
      if (error instanceof z.ZodError) {
        errors.push(`Schema validation failed: ${error.errors.map((e) => e.message).join(", ")}`);
      } else {
        errors.push(`Unknown validation error: ${error}`);
      }
    }

    // Security validations
    if (plan.security_level === "strict") {
      // Validate that all untrusted channels have quoted=true
      if (!plan.input_channels.user.quoted) {
        errors.push("User channel must have quoted=true in strict mode");
      }

      if (plan.input_channels.retrieved) {
        for (const retrieved of plan.input_channels.retrieved) {
          if (!retrieved.quoted) {
            errors.push(
              `Retrieved channel ${retrieved.receipt_id} must have quoted=true in strict mode`,
            );
          }
        }
      }

      if (plan.input_channels.file) {
        for (const file of plan.input_channels.file) {
          if (!file.quoted) {
            errors.push(`File channel ${file.sha256} must have quoted=true in strict mode`);
          }
        }
      }
    }

    // Validate capability matching
    for (const step of plan.steps) {
      for (const requiredCap of step.caps_required) {
        if (!plan.subject.caps.includes(requiredCap)) {
          errors.push(
            `Step ${step.tool} requires capability ${requiredCap} not possessed by subject ${plan.subject.id}`,
          );
        }
      }
    }

    // Validate allowed operations
    for (const step of plan.steps) {
      if (!plan.allowed_operations.includes(step.tool)) {
        errors.push(`Tool ${step.tool} is not in allowed_operations list`);
      }
    }

    // Validate constraints
    if (plan.constraints.budget > 10000) {
      errors.push("Budget exceeds maximum allowed value of 10000");
    }

    if (plan.constraints.dp_epsilon > 10) {
      errors.push("Differential privacy epsilon exceeds maximum allowed value of 10");
    }

    if (plan.constraints.dp_delta && plan.constraints.dp_delta > 1e-5) {
      errors.push("Differential privacy delta exceeds maximum allowed value of 1e-5");
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  // Validate step execution with capability and receipt checks
  validateStepExecution(
    step: Step,
    subject: Subject,
    receipts: AccessReceipt[],
    labels: string[],
  ): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    // Check capability matching
    for (const requiredCap of step.caps_required) {
      if (!subject.caps.includes(requiredCap)) {
        errors.push(`Required capability ${requiredCap} not possessed by subject ${subject.id}`);
      }
    }

    // Check receipt validation for retrieval steps
    if (step.tool === "retrieve" || step.tool === "data_query" || step.tool === "search") {
      if (!step.receipts || step.receipts.length === 0) {
        errors.push(`Retrieval step ${step.tool} must have access receipts`);
      } else {
        for (const receipt of step.receipts) {
          if (!this.validateReceipt(receipt)) {
            errors.push(`Invalid receipt ${receipt.receipt_id} for step ${step.tool}`);
          }
        }
      }
    }

    // Check label flow
    for (const requiredLabel of step.labels_in) {
      if (!labels.includes(requiredLabel)) {
        errors.push(`Required input label ${requiredLabel} not present for step ${step.tool}`);
      }
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  // Validate access receipt
  validateReceipt(receipt: AccessReceipt): boolean {
    // Basic validation - in production this would verify signatures
    if (!receipt.receipt_id || !receipt.tenant || !receipt.subject_id) {
      return false;
    }

    // Check timestamp (receipts should not be too old)
    const receiptTime = new Date(receipt.timestamp);
    const now = new Date();
    const ageHours = (now.getTime() - receiptTime.getTime()) / (1000 * 60 * 60);

    if (ageHours > 24) {
      return false; // Receipt too old
    }

    return true;
  }

  // Check for injection attempts
  checkForInjection(content: string): {
    blocked: boolean;
    pattern?: string;
    confidence: number;
  } {
    const normalizedContent = content.toLowerCase();

    for (const pattern of this.injectionCorpus) {
      if (normalizedContent.includes(pattern.toLowerCase())) {
        // Increment blocked attempts counter
        const currentCount = this.blockedInjectionAttempts.get(pattern) || 0;
        this.blockedInjectionAttempts.set(pattern, currentCount + 1);

        return {
          blocked: true,
          pattern,
          confidence: 0.95,
        };
      }
    }

    // Check for suspicious patterns
    const suspiciousPatterns = [
      /['";]\s*(drop|insert|update|delete|exec|eval|system)/i,
      /[<>]\s*script/i,
      /javascript:/i,
      /\.\.\/\.\.\//,
      /[{}]\s*\$[a-z]/i,
    ];

    for (const pattern of suspiciousPatterns) {
      if (pattern.test(content)) {
        return {
          blocked: true,
          pattern: pattern.source,
          confidence: 0.85,
        };
      }
    }

    return {
      blocked: false,
      confidence: 0.0,
    };
  }

  // Get injection blocking statistics
  getInjectionStats(): {
    totalPatterns: number;
    blockedAttempts: number;
    blockedPercentage: number;
    topBlockedPatterns: Array<{ pattern: string; count: number }>;
  } {
    const totalPatterns = this.injectionCorpus.size;
    const blockedAttempts = Array.from(this.blockedInjectionAttempts.values()).reduce(
      (sum, count) => sum + count,
      0,
    );

    const blockedPercentage =
      totalPatterns > 0 ? (this.blockedInjectionAttempts.size / totalPatterns) * 100 : 0;

    const topBlockedPatterns = Array.from(this.blockedInjectionAttempts.entries())
      .map(([pattern, count]) => ({ pattern, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    return {
      totalPatterns,
      blockedAttempts,
      blockedPercentage,
      topBlockedPatterns,
    };
  }

  // Validate numeric refinements
  validateNumericRefinements(
    constraints: Constraints,
    actualValues: Record<string, number>,
  ): { valid: boolean; violations: string[] } {
    const violations: string[] = [];

    if (actualValues.budget && actualValues.budget > constraints.budget) {
      violations.push(`Budget violation: ${actualValues.budget} > ${constraints.budget}`);
    }

    if (actualValues.dp_epsilon && actualValues.dp_epsilon > constraints.dp_epsilon) {
      violations.push(
        `DP epsilon violation: ${actualValues.dp_epsilon} > ${constraints.dp_epsilon}`,
      );
    }

    if (actualValues.latency && actualValues.latency > (constraints.latency_max || 300)) {
      violations.push(
        `Latency violation: ${actualValues.latency} > ${constraints.latency_max || 300}`,
      );
    }

    if (actualValues.tokens && actualValues.tokens > (constraints.max_tokens || 100000)) {
      violations.push(
        `Token violation: ${actualValues.tokens} > ${constraints.max_tokens || 100000}`,
      );
    }

    return {
      valid: violations.length === 0,
      violations,
    };
  }

  // Generate content hash for input validation
  generateContentHash(content: string): string {
    return createHash("sha256").update(content).digest("hex");
  }

  // Validate system prompt hash
  validateSystemPrompt(actualPrompt: string, expectedHash: string): boolean {
    const actualHash = this.generateContentHash(actualPrompt);
    return actualHash === expectedHash;
  }
}

// Tool Broker that enforces kernel decisions
export class ToolBroker {
  private kernel: PolicyKernel;
  private approvedTools: Set<string> = new Set();
  private executionLog: Array<{
    timestamp: string;
    tool: string;
    subject: string;
    approved: boolean;
    reason?: string;
  }> = [];

  constructor(kernel: PolicyKernel) {
    this.kernel = kernel;
  }

  // Request tool execution approval
  requestExecution(
    tool: string,
    subject: Subject,
    step: Step,
    receipts: AccessReceipt[],
    labels: string[],
  ): { approved: boolean; reason?: string; receipt?: string } {
    // Validate step execution
    const validation = this.kernel.validateStepExecution(step, subject, receipts, labels);

    if (!validation.valid) {
      this.logExecution(tool, subject.id, false, validation.errors.join(", "));
      return {
        approved: false,
        reason: `Step validation failed: ${validation.errors.join(", ")}`,
      };
    }

    // Check for injection attempts in arguments
    const argsString = JSON.stringify(step.args);
    const injectionCheck = this.kernel.checkForInjection(argsString);

    if (injectionCheck.blocked) {
      this.logExecution(
        tool,
        subject.id,
        false,
        `Injection attempt blocked: ${injectionCheck.pattern}`,
      );
      return {
        approved: false,
        reason: `Injection attempt detected: ${injectionCheck.pattern}`,
      };
    }

    // Generate execution receipt
    const receipt = this.generateExecutionReceipt(tool, subject.id, step);

    // Approve execution
    this.approvedTools.add(tool);
    this.logExecution(tool, subject.id, true);

    return {
      approved: true,
      receipt,
    };
  }

  // Execute approved tool
  executeTool(tool: string, args: Record<string, any>): any {
    if (!this.approvedTools.has(tool)) {
      throw new Error(`Tool ${tool} not approved for execution`);
    }

    // In a real implementation, this would execute the actual tool
    // For now, we'll just return a mock result
    return {
      success: true,
      tool,
      args,
      timestamp: new Date().toISOString(),
      result: `Mock execution of ${tool}`,
    };
  }

  // Get execution statistics
  getExecutionStats(): {
    totalRequests: number;
    approvedRequests: number;
    blockedRequests: number;
    approvalRate: number;
    topBlockedReasons: Array<{ reason: string; count: number }>;
  } {
    const totalRequests = this.executionLog.length;
    const approvedRequests = this.executionLog.filter((log) => log.approved).length;
    const blockedRequests = totalRequests - approvedRequests;
    const approvalRate = totalRequests > 0 ? (approvedRequests / totalRequests) * 100 : 0;

    // Count blocked reasons
    const blockedReasons = new Map<string, number>();
    this.executionLog
      .filter((log) => !log.approved && log.reason)
      .forEach((log) => {
        const reason = log.reason!;
        blockedReasons.set(reason, (blockedReasons.get(reason) || 0) + 1);
      });

    const topBlockedReasons = Array.from(blockedReasons.entries())
      .map(([reason, count]) => ({ reason, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    return {
      totalRequests,
      approvedRequests,
      blockedRequests,
      approvalRate,
      topBlockedReasons,
    };
  }

  private logExecution(tool: string, subject: string, approved: boolean, reason?: string): void {
    this.executionLog.push({
      timestamp: new Date().toISOString(),
      tool,
      subject,
      approved,
      reason,
    });
  }

  private generateExecutionReceipt(tool: string, subject: string, step: Step): string {
    const receiptData = {
      tool,
      subject,
      step_id: step.tool,
      timestamp: new Date().toISOString(),
      nonce: Math.random().toString(36).substring(7),
    };

    return createHash("sha256").update(JSON.stringify(receiptData)).digest("hex");
  }
}

// Export factory function
export const createPolicyKernel = (): PolicyKernel => {
  return new PolicyKernel();
};

export const createToolBroker = (kernel: PolicyKernel): ToolBroker => {
  return new ToolBroker(kernel);
};
