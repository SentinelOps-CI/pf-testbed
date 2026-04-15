import { createHash } from "crypto";
import { Plan, PlanStep, ExecutionContext } from "../../gateway/src/types";

// Kernel v2 with Model-Assisted Hints and DENY→REPLAN Loop
// Accepts LLM hints and auto-replans with structured denial reasons

export interface ValidationHint {
  id: string;
  type: "capability" | "receipt" | "labels" | "refinements" | "policy" | "security";
  content: string;
  confidence: number;
  source: "llm" | "rule_engine" | "policy_checker" | "security_scanner";
  timestamp: string;
  metadata: Record<string, any>;
}

export interface ValidationResult {
  valid: boolean;
  verdict: "APPROVED" | "DENIED" | "REQUIRES_REFINEMENT";
  confidence: number;
  denial_reasons: DenialReason[];
  required_refinements: Refinement[];
  hints: ValidationHint[];
  validation_timestamp: string;
  proof_hash: string;
}

export interface DenialReason {
  code: string;
  message: string;
  severity: "low" | "medium" | "high" | "critical";
  category: "capability" | "receipt" | "labels" | "policy" | "security" | "other";
  details: Record<string, any>;
  suggested_fixes: string[];
}

export interface Refinement {
  id: string;
  type:
    | "capability_addition"
    | "receipt_verification"
    | "label_adjustment"
    | "policy_update"
    | "security_enhancement";
  description: string;
  priority: "low" | "medium" | "high" | "critical";
  required_changes: string[];
  estimated_effort: "low" | "medium" | "high";
}

export interface ReplanRequest {
  original_plan: Plan;
  denial_reasons: DenialReason[];
  required_refinements: Refinement[];
  hints: ValidationHint[];
  max_replan_attempts: number;
  current_attempt: number;
}

export interface ReplanResult {
  success: boolean;
  new_plan?: Plan;
  refinements_applied: Refinement[];
  remaining_issues: DenialReason[];
  replan_metadata: {
    attempt_number: number;
    total_attempts: number;
    processing_time_ms: number;
    hints_used: string[];
  };
}

export class KernelValidator {
  private validationCache: Map<string, ValidationResult> = new Map();
  private replanHistory: Map<string, ReplanResult[]> = new Map();
  private validationStats = {
    total_validations: 0,
    approved: 0,
    denied: 0,
    requires_refinement: 0,
    successful_replans: 0,
    failed_replans: 0,
    avg_validation_time_ms: 0,
  };

  constructor() {}

  /**
   * Validate a plan with comprehensive checks
   */
  async validatePlan(
    plan: Plan,
    context: ExecutionContext,
    hints: ValidationHint[] = [],
  ): Promise<ValidationResult> {
    const startTime = Date.now();
    const cacheKey = this.generateCacheKey(plan, context);

    // Check cache first
    if (this.validationCache.has(cacheKey)) {
      return this.validationCache.get(cacheKey)!;
    }

    // Perform comprehensive validation
    const result = await this.performValidation(plan, context, hints);

    // Cache the result
    this.validationCache.set(cacheKey, result);

    // Update stats
    this.updateValidationStats(result);

    return result;
  }

  /**
   * Perform comprehensive plan validation
   */
  private async performValidation(
    plan: Plan,
    context: ExecutionContext,
    hints: ValidationHint[],
  ): Promise<ValidationResult> {
    const validationTimestamp = new Date().toISOString();
    const denialReasons: DenialReason[] = [];
    const requiredRefinements: Refinement[] = [];
    const validationHints: ValidationHint[] = [];

    // 1. Capability validation
    const capabilityResult = await this.validateCapabilities(plan, context);
    if (!capabilityResult.valid) {
      denialReasons.push(...capabilityResult.denialReasons);
      requiredRefinements.push(...capabilityResult.requiredRefinements);
    }
    validationHints.push(...capabilityResult.hints);

    // 2. Receipt validation
    const receiptResult = await this.validateReceipts(plan, context);
    if (!receiptResult.valid) {
      denialReasons.push(...receiptResult.denialReasons);
      requiredRefinements.push(...receiptResult.requiredRefinements);
    }
    validationHints.push(...receiptResult.hints);

    // 3. Label validation
    const labelResult = await this.validateLabels(plan, context);
    if (!labelResult.valid) {
      denialReasons.push(...labelResult.denialReasons);
      requiredRefinements.push(...labelResult.requiredRefinements);
    }
    validationHints.push(...labelResult.hints);

    // 4. Policy validation
    const policyResult = await this.validatePolicies(plan, context);
    if (!policyResult.valid) {
      denialReasons.push(...policyResult.denialReasons);
      requiredRefinements.push(...policyResult.requiredRefinements);
    }
    validationHints.push(...policyResult.hints);

    // 5. Security validation
    const securityResult = await this.validateSecurity(plan, context);
    if (!securityResult.valid) {
      denialReasons.push(...securityResult.denialReasons);
      requiredRefinements.push(...securityResult.requiredRefinements);
    }
    validationHints.push(...securityResult.hints);

    // Determine overall verdict
    const valid = denialReasons.length === 0;
    const verdict = valid
      ? "APPROVED"
      : requiredRefinements.length > 0
        ? "REQUIRES_REFINEMENT"
        : "DENIED";

    const confidence = this.calculateConfidence(
      denialReasons,
      requiredRefinements,
      validationHints,
    );

    const result: ValidationResult = {
      valid,
      verdict,
      confidence,
      denial_reasons: denialReasons,
      required_refinements: requiredRefinements,
      hints: validationHints,
      validation_timestamp: validationTimestamp,
      proof_hash: this.generateProofHash(plan, context, result),
    };

    return result;
  }

  /**
   * Validate plan capabilities
   */
  private async validateCapabilities(
    plan: Plan,
    context: ExecutionContext,
  ): Promise<{
    valid: boolean;
    denialReasons: DenialReason[];
    requiredRefinements: Refinement[];
    hints: ValidationHint[];
  }> {
    const denialReasons: DenialReason[] = [];
    const requiredRefinements: Refinement[] = [];
    const hints: ValidationHint[] = [];

    // Check if user has required capabilities for each step
    for (const step of plan.steps) {
      if (step.required_capabilities && step.required_capabilities.length > 0) {
        const missingCapabilities = step.required_capabilities.filter(
          (cap) => !context.user_capabilities?.includes(cap),
        );

        if (missingCapabilities.length > 0) {
          denialReasons.push({
            code: "MISSING_CAPABILITIES",
            message: `Step ${step.id} requires capabilities: ${missingCapabilities.join(", ")}`,
            severity: "high",
            category: "capability",
            details: { step_id: step.id, missing_capabilities: missingCapabilities },
            suggested_fixes: [
              "Request capability elevation",
              "Use alternative approach with available capabilities",
              "Contact administrator for capability assignment",
            ],
          });

          requiredRefinements.push({
            id: `cap_${step.id}_${Date.now()}`,
            type: "capability_addition",
            description: `Add missing capabilities for step ${step.id}`,
            priority: "high",
            required_changes: [`Grant capabilities: ${missingCapabilities.join(", ")}`],
            estimated_effort: "medium",
          });
        }
      }
    }

    return {
      valid: denialReasons.length === 0,
      denialReasons,
      requiredRefinements,
      hints,
    };
  }

  /**
   * Validate plan receipts
   */
  private async validateReceipts(
    plan: Plan,
    context: ExecutionContext,
  ): Promise<{
    valid: boolean;
    denialReasons: DenialReason[];
    requiredRefinements: Refinement[];
    hints: ValidationHint[];
  }> {
    const denialReasons: DenialReason[] = [];
    const requiredRefinements: Refinement[] = [];
    const hints: ValidationHint[] = [];

    // Check if retrieval steps have valid receipts
    const retrievalSteps = plan.steps.filter((s) => s.type === "retrieval");

    for (const step of retrievalSteps) {
      if (!step.receipt_id) {
        denialReasons.push({
          code: "MISSING_RECEIPT",
          message: `Retrieval step ${step.id} missing access receipt`,
          severity: "critical",
          category: "receipt",
          details: { step_id: step.id, step_type: step.type },
          suggested_fixes: [
            "Generate access receipt for retrieval step",
            "Verify receipt signature and validity",
            "Check receipt expiration",
          ],
        });

        requiredRefinements.push({
          id: `receipt_${step.id}_${Date.now()}`,
          type: "receipt_verification",
          description: `Verify receipt for retrieval step ${step.id}`,
          priority: "critical",
          required_changes: ["Generate and verify access receipt"],
          estimated_effort: "low",
        });
      }
    }

    return {
      valid: denialReasons.length === 0,
      denialReasons,
      requiredRefinements,
      hints,
    };
  }

  /**
   * Validate plan labels
   */
  private async validateLabels(
    plan: Plan,
    context: ExecutionContext,
  ): Promise<{
    valid: boolean;
    denialReasons: DenialReason[];
    requiredRefinements: Refinement[];
    hints: ValidationHint[];
  }> {
    const denialReasons: DenialReason[] = [];
    const requiredRefinements: Refinement[] = [];
    const hints: ValidationHint[] = [];

    // Check label consistency and access permissions
    for (const step of plan.steps) {
      if (step.labels && step.labels.length > 0) {
        const unauthorizedLabels = step.labels.filter(
          (label) => !this.isLabelAuthorized(label, context),
        );

        if (unauthorizedLabels.length > 0) {
          denialReasons.push({
            code: "UNAUTHORIZED_LABELS",
            message: `Step ${step.id} contains unauthorized labels: ${unauthorizedLabels.join(", ")}`,
            severity: "high",
            category: "labels",
            details: { step_id: step.id, unauthorized_labels: unauthorizedLabels },
            suggested_fixes: [
              "Remove unauthorized labels",
              "Request label access permissions",
              "Use alternative labels with proper access",
            ],
          });

          requiredRefinements.push({
            id: `label_${step.id}_${Date.now()}`,
            type: "label_adjustment",
            description: `Adjust labels for step ${step.id}`,
            priority: "high",
            required_changes: [`Remove or replace labels: ${unauthorizedLabels.join(", ")}`],
            estimated_effort: "low",
          });
        }
      }
    }

    return {
      valid: denialReasons.length === 0,
      denialReasons,
      requiredRefinements,
      hints,
    };
  }

  /**
   * Validate plan policies
   */
  private async validatePolicies(
    plan: Plan,
    context: ExecutionContext,
  ): Promise<{
    valid: boolean;
    denialReasons: DenialReason[];
    requiredRefinements: Refinement[];
    hints: ValidationHint[];
  }> {
    const denialReasons: DenialReason[] = [];
    const requiredRefinements: Refinement[] = [];
    const hints: ValidationHint[] = [];

    // Check policy compliance
    const policyViolations = this.checkPolicyCompliance(plan, context);

    if (policyViolations.length > 0) {
      policyViolations.forEach((violation) => {
        denialReasons.push({
          code: "POLICY_VIOLATION",
          message: violation.message,
          severity: violation.severity,
          category: "policy",
          details: violation.details,
          suggested_fixes: violation.suggested_fixes,
        });

        requiredRefinements.push({
          id: `policy_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          type: "policy_update",
          description: `Fix policy violation: ${violation.message}`,
          priority: violation.severity === "critical" ? "critical" : "high",
          required_changes: violation.suggested_fixes,
          estimated_effort: "medium",
        });
      });
    }

    return {
      valid: denialReasons.length === 0,
      denialReasons,
      requiredRefinements,
      hints,
    };
  }

  /**
   * Validate plan security
   */
  private async validateSecurity(
    plan: Plan,
    context: ExecutionContext,
  ): Promise<{
    valid: boolean;
    denialReasons: DenialReason[];
    requiredRefinements: Refinement[];
    hints: ValidationHint[];
  }> {
    const denialReasons: DenialReason[] = [];
    const requiredRefinements: Refinement[] = [];
    const hints: ValidationHint[] = [];

    // Check for security vulnerabilities
    const securityIssues = this.checkSecurityVulnerabilities(plan, context);

    if (securityIssues.length > 0) {
      securityIssues.forEach((issue) => {
        denialReasons.push({
          code: "SECURITY_ISSUE",
          message: issue.message,
          severity: issue.severity,
          category: "security",
          details: issue.details,
          suggested_fixes: issue.suggested_fixes,
        });

        requiredRefinements.push({
          id: `security_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          type: "security_enhancement",
          description: `Fix security issue: ${issue.message}`,
          priority: issue.severity === "critical" ? "critical" : "high",
          required_changes: issue.suggested_fixes,
          estimated_effort: "high",
        });
      });
    }

    return {
      valid: denialReasons.length === 0,
      denialReasons,
      requiredRefinements,
      hints,
    };
  }

  /**
   * Auto-replan based on validation results
   */
  async autoReplan(request: ReplanRequest): Promise<ReplanResult> {
    const startTime = Date.now();

    if (request.current_attempt >= request.max_replan_attempts) {
      return {
        success: false,
        refinements_applied: [],
        remaining_issues: request.denial_reasons,
        replan_metadata: {
          attempt_number: request.current_attempt,
          total_attempts: request.max_replan_attempts,
          processing_time_ms: Date.now() - startTime,
          hints_used: [],
        },
      };
    }

    try {
      // Apply refinements to create new plan
      const newPlan = await this.applyRefinements(
        request.original_plan,
        request.required_refinements,
      );

      // Validate the new plan
      const validationResult = await this.validatePlan(newPlan, {
        ...request.original_plan.context,
        replan_attempt: request.current_attempt + 1,
      });

      const success = validationResult.valid || validationResult.verdict === "REQUIRES_REFINEMENT";

      const result: ReplanResult = {
        success,
        new_plan: success ? newPlan : undefined,
        refinements_applied: request.required_refinements,
        remaining_issues: validationResult.denial_reasons,
        replan_metadata: {
          attempt_number: request.current_attempt,
          total_attempts: request.max_replan_attempts,
          processing_time_ms: Date.now() - startTime,
          hints_used: request.hints.map((h) => h.id),
        },
      };

      // Store replan history
      if (!this.replanHistory.has(request.original_plan.id)) {
        this.replanHistory.set(request.original_plan.id, []);
      }
      this.replanHistory.get(request.original_plan.id)!.push(result);

      // Update stats
      if (success) {
        this.validationStats.successful_replans++;
      } else {
        this.validationStats.failed_replans++;
      }

      return result;
    } catch (error) {
      console.error("Auto-replan failed:", error);
      return {
        success: false,
        refinements_applied: [],
        remaining_issues: request.denial_reasons,
        replan_metadata: {
          attempt_number: request.current_attempt,
          total_attempts: request.max_replan_attempts,
          processing_time_ms: Date.now() - startTime,
          hints_used: [],
        },
      };
    }
  }

  // Helper methods
  private isLabelAuthorized(label: string, context: ExecutionContext): boolean {
    // Implement label authorization logic
    return context.user_labels?.includes(label) || context.user_capabilities?.includes("admin");
  }

  private checkPolicyCompliance(
    plan: Plan,
    context: ExecutionContext,
  ): Array<{
    message: string;
    severity: "low" | "medium" | "high" | "critical";
    details: Record<string, any>;
    suggested_fixes: string[];
  }> {
    const violations = [];

    // Check for policy violations based on plan content and context
    // This is a simplified implementation

    return violations;
  }

  private checkSecurityVulnerabilities(
    plan: Plan,
    context: ExecutionContext,
  ): Array<{
    message: string;
    severity: "low" | "medium" | "high" | "critical";
    details: Record<string, any>;
    suggested_fixes: string[];
  }> {
    const issues = [];

    // Check for security vulnerabilities
    // This is a simplified implementation

    return issues;
  }

  private async applyRefinements(plan: Plan, refinements: Refinement[]): Promise<Plan> {
    // Create a copy of the plan and apply refinements
    const newPlan = JSON.parse(JSON.stringify(plan));

    // Apply refinements based on their types
    refinements.forEach((refinement) => {
      switch (refinement.type) {
        case "capability_addition":
          // Add required capabilities to context
          break;
        case "receipt_verification":
          // Ensure receipts are present and valid
          break;
        case "label_adjustment":
          // Adjust labels to authorized ones
          break;
        case "policy_update":
          // Update plan to comply with policies
          break;
        case "security_enhancement":
          // Apply security improvements
          break;
      }
    });

    return newPlan;
  }

  private calculateConfidence(
    denialReasons: DenialReason[],
    requiredRefinements: Refinement[],
    hints: ValidationHint[],
  ): number {
    let confidence = 1.0;

    // Reduce confidence based on denial reasons
    denialReasons.forEach((reason) => {
      switch (reason.severity) {
        case "critical":
          confidence -= 0.4;
          break;
        case "high":
          confidence -= 0.2;
          break;
        case "medium":
          confidence -= 0.1;
          break;
        case "low":
          confidence -= 0.05;
          break;
      }
    });

    // Increase confidence based on helpful hints
    hints.forEach((hint) => {
      if (hint.confidence > 0.8) {
        confidence += 0.05;
      }
    });

    return Math.max(0.0, Math.min(1.0, confidence));
  }

  private generateCacheKey(plan: Plan, context: ExecutionContext): string {
    const keyData = {
      plan_id: plan.id,
      plan_hash: this.hashPlan(plan),
      user_id: context.user_id,
      tenant: context.tenant,
      capabilities: context.user_capabilities?.sort(),
    };

    return createHash("sha256").update(JSON.stringify(keyData)).digest("hex");
  }

  private hashPlan(plan: Plan): string {
    return createHash("sha256").update(JSON.stringify(plan)).digest("hex");
  }

  private generateProofHash(
    plan: Plan,
    context: ExecutionContext,
    result: ValidationResult,
  ): string {
    const proofData = {
      plan_hash: this.hashPlan(plan),
      context_hash: createHash("sha256").update(JSON.stringify(context)).digest("hex"),
      validation_result: result,
      timestamp: Date.now(),
    };

    return createHash("sha256").update(JSON.stringify(proofData)).digest("hex");
  }

  private updateValidationStats(result: ValidationResult): void {
    this.validationStats.total_validations++;

    switch (result.verdict) {
      case "APPROVED":
        this.validationStats.approved++;
        break;
      case "DENIED":
        this.validationStats.denied++;
        break;
      case "REQUIRES_REFINEMENT":
        this.validationStats.requires_refinement++;
        break;
    }
  }

  // Public access methods
  getValidationStats() {
    return { ...this.validationStats };
  }

  getReplanHistory(planId: string): ReplanResult[] {
    return this.replanHistory.get(planId) || [];
  }

  clearCache(): void {
    this.validationCache.clear();
  }
}

// Export singleton instance
export const kernelValidator = new KernelValidator();
