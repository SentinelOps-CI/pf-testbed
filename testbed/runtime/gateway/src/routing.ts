import { createHash } from "crypto";
import { Plan, PlanStep, ExecutionContext } from "./types";

// Risk-Aware Model Routing & Semantic Cache
// Routes by risk and caches low-risk answers with receipt hash keys

export interface ModelTier {
  id: string;
  name: string;
  risk_level: "low" | "medium" | "high" | "critical";
  model_type: "gpt-4" | "gpt-3.5" | "claude-3" | "claude-2" | "gemini" | "custom";
  cost_per_1k_tokens: number;
  max_tokens: number;
  capabilities: string[];
  availability: number; // 0-1, percentage of time available
  latency_p95_ms: number;
  latency_p99_ms: number;
}

export interface RoutingDecision {
  id: string;
  plan_id: string;
  step_id: string;
  tenant: string;
  risk_assessment: RiskAssessment;
  selected_model: ModelTier;
  routing_reason: string;
  confidence: number;
  timestamp: string;
  metadata: Record<string, any>;
}

export interface RiskAssessment {
  overall_risk: "low" | "medium" | "high" | "critical";
  risk_score: number; // 0-100
  risk_factors: RiskFactor[];
  mitigation_strategies: string[];
  requires_approval: boolean;
}

export interface RiskFactor {
  category: "content" | "user" | "data" | "operation" | "compliance";
  description: string;
  severity: "low" | "medium" | "high" | "critical";
  weight: number; // 0-1, impact on overall risk
  details: Record<string, any>;
}

export interface SemanticCacheEntry {
  key: string;
  content_hash: string;
  receipt_hash: string;
  risk_level: "low" | "medium" | "high" | "critical";
  model_used: string;
  response: any;
  metadata: {
    created_at: string;
    accessed_at: string;
    access_count: number;
    ttl_seconds: number;
    tenant: string;
    labels: string[];
  };
}

export class RiskAwareRouter {
  private modelTiers: Map<string, ModelTier> = new Map();
  private routingHistory: Map<string, RoutingDecision[]> = new Map();
  private semanticCache: Map<string, SemanticCacheEntry> = new Map();
  private routingStats = {
    total_routes: 0,
    low_risk_routes: 0,
    medium_risk_routes: 0,
    high_risk_routes: 0,
    critical_risk_routes: 0,
    cache_hits: 0,
    cache_misses: 0,
    cost_savings_usd: 0,
    avg_routing_time_ms: 0,
  };

  constructor() {
    this.initializeModelTiers();
  }

  /**
   * Initialize available model tiers
   */
  private initializeModelTiers(): void {
    const tiers: ModelTier[] = [
      {
        id: "gpt-4-low",
        name: "GPT-4 Low Risk",
        risk_level: "low",
        model_type: "gpt-4",
        cost_per_1k_tokens: 0.03,
        max_tokens: 8192,
        capabilities: ["reasoning", "analysis", "generation"],
        availability: 0.99,
        latency_p95_ms: 2000,
        latency_p99_ms: 5000,
      },
      {
        id: "gpt-4-medium",
        name: "GPT-4 Medium Risk",
        risk_level: "medium",
        model_type: "gpt-4",
        cost_per_1k_tokens: 0.03,
        max_tokens: 8192,
        capabilities: ["reasoning", "analysis", "generation", "sensitive_content"],
        availability: 0.98,
        latency_p95_ms: 2500,
        latency_p99_ms: 6000,
      },
      {
        id: "gpt-4-high",
        name: "GPT-4 High Risk",
        risk_level: "high",
        model_type: "gpt-4",
        cost_per_1k_tokens: 0.03,
        max_tokens: 8192,
        capabilities: ["reasoning", "analysis", "generation", "sensitive_content", "compliance"],
        availability: 0.97,
        latency_p95_ms: 3000,
        latency_p99_ms: 7000,
      },
      {
        id: "claude-3-critical",
        name: "Claude-3 Critical Risk",
        risk_level: "critical",
        model_type: "claude-3",
        cost_per_1k_tokens: 0.015,
        max_tokens: 200000,
        capabilities: [
          "reasoning",
          "analysis",
          "generation",
          "sensitive_content",
          "compliance",
          "audit",
        ],
        availability: 0.96,
        latency_p95_ms: 4000,
        latency_p99_ms: 8000,
      },
      {
        id: "gpt-3.5-cache",
        name: "GPT-3.5 Cache Only",
        risk_level: "low",
        model_type: "gpt-3.5",
        cost_per_1k_tokens: 0.002,
        max_tokens: 4096,
        capabilities: ["cached_responses", "simple_generation"],
        availability: 0.99,
        latency_p95_ms: 500,
        latency_p99_ms: 1000,
      },
    ];

    tiers.forEach((tier) => {
      this.modelTiers.set(tier.id, tier);
    });
  }

  /**
   * Route a plan step based on risk assessment
   */
  async routeStep(step: PlanStep, plan: Plan, context: ExecutionContext): Promise<RoutingDecision> {
    const startTime = Date.now();

    // Check semantic cache first for low-risk operations
    const cacheEntry = await this.checkSemanticCache(step, plan, context);
    if (cacheEntry && cacheEntry.risk_level === "low") {
      this.routingStats.cache_hits++;
      return this.createCachedRoutingDecision(step, plan, context, cacheEntry);
    }

    this.routingStats.cache_misses++;

    // Perform risk assessment
    const riskAssessment = await this.assessRisk(step, plan, context);

    // Select appropriate model tier
    const selectedModel = this.selectModelTier(riskAssessment, context);

    // Create routing decision
    const decision: RoutingDecision = {
      id: `route_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      plan_id: plan.id,
      step_id: step.id,
      tenant: plan.tenant,
      risk_assessment: riskAssessment,
      selected_model: selectedModel,
      routing_reason: this.generateRoutingReason(riskAssessment, selectedModel),
      confidence: this.calculateRoutingConfidence(riskAssessment, selectedModel),
      timestamp: new Date().toISOString(),
      metadata: {
        user_risk_profile: context.user_risk_profile,
        tenant_risk_policy: context.tenant_risk_policy,
        step_complexity: this.assessStepComplexity(step),
      },
    };

    // Store routing decision
    this.storeRoutingDecision(decision);

    // Update stats
    this.updateRoutingStats(decision, Date.now() - startTime);

    return decision;
  }

  /**
   * Check semantic cache for existing responses
   */
  private async checkSemanticCache(
    step: PlanStep,
    plan: Plan,
    context: ExecutionContext,
  ): Promise<SemanticCacheEntry | null> {
    const cacheKey = this.generateCacheKey(step, plan, context);
    const entry = this.semanticCache.get(cacheKey);

    if (!entry) {
      return null;
    }

    // Check if entry is still valid
    if (this.isCacheEntryValid(entry)) {
      // Update access metadata
      entry.metadata.accessed_at = new Date().toISOString();
      entry.metadata.access_count++;
      return entry;
    } else {
      // Remove expired entry
      this.semanticCache.delete(cacheKey);
      return null;
    }
  }

  /**
   * Assess risk for a plan step
   */
  private async assessRisk(
    step: PlanStep,
    plan: Plan,
    context: ExecutionContext,
  ): Promise<RiskAssessment> {
    const riskFactors: RiskFactor[] = [];
    let totalRiskScore = 0;

    // 1. Content risk assessment
    const contentRisk = this.assessContentRisk(step, plan);
    riskFactors.push(contentRisk);
    totalRiskScore += contentRisk.weight * this.getRiskScore(contentRisk.severity);

    // 2. User risk assessment
    const userRisk = this.assessUserRisk(context);
    riskFactors.push(userRisk);
    totalRiskScore += userRisk.weight * this.getRiskScore(userRisk.severity);

    // 3. Data risk assessment
    const dataRisk = this.assessDataRisk(step, plan);
    riskFactors.push(dataRisk);
    totalRiskScore += dataRisk.weight * this.getRiskScore(dataRisk.severity);

    // 4. Operation risk assessment
    const operationRisk = this.assessOperationRisk(step, plan);
    riskFactors.push(operationRisk);
    totalRiskScore += operationRisk.weight * this.getRiskScore(operationRisk.severity);

    // 5. Compliance risk assessment
    const complianceRisk = this.assessComplianceRisk(step, plan, context);
    riskFactors.push(complianceRisk);
    totalRiskScore += complianceRisk.weight * this.getRiskScore(complianceRisk.severity);

    // Determine overall risk level
    const overallRisk = this.calculateOverallRisk(totalRiskScore);
    const requiresApproval = overallRisk === "high" || overallRisk === "critical";

    // Generate mitigation strategies
    const mitigationStrategies = this.generateMitigationStrategies(riskFactors, overallRisk);

    return {
      overall_risk: overallRisk,
      risk_score: Math.min(100, totalRiskScore),
      risk_factors: riskFactors,
      mitigation_strategies: mitigationStrategies,
      requires_approval: requiresApproval,
    };
  }

  /**
   * Assess content risk
   */
  private assessContentRisk(step: PlanStep, _plan: Plan): RiskFactor {
    let severity: "low" | "medium" | "high" | "critical" = "low";
    let weight = 0.2;

    // Check for sensitive content indicators
    if (step.content && step.content.includes("password")) {
      severity = "high";
      weight = 0.4;
    }
    if (step.content && step.content.includes("ssn")) {
      severity = "critical";
      weight = 0.5;
    }
    if (step.content && step.content.includes("credit_card")) {
      severity = "critical";
      weight = 0.5;
    }

    return {
      category: "content",
      description: "Content sensitivity assessment",
      severity,
      weight,
      details: {
        content_length: step.content?.length || 0,
        sensitive_patterns: this.detectSensitivePatterns(step.content || ""),
      },
    };
  }

  /**
   * Assess user risk
   */
  private assessUserRisk(context: ExecutionContext): RiskFactor {
    let severity: "low" | "medium" | "high" | "critical" = "low";
    let weight = 0.15;

    // Check user risk profile
    if (context.user_risk_profile === "high") {
      severity = "high";
      weight = 0.3;
    } else if (context.user_risk_profile === "critical") {
      severity = "critical";
      weight = 0.4;
    }

    // Check user capabilities
    if (context.user_capabilities?.includes("admin")) {
      weight += 0.1; // Admin users have higher risk potential
    }

    return {
      category: "user",
      description: "User risk profile assessment",
      severity,
      weight,
      details: {
        user_risk_profile: context.user_risk_profile,
        user_capabilities: context.user_capabilities,
        user_labels: context.user_labels,
      },
    };
  }

  /**
   * Assess data risk
   */
  private assessDataRisk(step: PlanStep, _plan: Plan): RiskFactor {
    let severity: "low" | "medium" | "high" | "critical" = "low";
    let weight = 0.25;

    // Check data sensitivity labels
    if (step.labels?.includes("confidential")) {
      severity = "high";
      weight = 0.4;
    }
    if (step.labels?.includes("secret")) {
      severity = "critical";
      weight = 0.5;
    }
    if (step.labels?.includes("public")) {
      severity = "low";
      weight = 0.1;
    }

    return {
      category: "data",
      description: "Data sensitivity assessment",
      severity,
      weight,
      details: {
        data_labels: step.labels,
        data_type: step.type,
        data_source: step.source,
      },
    };
  }

  /**
   * Assess operation risk
   */
  private assessOperationRisk(step: PlanStep, _plan: Plan): RiskFactor {
    let severity: "low" | "medium" | "high" | "critical" = "low";
    let weight = 0.2;

    // Check operation type
    if (step.operation === "write" || step.operation === "delete") {
      severity = "high";
      weight = 0.35;
    }
    if (step.operation === "admin" || step.operation === "system") {
      severity = "critical";
      weight = 0.45;
    }

    return {
      category: "operation",
      description: "Operation type assessment",
      severity,
      weight,
      details: {
        operation_type: step.type,
        operation_target: step.target,
        operation_scope: step.scope,
      },
    };
  }

  /**
   * Assess compliance risk
   */
  private assessComplianceRisk(step: PlanStep, plan: Plan, context: ExecutionContext): RiskFactor {
    let severity: "low" | "medium" | "high" | "critical" = "low";
    let weight = 0.2;

    // Check compliance requirements
    if (context.tenant_risk_policy === "strict") {
      severity = "high";
      weight = 0.35;
    }
    if (context.tenant_risk_policy === "critical") {
      severity = "critical";
      weight = 0.45;
    }

    return {
      category: "compliance",
      description: "Compliance policy assessment",
      severity,
      weight,
      details: {
        tenant_policy: context.tenant_risk_policy,
        compliance_requirements: step.compliance_requirements,
        audit_required: step.audit_required,
      },
    };
  }

  /**
   * Select appropriate model tier based on risk
   */
  private selectModelTier(riskAssessment: RiskAssessment, _context: ExecutionContext): ModelTier {
    const availableTiers = Array.from(this.modelTiers.values()).filter(
      (tier) => tier.availability > 0.95,
    ); // Only consider highly available models

    // Sort by risk level compatibility and cost
    const compatibleTiers = availableTiers
      .filter((tier) => this.isModelCompatibleWithRisk(tier, riskAssessment))
      .sort((a, b) => {
        // Primary: risk compatibility, Secondary: cost
        const riskDiff = this.getRiskScore(a.risk_level) - this.getRiskScore(b.risk_level);
        if (riskDiff !== 0) return riskDiff;
        return a.cost_per_1k_tokens - b.cost_per_1k_tokens;
      });

    if (compatibleTiers.length === 0) {
      // Fallback to highest capability model
      return availableTiers.sort(
        (a, b) => this.getRiskScore(b.risk_level) - this.getRiskScore(a.risk_level),
      )[0];
    }

    return compatibleTiers[0];
  }

  /**
   * Check if model is compatible with risk level
   */
  private isModelCompatibleWithRisk(model: ModelTier, riskAssessment: RiskAssessment): boolean {
    const modelRiskScore = this.getRiskScore(model.risk_level);
    const requiredRiskScore = this.getRiskScore(riskAssessment.overall_risk);

    // Model must have equal or higher risk handling capability
    return modelRiskScore >= requiredRiskScore;
  }

  /**
   * Get risk score for severity level
   */
  private getRiskScore(severity: "low" | "medium" | "high" | "critical"): number {
    switch (severity) {
      case "low":
        return 25;
      case "medium":
        return 50;
      case "high":
        return 75;
      case "critical":
        return 100;
      default:
        return 0;
    }
  }

  /**
   * Calculate overall risk level
   */
  private calculateOverallRisk(totalRiskScore: number): "low" | "medium" | "high" | "critical" {
    if (totalRiskScore >= 75) return "critical";
    if (totalRiskScore >= 50) return "high";
    if (totalRiskScore >= 25) return "medium";
    return "low";
  }

  /**
   * Generate mitigation strategies
   */
  private generateMitigationStrategies(
    riskFactors: RiskFactor[],
    overallRisk: "low" | "medium" | "high" | "critical",
  ): string[] {
    const strategies: string[] = [];

    if (overallRisk === "critical") {
      strategies.push("Require manual approval before execution");
      strategies.push("Enable enhanced logging and monitoring");
      strategies.push("Implement additional security checks");
    }

    if (overallRisk === "high") {
      strategies.push("Enable enhanced logging");
      strategies.push("Implement additional validation");
    }

    if (overallRisk === "medium") {
      strategies.push("Enable standard logging");
      strategies.push("Implement standard validation");
    }

    // Add specific strategies based on risk factors
    riskFactors.forEach((factor) => {
      if (factor.severity === "critical") {
        strategies.push(`Address ${factor.category} risk: ${factor.description}`);
      }
    });

    return strategies;
  }

  /**
   * Generate routing reason
   */
  private generateRoutingReason(riskAssessment: RiskAssessment, selectedModel: ModelTier): string {
    return `Selected ${selectedModel.name} (${selectedModel.risk_level} risk) for ${riskAssessment.overall_risk} risk operation. Risk score: ${riskAssessment.risk_score}/100`;
  }

  /**
   * Calculate routing confidence
   */
  private calculateRoutingConfidence(
    riskAssessment: RiskAssessment,
    selectedModel: ModelTier,
  ): number {
    let confidence = 0.8; // Base confidence

    // Adjust based on risk alignment
    if (selectedModel.risk_level === riskAssessment.overall_risk) {
      confidence += 0.15;
    } else if (
      this.getRiskScore(selectedModel.risk_level) > this.getRiskScore(riskAssessment.overall_risk)
    ) {
      confidence += 0.1;
    }

    // Adjust based on model availability
    confidence += selectedModel.availability * 0.05;

    return Math.min(1.0, confidence);
  }

  /**
   * Assess step complexity
   */
  private assessStepComplexity(step: PlanStep): "simple" | "moderate" | "complex" {
    if (step.parameters && Object.keys(step.parameters).length > 10) return "complex";
    if (step.parameters && Object.keys(step.parameters).length > 5) return "moderate";
    return "simple";
  }

  /**
   * Detect sensitive patterns in content
   */
  private detectSensitivePatterns(content: string): string[] {
    const patterns: string[] = [];

    if (/\bpassword\b/i.test(content)) patterns.push("password");
    if (/\bssn\b/i.test(content)) patterns.push("ssn");
    if (/\bcredit.?card\b/i.test(content)) patterns.push("credit_card");
    if (/\bapi.?key\b/i.test(content)) patterns.push("api_key");
    if (/\bprivate.?key\b/i.test(content)) patterns.push("private_key");

    return patterns;
  }

  // Helper methods
  private generateCacheKey(step: PlanStep, plan: Plan, context: ExecutionContext): string {
    const keyData = {
      step_hash: this.hashStep(step),
      plan_hash: this.hashPlan(plan),
      user_id: context.user_id,
      tenant: context.tenant,
      labels: step.labels?.sort(),
    };

    return createHash("sha256").update(JSON.stringify(keyData)).digest("hex");
  }

  private hashStep(step: PlanStep): string {
    return createHash("sha256").update(JSON.stringify(step)).digest("hex");
  }

  private hashPlan(plan: Plan): string {
    return createHash("sha256").update(JSON.stringify(plan)).digest("hex");
  }

  private isCacheEntryValid(entry: SemanticCacheEntry): boolean {
    const now = new Date();
    const created = new Date(entry.metadata.created_at);
    const ttlMs = entry.metadata.ttl_seconds * 1000;

    return now.getTime() - created.getTime() < ttlMs;
  }

  private createCachedRoutingDecision(
    step: PlanStep,
    plan: Plan,
    context: ExecutionContext,
    cacheEntry: SemanticCacheEntry,
  ): RoutingDecision {
    const modelTier =
      this.modelTiers.get(cacheEntry.model_used) || this.modelTiers.get("gpt-3.5-cache")!;

    return {
      id: `cached_route_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      plan_id: plan.id,
      step_id: step.id,
      tenant: plan.tenant,
      risk_assessment: {
        overall_risk: cacheEntry.risk_level,
        risk_score: 10, // Low risk for cached responses
        risk_factors: [],
        mitigation_strategies: ["Use cached response"],
        requires_approval: false,
      },
      selected_model: modelTier,
      routing_reason: `Using cached response from ${modelTier.name}`,
      confidence: 0.95,
      timestamp: new Date().toISOString(),
      metadata: {
        cached: true,
        cache_key: cacheEntry.key,
        original_response: cacheEntry.response,
      },
    };
  }

  private storeRoutingDecision(decision: RoutingDecision): void {
    if (!this.routingHistory.has(decision.plan_id)) {
      this.routingHistory.set(decision.plan_id, []);
    }
    this.routingHistory.get(decision.plan_id)!.push(decision);
  }

  private updateRoutingStats(decision: RoutingDecision, processingTime: number): void {
    this.routingStats.total_routes++;

    switch (decision.risk_assessment.overall_risk) {
      case "low":
        this.routingStats.low_risk_routes++;
        break;
      case "medium":
        this.routingStats.medium_risk_routes++;
        break;
      case "high":
        this.routingStats.high_risk_routes++;
        break;
      case "critical":
        this.routingStats.critical_risk_routes++;
        break;
    }

    // Update average routing time
    const totalTime = this.routingStats.avg_routing_time_ms * (this.routingStats.total_routes - 1);
    this.routingStats.avg_routing_time_ms =
      (totalTime + processingTime) / this.routingStats.total_routes;
  }

  // Public access methods
  getRoutingStats() {
    return { ...this.routingStats };
  }

  getRoutingHistory(planId: string): RoutingDecision[] {
    return this.routingHistory.get(planId) || [];
  }

  getModelTiers(): ModelTier[] {
    return Array.from(this.modelTiers.values());
  }

  addModelTier(tier: ModelTier): void {
    this.modelTiers.set(tier.id, tier);
  }

  getSemanticCacheSize(): number {
    return this.semanticCache.size;
  }

  clearCache(): void {
    this.semanticCache.clear();
  }
}

// Export singleton instance
export const riskAwareRouter = new RiskAwareRouter();
