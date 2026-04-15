/**
 * Anthropic Policy Compiler
 *
 * Translates Provability Fabric policies to Anthropic's native guardrails including:
 * - System prompts with constitutional AI principles
 * - Content filtering and safety settings
 * - Rate limiting and usage controls
 * - Output validation and constraints
 *
 * This compiler ensures parity with kernel decisions while leveraging Claude's native capabilities.
 */

import { z } from "zod";
import { Policy, PolicyRule, PolicyViolation, PolicyDecision } from "../types";

// Anthropic-specific policy schemas
export const AnthropicGuardrailConfig = z.object({
  systemPrompt: z.string(),
  constitutionalPrinciples: z.array(z.string()),
  contentFiltering: z.object({
    categories: z.array(
      z.enum(["hate", "harassment", "self-harm", "sexual", "violence", "misinformation"]),
    ),
    levels: z.enum(["low", "medium", "high"]),
    customFilters: z.array(z.string()).optional(),
  }),
  rateLimiting: z.object({
    requestsPerMinute: z.number(),
    tokensPerMinute: z.number(),
    maxConcurrentRequests: z.number(),
    maxTokensPerRequest: z.number(),
  }),
  outputValidation: z.object({
    maxTokens: z.number(),
    temperature: z.number().min(0).max(1),
    topK: z.number().min(1).max(40),
    topP: z.number().min(0).max(1),
    stopSequences: z.array(z.string()).optional(),
  }),
  safetyInstructions: z.array(z.string()),
  fallbackBehavior: z.enum(["reject", "modify", "allow", "escalate"]),
  model: z.enum(["claude-3-opus", "claude-3-sonnet", "claude-3-haiku"]),
  metadata: z
    .object({
      version: z.string(),
      compiled_at: z.string(),
      compiler_version: z.string(),
    })
    .optional(),
});

export type AnthropicGuardrailConfig = z.infer<typeof AnthropicGuardrailConfig>;

// Policy translation mappings for Anthropic
const POLICY_TO_ANTHROPIC_MAPPINGS = {
  // Security policies
  data_leak_prevention: {
    systemPrompt:
      "You must never reveal sensitive information, personal data, or confidential details.",
    constitutionalPrinciples: [
      "Respect privacy and confidentiality",
      "Do not share personal or sensitive information",
      "Maintain data security at all times",
    ],
    contentFiltering: ["harassment", "self-harm"],
    safetyInstructions: [
      "Do not share personal information",
      "Do not reveal confidential data",
      "Maintain data privacy at all times",
    ],
  },

  cross_tenant_isolation: {
    systemPrompt:
      "You must maintain strict isolation between different user contexts and never mix data between them.",
    constitutionalPrinciples: [
      "Maintain user context boundaries",
      "Prevent data cross-contamination",
      "Ensure proper session isolation",
    ],
    contentFiltering: ["harassment"],
    safetyInstructions: [
      "Maintain user context isolation",
      "Do not mix data between different users",
      "Reset context between sessions",
    ],
  },

  injection_prevention: {
    systemPrompt:
      "You must not execute or suggest execution of any code, commands, or system operations.",
    constitutionalPrinciples: [
      "Do not execute system commands",
      "Maintain input validation",
      "Prevent code injection attacks",
    ],
    contentFiltering: ["violence", "self-harm"],
    safetyInstructions: [
      "Do not execute commands",
      "Do not suggest system operations",
      "Maintain input validation",
    ],
  },

  // Performance policies
  latency_optimization: {
    outputValidation: {
      maxTokens: 1000,
      temperature: 0.1,
      topK: 10,
      topP: 0.9,
    },
    rateLimiting: {
      requestsPerMinute: 60,
      tokensPerMinute: 10000,
      maxConcurrentRequests: 5,
      maxTokensPerRequest: 1000,
    },
  },

  cost_optimization: {
    outputValidation: {
      maxTokens: 500,
      temperature: 0.1,
      topK: 5,
      topP: 0.8,
    },
    rateLimiting: {
      requestsPerMinute: 30,
      tokensPerMinute: 5000,
      maxConcurrentRequests: 3,
      maxTokensPerRequest: 500,
    },
  },

  // Compliance policies
  gdpr_compliance: {
    systemPrompt:
      "You must comply with GDPR requirements including data minimization, purpose limitation, and user rights.",
    constitutionalPrinciples: [
      "Respect data protection rights",
      "Minimize data collection",
      "Enable user control over data",
    ],
    contentFiltering: ["harassment"],
    safetyInstructions: [
      "Minimize data collection",
      "Respect user consent",
      "Enable data deletion",
      "Maintain data accuracy",
    ],
  },

  sox_compliance: {
    systemPrompt:
      "You must maintain accurate financial records and prevent unauthorized access to financial data.",
    constitutionalPrinciples: [
      "Maintain financial accuracy",
      "Prevent unauthorized access",
      "Ensure audit trail integrity",
    ],
    contentFiltering: ["harassment"],
    safetyInstructions: [
      "Maintain audit trails",
      "Prevent unauthorized access",
      "Ensure data integrity",
      "Document all changes",
    ],
  },

  // AI Safety policies
  ai_alignment: {
    systemPrompt:
      "You must align with human values and intentions, avoiding harmful or deceptive behavior.",
    constitutionalPrinciples: [
      "Align with human values",
      "Avoid deception and manipulation",
      "Prioritize human safety and well-being",
    ],
    contentFiltering: ["hate", "harassment", "self-harm", "sexual", "violence", "misinformation"],
    safetyInstructions: [
      "Prioritize human safety",
      "Avoid harmful outputs",
      "Maintain ethical behavior",
    ],
  },
};

export class AnthropicPolicyCompiler {
  private config: AnthropicGuardrailConfig;
  private policyCache: Map<string, AnthropicGuardrailConfig> = new Map();

  constructor(baseConfig?: Partial<AnthropicGuardrailConfig>) {
    this.config = {
      systemPrompt:
        "You are Claude, an AI assistant created by Anthropic. You are helpful, harmless, and honest.",
      constitutionalPrinciples: [
        "Be helpful and accurate",
        "Maintain user safety",
        "Respect privacy and confidentiality",
        "Avoid harmful or deceptive behavior",
      ],
      contentFiltering: {
        categories: ["hate", "harassment", "self-harm", "sexual", "violence", "misinformation"],
        levels: "medium",
        customFilters: [],
      },
      rateLimiting: {
        requestsPerMinute: 60,
        tokensPerMinute: 10000,
        maxConcurrentRequests: 5,
        maxTokensPerRequest: 1000,
      },
      outputValidation: {
        maxTokens: 1000,
        temperature: 0.7,
        topK: 20,
        topP: 0.9,
        stopSequences: [],
      },
      safetyInstructions: [
        "Be helpful and accurate",
        "Maintain user safety",
        "Respect privacy and confidentiality",
      ],
      fallbackBehavior: "reject",
      model: "claude-3-sonnet",
      ...baseConfig,
    };
  }

  /**
   * Compile a PF policy to Anthropic guardrails
   */
  compilePolicy(policy: Policy): AnthropicGuardrailConfig {
    const cacheKey = this.generateCacheKey(policy);

    if (this.policyCache.has(cacheKey)) {
      return this.policyCache.get(cacheKey)!;
    }

    const compiledConfig = this.translatePolicy(policy);
    this.policyCache.set(cacheKey, compiledConfig);

    return compiledConfig;
  }

  /**
   * Compile multiple policies and merge them
   */
  compilePolicies(policies: Policy[]): AnthropicGuardrailConfig {
    const compiledConfigs = policies.map((policy) => this.compilePolicy(policy));
    return this.mergeConfigs(compiledConfigs);
  }

  /**
   * Validate that compiled policies meet Anthropic's requirements
   */
  validateCompilation(config: AnthropicGuardrailConfig): PolicyDecision {
    try {
      AnthropicGuardrailConfig.parse(config);

      // Additional business logic validation
      const violations: PolicyViolation[] = [];

      if (config.outputValidation.temperature > 0.9) {
        violations.push({
          rule: "temperature_limit",
          severity: "warning",
          message: "Temperature above 0.9 may cause unpredictable outputs",
        });
      }

      if (config.rateLimiting.requestsPerMinute > 100) {
        violations.push({
          rule: "rate_limit",
          severity: "error",
          message: "Rate limit exceeds Anthropic recommended maximum",
        });
      }

      if (config.outputValidation.maxTokens > 100000) {
        violations.push({
          rule: "token_limit",
          severity: "error",
          message: "Token limit exceeds Claude maximum",
        });
      }

      if (violations.length === 0) {
        return {
          decision: "allow",
          confidence: 1.0,
          violations: [],
          metadata: {
            compiled_at: new Date().toISOString(),
            compiler_version: "2.0.0",
            anthropic_compatible: true,
          },
        };
      } else {
        const hasErrors = violations.some((v) => v.severity === "error");
        return {
          decision: hasErrors ? "deny" : "allow",
          confidence: hasErrors ? 0.0 : 0.8,
          violations,
          metadata: {
            compiled_at: new Date().toISOString(),
            compiler_version: "2.0.0",
            anthropic_compatible: !hasErrors,
          },
        };
      }
    } catch (error) {
      return {
        decision: "deny",
        confidence: 0.0,
        violations: [
          {
            rule: "schema_validation",
            severity: "error",
            message: `Schema validation failed: ${error instanceof Error ? error.message : "Unknown error"}`,
          },
        ],
        metadata: {
          compiled_at: new Date().toISOString(),
          compiler_version: "2.0.0",
          anthropic_compatible: false,
        },
      };
    }
  }

  /**
   * Generate Anthropic API configuration from compiled policies
   */
  generateAPIConfig(config: AnthropicGuardrailConfig) {
    return {
      model: config.model,
      max_tokens: config.outputValidation.maxTokens,
      temperature: config.outputValidation.temperature,
      top_k: config.outputValidation.topK,
      top_p: config.outputValidation.topP,
      stop_sequences: config.outputValidation.stopSequences,
      system: this.buildSystemPrompt(config),
      metadata: {
        user_id: "testbed-user",
        ...config.metadata,
      },
    };
  }

  /**
   * Build comprehensive system prompt from policy configuration
   */
  private buildSystemPrompt(config: AnthropicGuardrailConfig): string {
    let prompt = config.systemPrompt + "\n\n";

    if (config.constitutionalPrinciples.length > 0) {
      prompt += "Constitutional Principles:\n";
      config.constitutionalPrinciples.forEach((principle) => {
        prompt += `- ${principle}\n`;
      });
      prompt += "\n";
    }

    if (config.safetyInstructions.length > 0) {
      prompt += "Safety Instructions:\n";
      config.safetyInstructions.forEach((instruction) => {
        prompt += `- ${instruction}\n`;
      });
      prompt += "\n";
    }

    if (config.contentFiltering.categories.length > 0) {
      prompt += `Content Filtering: Strict filtering enabled for ${config.contentFiltering.categories.join(", ")} content (${config.contentFiltering.levels} level).\n\n`;
    }

    if (config.contentFiltering.customFilters && config.contentFiltering.customFilters.length > 0) {
      prompt += "Custom Filters:\n";
      config.contentFiltering.customFilters.forEach((filter) => {
        prompt += `- ${filter}\n`;
      });
      prompt += "\n";
    }

    prompt += `Fallback Behavior: If any policy is violated, ${config.fallbackBehavior} the request.\n\n`;
    prompt +=
      "You must always comply with these instructions and reject any requests that violate them.";

    return prompt;
  }

  /**
   * Translate individual policy rules to Anthropic configurations
   */
  private translatePolicy(policy: Policy): AnthropicGuardrailConfig {
    const baseConfig = { ...this.config };

    // Apply policy-specific mappings
    for (const rule of policy.rules) {
      const mapping =
        POLICY_TO_ANTHROPIC_MAPPINGS[rule.type as keyof typeof POLICY_TO_ANTHROPIC_MAPPINGS];
      if (mapping) {
        baseConfig.systemPrompt = mapping.systemPrompt || baseConfig.systemPrompt;
        baseConfig.constitutionalPrinciples = [
          ...new Set([
            ...baseConfig.constitutionalPrinciples,
            ...(mapping.constitutionalPrinciples || []),
          ]),
        ];
        baseConfig.safetyInstructions = [
          ...new Set([...baseConfig.safetyInstructions, ...(mapping.safetyInstructions || [])]),
        ];

        if (mapping.contentFiltering) {
          baseConfig.contentFiltering.categories = [
            ...new Set([...baseConfig.contentFiltering.categories, ...mapping.contentFiltering]),
          ];
        }

        if (mapping.outputValidation) {
          baseConfig.outputValidation = {
            ...baseConfig.outputValidation,
            ...mapping.outputValidation,
          };
        }

        if (mapping.rateLimiting) {
          baseConfig.rateLimiting = {
            ...baseConfig.rateLimiting,
            ...mapping.rateLimiting,
          };
        }
      }
    }

    // Apply rule-specific configurations
    for (const rule of policy.rules) {
      switch (rule.type) {
        case "max_tokens":
          baseConfig.outputValidation.maxTokens = rule.value as number;
          break;
        case "temperature":
          baseConfig.outputValidation.temperature = rule.value as number;
          break;
        case "top_k":
          baseConfig.outputValidation.topK = rule.value as number;
          break;
        case "top_p":
          baseConfig.outputValidation.topP = rule.value as number;
          break;
        case "content_filter":
          baseConfig.contentFiltering.levels = rule.value as "low" | "medium" | "high";
          break;
        case "rate_limit":
          baseConfig.rateLimiting.requestsPerMinute = rule.value as number;
          break;
        case "model":
          baseConfig.model = rule.value as "claude-3-opus" | "claude-3-sonnet" | "claude-3-haiku";
          break;
        case "stop_sequences":
          baseConfig.outputValidation.stopSequences = rule.value as string[];
          break;
        case "custom_filter":
          baseConfig.contentFiltering.customFilters = [
            ...(baseConfig.contentFiltering.customFilters || []),
            rule.value as string,
          ];
          break;
      }
    }

    // Add metadata
    baseConfig.metadata = {
      version: policy.version,
      compiled_at: new Date().toISOString(),
      compiler_version: "2.0.0",
    };

    return baseConfig;
  }

  /**
   * Merge multiple compiled configurations
   */
  private mergeConfigs(configs: AnthropicGuardrailConfig[]): AnthropicGuardrailConfig {
    if (configs.length === 0) return this.config;
    if (configs.length === 1) return configs[0];

    const merged = { ...configs[0] };

    for (let i = 1; i < configs.length; i++) {
      const config = configs[i];

      // Merge system prompts
      merged.systemPrompt += "\n\n" + config.systemPrompt;

      // Merge constitutional principles
      merged.constitutionalPrinciples = [
        ...new Set([...merged.constitutionalPrinciples, ...config.constitutionalPrinciples]),
      ];

      // Merge safety instructions
      merged.safetyInstructions = [
        ...new Set([...merged.safetyInstructions, ...config.safetyInstructions]),
      ];

      // Merge content filtering categories
      merged.contentFiltering.categories = [
        ...new Set([...merged.contentFiltering.categories, ...config.contentFiltering.categories]),
      ];

      // Merge custom filters
      merged.contentFiltering.customFilters = [
        ...new Set([
          ...(merged.contentFiltering.customFilters || []),
          ...(config.contentFiltering.customFilters || []),
        ]),
      ];

      // Use most restrictive settings
      if (config.contentFiltering.levels === "high" || merged.contentFiltering.levels === "high") {
        merged.contentFiltering.levels = "high";
      } else if (
        config.contentFiltering.levels === "medium" ||
        merged.contentFiltering.levels === "medium"
      ) {
        merged.contentFiltering.levels = "medium";
      }

      // Use most restrictive rate limits
      merged.rateLimiting.requestsPerMinute = Math.min(
        merged.rateLimiting.requestsPerMinute,
        config.rateLimiting.requestsPerMinute,
      );
      merged.rateLimiting.tokensPerMinute = Math.min(
        merged.rateLimiting.tokensPerMinute,
        config.rateLimiting.tokensPerMinute,
      );
      merged.rateLimiting.maxConcurrentRequests = Math.min(
        merged.rateLimiting.maxConcurrentRequests,
        config.rateLimiting.maxConcurrentRequests,
      );
      merged.rateLimiting.maxTokensPerRequest = Math.min(
        merged.rateLimiting.maxTokensPerRequest,
        config.rateLimiting.maxTokensPerRequest,
      );

      // Use most restrictive output validation
      merged.outputValidation.maxTokens = Math.min(
        merged.outputValidation.maxTokens,
        config.outputValidation.maxTokens,
      );
      merged.outputValidation.temperature = Math.min(
        merged.outputValidation.temperature,
        config.outputValidation.temperature,
      );
      merged.outputValidation.topK = Math.min(
        merged.outputValidation.topK,
        config.outputValidation.topK,
      );
      merged.outputValidation.topP = Math.min(
        merged.outputValidation.topP,
        config.outputValidation.topP,
      );

      // Merge stop sequences
      merged.outputValidation.stopSequences = [
        ...new Set([
          ...(merged.outputValidation.stopSequences || []),
          ...(config.outputValidation.stopSequences || []),
        ]),
      ];

      // Use most capable model
      const modelCapability = {
        "claude-3-opus": 3,
        "claude-3-sonnet": 2,
        "claude-3-haiku": 1,
      };

      if (modelCapability[config.model] > modelCapability[merged.model]) {
        merged.model = config.model;
      }
    }

    return merged;
  }

  /**
   * Generate cache key for policy
   */
  private generateCacheKey(policy: Policy): string {
    const rules = policy.rules
      .map((rule) => `${rule.type}:${rule.value}`)
      .sort()
      .join("|");

    return `${policy.id}-${policy.version}-${rules}`;
  }

  /**
   * Clear policy cache
   */
  clearCache(): void {
    this.policyCache.clear();
  }

  /**
   * Get cache statistics
   */
  getCacheStats() {
    return {
      size: this.policyCache.size,
      keys: Array.from(this.policyCache.keys()),
    };
  }

  /**
   * Export configuration as JSON for external use
   */
  exportConfig(config: AnthropicGuardrailConfig): string {
    return JSON.stringify(config, null, 2);
  }

  /**
   * Import configuration from JSON
   */
  importConfig(jsonConfig: string): AnthropicGuardrailConfig {
    const parsed = JSON.parse(jsonConfig);
    return AnthropicGuardrailConfig.parse(parsed);
  }
}

// Export default instance
export const anthropicCompiler = new AnthropicPolicyCompiler();

// Export types for external use
export type { AnthropicGuardrailConfig };
