/**
 * OpenAI Policy Compiler
 *
 * Translates Provability Fabric policies to OpenAI's native guardrails including:
 * - System prompts with safety instructions
 * - Function calling constraints
 * - Content filtering
 * - Rate limiting
 * - Output validation
 *
 * This compiler ensures parity with kernel decisions while leveraging OpenAI's native capabilities.
 */

import { z } from "zod";
import { Policy, PolicyRule, PolicyViolation, PolicyDecision } from "../types";

// OpenAI-specific policy schemas
export const OpenAIGuardrailConfig = z.object({
  systemPrompt: z.string(),
  functionCalling: z.object({
    enabled: z.boolean(),
    allowedFunctions: z.array(z.string()).optional(),
    requiredFunctions: z.array(z.string()).optional(),
  }),
  contentFiltering: z.object({
    categories: z.array(z.enum(["hate", "harassment", "self-harm", "sexual", "violence"])),
    levels: z.enum(["low", "medium", "high"]),
  }),
  rateLimiting: z.object({
    requestsPerMinute: z.number(),
    tokensPerMinute: z.number(),
    maxConcurrentRequests: z.number(),
  }),
  outputValidation: z.object({
    maxTokens: z.number(),
    temperature: z.number().min(0).max(2),
    topP: z.number().min(0).max(1),
    frequencyPenalty: z.number().min(-2).max(2),
    presencePenalty: z.number().min(-2).max(2),
  }),
  safetyInstructions: z.array(z.string()),
  fallbackBehavior: z.enum(["reject", "modify", "allow"]),
});

export type OpenAIGuardrailConfig = z.infer<typeof OpenAIGuardrailConfig>;

// Policy translation mappings
const POLICY_TO_OPENAI_MAPPINGS = {
  // Security policies
  data_leak_prevention: {
    systemPrompt:
      "You must never reveal sensitive information, personal data, or confidential details.",
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
      topP: 0.9,
    },
    rateLimiting: {
      requestsPerMinute: 60,
      tokensPerMinute: 10000,
      maxConcurrentRequests: 5,
    },
  },

  cost_optimization: {
    outputValidation: {
      maxTokens: 500,
      temperature: 0.1,
      topP: 0.8,
    },
    rateLimiting: {
      requestsPerMinute: 30,
      tokensPerMinute: 5000,
      maxConcurrentRequests: 3,
    },
  },

  // Compliance policies
  gdpr_compliance: {
    systemPrompt:
      "You must comply with GDPR requirements including data minimization, purpose limitation, and user rights.",
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
    contentFiltering: ["harassment"],
    safetyInstructions: [
      "Maintain audit trails",
      "Prevent unauthorized access",
      "Ensure data integrity",
      "Document all changes",
    ],
  },
};

export class OpenAIPolicyCompiler {
  private config: OpenAIGuardrailConfig;
  private policyCache: Map<string, OpenAIGuardrailConfig> = new Map();

  constructor(baseConfig?: Partial<OpenAIGuardrailConfig>) {
    this.config = {
      systemPrompt: "You are a safe, helpful AI assistant that follows all safety guidelines.",
      functionCalling: {
        enabled: false,
        allowedFunctions: [],
        requiredFunctions: [],
      },
      contentFiltering: {
        categories: ["hate", "harassment", "self-harm", "sexual", "violence"],
        levels: "medium",
      },
      rateLimiting: {
        requestsPerMinute: 60,
        tokensPerMinute: 10000,
        maxConcurrentRequests: 5,
      },
      outputValidation: {
        maxTokens: 1000,
        temperature: 0.7,
        topP: 0.9,
        frequencyPenalty: 0,
        presencePenalty: 0,
      },
      safetyInstructions: [
        "Be helpful and accurate",
        "Maintain user safety",
        "Respect privacy and confidentiality",
      ],
      fallbackBehavior: "reject",
      ...baseConfig,
    };
  }

  /**
   * Compile a PF policy to OpenAI guardrails
   */
  compilePolicy(policy: Policy): OpenAIGuardrailConfig {
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
  compilePolicies(policies: Policy[]): OpenAIGuardrailConfig {
    const compiledConfigs = policies.map((policy) => this.compilePolicy(policy));
    return this.mergeConfigs(compiledConfigs);
  }

  /**
   * Validate that compiled policies meet OpenAI's requirements
   */
  validateCompilation(config: OpenAIGuardrailConfig): PolicyDecision {
    try {
      OpenAIGuardrailConfig.parse(config);

      // Additional business logic validation
      const violations: PolicyViolation[] = [];

      if (config.outputValidation.temperature > 1.5) {
        violations.push({
          rule: "temperature_limit",
          severity: "warning",
          message: "Temperature above 1.5 may cause unpredictable outputs",
        });
      }

      if (config.rateLimiting.requestsPerMinute > 100) {
        violations.push({
          rule: "rate_limit",
          severity: "error",
          message: "Rate limit exceeds OpenAI recommended maximum",
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
            openai_compatible: true,
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
            openai_compatible: !hasErrors,
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
          openai_compatible: false,
        },
      };
    }
  }

  /**
   * Generate OpenAI API configuration from compiled policies
   */
  generateAPIConfig(config: OpenAIGuardrailConfig) {
    return {
      model: "gpt-4",
      messages: [
        {
          role: "system",
          content: this.buildSystemPrompt(config),
        },
      ],
      max_tokens: config.outputValidation.maxTokens,
      temperature: config.outputValidation.temperature,
      top_p: config.outputValidation.topP,
      frequency_penalty: config.outputValidation.frequencyPenalty,
      presence_penalty: config.outputValidation.presencePenalty,
      function_call: config.functionCalling.enabled ? "auto" : "none",
      functions:
        config.functionCalling.allowedFunctions?.map((name) => ({
          name,
          description: `Function: ${name}`,
          parameters: { type: "object", properties: {} },
        })) || undefined,
      user: "testbed-user",
      stream: false,
    };
  }

  /**
   * Build comprehensive system prompt from policy configuration
   */
  private buildSystemPrompt(config: OpenAIGuardrailConfig): string {
    let prompt = config.systemPrompt + "\n\n";

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

    prompt += `Fallback Behavior: If any policy is violated, ${config.fallbackBehavior} the request.\n\n`;
    prompt +=
      "You must always comply with these instructions and reject any requests that violate them.";

    return prompt;
  }

  /**
   * Translate individual policy rules to OpenAI configurations
   */
  private translatePolicy(policy: Policy): OpenAIGuardrailConfig {
    const baseConfig = { ...this.config };

    // Apply policy-specific mappings
    for (const rule of policy.rules) {
      const mapping =
        POLICY_TO_OPENAI_MAPPINGS[rule.type as keyof typeof POLICY_TO_OPENAI_MAPPINGS];
      if (mapping) {
        baseConfig.systemPrompt = mapping.systemPrompt || baseConfig.systemPrompt;
        baseConfig.safetyInstructions = [
          ...baseConfig.safetyInstructions,
          ...(mapping.safetyInstructions || []),
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
        case "content_filter":
          baseConfig.contentFiltering.levels = rule.value as "low" | "medium" | "high";
          break;
        case "rate_limit":
          baseConfig.rateLimiting.requestsPerMinute = rule.value as number;
          break;
        case "function_whitelist":
          baseConfig.functionCalling.enabled = true;
          baseConfig.functionCalling.allowedFunctions = rule.value as string[];
          break;
      }
    }

    return baseConfig;
  }

  /**
   * Merge multiple compiled configurations
   */
  private mergeConfigs(configs: OpenAIGuardrailConfig[]): OpenAIGuardrailConfig {
    if (configs.length === 0) return this.config;
    if (configs.length === 1) return configs[0];

    const merged = { ...configs[0] };

    for (let i = 1; i < configs.length; i++) {
      const config = configs[i];

      // Merge system prompts
      merged.systemPrompt += "\n\n" + config.systemPrompt;

      // Merge safety instructions
      merged.safetyInstructions = [
        ...new Set([...merged.safetyInstructions, ...config.safetyInstructions]),
      ];

      // Merge content filtering categories
      merged.contentFiltering.categories = [
        ...new Set([...merged.contentFiltering.categories, ...config.contentFiltering.categories]),
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

      // Use most restrictive output validation
      merged.outputValidation.maxTokens = Math.min(
        merged.outputValidation.maxTokens,
        config.outputValidation.maxTokens,
      );
      merged.outputValidation.temperature = Math.min(
        merged.outputValidation.temperature,
        config.outputValidation.temperature,
      );
      merged.outputValidation.topP = Math.min(
        merged.outputValidation.topP,
        config.outputValidation.topP,
      );

      // Merge function calling
      if (config.functionCalling.enabled) {
        merged.functionCalling.enabled = true;
        merged.functionCalling.allowedFunctions = [
          ...new Set([
            ...(merged.functionCalling.allowedFunctions || []),
            ...(config.functionCalling.allowedFunctions || []),
          ]),
        ];
        merged.functionCalling.requiredFunctions = [
          ...new Set([
            ...(merged.functionCalling.requiredFunctions || []),
            ...(config.functionCalling.requiredFunctions || []),
          ]),
        ];
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
}

// Export default instance
export const openaiCompiler = new OpenAIPolicyCompiler();

// Export types for external use
export type { OpenAIGuardrailConfig };
