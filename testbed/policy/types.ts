/**
 * Policy Types for Provability Fabric Testbed
 *
 * Defines the core types used by policy compilers and validation systems.
 */

export interface PolicyRule {
  id: string;
  type: string;
  value: any;
  description?: string;
  severity: "low" | "medium" | "high" | "critical";
  metadata?: Record<string, any>;
}

export interface Policy {
  id: string;
  name: string;
  version: string;
  description: string;
  rules: PolicyRule[];
  tags: string[];
  created_at: string;
  updated_at: string;
  metadata?: Record<string, any>;
}

export interface PolicyViolation {
  rule: string;
  severity: "warning" | "error" | "critical";
  message: string;
  details?: Record<string, any>;
  timestamp?: string;
}

export interface PolicyDecision {
  decision: "allow" | "deny" | "modify" | "escalate";
  confidence: number; // 0.0 to 1.0
  violations: PolicyViolation[];
  metadata: Record<string, any>;
  timestamp?: string;
}

export interface CompiledPolicy {
  id: string;
  original_policy: Policy;
  compiled_config: any;
  provider: "openai" | "anthropic" | "google" | "azure";
  compilation_metadata: {
    compiled_at: string;
    compiler_version: string;
    validation_status: "valid" | "invalid" | "warning";
    violations: PolicyViolation[];
  };
}

export interface PolicyTestResult {
  test_id: string;
  policy_id: string;
  test_input: any;
  expected_output: any;
  actual_output: any;
  passed: boolean;
  latency_ms: number;
  violations: PolicyViolation[];
  metadata: Record<string, any>;
}

export interface PolicyConformanceTest {
  id: string;
  name: string;
  description: string;
  test_cases: PolicyTestCase[];
  expected_results: Record<string, any>;
  metadata: Record<string, any>;
}

export interface PolicyTestCase {
  id: string;
  input: any;
  expected_decision: PolicyDecision;
  expected_violations: PolicyViolation[];
  tags: string[];
}

export interface PolicyCompilerStats {
  total_policies_compiled: number;
  successful_compilations: number;
  failed_compilations: number;
  average_compilation_time_ms: number;
  cache_hit_rate: number;
  last_compilation: string;
  provider_stats: Record<
    string,
    {
      total: number;
      successful: number;
      failed: number;
      average_time_ms: number;
    }
  >;
}

export interface PolicyValidationResult {
  policy_id: string;
  valid: boolean;
  violations: PolicyViolation[];
  warnings: PolicyViolation[];
  metadata: {
    validated_at: string;
    validator_version: string;
    validation_duration_ms: number;
  };
}

// Provider-specific types
export type ProviderType = "openai" | "anthropic" | "google" | "azure" | "custom";

export interface ProviderConfig {
  type: ProviderType;
  name: string;
  version: string;
  capabilities: string[];
  limitations: string[];
  metadata: Record<string, any>;
}

// Rate limiting types
export interface RateLimitConfig {
  requests_per_minute: number;
  tokens_per_minute: number;
  max_concurrent_requests: number;
  burst_limit: number;
  window_size_ms: number;
}

// Content filtering types
export interface ContentFilterConfig {
  categories: string[];
  levels: "low" | "medium" | "high" | "strict";
  custom_filters: string[];
  whitelist: string[];
  blacklist: string[];
}

// Output validation types
export interface OutputValidationConfig {
  max_tokens: number;
  temperature: number;
  top_p: number;
  top_k?: number;
  frequency_penalty?: number;
  presence_penalty?: number;
  stop_sequences?: string[];
  max_output_length?: number;
}

// Function calling types
export interface FunctionCallConfig {
  enabled: boolean;
  allowed_functions: string[];
  required_functions: string[];
  function_schemas: Record<string, any>;
  max_function_calls: number;
}

// Safety and compliance types
export interface SafetyConfig {
  safety_instructions: string[];
  constitutional_principles: string[];
  fallback_behavior: "reject" | "modify" | "allow" | "escalate";
  escalation_threshold: number;
  human_review_required: boolean;
}

export interface ComplianceConfig {
  standards: string[]; // GDPR, SOX, HIPAA, etc.
  audit_trail_enabled: boolean;
  data_retention_days: number;
  encryption_required: boolean;
  access_controls: string[];
}

// Performance and cost types
export interface PerformanceConfig {
  target_latency_ms: number;
  target_throughput: number;
  max_memory_mb: number;
  cpu_limit_percent: number;
  timeout_ms: number;
}

export interface CostConfig {
  max_cost_per_request: number;
  max_cost_per_day: number;
  cost_optimization_enabled: boolean;
  preferred_models: string[];
  fallback_models: string[];
}

// Monitoring and observability types
export interface MonitoringConfig {
  metrics_enabled: boolean;
  logging_level: "debug" | "info" | "warn" | "error";
  alerting_enabled: boolean;
  alert_thresholds: Record<string, number>;
  dashboard_urls: string[];
}

// Export all types
export type {
  PolicyRule,
  Policy,
  PolicyViolation,
  PolicyDecision,
  CompiledPolicy,
  PolicyTestResult,
  PolicyConformanceTest,
  PolicyTestCase,
  PolicyCompilerStats,
  PolicyValidationResult,
  ProviderType,
  ProviderConfig,
  RateLimitConfig,
  ContentFilterConfig,
  OutputValidationConfig,
  FunctionCallConfig,
  SafetyConfig,
  ComplianceConfig,
  PerformanceConfig,
  CostConfig,
  MonitoringConfig,
};
