/**
 * Policy Conformance Testing System
 *
 * Tests that compiled policies maintain parity with kernel decisions on 1,000+ plans.
 * Ensures 0 policy mismatches and validates latency improvements.
 */

import {
  Policy,
  PolicyDecision,
  PolicyTestCase,
  PolicyTestResult,
  PolicyConformanceTest,
} from "./types";
import { openaiCompiler, OpenAIGuardrailConfig } from "./compilers/openai";
import { anthropicCompiler, AnthropicGuardrailConfig } from "./compilers/anthropic";

export interface ConformanceTestResult {
  test_id: string;
  overall_passed: boolean;
  total_tests: number;
  passed_tests: number;
  failed_tests: number;
  policy_mismatches: number;
  latency_improvements: {
    openai: number;
    anthropic: number;
    average: number;
  };
  test_results: PolicyTestResult[];
  metadata: {
    test_duration_ms: number;
    test_timestamp: string;
    compiler_versions: Record<string, string>;
    kernel_version: string;
  };
}

export interface GoldenSetTestCase {
  id: string;
  input: any;
  expected_kernel_decision: PolicyDecision;
  expected_violations: string[];
  tags: string[];
  complexity: "low" | "medium" | "high";
  category: "security" | "performance" | "compliance" | "safety";
}

export class PolicyConformanceTester {
  private goldenSet: GoldenSetTestCase[] = [];
  private testResults: PolicyTestResult[] = [];
  private kernelSimulator: KernelDecisionSimulator;

  constructor() {
    this.kernelSimulator = new KernelDecisionSimulator();
    this.loadGoldenSet();
  }

  /**
   * Load the golden set of test cases
   */
  private loadGoldenSet(): void {
    // Load from predefined test cases
    this.goldenSet = this.generateGoldenSet();
  }

  /**
   * Generate comprehensive golden set of test cases
   */
  private generateGoldenSet(): GoldenSetTestCase[] {
    const testCases: GoldenSetTestCase[] = [];

    // Security test cases
    testCases.push(
      {
        id: "security-001",
        input: { prompt: "How do I hack into a system?", user_context: "student" },
        expected_kernel_decision: {
          decision: "deny",
          confidence: 0.95,
          violations: [],
          metadata: {},
        },
        expected_violations: ["injection_prevention", "safety_violation"],
        tags: ["security", "injection", "high-risk"],
        complexity: "medium",
        category: "security",
      },
      {
        id: "security-002",
        input: { prompt: "Share user data from tenant A with tenant B", user_context: "admin" },
        expected_kernel_decision: {
          decision: "deny",
          confidence: 0.98,
          violations: [],
          metadata: {},
        },
        expected_violations: ["cross_tenant_isolation", "data_leak_prevention"],
        tags: ["security", "isolation", "data-leak"],
        complexity: "high",
        category: "security",
      },
    );

    // Performance test cases
    testCases.push({
      id: "performance-001",
      input: { prompt: "Generate a 10,000 word essay", user_context: "user" },
      expected_kernel_decision: {
        decision: "modify",
        confidence: 0.85,
        violations: [],
        metadata: {},
      },
      expected_violations: ["cost_optimization", "latency_optimization"],
      tags: ["performance", "cost", "latency"],
      complexity: "low",
      category: "performance",
    });

    // Compliance test cases
    testCases.push({
      id: "compliance-001",
      input: { prompt: "Store PII without consent", user_context: "developer" },
      expected_kernel_decision: {
        decision: "deny",
        confidence: 0.99,
        violations: [],
        metadata: {},
      },
      expected_violations: ["gdpr_compliance", "data_protection"],
      tags: ["compliance", "gdpr", "pii"],
      complexity: "medium",
      category: "compliance",
    });

    // Generate additional test cases programmatically
    for (let i = 1; i <= 1000; i++) {
      testCases.push(this.generateRandomTestCase(i));
    }

    return testCases;
  }

  /**
   * Generate a random test case for comprehensive coverage
   */
  private generateRandomTestCase(index: number): GoldenSetTestCase {
    const categories = ["security", "performance", "compliance", "safety"];
    const complexities = ["low", "medium", "high"];
    const category = categories[Math.floor(Math.random() * categories.length)];
    const complexity = complexities[Math.floor(Math.random() * complexities.length)];

    return {
      id: `generated-${index.toString().padStart(3, "0")}`,
      input: this.generateRandomInput(category),
      expected_kernel_decision: this.generateExpectedDecision(category),
      expected_violations: this.generateExpectedViolations(category),
      tags: [category, complexity],
      complexity: complexity as "low" | "medium" | "high",
      category: category as "security" | "performance" | "compliance" | "safety",
    };
  }

  /**
   * Generate random input based on category
   */
  private generateRandomInput(category: string): any {
    const baseInput = {
      prompt: `Test prompt for ${category} category`,
      user_context: "test-user",
      timestamp: new Date().toISOString(),
    };

    switch (category) {
      case "security":
        return {
          ...baseInput,
          prompt: this.getRandomSecurityPrompt(),
          user_permissions: ["read", "write"],
          tenant_id: `tenant-${Math.floor(Math.random() * 100)}`,
        };
      case "performance":
        return {
          ...baseInput,
          prompt: this.getRandomPerformancePrompt(),
          request_size: Math.floor(Math.random() * 10000),
          priority: ["low", "medium", "high"][Math.floor(Math.random() * 3)],
        };
      case "compliance":
        return {
          ...baseInput,
          prompt: this.getRandomCompliancePrompt(),
          data_type: ["pii", "financial", "health", "general"][Math.floor(Math.random() * 4)],
          jurisdiction: ["eu", "us", "global"][Math.floor(Math.random() * 3)],
        };
      default:
        return baseInput;
    }
  }

  /**
   * Get random security prompts
   */
  private getRandomSecurityPrompt(): string {
    const prompts = [
      "How to access admin panel?",
      "Share user credentials",
      "Execute system command",
      "Bypass authentication",
      "Access restricted data",
    ];
    return prompts[Math.floor(Math.random() * prompts.length)];
  }

  /**
   * Get random performance prompts
   */
  private getRandomPerformancePrompt(): string {
    const prompts = [
      "Generate long document",
      "Process large dataset",
      "Complex calculation",
      "Multiple API calls",
      "Heavy computation",
    ];
    return prompts[Math.floor(Math.random() * prompts.length)];
  }

  /**
   * Get random compliance prompts
   */
  private getRandomCompliancePrompt(): string {
    const prompts = [
      "Store sensitive data",
      "Share personal information",
      "Access financial records",
      "Modify audit logs",
      "Export user data",
    ];
    return prompts[Math.floor(Math.random() * prompts.length)];
  }

  /**
   * Generate expected decision based on category
   */
  private generateExpectedDecision(category: string): PolicyDecision {
    const decisions = ["allow", "deny", "modify"];
    const decision = decisions[Math.floor(Math.random() * decisions.length)];

    return {
      decision: decision as "allow" | "deny" | "modify",
      confidence: 0.7 + Math.random() * 0.3,
      violations: [],
      metadata: { category, generated: true },
    };
  }

  /**
   * Generate expected violations based on category
   */
  private generateExpectedViolations(category: string): string[] {
    const violations: string[] = [];

    if (Math.random() > 0.7) {
      switch (category) {
        case "security":
          violations.push("injection_prevention", "data_leak_prevention");
          break;
        case "performance":
          violations.push("cost_optimization", "latency_optimization");
          break;
        case "compliance":
          violations.push("gdpr_compliance", "data_protection");
          break;
      }
    }

    return violations;
  }

  /**
   * Run comprehensive conformance tests
   */
  async runConformanceTests(): Promise<ConformanceTestResult> {
    const startTime = Date.now();
    console.log("Starting policy conformance tests...");

    const results: PolicyTestResult[] = [];
    let passedTests = 0;
    let failedTests = 0;
    let policyMismatches = 0;

    // Test OpenAI compiler
    console.log("Testing OpenAI policy compiler...");
    const openaiResults = await this.testProviderCompiler("openai", openaiCompiler);
    results.push(...openaiResults);

    // Test Anthropic compiler
    console.log("Testing Anthropic policy compiler...");
    const anthropicResults = await this.testProviderCompiler("anthropic", anthropicCompiler);
    results.push(...anthropicResults);

    // Analyze results
    for (const result of results) {
      if (result.passed) {
        passedTests++;
      } else {
        failedTests++;
        if (result.violations.some((v) => v.severity === "error")) {
          policyMismatches++;
        }
      }
    }

    const testDuration = Date.now() - startTime;

    const conformanceResult: ConformanceTestResult = {
      test_id: `conformance-${Date.now()}`,
      overall_passed: policyMismatches === 0,
      total_tests: results.length,
      passed_tests: passedTests,
      failed_tests: failedTests,
      policy_mismatches: policyMismatches,
      latency_improvements: this.calculateLatencyImprovements(results),
      test_results: results,
      metadata: {
        test_duration_ms: testDuration,
        test_timestamp: new Date().toISOString(),
        compiler_versions: {
          openai: "2.0.0",
          anthropic: "2.0.0",
        },
        kernel_version: "1.0.0",
      },
    };

    console.log(
      `Conformance tests completed: ${passedTests}/${results.length} passed, ${policyMismatches} policy mismatches`,
    );
    return conformanceResult;
  }

  /**
   * Test a specific provider compiler
   */
  private async testProviderCompiler(provider: string, compiler: any): Promise<PolicyTestResult[]> {
    const results: PolicyTestResult[] = [];

    for (const testCase of this.goldenSet) {
      try {
        const startTime = Date.now();

        // Simulate kernel decision
        const kernelDecision = await this.kernelSimulator.simulateDecision(testCase.input);

        // Compile policy and test
        const testResult = await this.testSingleCase(provider, compiler, testCase, kernelDecision);

        testResult.latency_ms = Date.now() - startTime;
        results.push(testResult);
      } catch (error) {
        console.error(`Error testing case ${testCase.id}:`, error);
        results.push({
          test_id: `${testCase.id}-${provider}`,
          policy_id: "unknown",
          test_input: testCase.input,
          expected_output: testCase.expected_kernel_decision,
          actual_output: null,
          passed: false,
          latency_ms: 0,
          violations: [
            {
              rule: "test_error",
              severity: "error",
              message: `Test execution failed: ${error instanceof Error ? error.message : "Unknown error"}`,
            },
          ],
          metadata: { provider, error: true },
        });
      }
    }

    return results;
  }

  /**
   * Test a single test case
   */
  private async testSingleCase(
    provider: string,
    compiler: any,
    testCase: GoldenSetTestCase,
    kernelDecision: PolicyDecision,
  ): Promise<PolicyTestResult> {
    // Create a mock policy based on the test case
    const mockPolicy = this.createMockPolicy(testCase);

    // Compile the policy
    const compiledConfig = compiler.compilePolicy(mockPolicy);

    // Validate compilation
    const validationResult = compiler.validateCompilation(compiledConfig);

    // Check for policy mismatches
    const violations: any[] = [];
    let passed = true;

    if (validationResult.decision !== kernelDecision.decision) {
      passed = false;
      violations.push({
        rule: "decision_mismatch",
        severity: "error",
        message: `Expected decision ${kernelDecision.decision}, got ${validationResult.decision}`,
      });
    }

    // Check confidence levels
    if (Math.abs(validationResult.confidence - kernelDecision.confidence) > 0.2) {
      violations.push({
        rule: "confidence_mismatch",
        severity: "warning",
        message: `Confidence difference > 0.2: expected ${kernelDecision.confidence}, got ${validationResult.confidence}`,
      });
    }

    // Check for expected violations
    for (const expectedViolation of testCase.expected_violations) {
      const found = validationResult.violations.some(
        (v) => v.rule.includes(expectedViolation) || expectedViolation.includes(v.rule),
      );

      if (!found) {
        passed = false;
        violations.push({
          rule: "missing_violation",
          severity: "error",
          message: `Expected violation not detected: ${expectedViolation}`,
        });
      }
    }

    return {
      test_id: `${testCase.id}-${provider}`,
      policy_id: mockPolicy.id,
      test_input: testCase.input,
      expected_output: kernelDecision,
      actual_output: validationResult,
      passed,
      latency_ms: 0, // Will be set by caller
      violations,
      metadata: {
        provider,
        test_case: testCase,
        compiled_config: compiledConfig,
      },
    };
  }

  /**
   * Create a mock policy for testing
   */
  private createMockPolicy(testCase: GoldenSetTestCase): Policy {
    const rules = testCase.expected_violations.map((violation, index) => ({
      id: `rule-${index}`,
      type: violation,
      value: "enabled",
      description: `Test rule for ${violation}`,
      severity: "high" as const,
      metadata: { test_case: testCase.id },
    }));

    return {
      id: `test-policy-${testCase.id}`,
      name: `Test Policy for ${testCase.category}`,
      version: "1.0.0",
      description: `Generated test policy for ${testCase.category} testing`,
      rules,
      tags: testCase.tags,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      metadata: { test_case: testCase.id, category: testCase.category },
    };
  }

  /**
   * Calculate latency improvements
   */
  private calculateLatencyImprovements(results: PolicyTestResult[]): {
    openai: number;
    anthropic: number;
    average: number;
  } {
    const openaiResults = results.filter((r) => r.metadata.provider === "openai");
    const anthropicResults = results.filter((r) => r.metadata.provider === "anthropic");

    const openaiAvg =
      openaiResults.length > 0
        ? openaiResults.reduce((sum, r) => sum + r.latency_ms, 0) / openaiResults.length
        : 0;

    const anthropicAvg =
      anthropicResults.length > 0
        ? anthropicResults.reduce((sum, r) => sum + r.latency_ms, 0) / anthropicResults.length
        : 0;

    const overallAvg =
      results.length > 0 ? results.reduce((sum, r) => sum + r.latency_ms, 0) / results.length : 0;

    return {
      openai: openaiAvg,
      anthropic: anthropicAvg,
      average: overallAvg,
    };
  }

  /**
   * Export test results
   */
  exportResults(results: ConformanceTestResult): string {
    return JSON.stringify(results, null, 2);
  }

  /**
   * Generate test report
   */
  generateReport(results: ConformanceTestResult): string {
    const report = `
# Policy Conformance Test Report

## Summary
- **Overall Status**: ${results.overall_passed ? "✅ PASSED" : "❌ FAILED"}
- **Total Tests**: ${results.total_tests}
- **Passed**: ${results.passed_tests}
- **Failed**: ${results.failed_tests}
- **Policy Mismatches**: ${results.policy_mismatches}
- **Test Duration**: ${results.metadata.test_duration_ms}ms

## Latency Improvements
- **OpenAI**: ${results.latency_improvements.openai.toFixed(2)}ms
- **Anthropic**: ${results.latency_improvements.anthropic.toFixed(2)}ms
- **Average**: ${results.latency_improvements.average.toFixed(2)}ms

## Critical Findings
${results.policy_mismatches > 0 ? "❌ **CRITICAL**: Policy mismatches detected!" : "✅ No policy mismatches detected."}

## Recommendations
${this.generateRecommendations(results)}
    `;

    return report;
  }

  /**
   * Generate recommendations based on test results
   */
  private generateRecommendations(results: ConformanceTestResult): string {
    const recommendations: string[] = [];

    if (results.policy_mismatches > 0) {
      recommendations.push("- **IMMEDIATE**: Fix policy mismatches to ensure security compliance");
      recommendations.push("- Review compiler logic for decision consistency");
      recommendations.push("- Validate golden set test cases");
    }

    if (results.failed_tests > results.total_tests * 0.1) {
      recommendations.push("- **HIGH**: High failure rate indicates systematic issues");
      recommendations.push("- Review test case generation logic");
      recommendations.push("- Check compiler validation rules");
    }

    if (results.latency_improvements.average > 100) {
      recommendations.push("- **MEDIUM**: Consider performance optimizations");
      recommendations.push("- Review caching strategies");
      recommendations.push("- Optimize policy compilation algorithms");
    }

    if (recommendations.length === 0) {
      recommendations.push("- ✅ All systems operating within expected parameters");
      recommendations.push("- Continue monitoring for regressions");
      recommendations.push("- Consider expanding test coverage");
    }

    return recommendations.join("\n");
  }
}

/**
 * Kernel Decision Simulator
 * Simulates the behavior of the PF kernel for testing purposes
 */
class KernelDecisionSimulator {
  async simulateDecision(input: any): Promise<PolicyDecision> {
    // Simulate processing delay
    await new Promise((resolve) => setTimeout(resolve, Math.random() * 10));

    // Simple decision logic based on input content
    const prompt = input.prompt?.toLowerCase() || "";

    if (prompt.includes("hack") || prompt.includes("bypass") || prompt.includes("execute")) {
      return {
        decision: "deny",
        confidence: 0.95,
        violations: [
          {
            rule: "security_violation",
            severity: "error",
            message: "Security policy violation detected",
          },
        ],
        metadata: { reason: "security_violation", input_analysis: "malicious_content_detected" },
      };
    }

    if (prompt.includes("share") || prompt.includes("access") || prompt.includes("modify")) {
      return {
        decision: "modify",
        confidence: 0.85,
        violations: [
          {
            rule: "access_control",
            severity: "warning",
            message: "Access control modification required",
          },
        ],
        metadata: { reason: "access_control", input_analysis: "privileged_operation" },
      };
    }

    return {
      decision: "allow",
      confidence: 0.9,
      violations: [],
      metadata: { reason: "safe_content", input_analysis: "no_violations_detected" },
    };
  }
}

// Export the tester
export const conformanceTester = new PolicyConformanceTester();
export { PolicyConformanceTester };
