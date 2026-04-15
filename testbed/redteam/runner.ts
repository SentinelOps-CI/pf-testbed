import { readFileSync, readdirSync } from "fs";
import { join } from "path";
import { createHash } from "crypto";

// Red-Team Test Runner
// Ships adversarial corpora and runners wired to dashboards

export interface TestCase {
  id: string;
  type: string;
  payload: any;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
  expected_result: "blocked" | "denied" | "allowed" | "error";
  category: string;
}

export interface TestResult {
  test_id: string;
  test_type: string;
  payload: any;
  timestamp: string;
  result: "passed" | "failed" | "error";
  actual_result: string;
  expected_result: string;
  response_time_ms: number;
  error_message?: string;
  metadata: Record<string, any>;
}

export interface TestSuite {
  name: string;
  type: string;
  test_cases: TestCase[];
  total_tests: number;
  passed_tests: number;
  failed_tests: number;
  error_tests: number;
  success_rate: number;
  execution_time_ms: number;
  severity_breakdown: Record<string, number>;
  category_breakdown: Record<string, number>;
}

export interface TestRun {
  id: string;
  timestamp: string;
  suites: TestSuite[];
  summary: {
    total_tests: number;
    total_passed: number;
    total_failed: number;
    total_errors: number;
    overall_success_rate: number;
    total_execution_time_ms: number;
    critical_failures: number;
    high_failures: number;
  };
  metadata: {
    runner_version: string;
    environment: string;
    target_system: string;
    test_mode: "automated" | "manual" | "scheduled";
  };
}

export class RedTeamRunner {
  private testCases: Map<string, TestCase[]> = new Map();
  private testResults: TestResult[] = [];
  private testSuites: TestSuite[] = [];
  private executionStats = {
    total_runs: 0,
    total_tests_executed: 0,
    total_passed: 0,
    total_failed: 0,
    total_errors: 0,
    avg_execution_time_ms: 0,
    last_run_timestamp: "",
  };

  constructor() {
    this.loadTestCases();
  }

  /**
   * Load test cases from all test files
   */
  private loadTestCases(): void {
    const testTypes = ["injection", "smuggling", "abac"];

    testTypes.forEach((type) => {
      const testCases: TestCase[] = [];
      const testDir = join(__dirname, type, "cases");

      try {
        const files = readdirSync(testDir).filter((file) => file.endsWith(".jsonl"));

        files.forEach((file) => {
          const filePath = join(testDir, file);
          const content = readFileSync(filePath, "utf-8");

          content.split("\n").forEach((line) => {
            if (line.trim()) {
              try {
                const testCase: TestCase = JSON.parse(line);
                testCases.push(testCase);
              } catch (error) {
                console.error(`Failed to parse test case in ${file}:`, error);
              }
            }
          });
        });

        this.testCases.set(type, testCases);
        console.log(`Loaded ${testCases.length} test cases for ${type}`);
      } catch (error) {
        console.error(`Failed to load test cases for ${type}:`, error);
      }
    });
  }

  /**
   * Run all test suites
   */
  async runAllTests(targetSystem: string = "testbed"): Promise<TestRun> {
    const startTime = Date.now();
    const runId = this.generateRunId();

    console.log(`Starting red-team test run: ${runId}`);

    const suites: TestSuite[] = [];

    // Run injection tests
    const injectionSuite = await this.runTestSuite("injection", targetSystem);
    suites.push(injectionSuite);

    // Run smuggling tests
    const smugglingSuite = await this.runTestSuite("smuggling", targetSystem);
    suites.push(smugglingSuite);

    // Run ABAC tests
    const abacSuite = await this.runTestSuite("abac", targetSystem);
    suites.push(abacSuite);

    const totalExecutionTime = Date.now() - startTime;

    // Calculate summary
    const summary = this.calculateRunSummary(suites);

    const testRun: TestRun = {
      id: runId,
      timestamp: new Date().toISOString(),
      suites,
      summary,
      metadata: {
        runner_version: "1.0.0",
        environment: process.env.NODE_ENV || "development",
        target_system: targetSystem,
        test_mode: "automated",
      },
    };

    // Update execution stats
    this.updateExecutionStats(testRun);

    // Log results
    this.logTestRunResults(testRun);

    return testRun;
  }

  /**
   * Run a specific test suite
   */
  async runTestSuite(type: string, targetSystem: string): Promise<TestSuite> {
    const startTime = Date.now();
    const testCases = this.testCases.get(type) || [];

    console.log(`Running ${type} test suite with ${testCases.length} test cases`);

    const results: TestResult[] = [];
    let passed = 0;
    let failed = 0;
    let errors = 0;

    // Execute each test case
    for (const testCase of testCases) {
      try {
        const result = await this.executeTestCase(testCase, targetSystem);
        results.push(result);

        if (result.result === "passed") {
          passed++;
        } else if (result.result === "failed") {
          failed++;
        } else {
          errors++;
        }
      } catch (error) {
        console.error(`Error executing test case ${testCase.id}:`, error);
        errors++;

        const errorResult: TestResult = {
          test_id: testCase.id,
          test_type: testCase.type,
          payload: testCase.payload,
          timestamp: new Date().toISOString(),
          result: "error",
          actual_result: "error",
          expected_result: testCase.expected_result,
          response_time_ms: 0,
          error_message: error instanceof Error ? error.message : "Unknown error",
          metadata: {},
        };

        results.push(errorResult);
      }
    }

    const executionTime = Date.now() - startTime;
    const successRate = testCases.length > 0 ? (passed / testCases.length) * 100 : 0;

    // Calculate severity and category breakdowns
    const severityBreakdown = this.calculateSeverityBreakdown(testCases);
    const categoryBreakdown = this.calculateCategoryBreakdown(testCases);

    const suite: TestSuite = {
      name: `${type} Test Suite`,
      type,
      test_cases: testCases,
      total_tests: testCases.length,
      passed_tests: passed,
      failed_tests: failed,
      error_tests: errors,
      success_rate: successRate,
      execution_time_ms: executionTime,
      severity_breakdown: severityBreakdown,
      category_breakdown: categoryBreakdown,
    };

    this.testSuites.push(suite);
    this.testResults.push(...results);

    return suite;
  }

  /**
   * Execute a single test case
   */
  private async executeTestCase(testCase: TestCase, targetSystem: string): Promise<TestResult> {
    const startTime = Date.now();

    try {
      // Simulate test execution based on type
      let actualResult: string;

      switch (testCase.type) {
        case "sql_injection":
          actualResult = await this.simulateSqlInjectionTest(testCase, targetSystem);
          break;
        case "http_smuggling":
          actualResult = await this.simulateHttpSmugglingTest(testCase, targetSystem);
          break;
        case "attribute_bypass":
          actualResult = await this.simulateAbacTest(testCase, targetSystem);
          break;
        default:
          actualResult = "unknown";
      }

      const responseTime = Date.now() - startTime;
      const result: "passed" | "failed" | "error" =
        actualResult === testCase.expected_result ? "passed" : "failed";

      return {
        test_id: testCase.id,
        test_type: testCase.type,
        payload: testCase.payload,
        timestamp: new Date().toISOString(),
        result,
        actual_result: actualResult,
        expected_result: testCase.expected_result,
        response_time_ms: responseTime,
        metadata: {
          severity: testCase.severity,
          category: testCase.category,
          target_system: targetSystem,
        },
      };
    } catch (error) {
      const responseTime = Date.now() - startTime;

      return {
        test_id: testCase.id,
        test_type: testCase.type,
        payload: testCase.payload,
        timestamp: new Date().toISOString(),
        result: "error",
        actual_result: "error",
        expected_result: testCase.expected_result,
        response_time_ms: responseTime,
        error_message: error instanceof Error ? error.message : "Unknown error",
        metadata: {
          severity: testCase.severity,
          category: testCase.category,
          target_system: targetSystem,
        },
      };
    }
  }

  /**
   * Simulate SQL injection test
   */
  private async simulateSqlInjectionTest(
    testCase: TestCase,
    targetSystem: string,
  ): Promise<string> {
    // Simulate different detection mechanisms
    const payload = JSON.stringify(testCase.payload);

    // Check for common SQL injection patterns
    if (
      payload.includes("' OR '1'='1") ||
      payload.includes("DROP TABLE") ||
      payload.includes("UNION SELECT") ||
      payload.includes("xp_cmdshell")
    ) {
      return "blocked";
    }

    // Simulate some false negatives for testing
    if (Math.random() < 0.1) {
      // 10% false negative rate
      return "allowed";
    }

    return "blocked";
  }

  /**
   * Simulate HTTP smuggling test
   */
  private async simulateHttpSmugglingTest(
    testCase: TestCase,
    targetSystem: string,
  ): Promise<string> {
    const payload = JSON.stringify(testCase.payload);

    // Check for HTTP smuggling patterns
    if (
      (payload.includes("Content-Length: 0") && payload.includes("GET /admin")) ||
      payload.includes("POST /admin") ||
      payload.includes("DELETE /users")
    ) {
      return "blocked";
    }

    // Simulate some false negatives
    if (Math.random() < 0.05) {
      // 5% false negative rate
      return "allowed";
    }

    return "blocked";
  }

  /**
   * Simulate ABAC test
   */
  private async simulateAbacTest(testCase: TestCase, targetSystem: string): Promise<string> {
    const payload = testCase.payload as any;

    // Check for privilege escalation attempts
    if (payload.user_role === "guest" && payload.target_resource === "admin_panel") {
      return "denied";
    }

    if (payload.user_role === "intern" && payload.target_resource === "customer_ssn") {
      return "denied";
    }

    if (payload.user_role === "vendor" && payload.target_resource === "employee_salaries") {
      return "denied";
    }

    // Check for cross-department access violations
    if (payload.user_department === "finance" && payload.target_resource === "hr_records") {
      return "denied";
    }

    if (payload.user_department === "sales" && payload.target_resource === "ceo_emails") {
      return "denied";
    }

    // Simulate some false negatives
    if (Math.random() < 0.08) {
      // 8% false negative rate
      return "allowed";
    }

    return "denied";
  }

  /**
   * Calculate severity breakdown
   */
  private calculateSeverityBreakdown(testCases: TestCase[]): Record<string, number> {
    const breakdown: Record<string, number> = {};

    testCases.forEach((testCase) => {
      const severity = testCase.severity;
      breakdown[severity] = (breakdown[severity] || 0) + 1;
    });

    return breakdown;
  }

  /**
   * Calculate category breakdown
   */
  private calculateCategoryBreakdown(testCases: TestCase[]): Record<string, number> {
    const breakdown: Record<string, number> = {};

    testCases.forEach((testCase) => {
      const category = testCase.category;
      breakdown[category] = (breakdown[category] || 0) + 1;
    });

    return breakdown;
  }

  /**
   * Calculate run summary
   */
  private calculateRunSummary(suites: TestSuite[]): TestRun["summary"] {
    let totalTests = 0;
    let totalPassed = 0;
    let totalFailed = 0;
    let totalErrors = 0;
    let totalExecutionTime = 0;
    let criticalFailures = 0;
    let highFailures = 0;

    suites.forEach((suite) => {
      totalTests += suite.total_tests;
      totalPassed += suite.passed_tests;
      totalFailed += suite.failed_tests;
      totalErrors += suite.error_tests;
      totalExecutionTime += suite.execution_time_ms;

      // Count critical and high failures
      if (suite.severity_breakdown.critical) {
        criticalFailures += suite.failed_tests;
      }
      if (suite.severity_breakdown.high) {
        highFailures += suite.failed_tests;
      }
    });

    const overallSuccessRate = totalTests > 0 ? (totalPassed / totalTests) * 100 : 0;

    return {
      total_tests: totalTests,
      total_passed: totalPassed,
      total_failed: totalFailed,
      total_errors: totalErrors,
      overall_success_rate: overallSuccessRate,
      total_execution_time_ms: totalExecutionTime,
      critical_failures: criticalFailures,
      high_failures: highFailures,
    };
  }

  /**
   * Update execution statistics
   */
  private updateExecutionStats(testRun: TestRun): void {
    this.executionStats.total_runs++;
    this.executionStats.total_tests_executed += testRun.summary.total_tests;
    this.executionStats.total_passed += testRun.summary.total_passed;
    this.executionStats.total_failed += testRun.summary.total_failed;
    this.executionStats.total_errors += testRun.summary.total_errors;
    this.executionStats.last_run_timestamp = testRun.timestamp;

    // Update average execution time
    const totalTime =
      this.executionStats.avg_execution_time_ms * (this.executionStats.total_runs - 1);
    this.executionStats.avg_execution_time_ms =
      (totalTime + testRun.summary.total_execution_time_ms) / this.executionStats.total_runs;
  }

  /**
   * Log test run results
   */
  private logTestRunResults(testRun: TestRun): void {
    console.log("\n" + "=".repeat(60));
    console.log(`RED-TEAM TEST RUN COMPLETED: ${testRun.id}`);
    console.log("=".repeat(60));

    console.log(`\nOverall Results:`);
    console.log(`  Total Tests: ${testRun.summary.total_tests}`);
    console.log(`  Passed: ${testRun.summary.total_passed}`);
    console.log(`  Failed: ${testRun.summary.total_failed}`);
    console.log(`  Errors: ${testRun.summary.total_errors}`);
    console.log(`  Success Rate: ${testRun.summary.overall_success_rate.toFixed(2)}%`);
    console.log(`  Execution Time: ${testRun.summary.total_execution_time_ms}ms`);

    console.log(`\nCritical Failures: ${testRun.summary.critical_failures}`);
    console.log(`High Failures: ${testRun.summary.high_failures}`);

    console.log(`\nSuite Results:`);
    testRun.suites.forEach((suite) => {
      console.log(
        `  ${suite.name}: ${suite.passed_tests}/${suite.total_tests} passed (${suite.success_rate.toFixed(2)}%)`,
      );
    });

    console.log("\n" + "=".repeat(60));
  }

  /**
   * Generate unique run ID
   */
  private generateRunId(): string {
    return `redteam_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Get execution statistics
   */
  getExecutionStats() {
    return { ...this.executionStats };
  }

  /**
   * Get test results
   */
  getTestResults(): TestResult[] {
    return [...this.testResults];
  }

  /**
   * Get test suites
   */
  getTestSuites(): TestSuite[] {
    return [...this.testSuites];
  }

  /**
   * Clear test results
   */
  clearResults(): void {
    this.testResults = [];
    this.testSuites = [];
  }

  /**
   * Export results for dashboard integration
   */
  exportResultsForDashboard(): any {
    return {
      execution_stats: this.getExecutionStats(),
      recent_test_runs: this.testSuites.slice(-5),
      test_results_summary: {
        total_tests: this.testResults.length,
        passed: this.testResults.filter((r) => r.result === "passed").length,
        failed: this.testResults.filter((r) => r.result === "failed").length,
        errors: this.testResults.filter((r) => r.result === "error").length,
      },
      severity_distribution: this.calculateOverallSeverityDistribution(),
      category_distribution: this.calculateOverallCategoryDistribution(),
    };
  }

  /**
   * Calculate overall severity distribution
   */
  private calculateOverallSeverityDistribution(): Record<string, number> {
    const distribution: Record<string, number> = {};

    this.testResults.forEach((result) => {
      const testCase = this.findTestCase(result.test_id);
      if (testCase) {
        const severity = testCase.severity;
        distribution[severity] = (distribution[severity] || 0) + 1;
      }
    });

    return distribution;
  }

  /**
   * Calculate overall category distribution
   */
  private calculateOverallCategoryDistribution(): Record<string, number> {
    const distribution: Record<string, number> = {};

    this.testResults.forEach((result) => {
      const testCase = this.findTestCase(result.test_id);
      if (testCase) {
        const category = testCase.category;
        distribution[category] = (distribution[category] || 0) + 1;
      }
    });

    return distribution;
  }

  /**
   * Find test case by ID
   */
  private findTestCase(testId: string): TestCase | undefined {
    for (const testCases of this.testCases.values()) {
      const testCase = testCases.find((tc) => tc.id === testId);
      if (testCase) return testCase;
    }
    return undefined;
  }
}

// Export singleton instance
export const redTeamRunner = new RedTeamRunner();
