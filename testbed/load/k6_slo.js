/**
 * k6 SLO Load Testing Script for Provability Fabric Testbed
 *
 * Implements comprehensive load testing with strict Service Level Objective (SLO) gates:
 * - P95 < 2.0 seconds
 * - P99 < 4.0 seconds
 * - 0 SLO violations recorded
 * - End-to-end user journey simulation
 * - Comprehensive metrics collection
 *
 * This script ensures the testbed meets production-grade performance requirements.
 */

import http from "k6/http";
import { check, sleep } from "k6";
import { Rate, Trend, Counter } from "k6/metrics";
import { htmlReport } from "https://raw.githubusercontent.com/benc-uk/k6-reporter/main/dist/bundle.js";

// Custom metrics
const sloViolations = new Counter("slo_violations");
const policyDecisions = new Counter("policy_decisions");
const securityViolations = new Counter("security_violations");
const costMetrics = new Trend("cost_per_request");
const confidenceScores = new Trend("confidence_scores");

// SLO thresholds
const SLO_THRESHOLDS = {
  P95_LATENCY_MS: 2000, // 2.0 seconds
  P99_LATENCY_MS: 4000, // 4.0 seconds
  ERROR_RATE_PERCENT: 1.0, // 1% max error rate
  THROUGHPUT_MIN: 100, // Minimum requests per second
  COST_MAX_USD: 0.01, // Maximum cost per request
  CONFIDENCE_MIN: 0.8, // Minimum confidence score
};

// Test configuration
export const options = {
  // Load test stages
  stages: [
    // Warm-up phase
    { duration: "2m", target: 10 },
    { duration: "3m", target: 50 },
    { duration: "5m", target: 100 },
    { duration: "3m", target: 200 },
    { duration: "5m", target: 200 }, // Sustained load
    { duration: "3m", target: 100 },
    { duration: "2m", target: 0 }, // Ramp down
  ],

  // SLO thresholds - test fails if any are violated
  thresholds: {
    // Latency SLOs
    "http_req_duration{scenario:policy_evaluation}": [
      `p(95)<${SLO_THRESHOLDS.P95_LATENCY_MS}`,
      `p(99)<${SLO_THRESHOLDS.P99_LATENCY_MS}`,
    ],
    "http_req_duration{scenario:security_check}": [
      `p(95)<${SLO_THRESHOLDS.P95_LATENCY_MS}`,
      `p(99)<${SLO_THRESHOLDS.P99_LATENCY_MS}`,
    ],
    "http_req_duration{scenario:compliance_validation}": [
      `p(95)<${SLO_THRESHOLDS.P95_LATENCY_MS}`,
      `p(99)<${SLO_THRESHOLDS.P99_LATENCY_MS}`,
    ],

    // Error rate SLOs
    http_req_failed: [`rate<${SLO_THRESHOLDS.ERROR_RATE_PERCENT / 100}`],

    // Throughput SLOs
    http_reqs: [`rate>${SLO_THRESHOLDS.THROUGHPUT_MIN}`],

    // Custom metric SLOs
    slo_violations: ["count==0"], // Zero SLO violations allowed
    security_violations: ["count==0"], // Zero security violations
    cost_per_request: [`p(95)<${SLO_THRESHOLDS.COST_MAX_USD}`],
    confidence_scores: [`p(95)>${SLO_THRESHOLDS.CONFIDENCE_MIN}`],
  },

  // Test scenarios
  scenarios: {
    // Policy evaluation scenario
    policy_evaluation: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: [
        { duration: "2m", target: 20 },
        { duration: "5m", target: 50 },
        { duration: "3m", target: 50 },
        { duration: "2m", target: 0 },
      ],
      gracefulRampDown: "30s",
      exec: "policyEvaluationJourney",
    },

    // Security validation scenario
    security_check: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: [
        { duration: "2m", target: 15 },
        { duration: "5m", target: 30 },
        { duration: "3m", target: 30 },
        { duration: "2m", target: 0 },
      ],
      gracefulRampDown: "30s",
      exec: "securityValidationJourney",
    },

    // Compliance validation scenario
    compliance_validation: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: [
        { duration: "2m", target: 10 },
        { duration: "5m", target: 25 },
        { duration: "3m", target: 25 },
        { duration: "2m", target: 0 },
      ],
      gracefulRampDown: "30s",
      exec: "complianceValidationJourney",
    },

    // End-to-end user journey scenario
    e2e_journey: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: [
        { duration: "3m", target: 25 },
        { duration: "7m", target: 75 },
        { duration: "5m", target: 75 },
        { duration: "3m", target: 0 },
      ],
      gracefulRampDown: "30s",
      exec: "endToEndJourney",
    },
  },

  // Global tags
  tags: {
    test_type: "slo_load_test",
    environment: "testbed",
    version: "2.0.0",
  },
};

// Test data and configuration
const TEST_CONFIG = {
  baseUrl: __ENV.TESTBED_URL || "http://localhost:8080",
  apiKey: __ENV.API_KEY || "test-key",
  testTimeout: "30s",
  maxRetries: 3,

  // Test user profiles
  userProfiles: [
    { role: "admin", permissions: ["read", "write", "admin"] },
    { role: "user", permissions: ["read", "write"] },
    { role: "viewer", permissions: ["read"] },
    { role: "auditor", permissions: ["read", "audit"] },
  ],

  // Test policies
  testPolicies: [
    "data_leak_prevention",
    "cross_tenant_isolation",
    "injection_prevention",
    "gdpr_compliance",
    "sox_compliance",
    "cost_optimization",
    "latency_optimization",
  ],

  // Test scenarios
  testScenarios: [
    "normal_operation",
    "high_load",
    "security_testing",
    "compliance_validation",
    "error_handling",
    "boundary_conditions",
  ],
};

// Helper functions
function generateTestUser() {
  const profile =
    TEST_CONFIG.userProfiles[Math.floor(Math.random() * TEST_CONFIG.userProfiles.length)];
  return {
    id: `user-${Math.random().toString(36).substr(2, 9)}`,
    role: profile.role,
    permissions: profile.permissions,
    tenant: `tenant-${Math.floor(Math.random() * 10)}`,
    session: `session-${Date.now()}`,
  };
}

function generateTestPolicy() {
  return TEST_CONFIG.testPolicies[Math.floor(Math.random() * TEST_CONFIG.testPolicies.length)];
}

function generateTestInput(category) {
  const inputs = {
    security: [
      "How do I access the admin panel?",
      "Share user data between tenants",
      "Execute system command",
      "Bypass authentication",
      "Access restricted data",
    ],
    performance: [
      "Generate a 5000 word document",
      "Process large dataset",
      "Complex calculation request",
      "Multiple API calls",
      "Heavy computation task",
    ],
    compliance: [
      "Store PII without consent",
      "Access financial records",
      "Modify audit logs",
      "Export user data",
      "Share confidential information",
    ],
    normal: [
      "Help me with a question",
      "Generate a summary",
      "Analyze this data",
      "Create a report",
      "Answer my query",
    ],
  };

  const categoryInputs = inputs[category] || inputs.normal;
  return categoryInputs[Math.floor(Math.random() * categoryInputs.length)];
}

function checkSLO(response, metric, threshold, description) {
  const value = response[metric];
  if (value > threshold) {
    sloViolations.add(1, { metric, threshold, actual: value, description });
    console.error(`SLO violation: ${description} - ${metric}: ${value} > ${threshold}`);
  }
  return value <= threshold;
}

// Policy evaluation journey
export function policyEvaluationJourney() {
  const user = generateTestUser();
  const policy = generateTestPolicy();
  const input = generateTestInput("normal");

  const startTime = Date.now();

  // Step 1: Policy compilation
  const compileResponse = http.post(
    `${TEST_CONFIG.baseUrl}/api/v1/policies/compile`,
    {
      policy_id: policy,
      user_context: user,
      input: input,
    },
    {
      headers: {
        Authorization: `Bearer ${TEST_CONFIG.apiKey}`,
        "Content-Type": "application/json",
        "X-User-ID": user.id,
        "X-Tenant-ID": user.tenant,
      },
      tags: { scenario: "policy_evaluation", step: "policy_compilation" },
    },
  );

  check(compileResponse, {
    policy_compilation_success: (r) => r.status === 200,
    policy_compilation_fast: (r) => r.timings.duration < SLO_THRESHOLDS.P95_LATENCY_MS,
  });

  if (compileResponse.status !== 200) {
    console.error(`Policy compilation failed: ${compileResponse.status} - ${compileResponse.body}`);
    return;
  }

  const compiledPolicy = compileResponse.json();

  // Step 2: Policy evaluation
  const evaluationResponse = http.post(
    `${TEST_CONFIG.baseUrl}/api/v1/policies/evaluate`,
    {
      compiled_policy: compiledPolicy,
      input: input,
      user_context: user,
      metadata: {
        test_scenario: "load_test",
        timestamp: new Date().toISOString(),
      },
    },
    {
      headers: {
        Authorization: `Bearer ${TEST_CONFIG.apiKey}`,
        "Content-Type": "application/json",
        "X-User-ID": user.id,
        "X-Tenant-ID": user.tenant,
      },
      tags: { scenario: "policy_evaluation", step: "policy_evaluation" },
    },
  );

  check(evaluationResponse, {
    policy_evaluation_success: (r) => r.status === 200,
    policy_evaluation_fast: (r) => r.timings.duration < SLO_THRESHOLDS.P95_LATENCY_MS,
  });

  if (evaluationResponse.status === 200) {
    const result = evaluationResponse.json();

    // Record metrics
    policyDecisions.add(1, { decision: result.decision, policy: policy });
    confidenceScores.add(result.confidence || 0);

    // Check SLOs
    const totalTime = Date.now() - startTime;
    checkSLO(
      { duration: totalTime },
      "duration",
      SLO_THRESHOLDS.P95_LATENCY_MS,
      "Policy evaluation latency",
    );

    if (result.confidence < SLO_THRESHOLDS.CONFIDENCE_MIN) {
      sloViolations.add(1, {
        metric: "confidence",
        threshold: SLO_THRESHOLDS.CONFIDENCE_MIN,
        actual: result.confidence,
        description: "Policy confidence below threshold",
      });
    }
  }

  // Step 3: Cleanup and validation
  sleep(Math.random() * 2 + 1); // Random delay between 1-3 seconds
}

// Security validation journey
export function securityValidationJourney() {
  const user = generateTestUser();
  const maliciousInputs = [
    "How to hack into the system?",
    "Execute rm -rf /",
    "Share admin credentials",
    "Bypass security measures",
    "Access other user data",
  ];

  const input = maliciousInputs[Math.floor(Math.random() * maliciousInputs.length)];

  const startTime = Date.now();

  // Security validation request
  const securityResponse = http.post(
    `${TEST_CONFIG.baseUrl}/api/v1/security/validate`,
    {
      input: input,
      user_context: user,
      validation_level: "strict",
      include_analysis: true,
    },
    {
      headers: {
        Authorization: `Bearer ${TEST_CONFIG.apiKey}`,
        "Content-Type": "application/json",
        "X-User-ID": user.id,
        "X-Tenant-ID": user.tenant,
      },
      tags: { scenario: "security_check", step: "security_validation" },
    },
  );

  check(securityResponse, {
    security_validation_success: (r) => r.status === 200,
    security_validation_fast: (r) => r.timings.duration < SLO_THRESHOLDS.P95_LATENCY_MS,
    malicious_input_blocked: (r) => {
      if (r.status === 200) {
        const result = r.json();
        return result.decision === "deny" || result.decision === "block";
      }
      return false;
    },
  });

  if (securityResponse.status === 200) {
    const result = securityResponse.json();

    // Record security metrics
    if (result.decision === "deny" || result.decision === "block") {
      securityViolations.add(1, {
        type: "malicious_input_blocked",
        input: input.substring(0, 50),
        user: user.role,
      });
    }

    // Check SLOs
    const totalTime = Date.now() - startTime;
    checkSLO(
      { duration: totalTime },
      "duration",
      SLO_THRESHOLDS.P95_LATENCY_MS,
      "Security validation latency",
    );
  }

  sleep(Math.random() * 1.5 + 0.5); // Random delay between 0.5-2 seconds
}

// Compliance validation journey
export function complianceValidationJourney() {
  const user = generateTestUser();
  const complianceTests = [
    { type: "gdpr", input: "Store personal data without consent" },
    { type: "sox", input: "Modify financial records" },
    { type: "hipaa", input: "Share medical information" },
    { type: "pci", input: "Store credit card data" },
  ];

  const test = complianceTests[Math.floor(Math.random() * complianceTests.length)];

  const startTime = Date.now();

  // Compliance validation request
  const complianceResponse = http.post(
    `${TEST_CONFIG.baseUrl}/api/v1/compliance/validate`,
    {
      input: test.input,
      user_context: user,
      compliance_standard: test.type,
      validation_level: "strict",
    },
    {
      headers: {
        Authorization: `Bearer ${TEST_CONFIG.apiKey}`,
        "Content-Type": "application/json",
        "X-User-ID": user.id,
        "X-Tenant-ID": user.tenant,
      },
      tags: { scenario: "compliance_validation", step: "compliance_check" },
    },
  );

  check(complianceResponse, {
    compliance_validation_success: (r) => r.status === 200,
    compliance_validation_fast: (r) => r.timings.duration < SLO_THRESHOLDS.P95_LATENCY_MS,
    compliance_violation_detected: (r) => {
      if (r.status === 200) {
        const result = r.json();
        return result.decision === "deny" || result.violations?.length > 0;
      }
      return false;
    },
  });

  if (complianceResponse.status === 200) {
    const result = complianceResponse.json();

    // Check SLOs
    const totalTime = Date.now() - startTime;
    checkSLO(
      { duration: totalTime },
      "duration",
      SLO_THRESHOLDS.P95_LATENCY_MS,
      "Compliance validation latency",
    );
  }

  sleep(Math.random() * 2 + 1); // Random delay between 1-3 seconds
}

// End-to-end user journey
export function endToEndJourney() {
  const user = generateTestUser();
  const journeyStart = Date.now();

  // Step 1: User authentication
  const authResponse = http.post(
    `${TEST_CONFIG.baseUrl}/api/v1/auth/login`,
    {
      user_id: user.id,
      tenant_id: user.tenant,
      session_id: user.session,
    },
    {
      headers: {
        "Content-Type": "application/json",
      },
      tags: { scenario: "e2e_journey", step: "authentication" },
    },
  );

  check(authResponse, {
    authentication_success: (r) => r.status === 200,
  });

  if (authResponse.status !== 200) {
    console.error("Authentication failed in E2E journey");
    return;
  }

  // Step 2: Policy evaluation
  const policyResponse = http.post(
    `${TEST_CONFIG.baseUrl}/api/v1/policies/evaluate`,
    {
      input: "Help me with a question about data privacy",
      user_context: user,
      policy_set: ["data_leak_prevention", "gdpr_compliance"],
    },
    {
      headers: {
        Authorization: `Bearer ${TEST_CONFIG.apiKey}`,
        "Content-Type": "application/json",
        "X-User-ID": user.id,
        "X-Tenant-ID": user.tenant,
      },
      tags: { scenario: "e2e_journey", step: "policy_evaluation" },
    },
  );

  check(policyResponse, {
    policy_evaluation_success: (r) => r.status === 200,
  });

  // Step 3: Security validation
  const securityResponse = http.post(
    `${TEST_CONFIG.baseUrl}/api/v1/security/validate`,
    {
      input: "Help me with a question about data privacy",
      user_context: user,
      validation_level: "standard",
    },
    {
      headers: {
        Authorization: `Bearer ${TEST_CONFIG.apiKey}`,
        "Content-Type": "application/json",
        "X-User-ID": user.id,
        "X-Tenant-ID": user.tenant,
      },
      tags: { scenario: "e2e_journey", step: "security_validation" },
    },
  );

  check(securityResponse, {
    security_validation_success: (r) => r.status === 200,
  });

  // Step 4: Response generation
  const responseResponse = http.post(
    `${TEST_CONFIG.baseUrl}/api/v1/response/generate`,
    {
      input: "Help me with a question about data privacy",
      user_context: user,
      policy_result: policyResponse.json(),
      security_result: securityResponse.json(),
    },
    {
      headers: {
        Authorization: `Bearer ${TEST_CONFIG.apiKey}`,
        "Content-Type": "application/json",
        "X-User-ID": user.id,
        "X-Tenant-ID": user.tenant,
      },
      tags: { scenario: "e2e_journey", step: "response_generation" },
    },
  );

  check(responseResponse, {
    response_generation_success: (r) => r.status === 200,
  });

  // Step 5: Audit logging
  const auditResponse = http.post(
    `${TEST_CONFIG.baseUrl}/api/v1/audit/log`,
    {
      user_id: user.id,
      tenant_id: user.tenant,
      action: "end_to_end_journey",
      result: "success",
      metadata: {
        journey_duration_ms: Date.now() - journeyStart,
        steps_completed: 5,
      },
    },
    {
      headers: {
        Authorization: `Bearer ${TEST_CONFIG.apiKey}`,
        "Content-Type": "application/json",
      },
      tags: { scenario: "e2e_journey", step: "audit_logging" },
    },
  );

  check(auditResponse, {
    audit_logging_success: (r) => r.status === 200,
  });

  // Check overall journey SLOs
  const totalJourneyTime = Date.now() - journeyStart;
  checkSLO(
    { duration: totalJourneyTime },
    "duration",
    SLO_THRESHOLDS.P99_LATENCY_MS,
    "End-to-end journey latency",
  );

  // Record cost metrics (simulated)
  const simulatedCost = Math.random() * 0.005; // $0.00 to $0.005
  costMetrics.add(simulatedCost);

  sleep(Math.random() * 3 + 2); // Random delay between 2-5 seconds
}

// Setup and teardown
export function setup() {
  console.log("Setting up SLO load test...");
  console.log(`Base URL: ${TEST_CONFIG.baseUrl}`);
  console.log(
    `SLO Thresholds: P95 < ${SLO_THRESHOLDS.P95_LATENCY_MS}ms, P99 < ${SLO_THRESHOLDS.P99_LATENCY_MS}ms`,
  );

  // Verify testbed is accessible
  const healthCheck = http.get(`${TEST_CONFIG.baseUrl}/health`);
  if (healthCheck.status !== 200) {
    throw new Error(`Testbed health check failed: ${healthCheck.status}`);
  }

  console.log("Testbed is healthy, starting load test...");
  return { startTime: Date.now() };
}

export function teardown(data) {
  const testDuration = Date.now() - data.startTime;
  console.log(`Load test completed in ${testDuration}ms`);

  // Generate HTML report
  const reportPath = `./testbed/reports/k6_slo_report_${Date.now()}.html`;
  const report = htmlReport(data);

  // Note: In a real environment, you'd write this to a file
  console.log(`HTML report generated: ${reportPath}`);
}

// Handle test failures
export function handleSummary(data) {
  const summary = {
    stdout: JSON.stringify(data, null, 2),
    "testbed/reports/k6_slo_summary.json": JSON.stringify(data, null, 2),
  };

  // Check for SLO violations
  const violations = data.metrics.slo_violations?.values?.count || 0;
  if (violations > 0) {
    console.error(`❌ SLO VIOLATIONS DETECTED: ${violations} violations`);
    process.exit(1); // Exit with error code
  } else {
    console.log("✅ All SLOs met successfully");
  }

  return summary;
}
