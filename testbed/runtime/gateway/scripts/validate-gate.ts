#!/usr/bin/env ts-node

import { UnifiedGateway } from "../src/unified-gateway";
import { GatewayConfig } from "../src/types";
import { OpenAIAssistantsRunner } from "../../agents/openai_assistants/runner";
import { LangChainRunner } from "../../agents/langchain/runner";
import { LangGraphRunner } from "../../agents/langgraph/runner";
import { DSPyRunner } from "../../agents/dspy/runner";

/**
 * Gate Validation Script for Agent-Zoo (TB-AGENTS)
 *
 * Validates that all five journeys run on all four stacks with comparable metrics.
 * This script must pass for the gate to be considered successful.
 */

interface ValidationResult {
  success: boolean;
  message: string;
  details?: any;
  duration?: number;
}

interface JourneyResult {
  journey: string;
  stack: string;
  success: boolean;
  execution_time: number;
  steps_completed: number;
  error?: string;
}

class GateValidator {
  private gateway: UnifiedGateway;
  private config: GatewayConfig;
  private results: JourneyResult[] = [];

  constructor() {
    this.config = {
      port: 3001,
      host: "localhost",
      cors_origins: ["http://localhost:3000"],
      rate_limit: {
        window_ms: 60000,
        max_requests: 1000,
      },
      auth: {
        enabled: false,
      },
      monitoring: {
        enabled: true,
        metrics_port: 9091,
        health_check_interval: 1000,
      },
    };

    this.gateway = new UnifiedGateway(this.config);
  }

  /**
   * Initialize all agent runners
   */
  async initializeAgents(): Promise<ValidationResult> {
    const startTime = Date.now();

    try {
      console.log("🤖 Initializing agent runners...");

      // Register all agents
      const openaiRunner = new OpenAIAssistantsRunner();
      const langchainRunner = new LangChainRunner();
      const langgraphRunner = new LangGraphRunner();
      const dspyRunner = new DSPyRunner();

      this.gateway.registerAgent("openai-assistants", openaiRunner);
      this.gateway.registerAgent("langchain", langchainRunner);
      this.gateway.registerAgent("langgraph", langgraphRunner);
      this.gateway.registerAgent("dspy", dspyRunner);

      // Verify registration
      const metrics = await this.gateway.getStackMetrics();
      const registeredStacks = Object.keys(metrics);

      if (registeredStacks.length !== 4) {
        return {
          success: false,
          message: `Expected 4 agent stacks, got ${registeredStacks.length}`,
          details: { registered: registeredStacks },
        };
      }

      const expectedStacks = ["openai-assistants", "langchain", "langgraph", "dspy"];
      for (const stack of expectedStacks) {
        if (!registeredStacks.includes(stack)) {
          return {
            success: false,
            message: `Missing agent stack: ${stack}`,
            details: { registered: registeredStacks, expected: expectedStacks },
          };
        }
      }

      const duration = Date.now() - startTime;
      return {
        success: true,
        message: "All agent runners initialized successfully",
        details: { registered: registeredStacks },
        duration,
      };
    } catch (error) {
      const duration = Date.now() - startTime;
      return {
        success: false,
        message: "Failed to initialize agent runners",
        details: {
          error: error instanceof Error ? error.message : "Unknown error",
        },
        duration,
      };
    }
  }

  /**
   * Execute all journeys on all stacks
   */
  async executeAllJourneys(): Promise<ValidationResult> {
    const startTime = Date.now();

    try {
      const journeys = [
        "support_triage",
        "expense_approval",
        "sales_outreach",
        "hr_onboarding",
        "dev_triage",
      ];

      const stacks = ["openai-assistants", "langchain", "langgraph", "dspy"];

      console.log("🚀 Executing all journeys on all stacks...");

      // Execute each journey on each stack
      for (const journey of journeys) {
        for (const stack of stacks) {
          const result = await this.executeJourney(journey, stack);
          this.results.push(result);

          // Log progress
          const status = result.success ? "✅" : "❌";
          console.log(`${status} ${journey} on ${stack}: ${result.execution_time}ms`);
        }
      }

      const duration = Date.now() - startTime;
      return {
        success: true,
        message: "All journeys executed on all stacks",
        details: { total_executions: this.results.length },
        duration,
      };
    } catch (error) {
      const duration = Date.now() - startTime;
      return {
        success: false,
        message: "Failed to execute all journeys",
        details: {
          error: error instanceof Error ? error.message : "Unknown error",
        },
        duration,
      };
    }
  }

  /**
   * Execute a single journey on a single stack
   */
  private async executeJourney(journey: string, stack: string): Promise<JourneyResult> {
    const startTime = Date.now();

    try {
      const plan = {
        id: `gate-test-${journey}-${stack}`,
        tenant: "acme",
        journey,
        steps: [
          {
            id: "step-1",
            type: "tool_call",
            tool: "slack",
            parameters: {
              channel: "general",
              message: `Gate test for ${journey}`,
            },
            capability: "read",
            status: "pending",
            timestamp: new Date().toISOString(),
          },
        ],
        metadata: {
          version: "1.0.0",
          agent: stack,
          model: "gpt-4",
          confidence: 0.8,
          risk_level: "low",
          tags: ["gate-test"],
          context: { test: true },
        },
        timestamp: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
      };

      const context = {
        tenant: "acme",
        session_id: `gate-session-${Date.now()}`,
        request_id: `gate-req-${Date.now()}`,
        timestamp: new Date().toISOString(),
        metadata: { gate_test: true },
      };

      const result = await this.gateway.executePlan(stack, plan, context);
      const executionTime = Date.now() - startTime;

      return {
        journey,
        stack,
        success: result.success,
        execution_time: executionTime,
        steps_completed: result.steps_completed,
        error: result.error,
      };
    } catch (error) {
      const executionTime = Date.now() - startTime;
      return {
        journey,
        stack,
        success: false,
        execution_time: executionTime,
        steps_completed: 0,
        error: error instanceof Error ? error.message : "Unknown error",
      };
    }
  }

  /**
   * Validate execution results
   */
  validateResults(): ValidationResult {
    try {
      console.log("🔍 Validating execution results...");

      // Check total executions
      if (this.results.length !== 20) {
        // 5 journeys × 4 stacks
        return {
          success: false,
          message: `Expected 20 executions, got ${this.results.length}`,
          details: { actual: this.results.length, expected: 20 },
        };
      }

      // Check success rate
      const successful = this.results.filter((r) => r.success);
      const successRate = successful.length / this.results.length;

      if (successRate < 0.8) {
        // 80% success rate threshold
        return {
          success: false,
          message: `Success rate too low: ${(successRate * 100).toFixed(1)}%`,
          details: {
            successful: successful.length,
            total: this.results.length,
            success_rate: successRate,
          },
        };
      }

      // Check performance requirements
      const executionTimes = this.results.map((r) => r.execution_time);
      const avgTime = executionTimes.reduce((a, b) => a + b, 0) / executionTimes.length;
      const maxTime = Math.max(...executionTimes);

      if (avgTime > 10000) {
        // 10 second average threshold
        return {
          success: false,
          message: `Average execution time too high: ${avgTime.toFixed(0)}ms`,
          details: { average_time: avgTime, max_time: maxTime },
        };
      }

      if (maxTime > 30000) {
        // 30 second max threshold
        return {
          success: false,
          message: `Maximum execution time too high: ${maxTime}ms`,
          details: { average_time: avgTime, max_time: maxTime },
        };
      }

      // Check stack coverage
      const stacks = [...new Set(this.results.map((r) => r.stack))];
      if (stacks.length !== 4) {
        return {
          success: false,
          message: `Not all stacks executed: ${stacks.length}/4`,
          details: {
            stacks,
            expected: ["openai-assistants", "langchain", "langgraph", "dspy"],
          },
        };
      }

      // Check journey coverage
      const journeys = [...new Set(this.results.map((r) => r.journey))];
      if (journeys.length !== 5) {
        return {
          success: false,
          message: `Not all journeys executed: ${journeys.length}/5`,
          details: {
            journeys,
            expected: [
              "support_triage",
              "expense_approval",
              "sales_outreach",
              "hr_onboarding",
              "dev_triage",
            ],
          },
        };
      }

      // Check per-stack performance
      for (const stack of stacks) {
        const stackResults = this.results.filter((r) => r.stack === stack);
        const stackSuccessRate = stackResults.filter((r) => r.success).length / stackResults.length;

        if (stackSuccessRate < 0.75) {
          // 75% success rate per stack
          return {
            success: false,
            message: `Stack ${stack} success rate too low: ${(stackSuccessRate * 100).toFixed(1)}%`,
            details: {
              stack,
              successful: stackResults.filter((r) => r.success).length,
              total: stackResults.length,
              success_rate: stackSuccessRate,
            },
          };
        }
      }

      return {
        success: true,
        message: "All validation checks passed",
        details: {
          total_executions: this.results.length,
          success_rate: successRate,
          average_time: avgTime,
          max_time: maxTime,
          stacks_covered: stacks.length,
          journeys_covered: journeys.length,
        },
      };
    } catch (error) {
      return {
        success: false,
        message: "Validation failed with error",
        details: {
          error: error instanceof Error ? error.message : "Unknown error",
        },
      };
    }
  }

  /**
   * Generate comprehensive report
   */
  generateReport(): void {
    console.log("\n📊 GATE VALIDATION REPORT");
    console.log("========================");

    // Summary
    const total = this.results.length;
    const successful = this.results.filter((r) => r.success).length;
    const successRate = (successful / total) * 100;

    console.log(`\n🎯 EXECUTION SUMMARY`);
    console.log(`Total Executions: ${total}`);
    console.log(`Successful: ${successful}`);
    console.log(`Failed: ${total - successful}`);
    console.log(`Success Rate: ${successRate.toFixed(1)}%`);

    // Performance metrics
    const executionTimes = this.results.map((r) => r.execution_time);
    const avgTime = executionTimes.reduce((a, b) => a + b, 0) / executionTimes.length;
    const minTime = Math.min(...executionTimes);
    const maxTime = Math.max(...executionTimes);

    console.log(`\n⚡ PERFORMANCE METRICS`);
    console.log(`Average Time: ${avgTime.toFixed(0)}ms`);
    console.log(`Min Time: ${minTime}ms`);
    console.log(`Max Time: ${maxTime}ms`);

    // Per-stack breakdown
    console.log(`\n🏗️  PER-STACK BREAKDOWN`);
    const stacks = [...new Set(this.results.map((r) => r.stack))];
    for (const stack of stacks) {
      const stackResults = this.results.filter((r) => r.stack === stack);
      const stackSuccessful = stackResults.filter((r) => r.success).length;
      const stackSuccessRate = (stackSuccessful / stackResults.length) * 100;
      const stackAvgTime =
        stackResults.reduce((a, b) => a + b.execution_time, 0) / stackResults.length;

      console.log(`\n${stack}:`);
      console.log(`  Success Rate: ${stackSuccessRate.toFixed(1)}%`);
      console.log(`  Average Time: ${stackAvgTime.toFixed(0)}ms`);
      console.log(`  Executions: ${stackResults.length}`);
    }

    // Per-journey breakdown
    console.log(`\n🛤️  PER-JOURNEY BREAKDOWN`);
    const journeys = [...new Set(this.results.map((r) => r.journey))];
    for (const journey of journeys) {
      const journeyResults = this.results.filter((r) => r.journey === journey);
      const journeySuccessful = journeyResults.filter((r) => r.success).length;
      const journeySuccessRate = (journeySuccessful / journeyResults.length) * 100;
      const journeyAvgTime =
        journeyResults.reduce((a, b) => a + b.execution_time, 0) / journeyResults.length;

      console.log(`\n${journey}:`);
      console.log(`  Success Rate: ${journeySuccessRate.toFixed(1)}%`);
      console.log(`  Average Time: ${journeyAvgTime.toFixed(0)}ms`);
      console.log(`  Executions: ${journeyResults.length}`);
    }

    // Failed executions
    const failed = this.results.filter((r) => !r.success);
    if (failed.length > 0) {
      console.log(`\n❌ FAILED EXECUTIONS`);
      for (const failure of failed) {
        console.log(`  ${failure.journey} on ${failure.stack}: ${failure.error}`);
      }
    }

    console.log("\n========================");
  }

  /**
   * Run complete gate validation
   */
  async runValidation(): Promise<boolean> {
    console.log("🚀 Starting Agent-Zoo Gate Validation (TB-AGENTS)");
    console.log("==================================================");

    try {
      // Step 1: Initialize agents
      console.log("\n📋 Step 1: Initializing Agent Runners");
      const initResult = await this.initializeAgents();
      if (!initResult.success) {
        console.error(`❌ Agent initialization failed: ${initResult.message}`);
        console.error("Details:", initResult.details);
        return false;
      }
      console.log(`✅ Agent initialization completed in ${initResult.duration}ms`);

      // Step 2: Execute all journeys
      console.log("\n📋 Step 2: Executing All Journeys on All Stacks");
      const executionResult = await this.executeAllJourneys();
      if (!executionResult.success) {
        console.error(`❌ Journey execution failed: ${executionResult.message}`);
        console.error("Details:", executionResult.details);
        return false;
      }
      console.log(`✅ Journey execution completed in ${executionResult.duration}ms`);

      // Step 3: Validate results
      console.log("\n📋 Step 3: Validating Results");
      const validationResult = this.validateResults();
      if (!validationResult.success) {
        console.error(`❌ Validation failed: ${validationResult.message}`);
        console.error("Details:", validationResult.details);
        return false;
      }
      console.log("✅ Validation completed successfully");

      // Generate report
      this.generateReport();

      console.log("\n🎉 GATE VALIDATION PASSED!");
      console.log("All five journeys run on all four stacks with comparable metrics.");

      return true;
    } catch (error) {
      console.error("\n💥 Gate validation failed with unexpected error:");
      console.error(error);
      return false;
    }
  }
}

// Main execution
async function main() {
  const validator = new GateValidator();
  const success = await validator.runValidation();

  if (success) {
    process.exit(0);
  } else {
    process.exit(1);
  }
}

// Run if called directly
if (require.main === module) {
  main().catch((error) => {
    console.error("💥 Unhandled error in gate validation:", error);
    process.exit(1);
  });
}

export { GateValidator };
