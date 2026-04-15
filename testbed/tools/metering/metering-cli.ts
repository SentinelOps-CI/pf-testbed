#!/usr/bin/env ts-node

import { Command } from "commander";
import { MeteringService, StripeConfig } from "../../runtime/gateway/src/metering";
import * as fs from "fs";
import * as path from "path";

const program = new Command();

// Default Stripe configuration (test mode)
const defaultStripeConfig: StripeConfig = {
  secret_key: process.env.STRIPE_SECRET_KEY || "sk_test_...",
  webhook_secret: process.env.STRIPE_WEBHOOK_SECRET || "whsec_...",
  price_ids: {
    basic: "price_basic_test",
    professional: "price_professional_test",
    enterprise: "price_enterprise_test",
  },
  enabled: process.env.STRIPE_ENABLED === "true",
};

// Initialize metering service
const meteringService = new MeteringService(defaultStripeConfig);

program
  .name("pf-metering")
  .description("Provability Fabric Testbed Metering & Billing CLI")
  .version("1.0.0");

// Generate invoice command
program
  .command("generate-invoice")
  .description("Generate invoice for a tenant and period")
  .argument("<tenant-id>", "Tenant ID")
  .argument("<period>", "Billing period (YYYY-MM format)")
  .option("-o, --output <file>", "Output file for invoice JSON")
  .option("--stripe", "Enable Stripe integration")
  .action(async (tenantId: string, period: string, options: any) => {
    try {
      console.log(`📊 Generating invoice for tenant ${tenantId} for period ${period}...`);

      const invoice = await meteringService.generateInvoice(tenantId, period);

      if (options.output) {
        const outputPath = path.resolve(options.output);
        fs.writeFileSync(outputPath, JSON.stringify(invoice, null, 2));
        console.log(`✅ Invoice saved to: ${outputPath}`);
      } else {
        console.log("\n📄 INVOICE DETAILS:");
        console.log(`  Invoice ID: ${invoice.invoice_id}`);
        console.log(`  Tenant: ${invoice.tenant_id}`);
        console.log(`  Period: ${invoice.period_start} to ${invoice.period_end}`);
        console.log(`  Status: ${invoice.status}`);
        console.log(`  Due Date: ${invoice.due_date}`);
        console.log(`  Total Cost: $${invoice.cost_breakdown.total_cost.toFixed(2)}`);

        if (invoice.stripe_invoice_id) {
          console.log(`  Stripe Invoice: ${invoice.stripe_invoice_id}`);
        }

        console.log("\n💰 COST BREAKDOWN:");
        console.log(`  Base Cost: $${invoice.cost_breakdown.base_cost.toFixed(2)}`);
        console.log(`  CPU Cost: $${invoice.cost_breakdown.cpu_cost.toFixed(4)}`);
        console.log(`  Network Cost: $${invoice.cost_breakdown.network_cost.toFixed(4)}`);
        console.log(`  API Cost: $${invoice.cost_breakdown.api_cost.toFixed(4)}`);
        console.log(`  Tool Cost: $${invoice.cost_breakdown.tool_cost.toFixed(4)}`);
        console.log(`  Data Cost: $${invoice.cost_breakdown.data_cost.toFixed(4)}`);
        console.log(`  Egress Cost: $${invoice.cost_breakdown.egress_cost.toFixed(4)}`);
        console.log(`  Policy Cost: $${invoice.cost_breakdown.policy_cost.toFixed(4)}`);
        console.log(`  Violation Cost: $${invoice.cost_breakdown.violation_cost.toFixed(4)}`);
        console.log(`  Risk Adjustment: $${invoice.cost_breakdown.risk_adjustment.toFixed(4)}`);

        console.log(`\n📊 USAGE SUMMARY:`);
        console.log(`  Total Sessions: ${invoice.usage_metrics.length}`);
        if (invoice.usage_metrics.length > 0) {
          const totalCpu = invoice.usage_metrics.reduce((sum, m) => sum + m.cpu_ms, 0);
          const totalNetwork = invoice.usage_metrics.reduce((sum, m) => sum + m.network_bytes, 0);
          const totalApiCalls = invoice.usage_metrics.reduce((sum, m) => sum + m.api_calls, 0);
          const totalToolExecutions = invoice.usage_metrics.reduce(
            (sum, m) => sum + m.tool_executions,
            0,
          );
          const totalDataRetrievals = invoice.usage_metrics.reduce(
            (sum, m) => sum + m.data_retrievals,
            0,
          );
          const totalViolations = invoice.usage_metrics.reduce((sum, m) => sum + m.violations, 0);

          console.log(`  Total CPU: ${(totalCpu / 1000).toFixed(2)}s`);
          console.log(`  Total Network: ${(totalNetwork / (1024 * 1024)).toFixed(2)} MB`);
          console.log(`  Total API Calls: ${totalApiCalls}`);
          console.log(`  Total Tool Executions: ${totalToolExecutions}`);
          console.log(`  Total Data Retrievals: ${totalDataRetrievals}`);
          console.log(`  Total Violations: ${totalViolations}`);
        }
      }
    } catch (error) {
      console.error("❌ Error generating invoice:", error);
      process.exit(1);
    }
  });

// View usage metrics command
program
  .command("usage")
  .description("View usage metrics for a tenant and period")
  .argument("<tenant-id>", "Tenant ID")
  .argument("<period>", "Billing period (YYYY-MM format)")
  .option("-f, --format <format>", "Output format (table, json, csv)", "table")
  .option("-o, --output <file>", "Output file")
  .action((tenantId: string, period: string, options: any) => {
    try {
      console.log(`📊 Usage metrics for tenant ${tenantId} for period ${period}...`);

      const metrics = meteringService.getUsageMetrics(tenantId, period);

      if (metrics.length === 0) {
        console.log("No usage metrics found for the specified period.");
        return;
      }

      if (options.format === "json") {
        const output = JSON.stringify(metrics, null, 2);
        if (options.output) {
          fs.writeFileSync(options.output, output);
          console.log(`✅ Metrics saved to: ${options.output}`);
        } else {
          console.log(output);
        }
      } else if (options.format === "csv") {
        const csv = generateCSV(metrics);
        if (options.output) {
          fs.writeFileSync(options.output, csv);
          console.log(`✅ Metrics saved to: ${options.output}`);
        } else {
          console.log(csv);
        }
      } else {
        // Table format
        displayUsageTable(metrics);
      }
    } catch (error) {
      console.error("❌ Error viewing usage metrics:", error);
      process.exit(1);
    }
  });

// List invoices command
program
  .command("invoices")
  .description("List invoices for a tenant")
  .argument("<tenant-id>", "Tenant ID")
  .option("-o, --output <file>", "Output file for invoices JSON")
  .action((tenantId: string, options: any) => {
    try {
      console.log(`📄 Invoices for tenant ${tenantId}...`);

      const invoices = meteringService.getInvoices(tenantId);

      if (invoices.length === 0) {
        console.log("No invoices found for this tenant.");
        return;
      }

      if (options.output) {
        const outputPath = path.resolve(options.output);
        fs.writeFileSync(outputPath, JSON.stringify(invoices, null, 2));
        console.log(`✅ Invoices saved to: ${outputPath}`);
      } else {
        console.log("\n📄 INVOICES:");
        invoices.forEach((invoice, index) => {
          console.log(`\n  ${index + 1}. Invoice ${invoice.invoice_id}`);
          console.log(`     Period: ${invoice.period_start} to ${invoice.period_end}`);
          console.log(`     Status: ${invoice.status}`);
          console.log(`     Total Cost: $${invoice.cost_breakdown.total_cost.toFixed(2)}`);
          console.log(`     Created: ${invoice.created_at}`);
          console.log(`     Due Date: ${invoice.due_date}`);
        });
      }
    } catch (error) {
      console.error("❌ Error listing invoices:", error);
      process.exit(1);
    }
  });

// Export Prometheus metrics command
program
  .command("export-metrics")
  .description("Export usage metrics in Prometheus format")
  .option("-o, --output <file>", "Output file for metrics")
  .action((options: any) => {
    try {
      console.log("📊 Exporting Prometheus metrics...");

      const metrics = meteringService.exportPrometheusMetrics();

      if (options.output) {
        const outputPath = path.resolve(options.output);
        fs.writeFileSync(outputPath, metrics);
        console.log(`✅ Metrics exported to: ${outputPath}`);
      } else {
        console.log(metrics);
      }
    } catch (error) {
      console.error("❌ Error exporting metrics:", error);
      process.exit(1);
    }
  });

// List billing tiers command
program
  .command("tiers")
  .description("List available billing tiers")
  .option("-o, --output <file>", "Output file for tiers JSON")
  .action((options: any) => {
    try {
      console.log("💰 Available Billing Tiers:");

      const tiers = meteringService.listBillingTiers();

      if (options.output) {
        const outputPath = path.resolve(options.output);
        fs.writeFileSync(outputPath, JSON.stringify(tiers, null, 2));
        console.log(`✅ Tiers saved to: ${outputPath}`);
      } else {
        tiers.forEach((tier, index) => {
          console.log(`\n  ${index + 1}. ${tier.name} Tier`);
          console.log(`     Base Price: $${tier.base_price_usd}/month`);
          console.log(`     CPU: $${(tier.cpu_price_per_ms * 3600000).toFixed(2)}/hour`);
          console.log(`     Network: $${tier.network_price_per_mb}/MB`);
          console.log(`     API Calls: $${tier.api_call_price}/call`);
          console.log(`     Tool Executions: $${tier.tool_execution_price}/execution`);
          console.log(`     Data Retrievals: $${tier.data_retrieval_price}/retrieval`);
          console.log(`     Risk Multiplier: ${tier.risk_multiplier}x`);

          console.log(`     Monthly Quotas:`);
          console.log(`       CPU: ${(tier.monthly_quota.cpu_ms / 3600000).toFixed(1)} hours`);
          console.log(`       Network: ${tier.monthly_quota.network_mb} MB`);
          console.log(`       API Calls: ${tier.monthly_quota.api_calls.toLocaleString()}`);
          console.log(
            `       Tool Executions: ${tier.monthly_quota.tool_executions.toLocaleString()}`,
          );
          console.log(
            `       Data Retrievals: ${tier.monthly_quota.data_retrievals.toLocaleString()}`,
          );
        });
      }
    } catch (error) {
      console.error("❌ Error listing billing tiers:", error);
      process.exit(1);
    }
  });

// Simulate usage command (for testing)
program
  .command("simulate-usage")
  .description("Simulate usage metrics for testing")
  .argument("<tenant-id>", "Tenant ID")
  .argument("<sessions>", "Number of sessions to simulate")
  .option("--period <period>", "Billing period (YYYY-MM format)", "2025-01")
  .action((tenantId: string, sessions: string, options: any) => {
    try {
      const sessionCount = parseInt(sessions);
      console.log(`🎭 Simulating ${sessionCount} sessions for tenant ${tenantId}...`);

      for (let i = 0; i < sessionCount; i++) {
        const metrics = {
          tenant_id: tenantId,
          session_id: `session_${Date.now()}_${i}`,
          timestamp: new Date().toISOString(),
          cpu_ms: Math.floor(Math.random() * 10000) + 100, // 100ms to 10s
          network_bytes: Math.floor(Math.random() * 1024 * 1024) + 1024, // 1KB to 1MB
          api_calls: Math.floor(Math.random() * 50) + 1,
          tool_executions: Math.floor(Math.random() * 20) + 1,
          data_retrievals: Math.floor(Math.random() * 10) + 1,
          egress_scans: Math.floor(Math.random() * 5) + 1,
          policy_checks: Math.floor(Math.random() * 100) + 10,
          violations: Math.floor(Math.random() * 3),
          risk_score: Math.random() * 0.3 + 0.1, // 0.1 to 0.4
        };

        meteringService.recordUsage(metrics);
      }

      console.log(`✅ Simulated ${sessionCount} usage sessions`);
    } catch (error) {
      console.error("❌ Error simulating usage:", error);
      process.exit(1);
    }
  });

// Helper functions
function generateCSV(metrics: any[]): string {
  if (metrics.length === 0) return "";

  const headers = Object.keys(metrics[0]);
  const csv = [headers.join(",")];

  for (const metric of metrics) {
    const row = headers.map((header) => {
      const value = metric[header];
      if (typeof value === "string" && value.includes(",")) {
        return `"${value}"`;
      }
      return value;
    });
    csv.push(row.join(","));
  }

  return csv.join("\n");
}

function displayUsageTable(metrics: any[]): void {
  if (metrics.length === 0) return;

  console.log("\n📊 USAGE METRICS TABLE:");
  console.log("─".repeat(120));

  // Display first few metrics in table format
  const displayCount = Math.min(metrics.length, 10);
  const headers = [
    "Session",
    "CPU (ms)",
    "Network (MB)",
    "API Calls",
    "Tools",
    "Data",
    "Violations",
    "Risk",
  ];

  console.log(headers.map((h) => h.padEnd(12)).join(" | "));
  console.log("─".repeat(120));

  for (let i = 0; i < displayCount; i++) {
    const m = metrics[i];
    const row = [
      m.session_id.slice(-8),
      m.cpu_ms.toString(),
      (m.network_bytes / (1024 * 1024)).toFixed(2),
      m.api_calls.toString(),
      m.tool_executions.toString(),
      m.data_retrievals.toString(),
      m.violations.toString(),
      m.risk_score.toFixed(2),
    ];

    console.log(row.map((cell) => cell.padEnd(12)).join(" | "));
  }

  if (metrics.length > displayCount) {
    console.log(`... and ${metrics.length - displayCount} more sessions`);
  }

  // Summary statistics
  const totalCpu = metrics.reduce((sum, m) => sum + m.cpu_ms, 0);
  const totalNetwork = metrics.reduce((sum, m) => sum + m.network_bytes, 0);
  const totalApiCalls = metrics.reduce((sum, m) => sum + m.api_calls, 0);
  const totalToolExecutions = metrics.reduce((sum, m) => sum + m.tool_executions, 0);
  const totalDataRetrievals = metrics.reduce((sum, m) => sum + m.data_retrievals, 0);
  const totalViolations = metrics.reduce((sum, m) => sum + m.violations, 0);
  const avgRiskScore = metrics.reduce((sum, m) => sum + m.risk_score, 0) / metrics.length;

  console.log("\n📈 SUMMARY STATISTICS:");
  console.log(`  Total Sessions: ${metrics.length}`);
  console.log(`  Total CPU: ${(totalCpu / 1000).toFixed(2)}s`);
  console.log(`  Total Network: ${(totalNetwork / (1024 * 1024)).toFixed(2)} MB`);
  console.log(`  Total API Calls: ${totalApiCalls}`);
  console.log(`  Total Tool Executions: ${totalToolExecutions}`);
  console.log(`  Total Data Retrievals: ${totalDataRetrievals}`);
  console.log(`  Total Violations: ${totalViolations}`);
  console.log(`  Average Risk Score: ${avgRiskScore.toFixed(3)}`);
}

// Parse command line arguments
program.parse();
