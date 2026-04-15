import { Plan, AccessReceipt, ToolTrace } from "../../contracts/types";
import { LeanTheoremMapping } from "../gateway/src/observability";

// Safety case bundle components
export interface SafetyCaseBundle {
  id: string;
  session_id: string;
  tenant: string;
  journey: string;
  timestamp: string;
  expires_at: string;

  // Core components
  capability_ids: string[];
  access_receipts: AccessReceipt[];
  plan_hash: string;
  kernel_decision_log: KernelDecisionLog[];
  egress_certificate: EgressCertificate;
  attestation_quote: AttestationQuote;

  // Metadata
  metadata: SafetyCaseMetadata;
  verification_status: "pending" | "verified" | "failed";
  verification_timestamp?: string;
  verification_errors?: string[];
}

export interface KernelDecisionLog {
  id: string;
  timestamp: string;
  decision_type: "capability_check" | "policy_enforcement" | "risk_assessment" | "access_grant";
  decision: "allow" | "deny" | "escalate";
  reason: string;
  context: Record<string, any>;
  evidence: string[];
}

export interface EgressCertificate {
  id: string;
  tenant: string;
  session_id: string;
  timestamp: string;
  expires_at: string;
  permissions: string[];
  restrictions: string[];
  signature: string;
  issuer: string;
}

export interface AttestationQuote {
  id: string;
  session_id: string;
  timestamp: string;
  platform: string;
  measurements: Record<string, string>;
  signature: string;
  public_key: string;
}

export interface SafetyCaseMetadata {
  version: string;
  created_by: string;
  risk_level: "low" | "medium" | "high" | "critical";
  compliance_frameworks: string[];
  tags: string[];
  notes?: string;
}

// Safety case bundle manager
export class SafetyCaseManager {
  private bundles: Map<string, SafetyCaseBundle> = new Map();
  private retentionDays: number = 90;

  // Create a new safety case bundle for a session
  createBundle(
    session_id: string,
    tenant: string,
    journey: string,
    plan: Plan,
    receipts: AccessReceipt[],
    traces: ToolTrace[],
    _theorems: LeanTheoremMapping[],
  ): SafetyCaseBundle {
    const bundle: SafetyCaseBundle = {
      id: this.generateBundleId(),
      session_id,
      tenant,
      journey,
      timestamp: new Date().toISOString(),
      expires_at: new Date(Date.now() + this.retentionDays * 24 * 60 * 60 * 1000).toISOString(),

      capability_ids: this.extractCapabilityIds(plan, receipts),
      access_receipts: receipts,
      plan_hash: this.generatePlanHash(plan),
      kernel_decision_log: this.generateKernelDecisionLog(plan, traces),
      egress_certificate: this.generateEgressCertificate(session_id, tenant, plan),
      attestation_quote: this.generateAttestationQuote(session_id),

      metadata: {
        version: "1.0.0",
        created_by: "system",
        risk_level: plan.metadata.risk_level,
        compliance_frameworks: ["SOC2", "ISO27001", "GDPR"],
        tags: [tenant, journey, plan.metadata.agent],
        notes: `Safety case bundle for ${journey} journey in ${tenant}`,
      },

      verification_status: "pending",
    };

    this.bundles.set(bundle.id, bundle);
    return bundle;
  }

  // Get bundle by ID
  getBundle(bundle_id: string): SafetyCaseBundle | null {
    return this.bundles.get(bundle_id) || null;
  }

  // Get bundles by session
  getBundlesBySession(session_id: string): SafetyCaseBundle[] {
    return Array.from(this.bundles.values()).filter((bundle) => bundle.session_id === session_id);
  }

  // Get bundles by tenant
  getBundlesByTenant(tenant: string): SafetyCaseBundle[] {
    return Array.from(this.bundles.values()).filter((bundle) => bundle.tenant === tenant);
  }

  // Verify bundle integrity
  verifyBundle(bundle_id: string): boolean {
    const bundle = this.bundles.get(bundle_id);
    if (!bundle) return false;

    try {
      // Verify all required components exist
      const hasAllComponents =
        bundle.capability_ids.length > 0 &&
        bundle.access_receipts.length > 0 &&
        bundle.plan_hash &&
        bundle.kernel_decision_log.length > 0 &&
        bundle.egress_certificate &&
        bundle.attestation_quote;

      if (!hasAllComponents) {
        bundle.verification_status = "failed";
        bundle.verification_errors = ["Missing required components"];
        return false;
      }

      // Verify receipts are valid
      const receiptsValid = bundle.access_receipts.every((receipt) =>
        this.validateReceipt(receipt),
      );

      if (!receiptsValid) {
        bundle.verification_status = "failed";
        bundle.verification_errors = ["Invalid access receipts"];
        return false;
      }

      // Verify certificates are not expired
      const certificatesValid =
        new Date(bundle.egress_certificate.expires_at) > new Date() &&
        new Date(bundle.attestation_quote.timestamp) > new Date(Date.now() - 24 * 60 * 60 * 1000);

      if (!certificatesValid) {
        bundle.verification_status = "failed";
        bundle.verification_errors = ["Expired certificates"];
        return false;
      }

      bundle.verification_status = "verified";
      bundle.verification_timestamp = new Date().toISOString();
      bundle.verification_errors = [];

      return true;
    } catch (error) {
      bundle.verification_status = "failed";
      const message = error instanceof Error ? error.message : "Unknown error";
      bundle.verification_errors = [`Verification error: ${message}`];
      return false;
    }
  }

  // Export bundle as ZIP
  async exportBundle(bundle_id: string): Promise<Buffer> {
    const bundle = this.bundles.get(bundle_id);
    if (!bundle) {
      throw new Error(`Bundle not found: ${bundle_id}`);
    }

    // Verify bundle before export
    if (!this.verifyBundle(bundle_id)) {
      throw new Error(`Bundle verification failed: ${bundle.verification_errors?.join(", ")}`);
    }

    // In a real implementation, you would use a ZIP library like JSZip
    // For now, we'll return a JSON representation
    const bundleData = JSON.stringify(bundle, null, 2);
    return Buffer.from(bundleData, "utf-8");
  }

  // Clean up expired bundles
  cleanupExpiredBundles(): number {
    const now = new Date();
    let cleanedCount = 0;

    for (const [bundle_id, bundle] of this.bundles.entries()) {
      if (new Date(bundle.expires_at) < now) {
        this.bundles.delete(bundle_id);
        cleanedCount++;
      }
    }

    return cleanedCount;
  }

  // Get bundle statistics
  getBundleStats(): {
    total_bundles: number;
    verified_bundles: number;
    failed_bundles: number;
    pending_bundles: number;
    expired_bundles: number;
  } {
    const bundles = Array.from(this.bundles.values());
    const now = new Date();

    return {
      total_bundles: bundles.length,
      verified_bundles: bundles.filter((b) => b.verification_status === "verified").length,
      failed_bundles: bundles.filter((b) => b.verification_status === "failed").length,
      pending_bundles: bundles.filter((b) => b.verification_status === "pending").length,
      expired_bundles: bundles.filter((b) => new Date(b.expires_at) < now).length,
    };
  }

  // Private helper methods
  private generateBundleId(): string {
    return `bundle_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private extractCapabilityIds(plan: Plan, receipts: AccessReceipt[]): string[] {
    const capabilityIds = new Set<string>();

    // Extract from plan steps
    plan.steps.forEach((step) => {
      if (step.capability) {
        capabilityIds.add(step.capability);
      }
    });

    // Extract from receipts
    receipts.forEach((receipt) => {
      // Parse capability from receipt if available
      if (receipt.query_hash) {
        // In a real implementation, you would decode the query hash to extract capabilities
        capabilityIds.add(`cap_${receipt.query_hash.substring(0, 8)}`);
      }
    });

    return Array.from(capabilityIds);
  }

  private generatePlanHash(plan: Plan): string {
    // Generate a hash of the plan content
    const planContent = JSON.stringify({
      id: plan.id,
      steps: plan.steps,
      metadata: plan.metadata,
    });

    // In a real implementation, use a proper hashing algorithm
    return `hash_${Buffer.from(planContent).toString("base64").substring(0, 16)}`;
  }

  private generateKernelDecisionLog(plan: Plan, traces: ToolTrace[]): KernelDecisionLog[] {
    const decisions: KernelDecisionLog[] = [];

    // Generate decisions based on plan execution
    plan.steps.forEach((step, _index) => {
      decisions.push({
        id: `decision_${step.id}`,
        timestamp: step.timestamp,
        decision_type: "capability_check",
        decision: step.status === "completed" ? "allow" : "deny",
        reason: step.status === "completed" ? "Capability verified" : "Capability check failed",
        context: {
          step_id: step.id,
          step_type: step.type,
          tool: step.tool,
          parameters: step.parameters,
        },
        evidence: traces.filter((trace) => trace.tool_call_id === step.id).map((trace) => trace.id),
      });
    });

    return decisions;
  }

  private generateEgressCertificate(
    session_id: string,
    tenant: string,
    plan: Plan,
  ): EgressCertificate {
    return {
      id: `cert_${session_id}`,
      tenant,
      session_id,
      timestamp: new Date().toISOString(),
      expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(), // 24 hours
      permissions: plan.steps.map((step) => step.type),
      restrictions: [`tenant:${tenant}`, `session:${session_id}`],
      signature: `sig_${Math.random().toString(36).substr(2, 16)}`,
      issuer: "testbed-kernel",
    };
  }

  private generateAttestationQuote(session_id: string): AttestationQuote {
    return {
      id: `attest_${session_id}`,
      session_id,
      timestamp: new Date().toISOString(),
      platform: "testbed-runtime",
      measurements: {
        testbed_version: "1.0.0",
        session_id: session_id,
        timestamp: new Date().toISOString(),
      },
      signature: `attest_sig_${Math.random().toString(36).substr(2, 16)}`,
      public_key: `pubkey_${Math.random().toString(36).substr(2, 16)}`,
    };
  }

  private validateReceipt(receipt: AccessReceipt): boolean {
    // Basic validation - in a real implementation, verify signatures
    const signature = receipt.signature || receipt.sig;
    const expiresAt = receipt.expires_at || receipt.exp;
    return !!(
      receipt.id &&
      receipt.tenant &&
      receipt.subject &&
      signature &&
      expiresAt &&
      new Date(expiresAt) > new Date()
    );
  }
}

// Export singleton instance
export const safetyCaseManager = new SafetyCaseManager();
