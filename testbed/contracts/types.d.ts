export interface Plan {
  id: string;
  tenant: string;
  journey: string;
  steps: PlanStep[];
  metadata: PlanMetadata;
  timestamp: string;
  expiresAt: string;
}
export interface PlanStep {
  id: string;
  type: "tool_call" | "decision" | "retrieval" | "verification";
  operation?: "read" | "write" | "delete" | "admin" | "system";
  tool?: string;
  parameters?: Record<string, any>;
  capability?: string;
  receipt?: string;
  content?: string;
  labels?: string[];
  source?: string;
  target?: string;
  scope?: string;
  compliance_requirements?: string[];
  audit_required?: boolean;
  status: "pending" | "executing" | "completed" | "failed";
  result?: any;
  error?: string;
  timestamp: string;
  duration?: number;
}
export interface PlanMetadata {
  version: string;
  agent: string;
  model: string;
  confidence: number;
  risk_level: "low" | "medium" | "high" | "critical";
  tags: string[];
  context: Record<string, any>;
}
export interface ToolCall {
  id: string;
  tool: string;
  parameters: Record<string, any>;
  capability: string;
  timestamp: string;
  tenant: string;
}
export interface ToolTrace {
  id: string;
  tool_call_id: string;
  inputs: Record<string, any>;
  outputs: Record<string, any>;
  metadata: Record<string, any>;
  replayable: boolean;
}
export interface ToolResult {
  id: string;
  success: boolean;
  result?: any;
  error?: string;
  capability_consumed: string;
  trace: ToolTrace;
  timestamp: string;
}
export interface AccessReceipt {
  id?: string;
  tenant: string;
  subject: string;
  shard: string;
  query_hash: string;
  result_hash: string;
  nonce: string;
  expires_at?: string;
  signature?: string;
  exp?: string;
  sig?: string;
}
export interface AgentConfig {
  model: string;
  provider: string;
  api_key?: string;
  endpoint?: string;
  timeout: number;
  max_retries: number;
  shadow_mode: boolean;
  enforce_policies: boolean;
}
export interface ExecutionContext {
  tenant: string;
  user_id?: string;
  session_id: string;
  request_id: string;
  timestamp: string;
  user_risk_profile?: "low" | "medium" | "high" | "critical";
  tenant_risk_policy?: "standard" | "strict" | "critical";
  user_capabilities?: string[];
  user_labels?: string[];
  metadata: Record<string, any>;
}
//# sourceMappingURL=types.d.ts.map
