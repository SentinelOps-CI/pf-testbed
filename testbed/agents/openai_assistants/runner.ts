import { BaseAgentRunner } from "../../../runtime/gateway/src/base-runner";
import { Plan, ToolCall, ToolResult, AgentConfig } from "../../contracts/types";

/**
 * OpenAI Assistants Agent Runner
 * Implements the AgentRunner interface for OpenAI's Assistant API
 */
export class OpenAIAssistantsRunner extends BaseAgentRunner {
  private openai: any;
  private assistantId?: string;
  private threadId?: string;

  constructor() {
    super("openai-assistants", "1.0.0", [
      "slack",
      "email",
      "calendar",
      "notion",
      "stripe",
      "github",
      "search",
      "fetch",
    ]);
  }

  /**
   * Configure the OpenAI client
   */
  async configure(config: AgentConfig): Promise<void> {
    await super.configure(config);

    // Initialize OpenAI client
    if (typeof window === "undefined") {
      // Node.js environment
      const { OpenAI } = await import("openai");
      this.openai = new OpenAI({
        apiKey: config.api_key,
        timeout: config.timeout,
        maxRetries: config.max_retries,
      });
    } else {
      throw new Error("OpenAI Assistants runner requires Node.js environment");
    }
  }

  /**
   * Create a plan using OpenAI Assistant
   */
  async plan(json: any): Promise<Plan> {
    try {
      // Create or get assistant
      if (!this.assistantId) {
        this.assistantId = await this.createOrGetAssistant();
      }

      // Create thread if needed
      if (!this.threadId) {
        this.threadId = await this.createThread();
      }

      // Send message to assistant
      const message = await this.openai.beta.threads.messages.create(this.threadId, {
        role: "user",
        content: JSON.stringify(json),
      });

      // Run the assistant
      const run = await this.openai.beta.threads.runs.create(this.threadId, {
        assistant_id: this.assistantId,
      });

      // Wait for completion
      const completedRun = await this.waitForRunCompletion(this.threadId, run.id);

      // Get the response
      const messages = await this.openai.beta.threads.messages.list(this.threadId);
      const lastMessage = messages.data[0];

      // Parse the response into a plan
      const plan = this.parseResponseToPlan(lastMessage.content[0], json);

      return plan;
    } catch (error) {
      throw new Error(
        `Failed to create plan: ${error instanceof Error ? error.message : "Unknown error"}`,
      );
    }
  }

  /**
   * Execute a tool call
   */
  async executeTool(call: ToolCall): Promise<ToolResult> {
    try {
      // Validate capability
      this.validateCapability(call.capability, this.capabilities);

      // Execute tool based on type
      let result: any;
      let success = true;
      let error: string | undefined;

      switch (call.tool) {
        case "slack":
          result = await this.executeSlackTool(call.parameters);
          break;
        case "email":
          result = await this.executeEmailTool(call.parameters);
          break;
        case "calendar":
          result = await this.executeCalendarTool(call.parameters);
          break;
        case "notion":
          result = await this.executeNotionTool(call.parameters);
          break;
        case "stripe":
          result = await this.executeStripeTool(call.parameters);
          break;
        case "github":
          result = await this.executeGitHubTool(call.parameters);
          break;
        case "search":
          result = await this.executeSearchTool(call.parameters);
          break;
        case "fetch":
          result = await this.executeFetchTool(call.parameters);
          break;
        default:
          throw new Error(`Unsupported tool: ${call.tool}`);
      }

      return {
        id: call.id,
        success,
        result,
        error,
        capability_consumed: call.capability,
        trace: {
          id: this.generateId(),
          tool_call_id: call.id,
          inputs: call.parameters,
          outputs: result,
          metadata: {
            tool: call.tool,
            tenant: call.tenant,
            timestamp: call.timestamp,
          },
          replayable: true,
        },
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      return {
        id: call.id,
        success: false,
        result: undefined,
        error: error instanceof Error ? error.message : "Unknown error",
        capability_consumed: call.capability,
        trace: {
          id: this.generateId(),
          tool_call_id: call.id,
          inputs: call.parameters,
          outputs: undefined,
          metadata: {
            tool: call.tool,
            tenant: call.tenant,
            timestamp: call.timestamp,
            error: error instanceof Error ? error.message : "Unknown error",
          },
          replayable: false,
        },
        timestamp: new Date().toISOString(),
      };
    }
  }

  /**
   * Create or get an OpenAI Assistant
   */
  private async createOrGetAssistant(): Promise<string> {
    try {
      // Check if we already have an assistant
      const assistants = await this.openai.beta.assistants.list();
      const existingAssistant = assistants.data.find((a) => a.name === "PF Testbed Assistant");

      if (existingAssistant) {
        return existingAssistant.id;
      }

      // Create new assistant
      const assistant = await this.openai.beta.assistants.create({
        name: "PF Testbed Assistant",
        instructions: `You are a Provability Fabric testbed assistant. 
        Create detailed plans for various business journeys including:
        - support_triage
        - expense_approval
        - sales_outreach
        - hr_onboarding
        - dev_triage
        
        Always include proper capabilities for tool calls and validate inputs.`,
        model: this.config?.model || "gpt-4",
        tools: [
          {
            type: "function",
            function: { name: "slack", description: "Send Slack messages" },
          },
          {
            type: "function",
            function: { name: "email", description: "Send emails" },
          },
          {
            type: "function",
            function: {
              name: "calendar",
              description: "Manage calendar events",
            },
          },
          {
            type: "function",
            function: { name: "notion", description: "Manage Notion pages" },
          },
          {
            type: "function",
            function: { name: "stripe", description: "Process payments" },
          },
          {
            type: "function",
            function: {
              name: "github",
              description: "Manage GitHub repositories",
            },
          },
          {
            type: "function",
            function: { name: "search", description: "Search the web" },
          },
          {
            type: "function",
            function: { name: "fetch", description: "Fetch data from APIs" },
          },
        ],
      });

      return assistant.id;
    } catch (error) {
      throw new Error(
        `Failed to create/get assistant: ${error instanceof Error ? error.message : "Unknown error"}`,
      );
    }
  }

  /**
   * Create a new thread
   */
  private async createThread(): Promise<string> {
    try {
      const thread = await this.openai.beta.threads.create();
      return thread.id;
    } catch (error) {
      throw new Error(
        `Failed to create thread: ${error instanceof Error ? error.message : "Unknown error"}`,
      );
    }
  }

  /**
   * Wait for a run to complete
   */
  private async waitForRunCompletion(threadId: string, runId: string): Promise<any> {
    let run;
    let attempts = 0;
    const maxAttempts = 60; // 5 minutes with 5-second intervals

    while (attempts < maxAttempts) {
      run = await this.openai.beta.threads.runs.retrieve(threadId, runId);

      if (run.status === "completed") {
        return run;
      } else if (run.status === "failed" || run.status === "cancelled") {
        throw new Error(`Run failed with status: ${run.status}`);
      }

      // Wait 5 seconds before checking again
      await new Promise((resolve) => setTimeout(resolve, 5000));
      attempts++;
    }

    throw new Error("Run timed out");
  }

  /**
   * Parse OpenAI response into a plan
   */
  private parseResponseToPlan(content: any, originalJson: any): Plan {
    try {
      // Extract text content
      const text = content.type === "text" ? content.text.value : "";

      // Try to parse as JSON first
      let planData: any;
      try {
        planData = JSON.parse(text);
      } catch {
        // If not JSON, try to extract plan information from text
        planData = this.extractPlanFromText(text, originalJson);
      }

      // Ensure required fields
      if (!planData.id) planData.id = this.generateId();
      if (!planData.timestamp) planData.timestamp = new Date().toISOString();
      if (!planData.expiresAt)
        planData.expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

      return planData as Plan;
    } catch (error) {
      // Fallback to basic plan structure
      return {
        id: this.generateId(),
        tenant: originalJson.tenant || "acme",
        journey: originalJson.journey || "support_triage",
        steps: [],
        metadata: {
          version: "1.0.0",
          agent: this.name,
          model: this.config?.model || "gpt-4",
          confidence: 0.5,
          risk_level: "medium",
          tags: [],
          context: originalJson,
        },
        timestamp: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
      };
    }
  }

  /**
   * Extract plan information from text response
   */
  private extractPlanFromText(text: string, originalJson: any): any {
    // This is a simplified parser - in production, use more sophisticated NLP
    const lines = text.split("\n");
    const steps: any[] = [];

    for (const line of lines) {
      if (line.includes("tool:") || line.includes("action:")) {
        const toolMatch = line.match(/tool:\s*(\w+)/i);
        const actionMatch = line.match(/action:\s*(\w+)/i);

        if (toolMatch || actionMatch) {
          const tool = toolMatch ? toolMatch[1] : actionMatch![1];
          steps.push({
            id: this.generateId(),
            type: "tool_call",
            tool,
            capability: "read", // Default capability
            status: "pending",
            timestamp: new Date().toISOString(),
          });
        }
      }
    }

    return {
      id: this.generateId(),
      tenant: originalJson.tenant || "acme",
      journey: originalJson.journey || "support_triage",
      steps,
      metadata: {
        version: "1.0.0",
        agent: this.name,
        model: this.config?.model || "gpt-4",
        confidence: 0.5,
        risk_level: "medium",
        tags: [],
        context: originalJson,
      },
      timestamp: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
    };
  }

  // Tool execution methods (implemented as stubs for now)
  private async executeSlackTool(params: any): Promise<any> {
    // Implement Slack tool execution
    return { message: "Slack message sent", params };
  }

  private async executeEmailTool(params: any): Promise<any> {
    // Implement email tool execution
    return { message: "Email sent", params };
  }

  private async executeCalendarTool(params: any): Promise<any> {
    // Implement calendar tool execution
    return { event: "Calendar event created", params };
  }

  private async executeNotionTool(params: any): Promise<any> {
    // Implement Notion tool execution
    return { page: "Notion page updated", params };
  }

  private async executeStripeTool(params: any): Promise<any> {
    // Implement Stripe tool execution
    return { payment: "Payment processed", params };
  }

  private async executeGitHubTool(params: any): Promise<any> {
    // Implement GitHub tool execution
    return { repo: "GitHub action completed", params };
  }

  private async executeSearchTool(params: any): Promise<any> {
    // Implement search tool execution
    return { results: "Search completed", params };
  }

  private async executeFetchTool(params: any): Promise<any> {
    // Implement fetch tool execution
    return { data: "Data fetched", params };
  }
}
