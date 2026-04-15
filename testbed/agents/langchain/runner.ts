import { BaseAgentRunner } from "../../../runtime/gateway/src/base-runner";
import { Plan, ToolCall, ToolResult, AgentConfig } from "../../contracts/types";

/**
 * LangChain Agent Runner
 * Implements the AgentRunner interface for LangChain agents
 */
export class LangChainRunner extends BaseAgentRunner {
  private langchain: any;
  private agent: any;
  private tools: any[];

  constructor() {
    super("langchain", "1.0.0", [
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
   * Configure the LangChain client
   */
  async configure(config: AgentConfig): Promise<void> {
    await super.configure(config);

    // Initialize LangChain
    if (typeof window === "undefined") {
      // Node.js environment
      try {
        const { ChatOpenAI } = await import("langchain/chat_models/openai");
        const { AgentExecutor, createOpenAIFunctionsAgent } = await import("langchain/agents");
        const { PromptTemplate } = await import("langchain/prompts");
        const { DynamicStructuredTool } = await import("langchain/tools");

        this.langchain = {
          ChatOpenAI,
          AgentExecutor,
          createOpenAIFunctionsAgent,
          PromptTemplate,
          DynamicStructuredTool,
        };
      } catch (error) {
        throw new Error(
          `Failed to import LangChain: ${error instanceof Error ? error.message : "Unknown error"}`,
        );
      }
    } else {
      throw new Error("LangChain runner requires Node.js environment");
    }

    // Initialize tools
    this.tools = this.createTools();

    // Initialize agent
    await this.initializeAgent(config);
  }

  /**
   * Create a plan using LangChain
   */
  async plan(json: any): Promise<Plan> {
    try {
      if (!this.agent) {
        throw new Error("Agent not initialized");
      }

      // Create prompt for planning
      const prompt = `Create a detailed plan for the ${json.journey} journey in tenant ${json.tenant}.
      
      The plan should include:
      - Specific steps with tool calls
      - Required capabilities for each step
      - Risk assessment
      - Confidence level
      
      Input: ${JSON.stringify(json, null, 2)}
      
      Return a structured plan with clear steps.`;

      // Execute the agent
      const result = await this.agent.invoke({
        input: prompt,
      });

      // Parse the response into a plan
      const plan = this.parseResponseToPlan(result.output, json);

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
   * Initialize the LangChain agent
   */
  private async initializeAgent(config: AgentConfig): Promise<void> {
    try {
      // Create LLM
      const llm = new this.langchain.ChatOpenAI({
        openAIApiKey: config.api_key,
        modelName: config.model || "gpt-4",
        temperature: 0,
        timeout: config.timeout,
      });

      // Create prompt template
      const prompt = this.langchain.PromptTemplate.fromTemplate(`
        You are a Provability Fabric testbed agent that executes plans for various business journeys.
        
        Supported journeys:
        - support_triage
        - expense_approval
        - sales_outreach
        - hr_onboarding
        - dev_triage
        
        Your role is to:
        1. Understand the plan and break it down into executable steps
        2. Execute each step using the appropriate tools
        3. Maintain context and state throughout the execution
        4. Handle errors gracefully and provide meaningful feedback
        5. Ensure all operations comply with security and privacy requirements
        
        Always validate capabilities before using tools and maintain proper audit trails.
        
        Current input: {input}
        
        Respond with a detailed plan or execute the requested action.
      `);

      // Create agent
      this.agent = await this.langchain.createOpenAIFunctionsAgent({
        llm,
        tools: this.tools,
        prompt,
      });

      // Create executor
      this.agent = this.langchain.AgentExecutor.fromAgentAndTools({
        agent: this.agent,
        tools: this.tools,
        verbose: true,
      });
    } catch (error) {
      throw new Error(
        `Failed to initialize LangChain agent: ${error instanceof Error ? error.message : "Unknown error"}`,
      );
    }
  }

  /**
   * Create LangChain tools
   */
  private createTools(): any[] {
    const tools = [];

    // Slack tool
    tools.push(
      new this.langchain.DynamicStructuredTool({
        name: "slack",
        description: "Send Slack messages",
        schema: {
          type: "object",
          properties: {
            channel: { type: "string", description: "Slack channel" },
            message: { type: "string", description: "Message to send" },
          },
          required: ["channel", "message"],
        },
        func: async (params: any) => {
          return await this.executeSlackTool(params);
        },
      }),
    );

    // Email tool
    tools.push(
      new this.langchain.DynamicStructuredTool({
        name: "email",
        description: "Send emails",
        schema: {
          type: "object",
          properties: {
            to: { type: "string", description: "Recipient email" },
            subject: { type: "string", description: "Email subject" },
            body: { type: "string", description: "Email body" },
          },
          required: ["to", "subject", "body"],
        },
        func: async (params: any) => {
          return await this.executeEmailTool(params);
        },
      }),
    );

    // Calendar tool
    tools.push(
      new this.langchain.DynamicStructuredTool({
        name: "calendar",
        description: "Manage calendar events",
        schema: {
          type: "object",
          properties: {
            action: {
              type: "string",
              enum: ["create", "update", "delete"],
              description: "Action to perform",
            },
            title: { type: "string", description: "Event title" },
            start: { type: "string", description: "Start time" },
            end: { type: "string", description: "End time" },
          },
          required: ["action", "title"],
        },
        func: async (params: any) => {
          return await this.executeCalendarTool(params);
        },
      }),
    );

    // Notion tool
    tools.push(
      new this.langchain.DynamicStructuredTool({
        name: "notion",
        description: "Manage Notion pages",
        schema: {
          type: "object",
          properties: {
            action: {
              type: "string",
              enum: ["create", "update", "delete"],
              description: "Action to perform",
            },
            title: { type: "string", description: "Page title" },
            content: { type: "string", description: "Page content" },
          },
          required: ["action", "title"],
        },
        func: async (params: any) => {
          return await this.executeNotionTool(params);
        },
      }),
    );

    // Stripe tool
    tools.push(
      new this.langchain.DynamicStructuredTool({
        name: "stripe",
        description: "Process payments",
        schema: {
          type: "object",
          properties: {
            action: {
              type: "string",
              enum: ["charge", "refund"],
              description: "Action to perform",
            },
            amount: { type: "number", description: "Amount in cents" },
            currency: { type: "string", description: "Currency code" },
          },
          required: ["action", "amount"],
        },
        func: async (params: any) => {
          return await this.executeStripeTool(params);
        },
      }),
    );

    // GitHub tool
    tools.push(
      new this.langchain.DynamicStructuredTool({
        name: "github",
        description: "Manage GitHub repositories",
        schema: {
          type: "object",
          properties: {
            action: {
              type: "string",
              enum: ["create_issue", "create_pr"],
              description: "Action to perform",
            },
            repo: { type: "string", description: "Repository name" },
            title: { type: "string", description: "Issue/PR title" },
          },
          required: ["action", "repo", "title"],
        },
        func: async (params: any) => {
          return await this.executeGitHubTool(params);
        },
      }),
    );

    // Search tool
    tools.push(
      new this.langchain.DynamicStructuredTool({
        name: "search",
        description: "Search the web",
        schema: {
          type: "object",
          properties: {
            query: { type: "string", description: "Search query" },
            max_results: {
              type: "number",
              description: "Maximum number of results",
            },
          },
          required: ["query"],
        },
        func: async (params: any) => {
          return await this.executeSearchTool(params);
        },
      }),
    );

    // Fetch tool
    tools.push(
      new this.langchain.DynamicStructuredTool({
        name: "fetch",
        description: "Fetch data from APIs",
        schema: {
          type: "object",
          properties: {
            url: { type: "string", description: "URL to fetch" },
            method: {
              type: "string",
              enum: ["GET", "POST", "PUT", "DELETE"],
              description: "HTTP method",
            },
          },
          required: ["url"],
        },
        func: async (params: any) => {
          return await this.executeFetchTool(params);
        },
      }),
    );

    return tools;
  }

  /**
   * Parse LangChain response into a plan
   */
  private parseResponseToPlan(output: any, originalJson: any): Plan {
    try {
      // Try to parse as JSON first
      let planData: any;
      try {
        planData = JSON.parse(output);
      } catch {
        // If not JSON, try to extract plan information from text
        planData = this.extractPlanFromText(output, originalJson);
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
