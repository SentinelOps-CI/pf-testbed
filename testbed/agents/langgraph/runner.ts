import { BaseAgentRunner } from "../../../runtime/gateway/src/base-runner";
import { Plan, ToolCall, ToolResult, AgentConfig } from "../../contracts/types";

/**
 * LangGraph Agent Runner
 * Implements the AgentRunner interface for LangGraph agents
 */
export class LangGraphRunner extends BaseAgentRunner {
  private langgraph: any;
  private graph: any;
  private tools: any[];

  constructor() {
    super("langgraph", "1.0.0", [
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
   * Configure the LangGraph client
   */
  async configure(config: AgentConfig): Promise<void> {
    await super.configure(config);

    // Initialize LangGraph
    if (typeof window === "undefined") {
      // Node.js environment
      try {
        const { ChatOpenAI } = await import("langchain/chat_models/openai");
        const { StateGraph, END } = await import("langchain/graphs");
        const { PromptTemplate } = await import("langchain/prompts");
        const { DynamicStructuredTool } = await import("langchain/tools");

        this.langgraph = {
          ChatOpenAI,
          StateGraph,
          END,
          PromptTemplate,
          DynamicStructuredTool,
        };
      } catch (error) {
        throw new Error(
          `Failed to import LangGraph: ${error instanceof Error ? error.message : "Unknown error"}`,
        );
      }
    } else {
      throw new Error("LangGraph runner requires Node.js environment");
    }

    // Initialize tools
    this.tools = this.createTools();

    // Initialize graph
    await this.initializeGraph(config);
  }

  /**
   * Create a plan using LangGraph
   */
  async plan(json: any): Promise<Plan> {
    try {
      if (!this.graph) {
        throw new Error("Graph not initialized");
      }

      // Create initial state
      const initialState = {
        input: json,
        journey: json.journey,
        tenant: json.tenant,
        steps: [],
        current_step: 0,
        plan_complete: false,
      };

      // Execute the graph
      const result = await this.graph.invoke(initialState);

      // Parse the result into a plan
      const plan = this.parseResultToPlan(result, json);

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
   * Initialize the LangGraph
   */
  private async initializeGraph(config: AgentConfig): Promise<void> {
    try {
      // Create LLM
      const llm = new this.langgraph.ChatOpenAI({
        openAIApiKey: config.api_key,
        modelName: config.model || "gpt-4",
        temperature: 0,
        timeout: config.timeout,
      });

      // Create the graph
      this.graph = this.createPlanningGraph(llm);

      // Compile the graph
      this.graph = this.graph.compile();
    } catch (error) {
      throw new Error(
        `Failed to initialize LangGraph: ${error instanceof Error ? error.message : "Unknown error"}`,
      );
    }
  }

  /**
   * Create the planning graph
   */
  private createPlanningGraph(llm: any): any {
    const workflow = new this.langgraph.StateGraph({
      channels: {
        input: { value: null },
        journey: { value: null },
        tenant: { value: null },
        steps: { value: [] },
        current_step: { value: 0 },
        plan_complete: { value: false },
      },
    });

    // Add nodes
    workflow.addNode("analyze_input", this.createAnalyzeInputNode(llm));
    workflow.addNode("plan_steps", this.createPlanStepsNode(llm));
    workflow.addNode("validate_plan", this.createValidatePlanNode(llm));
    workflow.addNode("execute_tools", this.createExecuteToolsNode(llm));
    workflow.addNode("finalize_plan", this.createFinalizePlanNode(llm));

    // Add edges
    workflow.addEdge("analyze_input", "plan_steps");
    workflow.addEdge("plan_steps", "validate_plan");
    workflow.addConditionalEdges("validate_plan", this.shouldExecuteTools, {
      true: "execute_tools",
      false: "finalize_plan",
    });
    workflow.addEdge("execute_tools", "finalize_plan");
    workflow.addEdge("finalize_plan", this.langgraph.END);

    return workflow;
  }

  /**
   * Create analyze input node
   */
  private createAnalyzeInputNode(llm: any): any {
    const prompt = this.langgraph.PromptTemplate.fromTemplate(`
      Analyze the input for the {journey} journey in tenant {tenant}.
      
      Extract key information:
      - Required actions
      - Dependencies
      - Risk factors
      - Required capabilities
      
      Input: {input}
      
      Return a structured analysis.
    `);

    return async (state: any) => {
      const response = await llm.invoke(
        prompt.format({
          journey: state.journey,
          tenant: state.tenant,
          input: JSON.stringify(state.input),
        }),
      );

      return {
        ...state,
        analysis: response.content,
      };
    };
  }

  /**
   * Create plan steps node
   */
  private createPlanStepsNode(llm: any): any {
    const prompt = this.langgraph.PromptTemplate.fromTemplate(`
      Based on the analysis, create a detailed plan with specific steps.
      
      Each step should include:
      - Tool to use
      - Required capability
      - Parameters
      - Expected outcome
      
      Analysis: {analysis}
      Journey: {journey}
      Tenant: {tenant}
      
      Return a structured plan with steps array.
    `);

    return async (state: any) => {
      const response = await llm.invoke(
        prompt.format({
          analysis: state.analysis,
          journey: state.journey,
          tenant: state.tenant,
        }),
      );

      // Parse response to extract steps
      const steps = this.parseStepsFromResponse(response.content);

      return {
        ...state,
        steps,
        current_step: 0,
      };
    };
  }

  /**
   * Create validate plan node
   */
  private createValidatePlanNode(llm: any): any {
    const prompt = this.langgraph.PromptTemplate.fromTemplate(`
      Validate the plan for the {journey} journey.
      
      Check:
      - All steps have required tools
      - Capabilities are properly specified
      - Parameters are valid
      - Plan is complete and logical
      
      Steps: {steps}
      
      Return validation result and any issues.
    `);

    return async (state: any) => {
      const response = await llm.invoke(
        prompt.format({
          journey: state.journey,
          steps: JSON.stringify(state.steps),
        }),
      );

      // Parse validation result
      const validation = this.parseValidationFromResponse(response.content);

      return {
        ...state,
        validation,
        plan_valid: validation.valid,
      };
    };
  }

  /**
   * Create execute tools node
   */
  private createExecuteToolsNode(llm: any): any {
    return async (state: any) => {
      const updatedSteps = [...state.steps];

      // Execute each step that requires tool execution
      for (let i = 0; i < updatedSteps.length; i++) {
        const step = updatedSteps[i];
        if (step.type === "tool_call" && step.status === "pending") {
          try {
            const toolCall: ToolCall = {
              id: step.id,
              tool: step.tool,
              parameters: step.parameters || {},
              capability: step.capability,
              timestamp: step.timestamp,
              tenant: state.tenant,
            };

            const result = await this.executeTool(toolCall);

            updatedSteps[i] = {
              ...step,
              status: result.success ? "completed" : "failed",
              result: result.result,
              error: result.error,
            };
          } catch (error) {
            updatedSteps[i] = {
              ...step,
              status: "failed",
              error: error instanceof Error ? error.message : "Unknown error",
            };
          }
        }
      }

      return {
        ...state,
        steps: updatedSteps,
        current_step: updatedSteps.length,
      };
    };
  }

  /**
   * Create finalize plan node
   */
  private createFinalizePlanNode(llm: any): any {
    return async (state: any) => {
      // Mark plan as complete
      return {
        ...state,
        plan_complete: true,
        final_result: {
          success: state.steps.every((s: any) => s.status === "completed"),
          steps_completed: state.steps.filter((s: any) => s.status === "completed").length,
          steps_failed: state.steps.filter((s: any) => s.status === "failed").length,
        },
      };
    };
  }

  /**
   * Conditional edge function
   */
  private shouldExecuteTools(state: any): string {
    return state.plan_valid && state.steps.some((s: any) => s.type === "tool_call")
      ? "true"
      : "false";
  }

  /**
   * Parse steps from response
   */
  private parseStepsFromResponse(content: string): any[] {
    try {
      // Try to parse as JSON first
      const parsed = JSON.parse(content);
      if (parsed.steps && Array.isArray(parsed.steps)) {
        return parsed.steps.map((step: any) => ({
          id: this.generateId(),
          type: step.type || "tool_call",
          tool: step.tool,
          parameters: step.parameters || {},
          capability: step.capability || "read",
          status: "pending",
          timestamp: new Date().toISOString(),
        }));
      }
    } catch {
      // Fallback to text parsing
    }

    // Simple text parsing fallback
    const lines = content.split("\n");
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
            capability: "read",
            status: "pending",
            timestamp: new Date().toISOString(),
          });
        }
      }
    }

    return steps;
  }

  /**
   * Parse validation from response
   */
  private parseValidationFromResponse(content: string): any {
    try {
      const parsed = JSON.parse(content);
      return {
        valid: parsed.valid !== false,
        issues: parsed.issues || [],
        warnings: parsed.warnings || [],
      };
    } catch {
      // Simple validation - assume valid if we can parse steps
      return {
        valid: true,
        issues: [],
        warnings: [],
      };
    }
  }

  /**
   * Parse result to plan
   */
  private parseResultToPlan(result: any, originalJson: any): Plan {
    try {
      // Extract steps from result
      const steps = result.steps || [];

      // Ensure all steps have required fields
      const validatedSteps = steps.map((step: any) => ({
        id: step.id || this.generateId(),
        type: step.type || "tool_call",
        tool: step.tool,
        parameters: step.parameters || {},
        capability: step.capability || "read",
        status: step.status || "pending",
        timestamp: step.timestamp || new Date().toISOString(),
        result: step.result,
        error: step.error,
      }));

      return {
        id: this.generateId(),
        tenant: originalJson.tenant || "acme",
        journey: originalJson.journey || "support_triage",
        steps: validatedSteps,
        metadata: {
          version: "1.0.0",
          agent: this.name,
          model: this.config?.model || "gpt-4",
          confidence: 0.8,
          risk_level: "medium",
          tags: [],
          context: originalJson,
        },
        timestamp: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
      };
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
   * Create LangGraph tools
   */
  private createTools(): any[] {
    const tools = [];

    // Slack tool
    tools.push(
      new this.langgraph.DynamicStructuredTool({
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
      new this.langgraph.DynamicStructuredTool({
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
      new this.langgraph.DynamicStructuredTool({
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
      new this.langgraph.DynamicStructuredTool({
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
      new this.langgraph.DynamicStructuredTool({
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
      new this.langgraph.DynamicStructuredTool({
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
      new this.langgraph.DynamicStructuredTool({
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
      new this.langgraph.DynamicStructuredTool({
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
