import { BaseToolEmulator, ToolEmulatorConfig } from "../base/emulator";
import { ToolCall } from "../../contracts/types";

/**
 * Slack Tool Emulator
 *
 * Provides high-fidelity emulation of Slack API operations including:
 * - Message sending
 * - Channel management
 * - User interactions
 * - File uploads
 */
export class SlackEmulator extends BaseToolEmulator {
  private slackClient: any; // Real Slack client when in real mode
  private mockChannels: Map<string, any>;
  private mockUsers: Map<string, any>;
  private mockMessages: Map<string, any[]>;

  constructor() {
    super("slack", "1.0.0", ["read", "write", "admin"]);

    this.mockChannels = new Map();
    this.mockUsers = new Map();
    this.mockMessages = new Map();

    this.initializeMockData();
  }

  /**
   * Initialize mock data for deterministic responses
   */
  private initializeMockData(): void {
    // Mock channels
    this.mockChannels.set("general", {
      id: "C1234567890",
      name: "general",
      is_private: false,
      is_archived: false,
      created: Date.now() / 1000,
      creator: "U1234567890",
      num_members: 150,
    });

    this.mockChannels.set("random", {
      id: "C0987654321",
      name: "random",
      is_private: false,
      is_archived: false,
      created: Date.now() / 1000,
      creator: "U1234567890",
      num_members: 89,
    });

    // Mock users
    this.mockUsers.set("U1234567890", {
      id: "U1234567890",
      name: "john.doe",
      real_name: "John Doe",
      profile: {
        email: "john.doe@acme.com",
        title: "Software Engineer",
        phone: "+1-555-0123",
      },
      is_admin: false,
      is_bot: false,
    });

    this.mockUsers.set("U0987654321", {
      id: "U0987654321",
      name: "jane.smith",
      real_name: "Jane Smith",
      profile: {
        email: "jane.smith@acme.com",
        title: "Product Manager",
        phone: "+1-555-0456",
      },
      is_admin: true,
      is_bot: false,
    });

    // Mock messages
    this.mockMessages.set("general", [
      {
        id: "M1234567890",
        type: "message",
        user: "U1234567890",
        text: "Hello everyone!",
        ts: Date.now() / 1000,
        thread_ts: undefined,
      },
      {
        id: "M0987654321",
        type: "message",
        user: "U0987654321",
        text: "Hi John! How's the project going?",
        ts: Date.now() / 1000,
        thread_ts: undefined,
      },
    ]);
  }

  /**
   * Configure the emulator
   */
  async configure(config: ToolEmulatorConfig): Promise<void> {
    await super.configure(config);

    // Initialize real Slack client if in real mode
    if (config.mode === "real" || config.mode === "hybrid") {
      await this.initializeRealClient();
    }
  }

  /**
   * Initialize real Slack client
   */
  private async initializeRealClient(): Promise<void> {
    try {
      // In a real implementation, you would initialize the Slack client here
      // For now, we'll just log that we're in real mode
      console.log("Slack emulator configured for real mode");
    } catch (error) {
      throw new Error(
        `Failed to initialize real Slack client: ${error instanceof Error ? error.message : "Unknown error"}`,
      );
    }
  }

  /**
   * Execute mock Slack operations
   */
  protected async executeMock(call: ToolCall): Promise<any> {
    await this.simulateDelay();

    const { action, ...params } = call.parameters;

    switch (action) {
      case "send_message":
        return this.mockSendMessage(params);
      case "create_channel":
        return this.mockCreateChannel(params);
      case "invite_user":
        return this.mockInviteUser(params);
      case "get_channel_info":
        return this.mockGetChannelInfo(params);
      case "get_user_info":
        return this.mockGetUserInfo(params);
      case "get_channel_history":
        return this.mockGetChannelHistory(params);
      case "upload_file":
        return this.mockUploadFile(params);
      default:
        throw new Error(`Unknown Slack action: ${action}`);
    }
  }

  /**
   * Execute real Slack operations
   */
  protected async executeReal(call: ToolCall): Promise<any> {
    const { action, ...params } = call.parameters;

    switch (action) {
      case "send_message":
        return this.realSendMessage(params);
      case "create_channel":
        return this.realCreateChannel(params);
      case "invite_user":
        return this.realInviteUser(params);
      case "get_channel_info":
        return this.realGetChannelInfo(params);
      case "get_user_info":
        return this.realGetUserInfo(params);
      case "get_channel_history":
        return this.realGetChannelHistory(params);
      case "upload_file":
        return this.realUploadFile(params);
      default:
        throw new Error(`Unknown Slack action: ${action}`);
    }
  }

  /**
   * Execute hybrid operations (mix of mock and real)
   */
  protected async executeHybrid(call: ToolCall): Promise<any> {
    const { action, ...params } = call.parameters;

    // Use real for read operations, mock for write operations
    if (["get_channel_info", "get_user_info", "get_channel_history"].includes(action)) {
      return this.executeReal(call);
    } else {
      return this.executeMock(call);
    }
  }

  // Mock implementations
  private mockSendMessage(params: any): any {
    const { channel, text, thread_ts } = params;

    if (!channel || !text) {
      throw new Error("Channel and text are required for sending messages");
    }

    const message = {
      id: `M${Date.now()}`,
      type: "message",
      user: "U1234567890", // Mock user
      text,
      ts: Date.now() / 1000,
      thread_ts,
      channel,
    };

    // Add to mock messages
    if (!this.mockMessages.has(channel)) {
      this.mockMessages.set(channel, []);
    }
    this.mockMessages.get(channel)!.push(message);

    return {
      ok: true,
      channel,
      ts: message.ts,
      message,
    };
  }

  private mockCreateChannel(params: any): any {
    const { name, is_private = false } = params;

    if (!name) {
      throw new Error("Channel name is required");
    }

    const channel = {
      id: `C${Date.now()}`,
      name,
      is_private,
      is_archived: false,
      created: Date.now() / 1000,
      creator: "U1234567890",
      num_members: 1,
    };

    this.mockChannels.set(name, channel);
    this.mockMessages.set(name, []);

    return {
      ok: true,
      channel,
    };
  }

  private mockInviteUser(params: any): any {
    const { channel, user } = params;

    if (!channel || !user) {
      throw new Error("Channel and user are required");
    }

    if (!this.mockChannels.has(channel)) {
      throw new Error("Channel not found");
    }

    if (!this.mockUsers.has(user)) {
      throw new Error("User not found");
    }

    return {
      ok: true,
      channel,
      user,
    };
  }

  private mockGetChannelInfo(params: any): any {
    const { channel } = params;

    if (!channel) {
      throw new Error("Channel is required");
    }

    const channelInfo = this.mockChannels.get(channel);
    if (!channelInfo) {
      throw new Error("Channel not found");
    }

    return {
      ok: true,
      channel: channelInfo,
    };
  }

  private mockGetUserInfo(params: any): any {
    const { user } = params;

    if (!user) {
      throw new Error("User is required");
    }

    const userInfo = this.mockUsers.get(user);
    if (!userInfo) {
      throw new Error("User not found");
    }

    return {
      ok: true,
      user: userInfo,
    };
  }

  private mockGetChannelHistory(params: any): any {
    const { channel, limit = 100 } = params;

    if (!channel) {
      throw new Error("Channel is required");
    }

    const messages = this.mockMessages.get(channel) || [];
    const limitedMessages = messages.slice(-limit);

    return {
      ok: true,
      messages: limitedMessages,
      has_more: messages.length > limit,
      latest: messages.length > 0 ? messages[messages.length - 1].ts : undefined,
      oldest: messages.length > 0 ? messages[0].ts : undefined,
    };
  }

  private mockUploadFile(params: any): any {
    const { channels, file, title, initial_comment } = params;

    if (!channels || !file) {
      throw new Error("Channels and file are required");
    }

    const fileInfo = {
      id: `F${Date.now()}`,
      created: Date.now() / 1000,
      title: title || file.name,
      name: file.name,
      size: file.size,
      url_private: `https://files.slack.com/files-pri/${Date.now()}-${file.name}`,
      permalink: `https://acme.slack.com/files/U1234567890/${file.name}`,
      channels: Array.isArray(channels) ? channels : [channels],
    };

    return {
      ok: true,
      file: fileInfo,
    };
  }

  // Real implementations (stubs for now)
  private async realSendMessage(params: any): Promise<any> {
    // TODO: Implement real Slack message sending
    throw new Error("Real Slack integration not yet implemented");
  }

  private async realCreateChannel(params: any): Promise<any> {
    // TODO: Implement real Slack channel creation
    throw new Error("Real Slack integration not yet implemented");
  }

  private async realInviteUser(params: any): Promise<any> {
    // TODO: Implement real Slack user invitation
    throw new Error("Real Slack integration not yet implemented");
  }

  private async realGetChannelInfo(params: any): Promise<any> {
    // TODO: Implement real Slack channel info retrieval
    throw new Error("Real Slack integration not yet implemented");
  }

  private async realGetUserInfo(params: any): Promise<any> {
    // TODO: Implement real Slack user info retrieval
    throw new Error("Real Slack integration not yet implemented");
  }

  private async realGetChannelHistory(params: any): Promise<any> {
    // TODO: Implement real Slack channel history retrieval
    throw new Error("Real Slack integration not yet implemented");
  }

  private async realUploadFile(params: any): Promise<any> {
    // TODO: Implement real Slack file upload
    throw new Error("Real Slack integration not yet implemented");
  }

  /**
   * Set mock data for specific operations
   */
  setMockData(data: any): void {
    super.setMockData(data);

    if (data.channels) {
      for (const [name, channel] of Object.entries(data.channels)) {
        this.mockChannels.set(name, channel);
      }
    }

    if (data.users) {
      for (const [id, user] of Object.entries(data.users)) {
        this.mockUsers.set(id, user);
      }
    }

    if (data.messages) {
      for (const [channel, messages] of Object.entries(data.messages)) {
        this.mockMessages.set(channel, messages as any[]);
      }
    }
  }

  /**
   * Get comprehensive mock data
   */
  getMockData(): any {
    const baseData = super.getMockData();
    return {
      ...baseData,
      channels: Object.fromEntries(this.mockChannels),
      users: Object.fromEntries(this.mockUsers),
      messages: Object.fromEntries(this.mockMessages),
    };
  }

  /**
   * Clear all mock data
   */
  clearMockData(): void {
    super.clearMockData();
    this.mockChannels.clear();
    this.mockUsers.clear();
    this.mockMessages.clear();
    this.initializeMockData(); // Restore default mock data
  }
}
