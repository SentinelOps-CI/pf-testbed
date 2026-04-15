import { BaseToolEmulator, ToolEmulatorConfig } from "../base/emulator";
import { ToolCall } from "../../contracts/types";

export interface SlackMessage {
  id: string;
  channel: string;
  text: string;
  user: string;
  timestamp: string;
  thread_ts?: string;
}

export interface SlackChannel {
  id: string;
  name: string;
  is_private: boolean;
  members: string[];
}

export class SlackEmulator extends BaseToolEmulator {
  private channels: Map<string, SlackChannel> = new Map();
  private messages: Map<string, SlackMessage[]> = new Map();
  private users: Map<string, any> = new Map();

  constructor() {
    super("slack", "1.0.0", ["slack:read", "slack:write", "slack:admin"]);

    // Initialize with default mock data
    this.initializeMockData();
  }

  private initializeMockData(): void {
    // Default channels
    this.channels.set("C1234567890", {
      id: "C1234567890",
      name: "general",
      is_private: false,
      members: ["U1234567890", "U0987654321"],
    });

    // Default users
    this.users.set("U1234567890", {
      id: "U1234567890",
      name: "john_doe",
      real_name: "John Doe",
      is_bot: false,
    });

    // Default messages
    this.messages.set("C1234567890", [
      {
        id: "M1234567890",
        channel: "C1234567890",
        text: "Hello world!",
        user: "U1234567890",
        timestamp: "1234567890.123456",
      },
    ]);
  }

  protected async executeMock(call: ToolCall): Promise<any> {
    await this.simulateDelay();

    switch (call.tool) {
      case "slack.post_message":
        return this.postMessageMock(call);
      case "slack.get_channels":
        return this.getChannelsMock(call);
      case "slack.get_messages":
        return this.getMessagesMock(call);
      case "slack.get_user":
        return this.getUserMock(call);
      default:
        throw new Error(`Unknown Slack tool: ${call.tool}`);
    }
  }

  protected async executeReal(call: ToolCall): Promise<any> {
    // Real Slack API integration would go here
    // For now, we'll use the mock implementation
    return this.executeMock(call);
  }

  protected async executeHybrid(call: ToolCall): Promise<any> {
    // Hybrid mode: use real for some operations, mock for others
    const realOperations = ["slack.post_message"];

    if (realOperations.includes(call.tool)) {
      return this.executeReal(call);
    } else {
      return this.executeMock(call);
    }
  }

  private async postMessageMock(call: ToolCall): Promise<any> {
    const { channel, text, thread_ts } = call.parameters;

    if (!this.channels.has(channel)) {
      throw new Error(`Channel ${channel} not found`);
    }

    const message: SlackMessage = {
      id: this.generateId(),
      channel,
      text,
      user: call.parameters.user || "U1234567890",
      timestamp: (Date.now() / 1000).toString(),
      thread_ts,
    };

    if (!this.messages.has(channel)) {
      this.messages.set(channel, []);
    }
    this.messages.get(channel)!.push(message);

    return {
      ok: true,
      channel,
      ts: message.timestamp,
      message: message,
    };
  }

  private async getChannelsMock(call: ToolCall): Promise<any> {
    const channels = Array.from(this.channels.values());
    return {
      ok: true,
      channels: channels.map((ch) => ({
        id: ch.id,
        name: ch.name,
        is_private: ch.is_private,
        num_members: ch.members.length,
      })),
    };
  }

  private async getMessagesMock(call: ToolCall): Promise<any> {
    const { channel, limit = 100 } = call.parameters;

    if (!this.messages.has(channel)) {
      return { ok: true, messages: [] };
    }

    const messages = this.messages.get(channel)!.slice(-limit);
    return {
      ok: true,
      messages: messages.map((msg) => ({
        type: "message",
        user: msg.user,
        text: msg.text,
        ts: msg.timestamp,
        thread_ts: msg.thread_ts,
      })),
    };
  }

  private async getUserMock(call: ToolCall): Promise<any> {
    const { user } = call.parameters;

    if (!this.users.has(user)) {
      throw new Error(`User ${user} not found`);
    }

    return {
      ok: true,
      user: this.users.get(user),
    };
  }

  // Override setMockData to handle Slack-specific data
  setMockData(data: any): void {
    super.setMockData(data);

    if (data.channels) {
      data.channels.forEach((ch: SlackChannel) => {
        this.channels.set(ch.id, ch);
      });
    }

    if (data.users) {
      data.users.forEach((user: any) => {
        this.users.set(user.id, user);
      });
    }

    if (data.messages) {
      Object.entries(data.messages).forEach(([channelId, msgs]: [string, any]) => {
        this.messages.set(channelId, msgs);
      });
    }
  }
}
