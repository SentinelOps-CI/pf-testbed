// Tool Emulators Index for TB-08
// Exports all emulators for easy importing and use

// Core emulators
export { SlackEmulator, createSlackEmulator, defaultSlackEmulator } from "./slack";

export { StripeEmulator, createStripeEmulator, defaultStripeEmulator } from "./stripe";

export { EmailEmulator, createEmailEmulator, defaultEmailEmulator } from "./email";

export { CalendarEmulator, createCalendarEmulator, defaultCalendarEmulator } from "./calendar";

export { NotionEmulator, createNotionEmulator, defaultNotionEmulator } from "./notion";

export { GitHubEmulator, createGitHubEmulator, defaultGitHubEmulator } from "./github";

export { SearchEmulator, createSearchEmulator, defaultSearchEmulator } from "./search";

export { FetchEmulator, createFetchEmulator, defaultFetchEmulator } from "./fetch";

// Emulator factory for creating multiple emulators with consistent configuration
export interface EmulatorConfig {
  seed: string;
  enforceMode: boolean;
  capabilityToken: string;
  tenant: string;
}

export class EmulatorFactory {
  private config: EmulatorConfig;

  constructor(config: EmulatorConfig) {
    this.config = config;
  }

  // Create all emulators with consistent configuration
  createAllEmulators() {
    return {
      slack: createSlackEmulator(
        this.config.seed,
        this.config.enforceMode,
        this.config.capabilityToken,
        this.config.tenant,
      ),
      stripe: createStripeEmulator(
        this.config.seed,
        this.config.enforceMode,
        this.config.capabilityToken,
        this.config.tenant,
      ),
      email: createEmailEmulator(
        this.config.seed,
        this.config.enforceMode,
        this.config.capabilityToken,
        this.config.tenant,
      ),
      calendar: createCalendarEmulator(
        this.config.seed,
        this.config.enforceMode,
        this.config.capabilityToken,
        this.config.tenant,
      ),
      notion: createNotionEmulator(
        this.config.seed,
        this.config.enforceMode,
        this.config.capabilityToken,
        this.config.tenant,
      ),
      github: createGitHubEmulator(
        this.config.seed,
        this.config.enforceMode,
        this.config.capabilityToken,
        this.config.tenant,
      ),
      search: createSearchEmulator(
        this.config.seed,
        this.config.enforceMode,
        this.config.capabilityToken,
        this.config.tenant,
      ),
      fetch: createFetchEmulator(
        this.config.seed,
        this.config.enforceMode,
        this.config.capabilityToken,
        this.config.tenant,
      ),
    };
  }

  // Create specific emulator
  createEmulator<T extends keyof ReturnType<EmulatorFactory["createAllEmulators"]>>(
    type: T,
  ): ReturnType<EmulatorFactory["createAllEmulators"]>[T] {
    const emulators = this.createAllEmulators();
    return emulators[type];
  }

  // Update configuration
  updateConfig(newConfig: Partial<EmulatorConfig>) {
    this.config = { ...this.config, ...newConfig };
  }

  // Get current configuration
  getConfig(): EmulatorConfig {
    return { ...this.config };
  }
}

// Utility function to create emulator factory
export const createEmulatorFactory = (config: EmulatorConfig): EmulatorFactory => {
  return new EmulatorFactory(config);
};

// Default emulator factory with default configuration
export const defaultEmulatorFactory = createEmulatorFactory({
  seed: "default",
  enforceMode: true,
  capabilityToken: "",
  tenant: "default",
});

// Export types for external use
export type {
  // Slack types
  SlackMessage,
  SlackResponse,
  SlackChannel,
  MockSlackConfig,
} from "./slack";

export type {
  // Stripe types
  StripePayment,
  StripeResponse,
  StripeCustomer,
  MockStripeConfig,
} from "./stripe";

export type {
  // Email types
  EmailRequest,
  EmailResponse,
  EmailTemplate,
  MockEmailConfig,
} from "./email";

export type {
  // Calendar types
  CalendarEvent,
  CalendarResponse,
  TimeSlot,
  MockCalendarConfig,
} from "./calendar";

export type {
  // Notion types
  NotionPage,
  NotionResponse,
  NotionDatabase,
  MockNotionConfig,
} from "./notion";

export type {
  // GitHub types
  GitHubIssue,
  GitHubPR,
  GitHubResponse,
  GitHubRepository,
  MockGitHubConfig,
} from "./github";

export type {
  // Search types
  SearchQuery,
  SearchResult,
  SearchResponse,
  SearchIndex,
  MockSearchConfig,
} from "./search";

export type {
  // Fetch types
  FetchRequest,
  FetchResponse,
  MockEndpoint,
  MockFetchConfig,
} from "./fetch";
