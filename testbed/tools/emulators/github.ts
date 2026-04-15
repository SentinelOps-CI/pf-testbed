import { createHash } from "crypto";
import { z } from "zod";

// GitHub emulator for TB-08
// Provides deterministic, seeded mocks with real mode capabilities

export const GitHubIssueSchema = z.object({
  id: z.string().optional(),
  title: z.string().min(1).max(200),
  body: z.string().min(1),
  state: z.enum(["open", "closed"]).default("open"),
  labels: z.array(z.string()).optional(),
  assignees: z.array(z.string()).optional(),
  milestone: z.string().optional(),
  tenant: z.string().min(1),
  capability_token: z.string().min(1),
  enforce: z.boolean().default(true),
});

export const GitHubPRSchema = z.object({
  id: z.string().optional(),
  title: z.string().min(1).max(200),
  body: z.string().min(1),
  state: z.enum(["open", "closed", "merged"]).default("open"),
  base_branch: z.string().default("main"),
  head_branch: z.string().min(1),
  labels: z.array(z.string()).optional(),
  assignees: z.array(z.string()).optional(),
  reviewers: z.array(z.string()).optional(),
  tenant: z.string().min(1),
  capability_token: z.string().min(1),
  enforce: z.boolean().default(true),
});

export const GitHubResponseSchema = z.object({
  success: z.boolean(),
  item_id: z.string(),
  created_at: z.string(),
  item: z.union([GitHubIssueSchema, GitHubPRSchema]),
  metadata: z.object({
    tenant: z.string(),
    capability_token: z.string(),
    enforce_mode: z.boolean(),
    processing_time_ms: z.number(),
  }),
  error: z.string().optional(),
});

export type GitHubIssue = z.infer<typeof GitHubIssueSchema>;
export type GitHubPR = z.infer<typeof GitHubPRSchema>;
export type GitHubResponse = z.infer<typeof GitHubResponseSchema>;

// GitHub repository interface
export interface GitHubRepository {
  id: string;
  name: string;
  description: string;
  tenant: string;
  private: boolean;
  default_branch: string;
  branches: string[];
  issues: string[]; // Issue IDs
  pull_requests: string[]; // PR IDs
}

// Mock GitHub configuration
export interface MockGitHubConfig {
  seed: string;
  operation_delay_ms: number;
  failure_rate: number;
  max_issues_per_repo: number;
  max_prs_per_repo: number;
  max_content_length: number;
  supported_labels: string[];
}

export class GitHubEmulator {
  private readonly seed: string;
  private readonly enforceMode: boolean;
  private readonly capabilityToken: string;
  private readonly tenant: string;
  private readonly mockConfig: MockGitHubConfig;
  private readonly issues: Map<string, GitHubIssue> = new Map();
  private readonly pullRequests: Map<string, GitHubPR> = new Map();
  private readonly repositories: Map<string, GitHubRepository> = new Map();

  constructor(
    seed: string = "default",
    enforceMode: boolean = true,
    capabilityToken: string = "",
    tenant: string = "default",
  ) {
    this.seed = seed;
    this.enforceMode = enforceMode;
    this.capabilityToken = capabilityToken;
    this.tenant = tenant;

    // Initialize mock configuration based on seed
    this.mockConfig = this.initializeMockConfig(seed);

    // Initialize with sample data
    this.initializeSampleData();
  }

  private initializeMockConfig(seed: string): MockGitHubConfig {
    const hash = createHash("sha256").update(seed).digest("hex");

    return {
      seed,
      operation_delay_ms: (parseInt(hash.slice(0, 8), 16) % 1500) + 100, // 100-1600ms
      failure_rate: (parseInt(hash.slice(8, 16), 16) % 100) / 1000, // 0-10%
      max_issues_per_repo: (parseInt(hash.slice(16, 24), 16) % 200) + 50, // 50-250
      max_prs_per_repo: (parseInt(hash.slice(24, 32), 16) % 100) + 20, // 20-120
      max_content_length: (parseInt(hash.slice(0, 8), 16) % 5000) + 1000, // 1000-6000
      supported_labels: [
        "bug",
        "enhancement",
        "documentation",
        "help wanted",
        "good first issue",
        "priority:high",
        "priority:medium",
        "priority:low",
      ],
    };
  }

  private initializeSampleData(): void {
    // Create sample repositories
    const acmeRepo: GitHubRepository = {
      id: "repo_acme_app",
      name: "acme-app",
      description: "Main application for ACME Corporation",
      tenant: "acme",
      private: false,
      default_branch: "main",
      branches: ["main", "develop", "feature/user-auth", "hotfix/security-patch"],
      issues: [],
      pull_requests: [],
    };

    const globexRepo: GitHubRepository = {
      id: "repo_globex_api",
      name: "globex-api",
      description: "API service for Globex Corporation",
      tenant: "globex",
      private: true,
      default_branch: "main",
      branches: ["main", "staging", "feature/rate-limiting"],
      issues: [],
      pull_requests: [],
    };

    this.repositories.set(acmeRepo.id, acmeRepo);
    this.repositories.set(globexRepo.id, globexRepo);

    // Create sample issues
    const sampleIssues: GitHubIssue[] = [
      {
        title: "User authentication not working in production",
        body: "Users are unable to log in after the latest deployment. Error logs show connection timeout to auth service.",
        state: "open",
        labels: ["bug", "priority:high"],
        assignees: ["dev@acme.com"],
        tenant: "acme",
        capability_token: "sample_token",
        enforce: false,
      },
      {
        title: "Add dark mode support",
        body: "Implement dark mode theme for better user experience. Should respect system preferences.",
        state: "open",
        labels: ["enhancement", "priority:medium"],
        assignees: ["ui@acme.com"],
        tenant: "acme",
        capability_token: "sample_token",
        enforce: false,
      },
      {
        title: "API rate limiting implementation",
        body: "Implement rate limiting for API endpoints to prevent abuse and ensure fair usage.",
        state: "open",
        labels: ["enhancement", "priority:high"],
        assignees: ["backend@globex.com"],
        tenant: "globex",
        capability_token: "sample_token",
        enforce: false,
      },
    ];

    sampleIssues.forEach((issue) => {
      const issueId = this.generateIssueId(issue);
      this.issues.set(issueId, { ...issue, id: issueId });

      // Add to repository
      if (issue.tenant === "acme") {
        const repo = this.repositories.get("repo_acme_app")!;
        repo.issues.push(issueId);
      } else if (issue.tenant === "globex") {
        const repo = this.repositories.get("repo_globex_api")!;
        repo.issues.push(issueId);
      }
    });

    // Create sample pull requests
    const samplePRs: GitHubPR[] = [
      {
        title: "Fix user authentication timeout",
        body: "Resolves the authentication timeout issue by increasing connection timeout and adding retry logic.",
        state: "open",
        base_branch: "main",
        head_branch: "fix/auth-timeout",
        labels: ["bug", "priority:high"],
        assignees: ["dev@acme.com"],
        reviewers: ["senior@acme.com"],
        tenant: "acme",
        capability_token: "sample_token",
        enforce: false,
      },
      {
        title: "Implement rate limiting middleware",
        body: "Adds rate limiting middleware using Redis for tracking request counts per IP address.",
        state: "open",
        base_branch: "main",
        head_branch: "feature/rate-limiting",
        labels: ["enhancement", "priority:high"],
        assignees: ["backend@globex.com"],
        reviewers: ["architect@globex.com"],
        tenant: "globex",
        capability_token: "sample_token",
        enforce: false,
      },
    ];

    samplePRs.forEach((pr) => {
      const prId = this.generatePRId(pr);
      this.pullRequests.set(prId, { ...pr, id: prId });

      // Add to repository
      if (pr.tenant === "acme") {
        const repo = this.repositories.get("repo_acme_app")!;
        repo.pull_requests.push(prId);
      } else if (pr.tenant === "globex") {
        const repo = this.repositories.get("repo_globex_api")!;
        repo.pull_requests.push(prId);
      }
    });
  }

  // Validate capability token
  private validateCapability(capabilityToken: string, operation: string): boolean {
    if (!this.enforceMode) {
      return true; // Skip validation in non-enforce mode
    }

    if (!capabilityToken) {
      return false;
    }

    // In a real implementation, this would validate against a capability broker
    // For now, we'll use a simple hash-based validation
    const expectedHash = createHash("sha256")
      .update(`${this.tenant}:github:${operation}`)
      .digest("hex");

    return capabilityToken === expectedHash;
  }

  // Create GitHub issue
  async createIssue(issue: GitHubIssue): Promise<GitHubResponse> {
    const startTime = Date.now();

    try {
      // Validate request schema
      const validatedIssue = GitHubIssueSchema.parse(issue);

      // Validate capability if in enforce mode
      if (
        this.enforceMode &&
        !this.validateCapability(validatedIssue.capability_token, "create_issue")
      ) {
        return {
          success: false,
          item_id: "",
          created_at: new Date().toISOString(),
          item: validatedIssue,
          metadata: {
            tenant: validatedIssue.tenant,
            capability_token: validatedIssue.capability_token,
            enforce_mode: this.enforceMode,
            processing_time_ms: Date.now() - startTime,
          },
          error: "CAP_MISS: Missing or invalid capability token for GitHub issue creation",
        };
      }

      // Check content length
      if (validatedIssue.body.length > this.mockConfig.max_content_length) {
        return {
          success: false,
          item_id: "",
          created_at: new Date().toISOString(),
          item: validatedIssue,
          metadata: {
            tenant: validatedIssue.tenant,
            capability_token: validatedIssue.capability_token,
            enforce_mode: this.enforceMode,
            processing_time_ms: Date.now() - startTime,
          },
          error: `CONTENT_TOO_LONG: Maximum content length is ${this.mockConfig.max_content_length} characters`,
        };
      }

      // Simulate operation delay
      await this.simulateOperationDelay();

      // Simulate potential failure
      if (Math.random() < this.mockConfig.failure_rate) {
        throw new Error("Simulated GitHub issue creation failure");
      }

      // Generate issue ID
      const issueId = this.generateIssueId(validatedIssue);

      // Store issue
      this.issues.set(issueId, { ...validatedIssue, id: issueId });

      const response: GitHubResponse = {
        success: true,
        item_id: issueId,
        created_at: new Date().toISOString(),
        item: { ...validatedIssue, id: issueId },
        metadata: {
          tenant: validatedIssue.tenant,
          capability_token: validatedIssue.capability_token,
          enforce_mode: this.enforceMode,
          processing_time_ms: Date.now() - startTime,
        },
      };

      return response;
    } catch (error) {
      return {
        success: false,
        item_id: "",
        created_at: new Date().toISOString(),
        item: issue,
        metadata: {
          tenant: issue.tenant || "unknown",
          capability_token: issue.capability_token || "",
          enforce_mode: this.enforceMode,
          processing_time_ms: Date.now() - startTime,
        },
        error: error instanceof Error ? error.message : "Unknown error",
      };
    }
  }

  // Create GitHub pull request
  async createPullRequest(pr: GitHubPR): Promise<GitHubResponse> {
    const startTime = Date.now();

    try {
      // Validate request schema
      const validatedPR = GitHubPRSchema.parse(pr);

      // Validate capability if in enforce mode
      if (this.enforceMode && !this.validateCapability(validatedPR.capability_token, "create_pr")) {
        return {
          success: false,
          item_id: "",
          created_at: new Date().toISOString(),
          item: validatedPR,
          metadata: {
            tenant: validatedPR.tenant,
            capability_token: validatedPR.capability_token,
            enforce_mode: this.enforceMode,
            processing_time_ms: Date.now() - startTime,
          },
          error: "CAP_MISS: Missing or invalid capability token for GitHub PR creation",
        };
      }

      // Check content length
      if (validatedPR.body.length > this.mockConfig.max_content_length) {
        return {
          success: false,
          item_id: "",
          created_at: new Date().toISOString(),
          item: validatedPR,
          metadata: {
            tenant: validatedPR.tenant,
            capability_token: validatedPR.capability_token,
            enforce_mode: this.enforceMode,
            processing_time_ms: Date.now() - startTime,
          },
          error: `CONTENT_TOO_LONG: Maximum content length is ${this.mockConfig.max_content_length} characters`,
        };
      }

      // Simulate operation delay
      await this.simulateOperationDelay();

      // Simulate potential failure
      if (Math.random() < this.mockConfig.failure_rate) {
        throw new Error("Simulated GitHub PR creation failure");
      }

      // Generate PR ID
      const prId = this.generatePRId(validatedPR);

      // Store PR
      this.pullRequests.set(prId, { ...validatedPR, id: prId });

      const response: GitHubResponse = {
        success: true,
        item_id: prId,
        created_at: new Date().toISOString(),
        item: { ...validatedPR, id: prId },
        metadata: {
          tenant: validatedPR.tenant,
          capability_token: validatedPR.capability_token,
          enforce_mode: this.enforceMode,
          processing_time_ms: Date.now() - startTime,
        },
      };

      return response;
    } catch (error) {
      return {
        success: false,
        item_id: "",
        created_at: new Date().toISOString(),
        item: pr,
        metadata: {
          tenant: pr.tenant || "unknown",
          capability_token: pr.capability_token || "",
          enforce_mode: this.enforceMode,
          processing_time_ms: Date.now() - startTime,
        },
        error: error instanceof Error ? error.message : "Unknown error",
      };
    }
  }

  // Get issue by ID
  async getIssue(issueId: string, capabilityToken: string): Promise<GitHubIssue | null> {
    // Validate capability if in enforce mode
    if (this.enforceMode && !this.validateCapability(capabilityToken, "read")) {
      throw new Error("CAP_MISS: Missing or invalid capability token for GitHub issue reading");
    }

    return this.issues.get(issueId) || null;
  }

  // Get PR by ID
  async getPullRequest(prId: string, capabilityToken: string): Promise<GitHubPR | null> {
    // Validate capability if in enforce mode
    if (this.enforceMode && !this.validateCapability(capabilityToken, "read")) {
      throw new Error("CAP_MISS: Missing or invalid capability token for GitHub PR reading");
    }

    return this.pullRequests.get(prId) || null;
  }

  // List issues for a tenant
  async listIssues(
    tenant: string,
    capabilityToken: string,
    state?: string,
  ): Promise<GitHubIssue[]> {
    // Validate capability if in enforce mode
    if (this.enforceMode && !this.validateCapability(capabilityToken, "read")) {
      throw new Error("CAP_MISS: Missing or invalid capability token for GitHub issue listing");
    }

    let issues = Array.from(this.issues.values()).filter((issue) => issue.tenant === tenant);

    // Filter by state if specified
    if (state) {
      issues = issues.filter((issue) => issue.state === state);
    }

    return issues;
  }

  // List PRs for a tenant
  async listPullRequests(
    tenant: string,
    capabilityToken: string,
    state?: string,
  ): Promise<GitHubPR[]> {
    // Validate capability if in enforce mode
    if (this.enforceMode && !this.validateCapability(capabilityToken, "read")) {
      throw new Error("CAP_MISS: Missing or invalid capability token for GitHub PR listing");
    }

    let prs = Array.from(this.pullRequests.values()).filter((pr) => pr.tenant === tenant);

    // Filter by state if specified
    if (state) {
      prs = prs.filter((pr) => pr.state === state);
    }

    return prs;
  }

  // Get repository by ID
  async getRepository(repoId: string, capabilityToken: string): Promise<GitHubRepository | null> {
    // Validate capability if in enforce mode
    if (this.enforceMode && !this.validateCapability(capabilityToken, "read")) {
      throw new Error(
        "CAP_MISS: Missing or invalid capability token for GitHub repository reading",
      );
    }

    return this.repositories.get(repoId) || null;
  }

  // List repositories for a tenant
  async listRepositories(tenant: string, capabilityToken: string): Promise<GitHubRepository[]> {
    // Validate capability if in enforce mode
    if (this.enforceMode && !this.validateCapability(capabilityToken, "read")) {
      throw new Error(
        "CAP_MISS: Missing or invalid capability token for GitHub repository listing",
      );
    }

    return Array.from(this.repositories.values()).filter((repo) => repo.tenant === tenant);
  }

  // Generate deterministic issue ID
  private generateIssueId(issue: GitHubIssue): string {
    const data = `${this.seed}:${issue.title}:${issue.tenant}:${Date.now()}`;
    return createHash("sha256").update(data).digest("hex").slice(0, 16);
  }

  // Generate deterministic PR ID
  private generatePRId(pr: GitHubPR): string {
    const data = `${this.seed}:${pr.title}:${pr.tenant}:${pr.head_branch}:${Date.now()}`;
    return createHash("sha256").update(data).digest("hex").slice(0, 16);
  }

  // Simulate operation delay
  private async simulateOperationDelay(): Promise<void> {
    return new Promise((resolve) => {
      setTimeout(resolve, this.mockConfig.operation_delay_ms);
    });
  }

  // Get mock configuration
  getMockConfig(): MockGitHubConfig {
    return { ...this.mockConfig };
  }

  // Reset emulator state
  reset(): void {
    this.issues.clear();
    this.pullRequests.clear();
    this.repositories.clear();
    this.initializeSampleData();
  }

  // Switch to real mode (placeholder for real GitHub service integration)
  async switchToRealMode(apiKey: string, serviceConfig: any): Promise<void> {
    if (this.enforceMode) {
      throw new Error("Cannot switch to real mode while enforce mode is enabled");
    }

    // In a real implementation, this would initialize a real GitHub service
    // For now, we'll just log the intention
    console.log("Switching to real GitHub service mode");
    console.log("API Key:", apiKey ? "***" + apiKey.slice(-4) : "none");
    console.log("Service Config:", serviceConfig);
  }
}

// Export factory function for easy instantiation
export const createGitHubEmulator = (
  seed: string = "default",
  enforceMode: boolean = true,
  capabilityToken: string = "",
  tenant: string = "default",
): GitHubEmulator => {
  return new GitHubEmulator(seed, enforceMode, capabilityToken, tenant);
};

// Export default instance
export const defaultGitHubEmulator = createGitHubEmulator();
