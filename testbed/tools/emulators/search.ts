import { createHash } from "crypto";
import { z } from "zod";

// Search emulator for TB-08
// Provides deterministic, seeded mocks with real mode capabilities

export const SearchQuerySchema = z.object({
  query: z.string().min(1).max(500),
  filters: z.record(z.any()).optional(),
  tenant: z.string().min(1),
  capability_token: z.string().min(1),
  enforce: z.boolean().default(true),
  max_results: z.number().min(1).max(100).default(10),
  offset: z.number().min(0).default(0),
});

export const SearchResultSchema = z.object({
  id: z.string(),
  title: z.string(),
  content: z.string(),
  url: z.string(),
  score: z.number(),
  metadata: z.record(z.unknown()),
  tenant: z.string(),
});

export const SearchResponseSchema = z.object({
  success: z.boolean(),
  query: z.string(),
  results: z.array(SearchResultSchema),
  total_results: z.number(),
  processing_time_ms: z.number(),
  metadata: z.object({
    tenant: z.string(),
    capability_token: z.string(),
    enforce_mode: z.boolean(),
    query_hash: z.string(),
  }),
  error: z.string().optional(),
});

export type SearchQuery = z.infer<typeof SearchQuerySchema>;
export type SearchResult = z.infer<typeof SearchResultSchema>;
export type SearchResponse = z.infer<typeof SearchResponseSchema>;

// Search index interface
export interface SearchIndex {
  id: string;
  name: string;
  tenant: string;
  documents: Map<string, SearchResult>;
  inverted_index: Map<string, string[]>; // term -> document IDs
}

// Mock search configuration
export interface MockSearchConfig {
  seed: string;
  search_delay_ms: number;
  failure_rate: number;
  max_documents_per_index: number;
  max_query_length: number;
  supported_filters: string[];
  relevance_boost: number;
}

export class SearchEmulator {
  private readonly seed: string;
  private readonly enforceMode: boolean;
  private readonly capabilityToken: string;
  private readonly tenant: string;
  private readonly mockConfig: MockSearchConfig;
  private readonly searchIndices: Map<string, SearchIndex> = new Map();
  private readonly searchHistory: Map<string, SearchQuery[]> = new Map(); // tenant -> queries

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

  private initializeMockConfig(seed: string): MockSearchConfig {
    const hash = createHash("sha256").update(seed).digest("hex");

    return {
      seed,
      search_delay_ms: (parseInt(hash.slice(0, 8), 16) % 1000) + 50, // 50-1050ms
      failure_rate: (parseInt(hash.slice(8, 16), 16) % 100) / 1000, // 0-10%
      max_documents_per_index: (parseInt(hash.slice(16, 24), 16) % 1000) + 100, // 100-1100
      max_query_length: (parseInt(hash.slice(24, 32), 16) % 200) + 100, // 100-300
      supported_filters: ["category", "date_range", "author", "tags", "language", "file_type"],
      relevance_boost: (parseInt(hash.slice(0, 8), 16) % 100) / 100 + 0.5, // 0.5-1.5
    };
  }

  private initializeSampleData(): void {
    // Create sample search indices
    const acmeIndex: SearchIndex = {
      id: "idx_acme_docs",
      name: "ACME Documentation",
      tenant: "acme",
      documents: new Map(),
      inverted_index: new Map(),
    };

    const globexIndex: SearchIndex = {
      id: "idx_globex_kb",
      name: "Globex Knowledge Base",
      tenant: "globex",
      documents: new Map(),
      inverted_index: new Map(),
    };

    this.searchIndices.set(acmeIndex.id, acmeIndex);
    this.searchIndices.set(globexIndex.id, globexIndex);

    // Create sample documents for ACME
    const acmeDocuments: SearchResult[] = [
      {
        id: "doc_acme_001",
        title: "User Authentication Guide",
        content:
          "Complete guide to implementing user authentication in the ACME application. Covers OAuth2, JWT tokens, and session management.",
        url: "https://docs.acme.com/auth/guide",
        score: 0.95,
        metadata: {
          category: "documentation",
          author: "security-team@acme.com",
          tags: ["authentication", "security", "oauth2", "jwt"],
          language: "en",
          file_type: "markdown",
          last_updated: "2024-01-15",
        },
        tenant: "acme",
      },
      {
        id: "doc_acme_002",
        title: "API Rate Limiting",
        content:
          "Implementation details for API rate limiting using Redis. Includes configuration options and monitoring.",
        url: "https://docs.acme.com/api/rate-limiting",
        score: 0.87,
        metadata: {
          category: "technical",
          author: "backend-team@acme.com",
          tags: ["api", "rate-limiting", "redis", "performance"],
          language: "en",
          file_type: "markdown",
          last_updated: "2024-01-10",
        },
        tenant: "acme",
      },
      {
        id: "doc_acme_003",
        title: "Deployment Checklist",
        content:
          "Pre-deployment checklist for production releases. Security checks, performance tests, and rollback procedures.",
        url: "https://docs.acme.com/deploy/checklist",
        score: 0.92,
        metadata: {
          category: "operations",
          author: "devops@acme.com",
          tags: ["deployment", "production", "security", "checklist"],
          language: "en",
          file_type: "markdown",
          last_updated: "2024-01-12",
        },
        tenant: "acme",
      },
    ];

    // Create sample documents for Globex
    const globexDocuments: SearchResult[] = [
      {
        id: "doc_globex_001",
        title: "Microservices Architecture",
        content:
          "Overview of Globex microservices architecture. Service boundaries, communication patterns, and deployment strategies.",
        url: "https://kb.globex.com/architecture/microservices",
        score: 0.89,
        metadata: {
          category: "architecture",
          author: "architect@globex.com",
          tags: ["microservices", "architecture", "design", "patterns"],
          language: "en",
          file_type: "markdown",
          last_updated: "2024-01-14",
        },
        tenant: "globex",
      },
      {
        id: "doc_globex_002",
        title: "Database Sharding Strategy",
        content:
          "Database sharding implementation for horizontal scaling. Shard key selection, data distribution, and query routing.",
        url: "https://kb.globex.com/database/sharding",
        score: 0.91,
        metadata: {
          category: "database",
          author: "dba@globex.com",
          tags: ["database", "sharding", "scaling", "performance"],
          language: "en",
          file_type: "markdown",
          last_updated: "2024-01-08",
        },
        tenant: "globex",
      },
    ];

    // Add documents to indices and build inverted index
    this.addDocumentsToIndex(acmeIndex, acmeDocuments);
    this.addDocumentsToIndex(globexIndex, globexDocuments);
  }

  private addDocumentsToIndex(index: SearchIndex, documents: SearchResult[]): void {
    documents.forEach((doc) => {
      index.documents.set(doc.id, doc);

      // Build inverted index
      const terms = this.tokenize(doc.title + " " + doc.content);
      terms.forEach((term) => {
        if (!index.inverted_index.has(term)) {
          index.inverted_index.set(term, []);
        }
        index.inverted_index.get(term)!.push(doc.id);
      });
    });
  }

  private tokenize(text: string): string[] {
    return text
      .toLowerCase()
      .replace(/[^\w\s]/g, " ")
      .split(/\s+/)
      .filter((term) => term.length > 2)
      .slice(0, 100); // Limit terms per document
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
      .update(`${this.tenant}:search:${operation}`)
      .digest("hex");

    return capabilityToken === expectedHash;
  }

  // Perform search
  async search(query: SearchQuery): Promise<SearchResponse> {
    const startTime = Date.now();

    try {
      // Validate request schema
      const validatedQuery = SearchQuerySchema.parse(query);

      // Validate capability if in enforce mode
      if (this.enforceMode && !this.validateCapability(validatedQuery.capability_token, "search")) {
        return {
          success: false,
          query: validatedQuery.query,
          results: [],
          total_results: 0,
          processing_time_ms: Date.now() - startTime,
          metadata: {
            tenant: validatedQuery.tenant,
            capability_token: validatedQuery.capability_token,
            enforce_mode: this.enforceMode,
            query_hash: "",
          },
          error: "CAP_MISS: Missing or invalid capability token for search operations",
        };
      }

      // Check query length
      if (validatedQuery.query.length > this.mockConfig.max_query_length) {
        return {
          success: false,
          query: validatedQuery.query,
          results: [],
          total_results: 0,
          processing_time_ms: Date.now() - startTime,
          metadata: {
            tenant: validatedQuery.tenant,
            capability_token: validatedQuery.capability_token,
            enforce_mode: this.enforceMode,
            query_hash: "",
          },
          error: `QUERY_TOO_LONG: Maximum query length is ${this.mockConfig.max_query_length} characters`,
        };
      }

      // Simulate search delay
      await this.simulateSearchDelay();

      // Simulate potential failure
      if (Math.random() < this.mockConfig.failure_rate) {
        throw new Error("Simulated search operation failure");
      }

      // Find relevant index for tenant
      const index = Array.from(this.searchIndices.values()).find(
        (idx) => idx.tenant === validatedQuery.tenant,
      );
      if (!index) {
        return {
          success: false,
          query: validatedQuery.query,
          results: [],
          total_results: 0,
          processing_time_ms: Date.now() - startTime,
          metadata: {
            tenant: validatedQuery.tenant,
            capability_token: validatedQuery.capability_token,
            enforce_mode: this.enforceMode,
            query_hash: "",
          },
          error: "INDEX_NOT_FOUND: No search index found for tenant",
        };
      }

      // Perform search
      const results = this.performSearch(index, validatedQuery);

      // Apply filters
      const filteredResults = this.applyFilters(results, validatedQuery.filters || {});

      // Apply pagination
      const paginatedResults = filteredResults.slice(
        validatedQuery.offset,
        validatedQuery.offset + validatedQuery.max_results,
      );

      // Store search history
      if (!this.searchHistory.has(validatedQuery.tenant)) {
        this.searchHistory.set(validatedQuery.tenant, []);
      }
      this.searchHistory.get(validatedQuery.tenant)!.push(validatedQuery);

      // Generate query hash
      const queryHash = createHash("sha256")
        .update(validatedQuery.query + validatedQuery.tenant + Date.now())
        .digest("hex");

      const response: SearchResponse = {
        success: true,
        query: validatedQuery.query,
        results: paginatedResults,
        total_results: filteredResults.length,
        processing_time_ms: Date.now() - startTime,
        metadata: {
          tenant: validatedQuery.tenant,
          capability_token: validatedQuery.capability_token,
          enforce_mode: this.enforceMode,
          query_hash: queryHash,
        },
      };

      return response;
    } catch (error) {
      return {
        success: false,
        query: query.query || "",
        results: [],
        total_results: 0,
        processing_time_ms: Date.now() - startTime,
        metadata: {
          tenant: query.tenant || "unknown",
          capability_token: query.capability_token || "",
          enforce_mode: this.enforceMode,
          query_hash: "",
        },
        error: error instanceof Error ? error.message : "Unknown error",
      };
    }
  }

  // Perform actual search using inverted index
  private performSearch(index: SearchIndex, query: SearchQuery): SearchResult[] {
    const terms = this.tokenize(query.query);
    const documentScores = new Map<string, number>();

    // Calculate relevance scores
    terms.forEach((term) => {
      const documentIds = index.inverted_index.get(term) || [];
      documentIds.forEach((docId) => {
        const currentScore = documentScores.get(docId) || 0;
        documentScores.set(docId, currentScore + 1);
      });
    });

    // Convert to results and sort by score
    const results: SearchResult[] = [];
    documentScores.forEach((score, docId) => {
      const doc = index.documents.get(docId);
      if (doc) {
        // Apply relevance boost
        const boostedScore = score * this.mockConfig.relevance_boost;
        results.push({ ...doc, score: Math.min(boostedScore, 1.0) });
      }
    });

    return results.sort((a, b) => b.score - a.score);
  }

  // Apply search filters
  private applyFilters(results: SearchResult[], filters: Record<string, any>): SearchResult[] {
    if (Object.keys(filters).length === 0) {
      return results;
    }

    return results.filter((result) => {
      for (const [key, value] of Object.entries(filters)) {
        if (result.metadata[key] !== value) {
          return false;
        }
      }
      return true;
    });
  }

  // Get search index by ID
  async getIndex(indexId: string, capabilityToken: string): Promise<SearchIndex | null> {
    // Validate capability if in enforce mode
    if (this.enforceMode && !this.validateCapability(capabilityToken, "read")) {
      throw new Error("CAP_MISS: Missing or invalid capability token for search index reading");
    }

    return this.searchIndices.get(indexId) || null;
  }

  // List search indices for a tenant
  async listIndices(tenant: string, capabilityToken: string): Promise<SearchIndex[]> {
    // Validate capability if in enforce mode
    if (this.enforceMode && !this.validateCapability(capabilityToken, "read")) {
      throw new Error("CAP_MISS: Missing or invalid capability token for search index listing");
    }

    return Array.from(this.searchIndices.values()).filter((idx) => idx.tenant === tenant);
  }

  // Get search history for a tenant
  async getSearchHistory(tenant: string, capabilityToken: string): Promise<SearchQuery[]> {
    // Validate capability if in enforce mode
    if (this.enforceMode && !this.validateCapability(capabilityToken, "read")) {
      throw new Error("CAP_MISS: Missing or invalid capability token for search history reading");
    }

    return this.searchHistory.get(tenant) || [];
  }

  // Simulate search delay
  private async simulateSearchDelay(): Promise<void> {
    return new Promise((resolve) => {
      setTimeout(resolve, this.mockConfig.search_delay_ms);
    });
  }

  // Get mock configuration
  getMockConfig(): MockSearchConfig {
    return { ...this.mockConfig };
  }

  // Reset emulator state
  reset(): void {
    this.searchIndices.clear();
    this.searchHistory.clear();
    this.initializeSampleData();
  }

  // Switch to real mode (placeholder for real search service integration)
  async switchToRealMode(apiKey: string, serviceConfig: any): Promise<void> {
    if (this.enforceMode) {
      throw new Error("Cannot switch to real mode while enforce mode is enabled");
    }

    // In a real implementation, this would initialize a real search service
    // For now, we'll just log the intention
    console.log("Switching to real search service mode");
    console.log("API Key:", apiKey ? "***" + apiKey.slice(-4) : "none");
    console.log("Service Config:", serviceConfig);
  }
}

// Export factory function for easy instantiation
export const createSearchEmulator = (
  seed: string = "default",
  enforceMode: boolean = true,
  capabilityToken: string = "",
  tenant: string = "default",
): SearchEmulator => {
  return new SearchEmulator(seed, enforceMode, capabilityToken, tenant);
};

// Export default instance
export const defaultSearchEmulator = createSearchEmulator();
