import { createHash } from "crypto";

// Semantic Cache Module
// Caches low-risk answers with receipt hash keys for efficient retrieval

export interface CacheEntry {
  key: string;
  content_hash: string;
  receipt_hash: string;
  response: any;
  metadata: CacheMetadata;
  created_at: string;
  accessed_at: string;
  expires_at: string;
  access_count: number;
  last_modified: string;
}

export interface CacheMetadata {
  tenant: string;
  user_id: string;
  plan_id: string;
  step_id: string;
  risk_level: "low" | "medium" | "high" | "critical";
  model_used: string;
  content_type: string;
  content_length: number;
  labels: string[];
  tags: string[];
  confidence: number;
  ttl_seconds: number;
  max_access_count: number;
  compression_ratio?: number;
  encryption_enabled: boolean;
  created_at?: string;
  accessed_at?: string;
  last_modified?: string;
}

export interface CacheQuery {
  content_hash?: string;
  receipt_hash?: string;
  tenant?: string;
  user_id?: string;
  plan_id?: string;
  step_id?: string;
  risk_level?: "low" | "medium" | "high" | "critical";
  labels?: string[];
  tags?: string[];
  content_type?: string;
  max_age_seconds?: number;
}

export interface CacheStats {
  total_entries: number;
  total_size_bytes: number;
  hit_rate: number;
  miss_rate: number;
  eviction_count: number;
  compression_ratio: number;
  avg_ttl_seconds: number;
  entries_by_risk: Record<string, number>;
  entries_by_tenant: Record<string, number>;
  entries_by_type: Record<string, number>;
}

export interface CacheEvictionPolicy {
  max_entries: number;
  max_size_bytes: number;
  max_age_seconds: number;
  max_access_count: number;
  priority: "lru" | "lfu" | "ttl" | "hybrid";
  enable_compression: boolean;
  enable_encryption: boolean;
}

export class SemanticCache {
  private cache: Map<string, CacheEntry> = new Map();
  private indexByContentHash: Map<string, Set<string>> = new Map();
  private indexByReceiptHash: Map<string, Set<string>> = new Map();
  private indexByTenant: Map<string, Set<string>> = new Map();
  private indexByRiskLevel: Map<string, Set<string>> = new Map();
  private indexByLabels: Map<string, Set<string>> = new Map();

  private evictionPolicy: CacheEvictionPolicy;
  private stats = {
    hits: 0,
    misses: 0,
    sets: 0,
    deletes: 0,
    evictions: 0,
    total_size_bytes: 0,
    compression_savings_bytes: 0,
  };

  constructor(evictionPolicy?: Partial<CacheEvictionPolicy>) {
    this.evictionPolicy = {
      max_entries: 10000,
      max_size_bytes: 100 * 1024 * 1024, // 100MB
      max_age_seconds: 24 * 60 * 60, // 24 hours
      max_access_count: 1000,
      priority: "hybrid",
      enable_compression: true,
      enable_encryption: false,
      ...evictionPolicy,
    };

    // Start background maintenance
    this.startMaintenance();
  }

  /**
   * Set a cache entry
   */
  async set(
    key: string,
    content: string,
    receipt: string,
    response: any,
    metadata: Omit<CacheMetadata, "created_at" | "accessed_at" | "last_modified">,
  ): Promise<void> {
    const contentHash = this.hashContent(content);
    const receiptHash = this.hashReceipt(receipt);

    // Check if entry already exists
    if (this.cache.has(key)) {
      await this.delete(key);
    }

    // Create cache entry
    const now = new Date();
    const entry: CacheEntry = {
      key,
      content_hash: contentHash,
      receipt_hash: receiptHash,
      response,
      metadata: {
        ...metadata,
        created_at: now.toISOString(),
        accessed_at: now.toISOString(),
        last_modified: now.toISOString(),
      },
      created_at: now.toISOString(),
      accessed_at: now.toISOString(),
      expires_at: new Date(now.getTime() + metadata.ttl_seconds * 1000).toISOString(),
      access_count: 0,
      last_modified: now.toISOString(),
    };

    // Compress response if enabled
    if (this.evictionPolicy.enable_compression) {
      entry.response = await this.compressResponse(response);
      entry.metadata.compression_ratio = this.calculateCompressionRatio(response, entry.response);
    }

    // Encrypt response if enabled
    if (this.evictionPolicy.enable_encryption) {
      entry.response = await this.encryptResponse(entry.response);
      entry.metadata.encryption_enabled = true;
    }

    // Store entry
    this.cache.set(key, entry);
    this.updateIndexes(key, entry);

    // Update stats
    this.stats.sets++;
    this.stats.total_size_bytes += this.calculateEntrySize(entry);

    // Check if eviction is needed
    await this.checkEviction();
  }

  /**
   * Get a cache entry
   */
  async get(key: string): Promise<CacheEntry | null> {
    const entry = this.cache.get(key);

    if (!entry) {
      this.stats.misses++;
      return null;
    }

    // Check if entry is expired
    if (this.isExpired(entry)) {
      await this.delete(key);
      this.stats.misses++;
      return null;
    }

    // Check access count limit
    if (entry.access_count >= entry.metadata.max_access_count) {
      await this.delete(key);
      this.stats.misses++;
      return null;
    }

    // Update access metadata
    entry.accessed_at = new Date().toISOString();
    entry.access_count++;

    // Decrypt response if needed
    if (entry.metadata.encryption_enabled) {
      entry.response = await this.decryptResponse(entry.response);
    }

    this.stats.hits++;
    return entry;
  }

  /**
   * Query cache by various criteria
   */
  async query(query: CacheQuery): Promise<CacheEntry[]> {
    const candidateKeys = new Set<string>();
    let firstIndex = true;

    // Build candidate set based on query criteria
    if (query.content_hash) {
      const keys = this.indexByContentHash.get(query.content_hash) || new Set();
      if (firstIndex) {
        keys.forEach((key) => candidateKeys.add(key));
        firstIndex = false;
      } else {
        candidateKeys.forEach((key) => {
          if (!keys.has(key)) candidateKeys.delete(key);
        });
      }
    }

    if (query.receipt_hash) {
      const keys = this.indexByReceiptHash.get(query.receipt_hash) || new Set();
      if (firstIndex) {
        keys.forEach((key) => candidateKeys.add(key));
        firstIndex = false;
      } else {
        candidateKeys.forEach((key) => {
          if (!keys.has(key)) candidateKeys.delete(key);
        });
      }
    }

    if (query.tenant) {
      const keys = this.indexByTenant.get(query.tenant) || new Set();
      if (firstIndex) {
        keys.forEach((key) => candidateKeys.add(key));
        firstIndex = false;
      } else {
        candidateKeys.forEach((key) => {
          if (!keys.has(key)) candidateKeys.delete(key);
        });
      }
    }

    if (query.risk_level) {
      const keys = this.indexByRiskLevel.get(query.risk_level) || new Set();
      if (firstIndex) {
        keys.forEach((key) => candidateKeys.add(key));
        firstIndex = false;
      } else {
        candidateKeys.forEach((key) => {
          if (!keys.has(key)) candidateKeys.delete(key);
        });
      }
    }

    if (query.labels && query.labels.length > 0) {
      query.labels.forEach((label) => {
        const keys = this.indexByLabels.get(label) || new Set();
        if (firstIndex) {
          keys.forEach((key) => candidateKeys.add(key));
          firstIndex = false;
        } else {
          candidateKeys.forEach((key) => {
            if (!keys.has(key)) candidateKeys.delete(key);
          });
        }
      });
    }

    // If no specific criteria, return all entries
    if (firstIndex) {
      this.cache.forEach((entry, key) => candidateKeys.add(key));
    }

    // Filter and return results
    const results: CacheEntry[] = [];
    for (const key of candidateKeys) {
      const entry = this.cache.get(key);
      if (entry && this.matchesQuery(entry, query)) {
        results.push(entry);
      }
    }

    return results;
  }

  /**
   * Delete a cache entry
   */
  async delete(key: string): Promise<boolean> {
    const entry = this.cache.get(key);
    if (!entry) {
      return false;
    }

    // Remove from main cache
    this.cache.delete(key);

    // Remove from indexes
    this.removeFromIndexes(key, entry);

    // Update stats
    this.stats.deletes++;
    this.stats.total_size_bytes -= this.calculateEntrySize(entry);

    return true;
  }

  /**
   * Clear all cache entries
   */
  async clear(): Promise<void> {
    this.cache.clear();
    this.indexByContentHash.clear();
    this.indexByReceiptHash.clear();
    this.indexByTenant.clear();
    this.indexByRiskLevel.clear();
    this.indexByLabels.clear();

    this.stats.total_size_bytes = 0;
  }

  /**
   * Get cache statistics
   */
  getStats(): CacheStats {
    const totalEntries = this.cache.size;
    const hitRate = totalEntries > 0 ? this.stats.hits / (this.stats.hits + this.stats.misses) : 0;
    const missRate = 1 - hitRate;

    const entriesByRisk: Record<string, number> = {};
    const entriesByTenant: Record<string, number> = {};
    const entriesByType: Record<string, number> = {};

    let totalTtl = 0;

    this.cache.forEach((entry) => {
      // Count by risk level
      const risk = entry.metadata.risk_level;
      entriesByRisk[risk] = (entriesByRisk[risk] || 0) + 1;

      // Count by tenant
      const tenant = entry.metadata.tenant;
      entriesByTenant[tenant] = (entriesByTenant[tenant] || 0) + 1;

      // Count by content type
      const type = entry.metadata.content_type;
      entriesByType[type] = (entriesByType[type] || 0) + 1;

      totalTtl += entry.metadata.ttl_seconds;
    });

    return {
      total_entries: totalEntries,
      total_size_bytes: this.stats.total_size_bytes,
      hit_rate: hitRate,
      miss_rate: missRate,
      eviction_count: this.stats.evictions,
      compression_ratio: this.stats.compression_savings_bytes / this.stats.total_size_bytes,
      avg_ttl_seconds: totalEntries > 0 ? totalTtl / totalEntries : 0,
      entries_by_risk: entriesByRisk,
      entries_by_tenant: entriesByTenant,
      entries_by_type: entriesByType,
    };
  }

  /**
   * Update cache indexes
   */
  private updateIndexes(key: string, entry: CacheEntry): void {
    // Index by content hash
    if (!this.indexByContentHash.has(entry.content_hash)) {
      this.indexByContentHash.set(entry.content_hash, new Set());
    }
    this.indexByContentHash.get(entry.content_hash)!.add(key);

    // Index by receipt hash
    if (!this.indexByReceiptHash.has(entry.receipt_hash)) {
      this.indexByReceiptHash.set(entry.receipt_hash, new Set());
    }
    this.indexByReceiptHash.get(entry.receipt_hash)!.add(key);

    // Index by tenant
    if (!this.indexByTenant.has(entry.metadata.tenant)) {
      this.indexByTenant.set(entry.metadata.tenant, new Set());
    }
    this.indexByTenant.get(entry.metadata.tenant)!.add(key);

    // Index by risk level
    if (!this.indexByRiskLevel.has(entry.metadata.risk_level)) {
      this.indexByRiskLevel.set(entry.metadata.risk_level, new Set());
    }
    this.indexByRiskLevel.get(entry.metadata.risk_level)!.add(key);

    // Index by labels
    entry.metadata.labels.forEach((label) => {
      if (!this.indexByLabels.has(label)) {
        this.indexByLabels.set(label, new Set());
      }
      this.indexByLabels.get(label)!.add(key);
    });
  }

  /**
   * Remove from cache indexes
   */
  private removeFromIndexes(key: string, entry: CacheEntry): void {
    // Remove from content hash index
    const contentHashSet = this.indexByContentHash.get(entry.content_hash);
    if (contentHashSet) {
      contentHashSet.delete(key);
      if (contentHashSet.size === 0) {
        this.indexByContentHash.delete(entry.content_hash);
      }
    }

    // Remove from receipt hash index
    const receiptHashSet = this.indexByReceiptHash.get(entry.receipt_hash);
    if (receiptHashSet) {
      receiptHashSet.delete(key);
      if (receiptHashSet.size === 0) {
        this.indexByReceiptHash.delete(entry.receipt_hash);
      }
    }

    // Remove from tenant index
    const tenantSet = this.indexByTenant.get(entry.metadata.tenant);
    if (tenantSet) {
      tenantSet.delete(key);
      if (tenantSet.size === 0) {
        this.indexByTenant.delete(entry.metadata.tenant);
      }
    }

    // Remove from risk level index
    const riskSet = this.indexByRiskLevel.get(entry.metadata.risk_level);
    if (riskSet) {
      riskSet.delete(key);
      if (riskSet.size === 0) {
        this.indexByRiskLevel.delete(entry.metadata.risk_level);
      }
    }

    // Remove from labels index
    entry.metadata.labels.forEach((label) => {
      const labelSet = this.indexByLabels.get(label);
      if (labelSet) {
        labelSet.delete(key);
        if (labelSet.size === 0) {
          this.indexByLabels.delete(label);
        }
      }
    });
  }

  /**
   * Check if entry matches query criteria
   */
  private matchesQuery(entry: CacheEntry, query: CacheQuery): boolean {
    if (query.content_hash && entry.content_hash !== query.content_hash) return false;
    if (query.receipt_hash && entry.receipt_hash !== query.receipt_hash) return false;
    if (query.tenant && entry.metadata.tenant !== query.tenant) return false;
    if (query.user_id && entry.metadata.user_id !== query.user_id) return false;
    if (query.plan_id && entry.metadata.plan_id !== query.plan_id) return false;
    if (query.step_id && entry.metadata.step_id !== query.step_id) return false;
    if (query.risk_level && entry.metadata.risk_level !== query.risk_level) return false;
    if (query.content_type && entry.metadata.content_type !== query.content_type) return false;

    if (query.max_age_seconds) {
      const age = (Date.now() - new Date(entry.created_at).getTime()) / 1000;
      if (age > query.max_age_seconds) return false;
    }

    if (query.labels && query.labels.length > 0) {
      const hasAllLabels = query.labels.every((label) => entry.metadata.labels.includes(label));
      if (!hasAllLabels) return false;
    }

    if (query.tags && query.tags.length > 0) {
      const hasAllTags = query.tags.every((tag) => entry.metadata.tags.includes(tag));
      if (!hasAllTags) return false;
    }

    return true;
  }

  /**
   * Check if entry is expired
   */
  private isExpired(entry: CacheEntry): boolean {
    return new Date() > new Date(entry.expires_at);
  }

  /**
   * Check if eviction is needed and perform it
   */
  private async checkEviction(): Promise<void> {
    const needsEviction =
      this.cache.size > this.evictionPolicy.max_entries ||
      this.stats.total_size_bytes > this.evictionPolicy.max_size_bytes;

    if (needsEviction) {
      await this.performEviction();
    }
  }

  /**
   * Perform cache eviction based on policy
   */
  private async performEviction(): Promise<void> {
    const entries = Array.from(this.cache.entries());
    let evictedCount = 0;

    switch (this.evictionPolicy.priority) {
      case "lru":
        entries.sort(
          (a, b) => new Date(a[1].accessed_at).getTime() - new Date(b[1].accessed_at).getTime(),
        );
        break;
      case "lfu":
        entries.sort((a, b) => a[1].access_count - b[1].access_count);
        break;
      case "ttl":
        entries.sort(
          (a, b) => new Date(a[1].expires_at).getTime() - new Date(b[1].expires_at).getTime(),
        );
        break;
      case "hybrid":
        entries.sort((a, b) => {
          const aScore = this.calculateEvictionScore(a[1]);
          const bScore = this.calculateEvictionScore(b[1]);
          return aScore - bScore;
        });
        break;
    }

    // Evict entries until we're under limits
    for (const [key] of entries) {
      if (
        this.cache.size <= this.evictionPolicy.max_entries * 0.8 &&
        this.stats.total_size_bytes <= this.evictionPolicy.max_size_bytes * 0.8
      ) {
        break;
      }

      await this.delete(key);
      evictedCount++;
    }

    this.stats.evictions += evictedCount;
  }

  /**
   * Calculate eviction score for hybrid policy
   */
  private calculateEvictionScore(entry: CacheEntry): number {
    const now = Date.now();
    const age = (now - new Date(entry.created_at).getTime()) / 1000;
    const timeToExpiry = (new Date(entry.expires_at).getTime() - now) / 1000;
    const accessRate = entry.access_count / Math.max(age, 1);

    // Lower score = higher priority for eviction
    return (
      age * 0.4 + (1 / Math.max(accessRate, 0.1)) * 0.3 + (1 / Math.max(timeToExpiry, 1)) * 0.3
    );
  }

  /**
   * Start background maintenance
   */
  private startMaintenance(): void {
    setInterval(
      () => {
        this.performMaintenance();
      },
      5 * 60 * 1000,
    ); // Every 5 minutes
  }

  /**
   * Perform background maintenance
   */
  private async performMaintenance(): Promise<void> {
    const keysToDelete: string[] = [];

    // Find expired entries
    this.cache.forEach((entry, key) => {
      if (this.isExpired(entry)) {
        keysToDelete.push(key);
      }
    });

    // Delete expired entries
    for (const key of keysToDelete) {
      await this.delete(key);
    }

    // Check eviction
    await this.checkEviction();
  }

  // Utility methods
  private hashContent(content: string): string {
    return createHash("sha256").update(content).digest("hex");
  }

  private hashReceipt(receipt: string): string {
    return createHash("sha256").update(receipt).digest("hex");
  }

  private async compressResponse(response: any): Promise<any> {
    // Simple compression - in production, use proper compression libraries
    const responseStr = JSON.stringify(response);
    if (responseStr.length > 1024) {
      // For large responses, store compressed version
      return `COMPRESSED:${responseStr.length}:${responseStr.substring(0, 100)}...`;
    }
    return response;
  }

  private async encryptResponse(response: any): Promise<any> {
    // Simple encryption simulation - in production, use proper encryption
    return `ENCRYPTED:${JSON.stringify(response)}`;
  }

  private async decryptResponse(response: any): Promise<any> {
    // Simple decryption simulation
    if (typeof response === "string" && response.startsWith("ENCRYPTED:")) {
      return JSON.parse(response.substring(10));
    }
    return response;
  }

  private calculateCompressionRatio(original: any, compressed: any): number {
    const originalSize = JSON.stringify(original).length;
    const compressedSize = JSON.stringify(compressed).length;
    return originalSize > 0 ? (originalSize - compressedSize) / originalSize : 0;
  }

  private calculateEntrySize(entry: CacheEntry): number {
    return JSON.stringify(entry).length;
  }

  // Public access methods
  getCacheSize(): number {
    return this.cache.size;
  }

  getIndexSizes(): Record<string, number> {
    return {
      content_hash: this.indexByContentHash.size,
      receipt_hash: this.indexByReceiptHash.size,
      tenant: this.indexByTenant.size,
      risk_level: this.indexByRiskLevel.size,
      labels: this.indexByLabels.size,
    };
  }

  updateEvictionPolicy(policy: Partial<CacheEvictionPolicy>): void {
    this.evictionPolicy = { ...this.evictionPolicy, ...policy };
  }
}

// Export singleton instance
export const semanticCache = new SemanticCache();
