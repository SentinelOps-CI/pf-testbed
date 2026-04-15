import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
  type KeyObject,
} from "crypto";
import { z } from "zod";

/** PKCS#8 DER prefix for a raw 32-byte Ed25519 seed (RFC 8410 / OpenSSL layout). */
const ED25519_SEED_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

function ed25519KeyPairFromSeed(seed32: Buffer): { privateKey: KeyObject; publicKey: KeyObject } {
  if (seed32.length !== 32) {
    throw new Error("Ed25519 private key seed must be 32 bytes");
  }
  const der = Buffer.concat([ED25519_SEED_PKCS8_PREFIX, seed32]);
  const privateKey = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  return { privateKey, publicKey: createPublicKey(privateKey) };
}

function ed25519PublicKeyRawHex(publicKey: KeyObject): string {
  const jwk = publicKey.export({ format: "jwk" }) as { x?: string };
  if (!jwk.x) {
    throw new Error("Ed25519 public key JWK export missing x");
  }
  const pad = (4 - (jwk.x.length % 4)) % 4;
  const b64 = jwk.x.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(pad);
  return Buffer.from(b64, "base64").toString("hex");
}

function levenshteinDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  if (m === 0) {
    return n;
  }
  if (n === 0) {
    return m;
  }
  let prev = Array.from({ length: n + 1 }, (_, j) => j);
  for (let i = 1; i <= m; i++) {
    const cur = new Array<number>(n + 1);
    cur[0] = i;
    const ai = a[i - 1]!;
    for (let j = 1; j <= n; j++) {
      const cost = ai === b[j - 1] ? 0 : 1;
      cur[j] = Math.min(prev[j]! + 1, cur[j - 1]! + 1, prev[j - 1]! + cost);
    }
    prev = cur;
  }
  return prev[n]!;
}

function normalizedNearDuplicateScore(prev: string, curr: string): number {
  const maxLen = 800;
  const p = prev.length > maxLen ? prev.slice(0, maxLen) : prev;
  const c = curr.length > maxLen ? curr.slice(0, maxLen) : curr;
  const d = levenshteinDistance(p, c);
  return 1 - d / Math.max(p.length, c.length, 1);
}

// Egress Certificate Schema
export const EgressCertificateSchema = z.object({
  pii: z.enum(["detected", "none", "masked"]),
  secrets: z.enum(["detected", "none", "masked"]),
  near_dupe: z.enum(["detected", "none"]),
  non_interference: z.enum(["passed", "failed"]),
  influencing_labels: z.array(z.string()),
  policy_hash: z.string(),
  text_hash: z.string(),
  attestation_ref: z.string(),
  sig: z.string(),
});

export type EgressCertificate = z.infer<typeof EgressCertificateSchema>;

// Content Processing Request
export const ContentRequestSchema = z.object({
  content: z.string(),
  tenant: z.string(),
  context: z.string(),
  policy: z.string().optional(),
  labels: z.array(z.string()).optional(),
});

export type ContentRequest = z.infer<typeof ContentRequestSchema>;

// Content Processing Result
export const ContentResultSchema = z.object({
  content: z.string(),
  certificate: EgressCertificateSchema,
  processing_time: z.number(),
  blocked: z.boolean(),
  reason: z.string().optional(),
});

export type ContentResult = z.infer<typeof ContentResultSchema>;

// Pattern for sensitive data detection
export interface SensitivePattern {
  name: string;
  pattern: RegExp;
  category: "pii" | "secret" | "other";
  confidence: number;
  replacement?: string;
}

/** Runs registered RegExp patterns over text (true multi-pattern regex scan). */
class AhoCorasick {
  private readonly patterns: SensitivePattern[];

  constructor(patterns: SensitivePattern[]) {
    this.patterns = patterns;
  }

  search(text: string): Array<{ pattern: SensitivePattern; start: number; end: number }> {
    const matches: Array<{
      pattern: SensitivePattern;
      start: number;
      end: number;
    }> = [];

    for (const sp of this.patterns) {
      const re = sp.pattern;
      const flags = re.flags.includes("g") ? re.flags : `${re.flags}g`;
      const globalRe = new RegExp(re.source, flags);
      let m: RegExpExecArray | null;
      while ((m = globalRe.exec(text)) !== null) {
        matches.push({ pattern: sp, start: m.index, end: m.index + m[0].length });
        if (m[0].length === 0) {
          globalRe.lastIndex++;
        }
      }
    }

    return matches;
  }
}

// SimHash implementation for near-duplicate detection
class SimHash {
  private readonly hashBits = 64;

  compute(text: string): string {
    const hash = createHash("sha256").update(text).digest();
    const bits = new Array(this.hashBits).fill(0);

    // Convert hash to bit array
    for (let i = 0; i < hash.length && i * 8 < this.hashBits; i++) {
      const byte = hash[i]!;
      for (let j = 0; j < 8 && i * 8 + j < this.hashBits; j++) {
        bits[i * 8 + j] = (byte >> j) & 1;
      }
    }

    // Convert bits to hex string
    let result = "";
    for (let i = 0; i < this.hashBits; i += 4) {
      let nibble = 0;
      for (let j = 0; j < 4 && i + j < this.hashBits; j++) {
        nibble |= bits[i + j] << j;
      }
      result += nibble.toString(16);
    }

    return result;
  }

  similarity(hash1: string, hash2: string): number {
    if (hash1.length !== hash2.length) return 0;

    let differences = 0;
    for (let i = 0; i < hash1.length; i++) {
      if (hash1[i] !== hash2[i]) differences++;
    }

    return 1 - differences / hash1.length;
  }
}

// MinHash implementation for similarity analysis
class MinHash {
  private readonly numHashes: number;
  private readonly hashFunctions: Array<(value: string) => number>;

  constructor(numHashes: number = 100) {
    this.numHashes = numHashes;
    this.hashFunctions = this.generateHashFunctions();
  }

  private generateHashFunctions(): Array<(value: string) => number> {
    const functions: Array<(value: string) => number> = [];

    for (let i = 0; i < this.numHashes; i++) {
      const a = Math.floor(Math.random() * 1000000) + 1;
      const b = Math.floor(Math.random() * 1000000) + 1;
      const p = 1000000007; // Large prime

      functions.push((value: string) => {
        const hash = createHash("sha256")
          .update(value + i.toString())
          .digest("hex");
        const numericHash = parseInt(hash.substring(0, 8), 16);
        return (a * numericHash + b) % p;
      });
    }

    return functions;
  }

  compute(text: string): number[] {
    let words = text.toLowerCase().split(/\s+/);
    if (words.length > 400) {
      words = words.slice(0, 400);
    }
    const signatures: number[] = [];

    for (const hashFn of this.hashFunctions) {
      let minHash = Infinity;
      for (const word of words) {
        const hash = hashFn(word);
        if (hash < minHash) minHash = hash;
      }
      signatures.push(minHash);
    }

    return signatures;
  }

  similarity(sig1: number[], sig2: number[]): number {
    if (sig1.length !== sig2.length) return 0;

    let matches = 0;
    for (let i = 0; i < sig1.length; i++) {
      if (sig1[i] === sig2[i]) matches++;
    }

    return matches / sig1.length;
  }
}

// Format and entropy analysis
class FormatAnalyzer {
  analyze(text: string): {
    entropy: number;
    hasStructuredData: boolean;
    dataTypes: string[];
    suspiciousPatterns: string[];
  } {
    const entropy = this.calculateEntropy(text);
    const hasStructuredData = this.detectStructuredData(text);
    const dataTypes = this.identifyDataTypes(text);
    const suspiciousPatterns = this.findSuspiciousPatterns(text);

    return {
      entropy,
      hasStructuredData,
      dataTypes,
      suspiciousPatterns,
    };
  }

  private calculateEntropy(text: string): number {
    const charCount = new Map<string, number>();
    for (const char of text) {
      charCount.set(char, (charCount.get(char) || 0) + 1);
    }

    let entropy = 0;
    const length = text.length;

    for (const count of charCount.values()) {
      const probability = count / length;
      entropy -= probability * Math.log2(probability);
    }

    return entropy;
  }

  private detectStructuredData(text: string): boolean {
    const patterns = [
      /\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/, // Credit card
      /\b\d{3}-\d{2}-\d{4}\b/, // SSN
      /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/, // Email
      /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/, // IP address
      /\b[A-Za-z0-9+/]{20,}={0,2}\b/, // Base64
      /\b[A-Fa-f0-9]{32,}\b/, // Hex strings
    ];

    return patterns.some((pattern) => pattern.test(text));
  }

  private identifyDataTypes(text: string): string[] {
    const types: string[] = [];

    if (/\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/.test(text)) types.push("credit_card");
    if (/\b\d{3}-\d{2}-\d{4}\b/.test(text)) types.push("ssn");
    if (/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/.test(text)) types.push("email");
    if (/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(text)) types.push("ip_address");
    if (/\b[A-Za-z0-9+/]{20,}={0,2}\b/.test(text)) types.push("base64");
    if (/\b[A-Fa-f0-9]{32,}\b/.test(text)) types.push("hex_string");
    if (/\b(api_key|password|secret|token)\s*[:=]\s*\S+/i.test(text)) types.push("credential");

    return types;
  }

  private findSuspiciousPatterns(text: string): string[] {
    const patterns: string[] = [];

    if (text.includes("DROP TABLE") || text.includes("INSERT INTO")) patterns.push("sql_injection");
    if (text.includes("<script>") || text.includes("javascript:")) patterns.push("xss");
    if (text.includes("rm -rf") || text.includes("cat /etc")) patterns.push("command_injection");
    if (text.includes("../../../")) patterns.push("path_traversal");
    if (text.includes("{{") || text.includes("${")) patterns.push("template_injection");

    return patterns;
  }
}

// LLM Analysis for ambiguous cases
class LLMAnalyzer {
  private readonly provider: string;

  constructor(provider: string = "mock", _apiKey?: string) {
    this.provider = provider;
  }

  async analyze(
    content: string,
    context: string,
  ): Promise<{
    isSensitive: boolean;
    confidence: number;
    reasoning: string;
    category: string;
  }> {
    // Mock implementation - in production this would call actual LLM APIs
    if (this.provider === "mock") {
      return this.mockAnalysis(content, context);
    }

    // Real LLM implementation would go here
    throw new Error("Real LLM provider not implemented");
  }

  private mockAnalysis(
    content: string,
    _context: string,
  ): {
    isSensitive: boolean;
    confidence: number;
    reasoning: string;
    category: string;
  } {
    const lowerContent = content.toLowerCase();

    // Simple heuristics for demonstration
    if (
      lowerContent.includes("password") ||
      lowerContent.includes("secret") ||
      /\b(?:api|access)\s+key\b/i.test(content) ||
      /\bpwd\b/i.test(content) ||
      /\bpass\s*:/i.test(content)
    ) {
      return {
        isSensitive: true,
        confidence: 0.9,
        reasoning: "Contains credential-related terms",
        category: "credential",
      };
    }

    if (lowerContent.includes("ssn") || lowerContent.includes("social security")) {
      return {
        isSensitive: true,
        confidence: 0.95,
        reasoning: "Contains SSN-related terms",
        category: "pii",
      };
    }

    if (lowerContent.includes("credit card") || lowerContent.includes("cc number")) {
      return {
        isSensitive: true,
        confidence: 0.9,
        reasoning: "Contains credit card information",
        category: "pii",
      };
    }

    return {
      isSensitive: false,
      confidence: 0.8,
      reasoning: "No obvious sensitive content detected",
      category: "safe",
    };
  }
}

// Main Egress Firewall class
export class EgressFirewall {
  private readonly patterns: SensitivePattern[];
  private readonly policies: string[];
  private readonly ahoCorasick: AhoCorasick;
  private readonly simHash: SimHash;
  private readonly minHash: MinHash;
  private readonly formatAnalyzer: FormatAnalyzer;
  private readonly llmAnalyzer: LLMAnalyzer;
  private readonly privateKey: KeyObject;
  private readonly publicKey: KeyObject;
  private readonly knownContentHashes: Set<string> = new Set();
  private readonly recentNormalized: string[] = [];
  private readonly maxRecentNormalized = 300;

  constructor(config: {
    patterns?: SensitivePattern[];
    policies: string[];
    llmProvider?: string;
    llmApiKey?: string;
    privateKeyHex: string;
  }) {
    this.patterns = config.patterns || this.getDefaultPatterns();
    this.policies = config.policies;
    this.ahoCorasick = new AhoCorasick(this.patterns);
    this.simHash = new SimHash();
    this.minHash = new MinHash();
    this.formatAnalyzer = new FormatAnalyzer();
    this.llmAnalyzer = new LLMAnalyzer(config.llmProvider || "mock", config.llmApiKey);

    const seed = Buffer.from(config.privateKeyHex, "hex");
    const pair = ed25519KeyPairFromSeed(seed);
    this.privateKey = pair.privateKey;
    this.publicKey = pair.publicKey;
  }

  private getDefaultPatterns(): SensitivePattern[] {
    return [
      {
        name: "credit_card",
        pattern: /\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/,
        category: "pii",
        confidence: 0.95,
        replacement: "[CREDIT_CARD_MASKED]",
      },
      {
        name: "ssn",
        pattern: /\b\d{3}-\d{2}-\d{4}\b/,
        category: "pii",
        confidence: 0.95,
        replacement: "[SSN_MASKED]",
      },
      {
        name: "email",
        pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/,
        category: "pii",
        confidence: 0.9,
        replacement: "[EMAIL_MASKED]",
      },
      {
        name: "api_key",
        pattern: /\b(api_key|api_key_id|access_key)\s*[:=]\s*[A-Za-z0-9+/]{20,}\b/i,
        category: "secret",
        confidence: 0.9,
        replacement: "[API_KEY_MASKED]",
      },
      {
        name: "password",
        pattern: /\b(password|passwd|pwd)\s*[:=]\s*\S+\b/i,
        category: "secret",
        confidence: 0.9,
        replacement: "[PASSWORD_MASKED]",
      },
      {
        name: "credit_card_dense",
        pattern: /\b\d{16}\b/,
        category: "pii",
        confidence: 0.9,
        replacement: "[CREDIT_CARD_MASKED]",
      },
      {
        name: "credit_card_spaced_digits",
        pattern: /(?:\d[-\s]){15}\d/,
        category: "pii",
        confidence: 0.9,
        replacement: "[CREDIT_CARD_MASKED]",
      },
      {
        name: "ssn_dots",
        pattern: /\b\d{3}\.\d{2}\.\d{4}\b/,
        category: "pii",
        confidence: 0.95,
        replacement: "[SSN_MASKED]",
      },
      {
        name: "tax_id_9",
        pattern: /\b\d{9}\b/,
        category: "pii",
        confidence: 0.9,
        replacement: "[TAX_ID_MASKED]",
      },
      {
        name: "sk_key",
        pattern: /\bsk-[A-Za-z0-9]{20,}\b/,
        category: "secret",
        confidence: 0.9,
        replacement: "[API_KEY_MASKED]",
      },
      {
        name: "aws_key",
        pattern: /\bAKIA[A-Z0-9]{16}\b/,
        category: "secret",
        confidence: 0.9,
        replacement: "[API_KEY_MASKED]",
      },
      {
        name: "ghp_key",
        pattern: /\bghp_[A-Za-z0-9]{20,}\b/,
        category: "secret",
        confidence: 0.9,
        replacement: "[API_KEY_MASKED]",
      },
      {
        name: "password_label",
        pattern: /\b(?:Password|PWD|Pass)\s*:\s*\S+/i,
        category: "secret",
        confidence: 0.9,
        replacement: "[PASSWORD_MASKED]",
      },
    ];
  }

  async process(request: ContentRequest): Promise<ContentResult> {
    const startTime = Date.now();

    try {
      // Validate request
      const validatedRequest = ContentRequestSchema.parse(request);

      // Stage 1: Aho-Corasick pattern matching
      const patternMatches = this.ahoCorasick.search(validatedRequest.content);

      // Stage 2: Format and entropy analysis
      const formatAnalysis = this.formatAnalyzer.analyze(validatedRequest.content);

      // Stage 3: SimHash for near-duplicate detection
      const contentHash = this.simHash.compute(validatedRequest.content);
      const isNearDupe = this.detectNearDuplicates(validatedRequest.content, contentHash);

      // Stage 4: MinHash for similarity analysis (optional)
      void this.minHash.compute(validatedRequest.content);

      // Stage 5: LLM analysis for ambiguous cases
      const llmAnalysis = await this.llmAnalyzer.analyze(
        validatedRequest.content,
        validatedRequest.context,
      );

      // Determine if content should be blocked
      const shouldBlock = this.shouldBlockContent(
        patternMatches,
        formatAnalysis,
        llmAnalysis,
        isNearDupe,
      );

      // Generate certificate
      const certificate = await this.generateCertificate({
        patternMatches,
        formatAnalysis,
        llmAnalysis,
        isNearDupe,
        contentHash,
        shouldBlock,
        request: validatedRequest,
      });

      // Process content (mask sensitive data if needed)
      const processedContent = this.processContent(validatedRequest.content, patternMatches);

      const processingTime = Date.now() - startTime;

      return {
        content: processedContent,
        certificate,
        processing_time: processingTime,
        blocked: shouldBlock,
        reason: shouldBlock ? "Content blocked by egress firewall" : undefined,
      };
    } catch (error) {
      const processingTime = Date.now() - startTime;

      // Generate error certificate
      const errorCertificate = await this.generateErrorCertificate(
        error instanceof Error ? error.message : "Unknown error",
        request,
      );

      return {
        content: request.content,
        certificate: errorCertificate,
        processing_time: processingTime,
        blocked: true,
        reason: "Processing error",
      };
    }
  }

  private detectNearDuplicates(content: string, contentHash: string): boolean {
    const norm = content.toLowerCase().replace(/\s+/g, " ").trim();
    for (const prev of this.recentNormalized) {
      if (normalizedNearDuplicateScore(prev, norm) >= 0.94) {
        return true;
      }
    }

    for (const knownHash of this.knownContentHashes) {
      if (this.simHash.similarity(contentHash, knownHash) > 0.8) {
        return true;
      }
    }

    this.recentNormalized.push(norm);
    if (this.recentNormalized.length > this.maxRecentNormalized) {
      this.recentNormalized.shift();
    }
    this.knownContentHashes.add(contentHash);
    return false;
  }

  private shouldBlockContent(
    patternMatches: Array<{
      pattern: SensitivePattern;
      start: number;
      end: number;
    }>,
    formatAnalysis: ReturnType<FormatAnalyzer["analyze"]>,
    llmAnalysis: Awaited<ReturnType<LLMAnalyzer["analyze"]>>,
    isNearDupe: boolean,
  ): boolean {
    // Block if critical PII or secrets detected
    const hasCriticalPII = patternMatches.some(
      (match) => match.pattern.category === "pii" && match.pattern.confidence >= 0.9,
    );

    const hasSecrets = patternMatches.some(
      (match) => match.pattern.category === "secret" && match.pattern.confidence >= 0.9,
    );

    // Block if LLM analysis indicates sensitive content
    const llmSensitive = llmAnalysis.isSensitive && llmAnalysis.confidence > 0.8;

    // Block if suspicious patterns detected
    const hasSuspiciousPatterns = formatAnalysis.suspiciousPatterns.length > 0;

    return hasCriticalPII || hasSecrets || llmSensitive || hasSuspiciousPatterns || isNearDupe;
  }

  private processContent(
    content: string,
    matches: Array<{ pattern: SensitivePattern; start: number; end: number }>,
  ): string {
    let processedContent = content;

    // Sort matches by start position in reverse order to avoid index shifting
    const sortedMatches = [...matches].sort((a, b) => b.start - a.start);

    for (const match of sortedMatches) {
      if (match.pattern.replacement) {
        processedContent =
          processedContent.substring(0, match.start) +
          match.pattern.replacement +
          processedContent.substring(match.end);
      }
    }

    return processedContent;
  }

  private async generateCertificate(data: {
    patternMatches: Array<{
      pattern: SensitivePattern;
      start: number;
      end: number;
    }>;
    formatAnalysis: ReturnType<FormatAnalyzer["analyze"]>;
    llmAnalysis: Awaited<ReturnType<LLMAnalyzer["analyze"]>>;
    isNearDupe: boolean;
    contentHash: string;
    shouldBlock: boolean;
    request: ContentRequest;
  }): Promise<EgressCertificate> {
    const { patternMatches, isNearDupe, shouldBlock, request, llmAnalysis } = data;

    // Determine PII status
    let pii: "detected" | "none" | "masked" = "none";
    if (patternMatches.some((m) => m.pattern.category === "pii")) {
      pii = shouldBlock ? "masked" : "detected";
    } else if (shouldBlock && llmAnalysis.category === "pii") {
      pii = "masked";
    }

    // Determine secrets status
    let secrets: "detected" | "none" | "masked" = "none";
    if (patternMatches.some((m) => m.pattern.category === "secret")) {
      secrets = shouldBlock ? "masked" : "detected";
    } else if (shouldBlock && llmAnalysis.category === "credential") {
      secrets = "masked";
    }

    // Determine near-duplicate status
    const near_dupe: "detected" | "none" = isNearDupe ? "detected" : "none";

    // Determine non-interference status
    const non_interference: "passed" | "failed" = shouldBlock ? "failed" : "passed";

    // Generate policy hash
    const policyHash = createHash("sha256").update(JSON.stringify(this.policies)).digest("hex");

    // Generate text hash
    const textHash = createHash("sha256").update(request.content).digest("hex");

    // Generate attestation reference
    const attestationRef = `attestation:${request.tenant}:${Date.now()}:${Math.random().toString(36).substring(7)}`;

    // Create certificate data
    const certificateData = {
      pii,
      secrets,
      near_dupe,
      non_interference,
      influencing_labels: request.labels || [],
      policy_hash: policyHash,
      text_hash: textHash,
      attestation_ref: attestationRef,
    };

    // Sign the certificate
    const dataString = JSON.stringify(certificateData, Object.keys(certificateData).sort());
    const message = Buffer.from(dataString, "utf8");
    const signature = cryptoSign(null, message, this.privateKey);
    const sig = Buffer.from(signature).toString("hex");

    return {
      ...certificateData,
      sig,
    };
  }

  private async generateErrorCertificate(
    _error: string,
    request: ContentRequest,
  ): Promise<EgressCertificate> {
    const policyHash = createHash("sha256").update(JSON.stringify(this.policies)).digest("hex");

    const textHash = createHash("sha256").update(request.content).digest("hex");

    const attestationRef = `error:${request.tenant}:${Date.now()}`;

    const certificateData = {
      pii: "none" as const,
      secrets: "none" as const,
      near_dupe: "none" as const,
      non_interference: "failed" as const,
      influencing_labels: request.labels || [],
      policy_hash: policyHash,
      text_hash: textHash,
      attestation_ref: attestationRef,
    };

    const dataString = JSON.stringify(certificateData, Object.keys(certificateData).sort());
    const message = Buffer.from(dataString, "utf8");
    const signature = cryptoSign(null, message, this.privateKey);
    const sig = Buffer.from(signature).toString("hex");

    return {
      ...certificateData,
      sig,
    };
  }

  // Verify certificate signature
  async verifyCertificate(certificate: EgressCertificate): Promise<boolean> {
    try {
      const { sig, ...dataToSign } = certificate;
      const dataString = JSON.stringify(dataToSign, Object.keys(dataToSign).sort());
      const message = Buffer.from(dataString, "utf8");

      const signature = Buffer.from(sig, "hex");
      return cryptoVerify(null, message, this.publicKey, signature);
    } catch (error) {
      return false;
    }
  }

  // Get public key for verification
  getPublicKey(): string {
    return ed25519PublicKeyRawHex(this.publicKey);
  }

  // Get processing statistics
  getStats(): {
    totalProcessed: number;
    blockedCount: number;
    piiDetected: number;
    secretsDetected: number;
    nearDuplicatesDetected: number;
    averageProcessingTime: number;
  } {
    // This would track actual statistics in production
    return {
      totalProcessed: 0,
      blockedCount: 0,
      piiDetected: 0,
      secretsDetected: 0,
      nearDuplicatesDetected: 0,
      averageProcessingTime: 0,
    };
  }
}

// Export factory function
export const createEgressFirewall = (config: {
  patterns?: SensitivePattern[];
  policies: string[];
  llmProvider?: string;
  llmApiKey?: string;
  privateKeyHex: string;
}): EgressFirewall => {
  return new EgressFirewall(config);
};
