import { RetrievalGateway, InMemoryShardedStore, AccessReceipt } from "../src/gateway";
import { randomBytes } from "crypto";

describe("Retrieval Gateway Ed25519 & Honeytoken Tests", () => {
  let gateway: RetrievalGateway;
  let dataStore: InMemoryShardedStore;

  beforeEach(async () => {
    dataStore = new InMemoryShardedStore();
    gateway = new RetrievalGateway(
      dataStore,
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
  });

  describe("Ed25519 Signature Verification", () => {
    it("should generate valid Ed25519 signatures for access receipts", async () => {
      const request = {
        tenant: "acme",
        subject: "ticket_123",
        query: {},
        user_id: "user1",
        capabilities: ["read"],
        nonce: randomBytes(16).toString("hex"),
      };

      const response = await gateway.retrieve(request);
      const receipt = response.receipt;

      // Verify the signature is valid
      const isValid = await gateway.verifyReceipt(receipt);
      expect(isValid).toBe(true);

      // HMAC-SHA256 signatures are 32 bytes = 64 hex characters
      expect(receipt.sig).toHaveLength(64);
    });

    it("should reject tampered receipts", async () => {
      const request = {
        tenant: "acme",
        subject: "ticket_123",
        query: {},
        user_id: "user1",
        capabilities: ["read"],
        nonce: randomBytes(16).toString("hex"),
      };

      const response = await gateway.retrieve(request);
      const receipt = response.receipt;

      // Tamper with the receipt
      const tamperedReceipt: AccessReceipt = {
        ...receipt,
        tenant: "globex", // Changed from 'acme' to 'globex'
      };

      const isValid = await gateway.verifyReceipt(tamperedReceipt);
      expect(isValid).toBe(false);
    });

    it("should reject receipts with invalid signature format", async () => {
      const request = {
        tenant: "acme",
        subject: "ticket_123",
        query: {},
        user_id: "user1",
        capabilities: ["read"],
        nonce: randomBytes(16).toString("hex"),
      };

      const response = await gateway.retrieve(request);
      const receipt = response.receipt;

      // Create receipt with invalid signature
      const invalidReceipt: AccessReceipt = {
        ...receipt,
        sig: "invalid-signature",
      };

      const isValid = await gateway.verifyReceipt(invalidReceipt);
      expect(isValid).toBe(false);
    });

    it("should verify receipts from different gateway instances with same key", async () => {
      const request = {
        tenant: "acme",
        subject: "ticket_123",
        query: {},
        user_id: "user1",
        capabilities: ["read"],
        nonce: randomBytes(16).toString("hex"),
      };

      const response = await gateway.retrieve(request);
      const receipt = response.receipt;

      // Create new gateway instance with same private key
      const newGateway = new RetrievalGateway(
        dataStore,
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      );

      const isValid = await newGateway.verifyReceipt(receipt);
      expect(isValid).toBe(true);
    });
  });

  describe("Honeytoken Functionality", () => {
    it("should detect honeytoken access and trigger alerts", async () => {
      const request = {
        tenant: "acme",
        subject: "honeytoken_001",
        query: {},
        user_id: "user1",
        capabilities: ["read"],
        nonce: randomBytes(16).toString("hex"),
      };

      // Mock console.warn to capture honeytoken alerts
      const consoleSpy = jest.spyOn(console, "warn").mockImplementation();

      const response = await gateway.retrieve(request);

      expect(response.success).toBe(true);
      expect(response.data.is_honeytoken).toBe(true);
      expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining("🚨 HONEYTOKEN ALERT"));

      consoleSpy.mockRestore();
    });

    it("should track honeytoken access count", async () => {
      const request = {
        tenant: "acme",
        subject: "honeytoken_001",
        query: {},
        user_id: "user1",
        capabilities: ["read"],
        nonce: randomBytes(16).toString("hex"),
      };

      // Access honeytoken multiple times
      await gateway.retrieve(request);
      await gateway.retrieve(request);
      await gateway.retrieve(request);

      // Check if honeytoken access was tracked
      const honeytoken = await dataStore.getHoneytoken("acme", "honeytoken_001");
      expect(honeytoken).toBeDefined();
      expect(honeytoken!.accessed_count).toBe(3);
    });

    it("should maintain honeytoken isolation between tenants", async () => {
      const acmeRequest = {
        tenant: "acme",
        subject: "honeytoken_001",
        query: {},
        user_id: "user1",
        capabilities: ["read"],
        nonce: randomBytes(16).toString("hex"),
      };

      const globexRequest = {
        tenant: "globex",
        subject: "honeytoken_001",
        query: {},
        user_id: "user1",
        capabilities: ["read"],
        nonce: randomBytes(16).toString("hex"),
      };

      await gateway.retrieve(acmeRequest);
      await gateway.retrieve(globexRequest);

      const acmeHoneytoken = await dataStore.getHoneytoken("acme", "honeytoken_001");
      const globexHoneytoken = await dataStore.getHoneytoken("globex", "honeytoken_001");

      expect(acmeHoneytoken!.accessed_count).toBe(1);
      expect(globexHoneytoken!.accessed_count).toBe(1);
      expect(acmeHoneytoken!.tenant).toBe("acme");
      expect(globexHoneytoken!.tenant).toBe("globex");
    });
  });

  describe("Receipt Expiration", () => {
    it("should generate receipts with correct expiration time", async () => {
      const request = {
        tenant: "acme",
        subject: "ticket_123",
        query: {},
        user_id: "user1",
        capabilities: ["read"],
        nonce: randomBytes(16).toString("hex"),
      };

      const response = await gateway.retrieve(request);
      const receipt = response.receipt;

      const now = new Date();
      const expiry = new Date(receipt.exp);
      const timeDiff = expiry.getTime() - now.getTime();

      // Receipt should expire in approximately 24 hours
      expect(timeDiff).toBeGreaterThan(23 * 60 * 60 * 1000); // > 23 hours
      expect(timeDiff).toBeLessThan(25 * 60 * 60 * 1000); // < 25 hours
    });

    it("should detect expired receipts", async () => {
      const request = {
        tenant: "acme",
        subject: "ticket_123",
        query: {},
        user_id: "user1",
        capabilities: ["read"],
        nonce: randomBytes(16).toString("hex"),
      };

      const response = await gateway.retrieve(request);
      const receipt = response.receipt;

      // Manually expire the receipt
      const expiredReceipt: AccessReceipt = {
        ...receipt,
        exp: new Date(Date.now() - 1000).toISOString(), // 1 second ago
      };

      const isExpired = gateway.isReceiptExpired(expiredReceipt);
      expect(isExpired).toBe(true);
    });
  });

  describe("Public Key Management", () => {
    it("should provide public key for external verification", async () => {
      const publicKey = gateway.getPublicKey();

      expect(publicKey).toBeDefined();
      expect(publicKey).toHaveLength(64); // Ed25519 public key is 32 bytes = 64 hex chars
      expect(publicKey).toMatch(/^[0-9a-f]{64}$/); // Should be hex string
    });

    it("should generate consistent public key from same private key", async () => {
      const gateway1 = new RetrievalGateway(
        dataStore,
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      );

      const gateway2 = new RetrievalGateway(
        dataStore,
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      );

      expect(gateway1.getPublicKey()).toBe(gateway2.getPublicKey());
    });
  });
});
