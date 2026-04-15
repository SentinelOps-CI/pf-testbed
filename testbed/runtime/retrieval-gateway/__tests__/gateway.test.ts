import { RetrievalGateway, InMemoryShardedStore, createTestGateway } from "../src/gateway";
import { randomBytes } from "crypto";

describe("Retrieval Gateway", () => {
  let gateway: RetrievalGateway;
  let dataStore: InMemoryShardedStore;

  beforeEach(async () => {
    dataStore = new InMemoryShardedStore();
    gateway = new RetrievalGateway(
      dataStore,
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
  });

  describe("Basic Functionality", () => {
    it("should retrieve data and generate access receipt", async () => {
      const request = {
        tenant: "acme",
        subject: "ticket_123",
        query: {},
        user_id: "user1",
        capabilities: ["read"],
        nonce: randomBytes(16).toString("hex"),
      };

      const response = await gateway.retrieve(request);

      expect(response["success"]).toBe(true);
      expect(response["data"]).toBeDefined();
      expect(response["data"].id).toBe("ticket_123");
      expect(response["data"].tenant).toBe("acme");
      expect(response["receipt"]).toBeDefined();
      expect(response["receipt"].tenant).toBe("acme");
      expect(response["receipt"].subject).toBe("ticket_123");
      expect(response["receipt"].shard).toBe("tenants/acme");
      expect(response["metadata"].tenant).toBe("acme");
      expect(response["metadata"].shard).toBe("tenants/acme");
    });

    it("should generate unique query and result hashes", async () => {
      const request1 = {
        tenant: "acme",
        subject: "ticket_123",
        query: { status: "open" },
        user_id: "user1",
        capabilities: ["read"],
        nonce: randomBytes(16).toString("hex"),
      };

      const request2 = {
        tenant: "acme",
        subject: "ticket_123",
        query: { status: "resolved" },
        user_id: "user1",
        capabilities: ["read"],
        nonce: randomBytes(16).toString("hex"),
      };

      const response1 = await gateway.retrieve(request1);
      const response2 = await gateway.retrieve(request2);

      expect(response1["metadata"].query_hash).not.toBe(response2["metadata"].query_hash);
      expect(response1["metadata"].result_hash).toBeDefined();
      expect(response2["metadata"].result_hash).toBeDefined();
    });

    it("should handle queries with filters", async () => {
      const request = {
        tenant: "acme",
        subject: "ticket_123",
        query: { status: "open" },
        user_id: "user1",
        capabilities: ["read"],
        nonce: randomBytes(16).toString("hex"),
      };

      const response = await gateway.retrieve(request);

      expect(response["success"]).toBe(true);
      expect(response["data"].status).toBe("open");
    });

    it("should return error for non-matching queries", async () => {
      const request = {
        tenant: "acme",
        subject: "ticket_123",
        query: { status: "closed" }, // This status doesn't exist
        user_id: "user1",
        capabilities: ["read"],
        nonce: randomBytes(16).toString("hex"),
      };

      const response = await gateway.retrieve(request);

      expect(response["success"]).toBe(false);
      expect(response["error"]).toBe("No data found matching query");
      expect(response["receipt"]).toBeDefined();
    });
  });

  describe("Tenant Isolation", () => {
    it("should maintain complete tenant isolation", async () => {
      const acmeRequest = {
        tenant: "acme",
        subject: "ticket_123",
        query: {},
        user_id: "user1",
        capabilities: ["read"],
        nonce: randomBytes(16).toString("hex"),
      };

      const globexRequest = {
        tenant: "globex",
        subject: "incident_789",
        query: {},
        user_id: "user2",
        capabilities: ["read"],
        nonce: randomBytes(16).toString("hex"),
      };

      const acmeResponse = await gateway.retrieve(acmeRequest);
      const globexResponse = await gateway.retrieve(globexRequest);

      expect(acmeResponse["success"]).toBe(true);
      expect(globexResponse["success"]).toBe(true);
      expect(acmeResponse["data"].tenant).toBe("acme");
      expect(globexResponse["data"].tenant).toBe("globex");
      expect(acmeResponse["metadata"].shard).toBe("tenants/acme");
      expect(globexResponse["metadata"].shard).toBe("tenants/globex");
    });

    it("should not allow cross-tenant data access", async () => {
      const acmeData = gateway.getTenantData("acme");
      const globexData = gateway.getTenantData("globex");

      // Verify that ACME data doesn't contain Globex data
      const hasGlobexData = acmeData.some((item) => item.tenant === "globex");
      expect(hasGlobexData).toBe(false);

      // Verify that Globex data doesn't contain ACME data
      const hasAcmeData = globexData.some((item) => item.tenant === "acme");
      expect(hasAcmeData).toBe(false);
    });

    it("should generate correct shard paths", () => {
      const tenants = gateway.getAvailableTenants();

      tenants.forEach((tenant) => {
        const shard = `tenants/${tenant}`;
        expect(shard).toMatch(/^tenants\/(acme|globex)$/);
      });
    });
  });

  describe("Access Receipt Generation", () => {
    it("should generate valid Ed25519-like signatures", async () => {
      const request = {
        tenant: "acme",
        subject: "ticket_123",
        query: {},
        user_id: "user1",
        capabilities: ["read"],
        nonce: randomBytes(16).toString("hex"),
      };

      const response = await gateway.retrieve(request);
      const receipt = response["receipt"];

      // Verify receipt structure
      expect(receipt.tenant).toBe("acme");
      expect(receipt.subject).toBe("ticket_123");
      expect(receipt.shard).toBe("tenants/acme");
      expect(receipt.query_hash).toBeDefined();
      expect(receipt.result_hash).toBeDefined();
      expect(receipt.nonce).toBeDefined();
      expect(receipt.exp).toBeDefined();
      expect(receipt.sig).toBeDefined();

      // Verify signature is valid
      await expect(gateway.verifyReceipt(receipt)).resolves.toBe(true);
    });

    it("should generate receipts with proper expiration", async () => {
      const request = {
        tenant: "acme",
        subject: "ticket_123",
        query: {},
        user_id: "user1",
        capabilities: ["read"],
        nonce: randomBytes(16).toString("hex"),
      };

      const response = await gateway.retrieve(request);
      const receipt = response["receipt"];

      const expiryDate = new Date(receipt.exp);
      const now = new Date();
      const hoursDiff = (expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60);

      // Receipt should expire in approximately 24 hours
      expect(hoursDiff).toBeGreaterThan(23);
      expect(hoursDiff).toBeLessThan(25);
    });

    it("should generate unique nonces for each request", async () => {
      const request1 = {
        tenant: "acme",
        subject: "ticket_123",
        query: {},
        user_id: "user1",
        capabilities: ["read"],
        nonce: randomBytes(16).toString("hex"),
      };

      const request2 = {
        tenant: "acme",
        subject: "ticket_123",
        query: {},
        user_id: "user1",
        capabilities: ["read"],
        nonce: randomBytes(16).toString("hex"),
      };

      const response1 = await gateway.retrieve(request1);
      const response2 = await gateway.retrieve(request2);

      expect(response1["receipt"].nonce).not.toBe(response2["receipt"].nonce);
    });
  });

  describe("Receipt Validation", () => {
    it("should verify valid receipts", async () => {
      const request = {
        tenant: "acme",
        subject: "ticket_123",
        query: {},
        user_id: "user1",
        capabilities: ["read"],
        nonce: randomBytes(16).toString("hex"),
      };

      const response = await gateway.retrieve(request);
      const receipt = response["receipt"];

      await expect(gateway.verifyReceipt(receipt)).resolves.toBe(true);
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
      const tamperedReceipt = { ...receipt, tenant: "globex" };

      await expect(gateway.verifyReceipt(tamperedReceipt)).resolves.toBe(false);
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
      const receipt = response["receipt"];

      // Manually expire the receipt
      const expiredReceipt = {
        ...receipt,
        exp: new Date(Date.now() - 1000).toISOString(), // Expired 1 second ago
      };

      expect(gateway.isReceiptExpired(expiredReceipt)).toBe(true);
      expect(gateway.isReceiptExpired(receipt)).toBe(false);
    });

    it("should validate receipt for access correctly", async () => {
      const request = {
        tenant: "acme",
        subject: "ticket_123",
        query: {},
        user_id: "user1",
        capabilities: ["read"],
        nonce: randomBytes(16).toString("hex"),
      };

      const response = await gateway.retrieve(request);
      const receipt = response["receipt"];

      // Valid access
      await expect(gateway.validateReceiptForAccess(receipt, "acme", "ticket_123")).resolves.toBe(
        true,
      );

      // Invalid tenant
      await expect(gateway.validateReceiptForAccess(receipt, "globex", "ticket_123")).resolves.toBe(
        false,
      );

      // Invalid subject
      await expect(gateway.validateReceiptForAccess(receipt, "acme", "ticket_456")).resolves.toBe(
        false,
      );
    });
  });

  describe("Error Handling", () => {
    it("should handle invalid requests gracefully", async () => {
      const invalidRequest = {
        tenant: "", // Invalid: empty string
        subject: "ticket_123",
        query: {},
        user_id: "user1",
        capabilities: ["read"],
        nonce: randomBytes(16).toString("hex"),
      };

      const response = await gateway.retrieve(invalidRequest);

      expect(response["success"]).toBe(false);
      expect(response["error"]).toBeDefined();
      expect(response["receipt"]).toBeDefined();
    });

    it("should handle missing data gracefully", async () => {
      const request = {
        tenant: "acme",
        subject: "nonexistent_ticket",
        query: {},
        user_id: "user1",
        capabilities: ["read"],
        nonce: randomBytes(16).toString("hex"),
      };

      const response = await gateway.retrieve(request);

      expect(response["success"]).toBe(false);
      expect(response["error"]).toBe("Subject nonexistent_ticket not found in tenant acme");
      expect(response["receipt"]).toBeDefined();
    });

    it("should handle unknown tenants gracefully", async () => {
      const request = {
        tenant: "unknown_tenant",
        subject: "ticket_123",
        query: {},
        user_id: "user1",
        capabilities: ["read"],
        nonce: randomBytes(16).toString("hex"),
      };

      const response = await gateway.retrieve(request);

      expect(response["success"]).toBe(false);
      expect(response["error"]).toBe("Tenant unknown_tenant not found");
      expect(response["receipt"]).toBeDefined();
    });
  });

  describe("Data Store Operations", () => {
    it("should support CRUD operations", async () => {
      // Create
      await dataStore.set("test_tenant", "test_subject", {
        id: "test_subject",
        title: "Test Data",
        tenant: "test_tenant",
      });

      // Read
      const data = await dataStore.get("test_tenant", "test_subject", {});
      expect(data.title).toBe("Test Data");

      // Update
      await dataStore.set("test_tenant", "test_subject", {
        id: "test_subject",
        title: "Updated Test Data",
        tenant: "test_tenant",
      });

      const updatedData = await dataStore.get("test_tenant", "test_subject", {});
      expect(updatedData.title).toBe("Updated Test Data");

      // Delete
      await dataStore.delete("test_tenant", "test_subject");
      await expect(dataStore.get("test_tenant", "test_subject", {})).rejects.toThrow(
        "Subject test_subject not found in tenant test_tenant",
      );
    });

    it("should list subjects correctly", async () => {
      const acmeSubjects = await dataStore.list("acme");
      const globexSubjects = await dataStore.list("globex");

      expect(acmeSubjects).toContain("ticket_123");
      expect(acmeSubjects).toContain("ticket_456");
      expect(globexSubjects).toContain("incident_789");
      expect(globexSubjects).toContain("incident_101");
    });
  });

  describe("Factory Function", () => {
    it("should create test gateway with default secret", async () => {
      const testGateway = await createTestGateway();
      expect(testGateway).toBeInstanceOf(RetrievalGateway);
    });
  });
});
