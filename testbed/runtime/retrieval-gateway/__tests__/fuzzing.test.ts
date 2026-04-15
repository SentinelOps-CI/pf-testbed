import { RetrievalGateway, InMemoryShardedStore } from "../src/gateway";
import { randomBytes, randomInt } from "crypto";

describe("Retrieval Gateway Fuzzing Tests", () => {
  let gateway: RetrievalGateway;
  let dataStore: InMemoryShardedStore;

  beforeEach(async () => {
    dataStore = new InMemoryShardedStore();
    gateway = new RetrievalGateway(
      dataStore,
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
  });

  describe("Cross-Tenant Isolation Fuzzing", () => {
    it("should maintain zero cross-tenant reads in fuzzed queries", async () => {
      const tenants = ["acme", "globex"];
      const subjects = ["ticket_123", "ticket_456", "incident_789", "incident_101"];
      const statuses = ["open", "resolved", "investigating", "closed"];
      const priorities = ["low", "medium", "high", "critical"];

      let crossTenantReads = 0;
      const totalQueries = process.env["LONG_FUZZ"] === "1" ? 100000 : 10000;
      const batchSize = 1000;

      console.log(`Running ${totalQueries} fuzzed queries...`);

      for (let batch = 0; batch < totalQueries / batchSize; batch++) {
        const batchPromises = [];

        for (let i = 0; i < batchSize; i++) {
          // Generate random request parameters
          const request = {
            tenant: tenants[randomInt(0, tenants.length)] as string,
            subject: subjects[randomInt(0, subjects.length)] as string,
            query: {
              status: statuses[randomInt(0, statuses.length)],
              priority: priorities[randomInt(0, priorities.length)],
              random_field: randomBytes(8).toString("hex"),
            },
            user_id: `user_${randomInt(1, 1000)}`,
            capabilities: ["read"],
            nonce: randomBytes(16).toString("hex"),
          };

          batchPromises.push(gateway.retrieve(request));
        }

        // Execute batch
        const responses = await Promise.all(batchPromises);

        // Check for cross-tenant reads
        for (const response of responses) {
          if (response.success && response.data) {
            // Verify that the returned data belongs to the requested tenant
            if (response.data.tenant !== response.metadata.tenant) {
              crossTenantReads++;
              console.error(
                `Cross-tenant read detected! Requested: ${response.metadata.tenant}, Got: ${response.data.tenant}`,
              );
            }
          }
        }

        if (batch % 10 === 0) {
          console.log(`Completed batch ${batch + 1}/${totalQueries / batchSize}`);
        }
      }

      console.log(`Fuzzing complete. Cross-tenant reads: ${crossTenantReads}`);
      expect(crossTenantReads).toBe(0);
    }, 300000); // 5 minute timeout for large fuzzing test

    it("should maintain tenant isolation under concurrent access", async () => {
      const tenants = ["acme", "globex"];
      const concurrentRequests = 1000;

      const requests = Array.from({ length: concurrentRequests }, () => ({
        tenant: tenants[randomInt(0, tenants.length)] as string,
        subject: "ticket_123",
        query: {},
        user_id: `user_${randomInt(1, 100)}`,
        capabilities: ["read"],
        nonce: randomBytes(16).toString("hex"),
      }));

      const responses = await Promise.all(requests.map((request) => gateway.retrieve(request)));

      let crossTenantReads = 0;
      for (const response of responses) {
        if (response.success && response.data) {
          if (response.data.tenant !== response.metadata.tenant) {
            crossTenantReads++;
          }
        }
      }

      expect(crossTenantReads).toBe(0);
    });

    it("should handle malformed queries without breaking tenant isolation", async () => {
      const malformedQueries = [
        { invalid_field: "value" },
        { status: null },
        { priority: undefined },
        { nested: { field: "value" } },
        { array_field: [1, 2, 3] },
        { empty_string: "" },
        { very_long_field: "a".repeat(1000) },
        { special_chars: "!@#$%^&*()" },
        { unicode: "🚀🌟💫" },
        { sql_injection: "'; DROP TABLE users; --" },
      ];

      const tenants = ["acme", "globex"];
      let crossTenantReads = 0;

      for (const malformedQuery of malformedQueries) {
        for (const tenant of tenants) {
          const request = {
            tenant,
            subject: "ticket_123",
            query: malformedQuery,
            user_id: "user1",
            capabilities: ["read"],
            nonce: randomBytes(16).toString("hex"),
          };

          const response = await gateway.retrieve(request);

          if (response.success && response.data) {
            if (response.data.tenant !== tenant) {
              crossTenantReads++;
            }
          }
        }
      }

      expect(crossTenantReads).toBe(0);
    });
  });

  describe("Edge Case Fuzzing", () => {
    it("should handle extreme query values without breaking isolation", async () => {
      const extremeQueries = [
        { max_int: Number.MAX_SAFE_INTEGER },
        { min_int: Number.MIN_SAFE_INTEGER },
        { infinity: Infinity },
        { negative_infinity: -Infinity },
        { nan: NaN },
        { max_string: "a".repeat(10000) },
        { empty_object: {} },
        { null_value: null },
        { undefined_value: undefined },
        { boolean_true: true },
        { boolean_false: false },
      ];

      const tenants = ["acme", "globex"];
      let crossTenantReads = 0;

      for (const extremeQuery of extremeQueries) {
        for (const tenant of tenants) {
          const request = {
            tenant,
            subject: "ticket_123",
            query: extremeQuery,
            user_id: "user1",
            capabilities: ["read"],
            nonce: randomBytes(16).toString("hex"),
          };

          const response = await gateway.retrieve(request);

          if (response.success && response.data) {
            if (response.data.tenant !== tenant) {
              crossTenantReads++;
            }
          }
        }
      }

      expect(crossTenantReads).toBe(0);
    });

    it("should handle rapid successive requests without isolation issues", async () => {
      const rapidRequests = Array.from({ length: 1000 }, (_, i) => ({
        tenant: i % 2 === 0 ? "acme" : "globex",
        subject: `item_${i}`,
        query: { index: i },
        user_id: `user_${i}`,
        capabilities: ["read"],
        nonce: randomBytes(16).toString("hex"),
      }));

      let crossTenantReads = 0;

      // Execute requests rapidly in sequence
      for (const request of rapidRequests) {
        const response = await gateway.retrieve(request);

        if (response.success && response.data) {
          if (response.data.tenant !== request.tenant) {
            crossTenantReads++;
          }
        }
      }

      expect(crossTenantReads).toBe(0);
    });
  });

  describe("Data Integrity Fuzzing", () => {
    it("should maintain data integrity under fuzzed access patterns", async () => {
      const accessPatterns = [];

      // Generate various access patterns
      for (let i = 0; i < 1000; i++) {
        accessPatterns.push({
          tenant: i % 3 === 0 ? "acme" : "globex",
          subject: `item_${i}`,
          query: {
            pattern: i,
            random: randomBytes(4).toString("hex"),
            timestamp: Date.now(),
          },
          user_id: `user_${i % 100}`,
          capabilities: ["read"],
          nonce: randomBytes(16).toString("hex"),
        });
      }

      let dataIntegrityViolations = 0;

      for (const pattern of accessPatterns) {
        const response = await gateway.retrieve(pattern);

        if (response.success && response.data) {
          // Check that data integrity is maintained
          if (response.data.tenant !== pattern.tenant) {
            dataIntegrityViolations++;
          }

          // Check that the data structure is consistent
          if (!response.data.id || !response.data.tenant) {
            dataIntegrityViolations++;
          }
        }
      }

      expect(dataIntegrityViolations).toBe(0);
    });
  });
});
