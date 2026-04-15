import request from "supertest";
import express from "express";
import {
  ValidationMiddleware,
  TenantRateLimiter,
  requestIdMiddleware,
  VALIDATION_ERROR_CODES,
} from "../middleware/validation";

describe("Validation Middleware", () => {
  let app: express.Application;
  let validationMiddleware: ValidationMiddleware;
  let tenantRateLimiter: TenantRateLimiter;
  const secretKey = "test-secret-key";

  beforeEach(() => {
    app = express();
    validationMiddleware = new ValidationMiddleware(secretKey);
    tenantRateLimiter = new TenantRateLimiter(15 * 60 * 1000, 100);

    // Setup middleware
    app.use(express.json());
    app.use(requestIdMiddleware);
    app.use(validationMiddleware.validateRequest);
    app.use(tenantRateLimiter.limitByTenant);

    // Test endpoint
    app.post("/test", (req, res) => {
      res.json({
        success: true,
        tenant: req.tenant,
        user_id: req.userId,
        capabilities: req.capabilities,
        request_id: res.locals["requestId"],
      });
    });
  });

  describe("PF Signature Validation", () => {
    it("should accept valid PF signature", async () => {
      console.log("Starting test: should accept valid PF signature");

      const signature = validationMiddleware.generateSignature({
        tenant: "acme",
        user_id: "user123",
        capabilities: ["support_triage"],
        expires_in: 3600,
      });

      console.log("Generated signature:", signature);

      const response = await request(app).post("/test").set("x-pf-signature", signature);

      console.log("Response status:", response.status);
      console.log("Response body:", JSON.stringify(response.body, null, 2));

      if (response.status !== 200) {
        console.log("Request failed with status:", response.status);
        console.log("Error details:", response.body);
      }

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.tenant).toBe("acme");
      expect(response.body.user_id).toBe("user123");
      expect(response.body.capabilities).toEqual(["support_triage"]);
      expect(response.body.request_id).toBeDefined();
    });

    it("should reject missing PF signature with 403 and PF_SIG_MISSING code", async () => {
      const response = await request(app).post("/test").expect(403);

      expect(response.body.error.code).toBe(VALIDATION_ERROR_CODES.PF_SIG_MISSING);
      expect(response.body.error.message).toBe("PF signature is required");
      expect(response.body.timestamp).toBeDefined();
      expect(response.body.request_id).toBeDefined();
    });

    it("should reject invalid PF signature with 403 and PF_SIG_INVALID code", async () => {
      const response = await request(app)
        .post("/test")
        .set("x-pf-signature", "invalid-signature")
        .expect(403);

      expect(response.body.error.code).toBe(VALIDATION_ERROR_CODES.PF_SIG_INVALID);
      expect(response.body.error.message).toBe("Failed to parse signature");
      expect(response.body.timestamp).toBeDefined();
      expect(response.body.request_id).toBeDefined();
    });

    it("should reject expired PF signature with 403 and PF_SIG_EXPIRED code", async () => {
      const signature = validationMiddleware.generateSignature({
        tenant: "acme",
        user_id: "user123",
        capabilities: ["support_triage"],
        expires_in: -1, // Expired
      });

      const response = await request(app)
        .post("/test")
        .set("x-pf-signature", signature)
        .expect(403);

      expect(response.body.error.code).toBe(VALIDATION_ERROR_CODES.PF_SIG_EXPIRED);
      expect(response.body.error.message).toBe("PF signature has expired");
      expect(response.body.timestamp).toBeDefined();
      expect(response.body.request_id).toBeDefined();
    });

    it("should reject tampered signature with 403 and PF_SIG_INVALID code", async () => {
      const signature = validationMiddleware.generateSignature({
        tenant: "acme",
        user_id: "user123",
        capabilities: ["support_triage"],
        expires_in: 3600,
      });

      // Tamper with the signature by changing the tenant
      const decoded = Buffer.from(signature, "base64").toString("utf-8");
      const parsed = JSON.parse(decoded);
      parsed.tenant = "globex"; // Changed tenant
      const tamperedSignature = Buffer.from(JSON.stringify(parsed)).toString("base64");

      const response = await request(app)
        .post("/test")
        .set("x-pf-signature", tamperedSignature)
        .expect(403);

      expect(response.body.error.code).toBe(VALIDATION_ERROR_CODES.PF_SIG_INVALID);
      expect(response.body.error.message).toBe("Invalid signature");
      expect(response.body.timestamp).toBeDefined();
      expect(response.body.request_id).toBeDefined();
    });
  });

  describe("Access Receipt Validation", () => {
    it("should accept valid access receipts", async () => {
      const signature = validationMiddleware.generateSignature({
        tenant: "acme",
        user_id: "user123",
        capabilities: ["support_triage"],
        expires_in: 3600,
      });

      const receipt = validationMiddleware.generateAccessReceipt({
        tenant: "acme",
        subject: "ticket_123",
        shard: "tenants/acme",
        query_hash: "abc123",
        result_hash: "def456",
        expires_in: 1800,
      });

      const response = await request(app)
        .post("/test")
        .set("x-pf-signature", signature)
        .set("x-access-receipts", JSON.stringify([receipt]))
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.tenant).toBe("acme");
    });

    it("should reject access receipt with mismatched tenant", async () => {
      const signature = validationMiddleware.generateSignature({
        tenant: "acme",
        user_id: "user123",
        capabilities: ["support_triage"],
        expires_in: 3600,
      });

      const receipt = validationMiddleware.generateAccessReceipt({
        tenant: "globex", // Different tenant
        subject: "ticket_123",
        shard: "tenants/globex",
        query_hash: "abc123",
        result_hash: "def456",
        expires_in: 1800,
      });

      const response = await request(app)
        .post("/test")
        .set("x-pf-signature", signature)
        .set("x-access-receipts", JSON.stringify([receipt]))
        .expect(403);

      expect(response.body.error.code).toBe(VALIDATION_ERROR_CODES.ACCESS_RECEIPT_INVALID);
      expect(response.body.error.message).toBe("Receipt tenant mismatch");
      expect(response.body.timestamp).toBeDefined();
      expect(response.body.request_id).toBeDefined();
    });

    it("should reject expired access receipt", async () => {
      const signature = validationMiddleware.generateSignature({
        tenant: "acme",
        user_id: "user123",
        capabilities: ["support_triage"],
        expires_in: 3600,
      });

      const receipt = validationMiddleware.generateAccessReceipt({
        tenant: "acme",
        subject: "ticket_123",
        shard: "tenants/acme",
        query_hash: "abc123",
        result_hash: "def456",
        expires_in: -1, // Expired
      });

      const response = await request(app)
        .post("/test")
        .set("x-pf-signature", signature)
        .set("x-access-receipts", JSON.stringify([receipt]))
        .expect(403);

      expect(response.body.error.code).toBe(VALIDATION_ERROR_CODES.ACCESS_RECEIPT_EXPIRED);
      expect(response.body.error.message).toBe("Receipt has expired");
      expect(response.body.timestamp).toBeDefined();
      expect(response.body.request_id).toBeDefined();
    });

    it("should reject invalid access receipt schema", async () => {
      const signature = validationMiddleware.generateSignature({
        tenant: "acme",
        user_id: "user123",
        capabilities: ["support_triage"],
        expires_in: 3600,
      });

      const invalidReceipt = {
        tenant: "acme",
        // Missing required fields
        subject: "ticket_123",
      };

      const response = await request(app)
        .post("/test")
        .set("x-pf-signature", signature)
        .set("x-access-receipts", JSON.stringify([invalidReceipt]))
        .expect(403);

      expect(response.body.error.code).toBe(VALIDATION_ERROR_CODES.ACCESS_RECEIPT_INVALID);
      expect(response.body.error.message).toBe("Invalid receipt schema");
      expect(response.body.timestamp).toBeDefined();
      expect(response.body.request_id).toBeDefined();
    });
  });

  describe("Rate Limiting", () => {
    it("should allow requests within rate limit", async () => {
      const signature = validationMiddleware.generateSignature({
        tenant: "acme",
        user_id: "user123",
        capabilities: ["support_triage"],
        expires_in: 3600,
      });

      // Make multiple requests within limit
      for (let i = 0; i < 5; i++) {
        const response = await request(app)
          .post("/test")
          .set("x-pf-signature", signature)
          .expect(200);

        expect(response.body.success).toBe(true);
      }
    });

    it("should reject requests exceeding rate limit", async () => {
      const signature = validationMiddleware.generateSignature({
        tenant: "acme",
        user_id: "user123",
        capabilities: ["support_triage"],
        expires_in: 3600,
      });

      // Create a new rate limiter with very low limits for testing
      const testRateLimiter = new TenantRateLimiter(1000, 3); // 1 second window, 3 requests max
      app._router.stack = app._router.stack.filter(
        (layer: any) => !layer.route || layer.route.path !== "/test",
      );

      app.use(testRateLimiter.limitByTenant);
      app.post("/test", (req, res) => {
        res.json({
          success: true,
          tenant: req.tenant,
          user_id: req.userId,
          capabilities: req.capabilities,
          request_id: res.locals["requestId"],
        });
      });

      // Make requests up to limit
      for (let i = 0; i < 3; i++) {
        await request(app).post("/test").set("x-pf-signature", signature).expect(200);
      }

      // Next request should be rate limited
      const response = await request(app)
        .post("/test")
        .set("x-pf-signature", signature)
        .expect(429);

      expect(response.body.error.code).toBe(VALIDATION_ERROR_CODES.RATE_LIMIT_EXCEEDED);
      expect(response.body.error.message).toBe("Rate limit exceeded for tenant");
      expect(response.body.error.details.tenant).toBe("acme");
      expect(response.body.error.details.limit).toBe(3);
      expect(response.body.timestamp).toBeDefined();
      expect(response.body.request_id).toBeDefined();
    });
  });

  describe("Request ID Middleware", () => {
    it("should generate request ID if not provided", async () => {
      const signature = validationMiddleware.generateSignature({
        tenant: "acme",
        user_id: "user123",
        capabilities: ["support_triage"],
        expires_in: 3600,
      });

      const response = await request(app)
        .post("/test")
        .set("x-pf-signature", signature)
        .expect(200);

      expect(response.body.request_id).toBeDefined();
      expect(typeof response.body.request_id).toBe("string");
      expect(response.body.request_id.length).toBeGreaterThan(0);
    });

    it("should use provided request ID", async () => {
      const signature = validationMiddleware.generateSignature({
        tenant: "acme",
        user_id: "user123",
        capabilities: ["support_triage"],
        expires_in: 3600,
      });

      const customRequestId = "custom-request-123";

      const response = await request(app)
        .post("/test")
        .set("x-pf-signature", signature)
        .set("x-request-id", customRequestId)
        .expect(200);

      expect(response.body.request_id).toBe(customRequestId);
    });
  });

  describe("Error Handling", () => {
    it("should handle internal validation errors gracefully", async () => {
      // Test that the validation middleware gracefully handles malformed signatures
      const response = await request(app)
        .post("/test")
        .set("x-pf-signature", "malformed-base64-signature!@#")
        .expect(403);

      expect(response.body.error.code).toBe(VALIDATION_ERROR_CODES.PF_SIG_INVALID);
      expect(response.body.error.message).toBe("Failed to parse signature");
      expect(response.body.timestamp).toBeDefined();
      expect(response.body.request_id).toBeDefined();
    });
  });
});
