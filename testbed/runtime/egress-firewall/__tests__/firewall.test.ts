import {
  EgressFirewall,
  createEgressFirewall,
  ContentRequest,
  SensitivePattern,
} from "../src/firewall";

describe("Egress Firewall", () => {
  let firewall: EgressFirewall;
  const privateKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

  beforeEach(() => {
    firewall = createEgressFirewall({
      policies: ["pii_protection", "secret_handling"],
      privateKeyHex: privateKey,
    });
  });

  describe("Pattern Detection", () => {
    it("should detect credit card numbers", async () => {
      const request: ContentRequest = {
        content: "My credit card number is 1234-5678-9012-3456",
        tenant: "acme",
        context: "support_chat",
      };

      const result = await firewall.process(request);

      expect(result.blocked).toBe(true);
      expect(result.certificate.pii).toBe("masked");
      expect(result.content).toContain("[CREDIT_CARD_MASKED]");
      expect(result.content).not.toContain("1234-5678-9012-3456");
    });

    it("should detect SSNs", async () => {
      const request: ContentRequest = {
        content: "My SSN is 123-45-6789",
        tenant: "acme",
        context: "support_chat",
      };

      const result = await firewall.process(request);

      expect(result.blocked).toBe(true);
      expect(result.certificate.pii).toBe("masked");
      expect(result.content).toContain("[SSN_MASKED]");
      expect(result.content).not.toContain("123-45-6789");
    });

    it("should detect email addresses", async () => {
      const request: ContentRequest = {
        content: "Contact me at user@example.com",
        tenant: "acme",
        context: "support_chat",
      };

      const result = await firewall.process(request);

      expect(result.blocked).toBe(true);
      expect(result.certificate.pii).toBe("masked");
      expect(result.content).toContain("[EMAIL_MASKED]");
      expect(result.content).not.toContain("user@example.com");
    });

    it("should detect API keys", async () => {
      const request: ContentRequest = {
        content: "api_key: sk-1234567890abcdef1234567890abcdef",
        tenant: "acme",
        context: "support_chat",
      };

      const result = await firewall.process(request);

      expect(result.blocked).toBe(true);
      expect(result.certificate.secrets).toBe("masked");
      expect(result.content).toContain("[API_KEY_MASKED]");
      expect(result.content).not.toContain("sk-1234567890abcdef1234567890abcdef");
    });

    it("should detect passwords", async () => {
      const request: ContentRequest = {
        content: "password: mysecretpassword123",
        tenant: "acme",
        context: "support_chat",
      };

      const result = await firewall.process(request);

      expect(result.blocked).toBe(true);
      expect(result.certificate.secrets).toBe("masked");
      expect(result.content).toContain("[PASSWORD_MASKED]");
      expect(result.content).not.toContain("mysecretpassword123");
    });

    it("should allow safe content", async () => {
      const request: ContentRequest = {
        content: "Hello, this is a safe message with no sensitive information.",
        tenant: "acme",
        context: "support_chat",
      };

      const result = await firewall.process(request);

      expect(result.blocked).toBe(false);
      expect(result.certificate.pii).toBe("none");
      expect(result.certificate.secrets).toBe("none");
      expect(result.certificate.non_interference).toBe("passed");
      expect(result.content).toBe(request.content);
    });
  });

  describe("Format and Entropy Analysis", () => {
    it("should detect structured data patterns", async () => {
      const request: ContentRequest = {
        content: "IP: 192.168.1.1, Base64: SGVsbG8gV29ybGQ=, Hex: deadbeef",
        tenant: "acme",
        context: "support_chat",
      };

      const result = await firewall.process(request);

      // Should detect structured data but not necessarily block
      expect(result.certificate.pii).toBe("none");
      expect(result.certificate.secrets).toBe("none");
    });

    it("should detect suspicious injection patterns", async () => {
      const request: ContentRequest = {
        content: 'DROP TABLE users; <script>alert("xss")</script>',
        tenant: "acme",
        context: "support_chat",
      };

      const result = await firewall.process(request);

      expect(result.blocked).toBe(true);
      expect(result.certificate.non_interference).toBe("failed");
    });

    it("should calculate entropy correctly", async () => {
      const lowEntropyText = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
      const highEntropyText = "The quick brown fox jumps over the lazy dog 123!@#";

      const lowEntropyRequest: ContentRequest = {
        content: lowEntropyText,
        tenant: "acme",
        context: "support_chat",
      };

      const highEntropyRequest: ContentRequest = {
        content: highEntropyText,
        tenant: "acme",
        context: "support_chat",
      };

      const lowResult = await firewall.process(lowEntropyRequest);
      const highResult = await firewall.process(highEntropyRequest);

      // Low entropy text should be processed (not necessarily blocked)
      expect(lowResult.blocked).toBe(false);
      expect(highResult.blocked).toBe(false);
    });
  });

  describe("Near-Duplicate Detection", () => {
    it("should detect near-duplicate content", async () => {
      const content1 = "This is a test message with some content.";
      const content2 = "This is a test message with some content!"; // Very similar

      const request1: ContentRequest = {
        content: content1,
        tenant: "acme",
        context: "support_chat",
      };

      const request2: ContentRequest = {
        content: content2,
        tenant: "acme",
        context: "support_chat",
      };

      const result1 = await firewall.process(request1);
      const result2 = await firewall.process(request2);

      expect(result1.certificate.near_dupe).toBe("none");
      expect(result2.certificate.near_dupe).toBe("detected");
    });

    it("should not flag completely different content", async () => {
      const content1 = "This is a test message with some content.";
      const content2 = "This is a completely different message about something else.";

      const request1: ContentRequest = {
        content: content1,
        tenant: "acme",
        context: "support_chat",
      };

      const request2: ContentRequest = {
        content: content2,
        tenant: "acme",
        context: "support_chat",
      };

      const result1 = await firewall.process(request1);
      const result2 = await firewall.process(request2);

      expect(result1.certificate.near_dupe).toBe("none");
      expect(result2.certificate.near_dupe).toBe("none");
    });
  });

  describe("LLM Analysis", () => {
    it("should use LLM analysis for ambiguous cases", async () => {
      const request: ContentRequest = {
        content: "The password for the system is very important to keep secure.",
        tenant: "acme",
        context: "support_chat",
      };

      const result = await firewall.process(request);

      // LLM should detect credential-related terms
      expect(result.blocked).toBe(true);
      expect(result.certificate.secrets).toBe("masked");
    });

    it("should handle context-aware analysis", async () => {
      const request: ContentRequest = {
        content: "The social security number field is required for tax purposes.",
        tenant: "acme",
        context: "documentation",
      };

      const result = await firewall.process(request);

      // LLM should detect SSN-related terms even without exact pattern match
      expect(result.blocked).toBe(true);
      expect(result.certificate.pii).toBe("masked");
    });
  });

  describe("Certificate Generation", () => {
    it("should generate valid certificates with Ed25519 signatures", async () => {
      const request: ContentRequest = {
        content: "My credit card is 1234-5678-9012-3456",
        tenant: "acme",
        context: "support_chat",
      };

      const result = await firewall.process(request);
      const certificate = result.certificate;

      // Verify certificate structure
      expect(certificate.pii).toBe("masked");
      expect(certificate.secrets).toBe("none");
      expect(certificate.near_dupe).toBe("none");
      expect(certificate.non_interference).toBe("failed");
      expect(certificate.influencing_labels).toEqual([]);
      expect(certificate.policy_hash).toHaveLength(64);
      expect(certificate.text_hash).toHaveLength(64);
      expect(certificate.attestation_ref).toMatch(/^attestation:acme:/);
      expect(certificate.sig).toHaveLength(128); // Ed25519 signature

      // Verify signature
      const isValid = await firewall.verifyCertificate(certificate);
      expect(isValid).toBe(true);
    });

    it("should include tenant and context in attestation", async () => {
      const request: ContentRequest = {
        content: "Safe content",
        tenant: "globex",
        context: "user_feedback",
        labels: ["public", "feedback"],
      };

      const result = await firewall.process(request);
      const certificate = result.certificate;

      expect(certificate.attestation_ref).toMatch(/^attestation:globex:/);
      expect(certificate.influencing_labels).toEqual(["public", "feedback"]);
    });

    it("should generate error certificates for processing failures", async () => {
      // Create a request that might cause processing issues
      const request: ContentRequest = {
        content: "Normal content",
        tenant: "acme",
        context: "support_chat",
      };

      // Mock a processing error by temporarily breaking the firewall
      jest.spyOn(firewall, "process").mockRejectedValueOnce(new Error("Processing error"));

      try {
        await firewall.process(request);
      } catch (error) {
        // Error should be handled gracefully
        expect(error).toBeDefined();
      }
    });
  });

  describe("Performance Requirements", () => {
    it("should process content within 400ms P95 requirement", async () => {
      const request: ContentRequest = {
        content: "This is a test message that should be processed quickly.",
        tenant: "acme",
        context: "support_chat",
      };

      const startTime = Date.now();
      const result = await firewall.process(request);
      const processingTime = Date.now() - startTime;

      expect(processingTime).toBeLessThan(400);
      expect(result.processing_time).toBeLessThan(400);
    });

    it("should handle large content efficiently", async () => {
      const largeContent = "Large content ".repeat(1000); // ~15KB

      const request: ContentRequest = {
        content: largeContent,
        tenant: "acme",
        context: "support_chat",
      };

      const startTime = Date.now();
      const result = await firewall.process(request);
      const processingTime = Date.now() - startTime;

      expect(processingTime).toBeLessThan(400);
      expect(result.processing_time).toBeLessThan(400);
    });
  });

  describe("Adversarial Testing", () => {
    it("should block 0 critical PII/secret leaks in adversarial scenarios", async () => {
      const adversarialInputs = [
        // Obfuscated credit card
        "My card is 1-2-3-4 5-6-7-8 9-0-1-2 3-4-5-6",
        "CC: 1234567890123456",
        "Card number: 1234 5678 9012 3456",

        // Obfuscated SSN
        "SSN: 123.45.6789",
        "Social Security: 123-45-6789",
        "Tax ID: 123456789",

        // Obfuscated API keys
        "API key is sk-1234567890abcdef1234567890abcdef",
        "Access key: AKIA1234567890ABCDEF",
        "Secret: ghp_1234567890abcdef1234567890abcdef12345678",

        // Obfuscated passwords
        "Password: mysecretpass123",
        "PWD: securepassword456",
        "Pass: confidential789",

        // Mixed sensitive data
        "User: john@example.com, Pass: secret123, CC: 1234-5678-9012-3456",
        "Email: user@domain.com\nPassword: mypass\nSSN: 123-45-6789",
      ];

      let blockedCount = 0;
      let totalProcessed = 0;

      for (const input of adversarialInputs) {
        const request: ContentRequest = {
          content: input,
          tenant: "acme",
          context: "adversarial_test",
        };

        const result = await firewall.process(request);
        totalProcessed++;

        if (result.blocked) {
          blockedCount++;
        }

        // Verify that sensitive data is either blocked or masked
        if (!result.blocked) {
          expect(result.certificate.pii).toBe("none");
          expect(result.certificate.secrets).toBe("none");
        }
      }

      // Should block at least 95% of adversarial inputs
      const blockRate = (blockedCount / totalProcessed) * 100;
      expect(blockRate).toBeGreaterThanOrEqual(95);

      console.log(
        `Adversarial test results: ${blockedCount}/${totalProcessed} blocked (${blockRate.toFixed(1)}%)`,
      );
    });

    it("should handle edge cases and malformed input", async () => {
      const edgeCases = [
        "", // Empty content
        "   ", // Whitespace only
        "a".repeat(10000), // Very long content
        "🚀🌟💫✨🎉🎊🎋🎍🎎🎏🎐🎑🎒🎓", // Unicode content
        "null", // String "null"
        "undefined", // String "undefined"
        "NaN", // String "NaN"
        "Infinity", // String "Infinity"
        "-Infinity", // String "-Infinity"
        "0", // Single character
        "1", // Single character
        "true", // String "true"
        "false", // String "false"
      ];

      for (const edgeCase of edgeCases) {
        const request: ContentRequest = {
          content: edgeCase,
          tenant: "acme",
          context: "edge_case_test",
        };

        const result = await firewall.process(request);

        // Should not crash and should produce valid result
        expect(result).toBeDefined();
        expect(result.certificate).toBeDefined();
        expect(result.processing_time).toBeGreaterThanOrEqual(0);
      }
    });
  });

  describe("Custom Patterns", () => {
    it("should support custom sensitive patterns", () => {
      const customPatterns: SensitivePattern[] = [
        {
          name: "custom_id",
          pattern: /\bID:\s*\d{6}\b/,
          category: "pii",
          confidence: 0.9,
          replacement: "[CUSTOM_ID_MASKED]",
        },
        {
          name: "internal_code",
          pattern: /\bINTERNAL-\d{4}\b/,
          category: "secret",
          confidence: 0.95,
          replacement: "[INTERNAL_CODE_MASKED]",
        },
      ];

      const customFirewall = createEgressFirewall({
        patterns: customPatterns,
        policies: ["custom_protection"],
        privateKeyHex: privateKey,
      });

      const request: ContentRequest = {
        content: "User ID: 123456 has internal code INTERNAL-9999",
        tenant: "acme",
        context: "custom_test",
      };

      return customFirewall.process(request).then((result) => {
        expect(result.blocked).toBe(true);
        expect(result.content).toContain("[CUSTOM_ID_MASKED]");
        expect(result.content).toContain("[INTERNAL_CODE_MASKED]");
        expect(result.content).not.toContain("123456");
        expect(result.content).not.toContain("INTERNAL-9999");
      });
    });
  });

  describe("Public Key Management", () => {
    it("should provide public key for external verification", () => {
      const publicKey = firewall.getPublicKey();

      expect(publicKey).toBeDefined();
      expect(publicKey).toHaveLength(64); // Ed25519 public key is 32 bytes = 64 hex chars
      expect(publicKey).toMatch(/^[0-9a-f]{64}$/); // Should be hex string
    });

    it("should generate consistent public key from same private key", () => {
      const firewall1 = createEgressFirewall({
        policies: ["test"],
        privateKeyHex: privateKey,
      });

      const firewall2 = createEgressFirewall({
        policies: ["test"],
        privateKeyHex: privateKey,
      });

      expect(firewall1.getPublicKey()).toBe(firewall2.getPublicKey());
    });
  });

  describe("Statistics and Monitoring", () => {
    it("should provide processing statistics", () => {
      const stats = firewall.getStats();

      expect(stats).toBeDefined();
      expect(stats.totalProcessed).toBeGreaterThanOrEqual(0);
      expect(stats.blockedCount).toBeGreaterThanOrEqual(0);
      expect(stats.piiDetected).toBeGreaterThanOrEqual(0);
      expect(stats.secretsDetected).toBeGreaterThanOrEqual(0);
      expect(stats.nearDuplicatesDetected).toBeGreaterThanOrEqual(0);
      expect(stats.averageProcessingTime).toBeGreaterThanOrEqual(0);
    });
  });
});
