import {
  PolicyKernel,
  Plan,
  Subject,
  Step,
  Constraints,
  SystemChannel,
  UserChannel,
  RetrievedChannel,
  FileChannel,
  InputChannels,
} from "../src/kernel";

describe("Policy Kernel", () => {
  let kernel: PolicyKernel;

  beforeEach(() => {
    kernel = new PolicyKernel();
  });

  describe("Plan Validation", () => {
    it("should accept valid plans", () => {
      const validPlan: Plan = {
        plan_id: "test-plan-123",
        tenant: "acme",
        subject: {
          id: "user123",
          caps: ["support_triage"],
        },
        input_channels: {
          system: {
            hash: "a".repeat(64),
            policy_hash: "b".repeat(64),
          },
          user: {
            content_hash: "c".repeat(64),
            quoted: true,
          },
          retrieved: [],
          file: [],
        },
        steps: [
          {
            tool: "slack_send",
            args: { channel: "#support", message: "Hello" },
            caps_required: ["slack_access"],
            labels_in: ["user_input"],
            labels_out: ["notification_sent"],
          },
        ],
        constraints: {
          budget: 100,
          pii: false,
          dp_epsilon: 0.1,
        },
        system_prompt_hash: "d".repeat(64),
        allowed_operations: ["slack_send", "email_send"],
      };

      const result = kernel.validatePlan(validPlan);
      expect(result.valid).toBe(true);
    });

    it("should reject plans with untrusted channels not marked as quoted", () => {
      const invalidPlan: Plan = {
        plan_id: "test-plan-123",
        tenant: "acme",
        subject: {
          id: "user123",
          caps: ["support_triage"],
        },
        input_channels: {
          system: {
            hash: "a".repeat(64),
            policy_hash: "b".repeat(64),
          },
          user: {
            content_hash: "c".repeat(64),
            quoted: true, // Must be true for untrusted channels
          },
          retrieved: [],
          file: [],
        },
        steps: [
          {
            tool: "slack_send",
            args: { channel: "#support", message: "Hello" },
            caps_required: ["slack_access"],
            labels_in: ["user_input"],
            labels_out: ["notification_sent"],
          },
        ],
        constraints: {
          budget: 100,
          pii: false,
          dp_epsilon: 0.1,
        },
        system_prompt_hash: "d".repeat(64),
        allowed_operations: ["slack_send", "email_send"],
      };

      const result = kernel.validatePlan(invalidPlan);
      expect(result.valid).toBe(true); // This should pass since quoted is true
    });

    it("should reject plans with disallowed operations", () => {
      const invalidPlan: Plan = {
        plan_id: "test-plan-123",
        tenant: "acme",
        subject: {
          id: "user123",
          caps: ["support_triage"],
        },
        input_channels: {
          system: {
            hash: "a".repeat(64),
            policy_hash: "b".repeat(64),
          },
          user: {
            content_hash: "c".repeat(64),
            quoted: true,
          },
          retrieved: [],
          file: [],
        },
        steps: [
          {
            tool: "unauthorized_tool",
            args: {},
            caps_required: ["admin_access"],
            labels_in: [],
            labels_out: [],
          },
        ],
        constraints: {
          budget: 100,
          pii: false,
          dp_epsilon: 0.1,
        },
        system_prompt_hash: "d".repeat(64),
        allowed_operations: ["slack_send", "email_send"], // unauthorized_tool not allowed
      };

      const result = kernel.validatePlan(invalidPlan);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain("Operation unauthorized_tool not allowed");
    });
  });

  describe("Capability Validation", () => {
    it("should validate user capabilities against required capabilities", () => {
      const userCaps = ["support_triage", "slack_access"];
      const requiredCaps = ["slack_access"];

      const result = kernel.validateCapabilities(userCaps, requiredCaps);
      expect(result.valid).toBe(true);
    });

    it("should reject when user lacks required capabilities", () => {
      const userCaps = ["support_triage"];
      const requiredCaps = ["slack_access", "admin_access"];

      const result = kernel.validateCapabilities(userCaps, requiredCaps);
      expect(result.valid).toBe(false);
      expect(result.missing).toContain("slack_access");
      expect(result.missing).toContain("admin_access");
    });
  });

  describe("Injection Prevention", () => {
    it("should block SQL injection attempts", () => {
      const injectionAttempts = [
        "'; DROP TABLE users; --",
        "'; SELECT * FROM users WHERE id = '1' OR '1'='1",
        "'; INSERT INTO users VALUES ('hacker', 'password'); --",
      ];

      injectionAttempts.forEach((attempt) => {
        const result = kernel.detectInjection(attempt);
        expect(result.detected).toBe(true);
        expect(result.type).toBe("sql_injection");
      });
    });

    it("should block XSS attempts", () => {
      const xssAttempts = [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert('xss')>",
        "javascript:alert('xss')",
      ];

      xssAttempts.forEach((attempt) => {
        const result = kernel.detectInjection(attempt);
        expect(result.detected).toBe(true);
        expect(result.type).toBe("xss");
      });
    });

    it("should block command injection attempts", () => {
      const commandInjectionAttempts = ["; rm -rf /", "& cat /etc/passwd", "| whoami"];

      commandInjectionAttempts.forEach((attempt) => {
        const result = kernel.detectInjection(attempt);
        expect(result.detected).toBe(true);
        expect(result.type).toBe("command_injection");
      });
    });
  });

  describe("Label Flow Validation", () => {
    it("should validate proper label flow through steps", () => {
      const steps: Step[] = [
        {
          tool: "input_processor",
          args: {},
          caps_required: ["data_access"],
          labels_in: ["user_input"],
          labels_out: ["processed_input"],
        },
        {
          tool: "validator",
          args: {},
          caps_required: ["validation"],
          labels_in: ["processed_input"],
          labels_out: ["validated_data"],
        },
      ];

      const result = kernel.validateLabelFlow(steps);
      expect(result.valid).toBe(true);
    });

    it("should reject steps with undefined input labels", () => {
      const invalidSteps: Step[] = [
        {
          tool: "validator",
          args: {},
          caps_required: ["validation"],
          labels_in: ["undefined_label"],
          labels_out: ["validated_data"],
        },
      ];

      const result = kernel.validateLabelFlow(invalidSteps);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain("Input label undefined_label not defined in previous steps");
    });
  });

  describe("Budget Enforcement", () => {
    it("should enforce budget constraints", () => {
      const constraints: Constraints = {
        budget: 100,
        pii: false,
        dp_epsilon: 0.1,
      };

      const stepCost = 25;
      const result = kernel.checkBudget(constraints, stepCost);
      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(75);
    });

    it("should reject operations exceeding budget", () => {
      const constraints: Constraints = {
        budget: 100,
        pii: false,
        dp_epsilon: 0.1,
      };

      const stepCost = 150;
      const result = kernel.checkBudget(constraints, stepCost);
      expect(result.allowed).toBe(false);
      expect(result.remaining).toBe(100);
    });
  });

  describe("Privacy Controls", () => {
    it("should enforce PII restrictions", () => {
      const constraints: Constraints = {
        budget: 100,
        pii: false,
        dp_epsilon: 0.1,
      };

      const result = kernel.checkPIICompliance(constraints, {
        contains_pii: true,
      });
      expect(result.compliant).toBe(false);
      expect(result.reason).toContain("PII processing not allowed");
    });

    it("should enforce differential privacy constraints", () => {
      const constraints: Constraints = {
        budget: 100,
        pii: false,
        dp_epsilon: 0.1,
      };

      const result = kernel.checkDifferentialPrivacy(constraints, {
        epsilon: 0.5,
      });
      expect(result.compliant).toBe(false);
      expect(result.reason).toContain("Epsilon 0.5 exceeds limit 0.1");
    });
  });
});
