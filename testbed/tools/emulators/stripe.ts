import { BaseToolEmulator, ToolEmulatorConfig } from "../base/emulator";
import { ToolCall } from "../../contracts/types";

export interface StripePaymentIntent {
  id: string;
  amount: number;
  currency: string;
  status:
    | "requires_payment_method"
    | "requires_confirmation"
    | "requires_action"
    | "processing"
    | "requires_capture"
    | "canceled"
    | "succeeded";
  customer?: string;
  metadata: Record<string, string>;
  created: number;
}

export interface StripeCustomer {
  id: string;
  email: string;
  name?: string;
  phone?: string;
  metadata: Record<string, string>;
  created: number;
}

export class StripeEmulator extends BaseToolEmulator {
  private paymentIntents: Map<string, StripePaymentIntent> = new Map();
  private customers: Map<string, StripeCustomer> = new Map();
  private testMode: boolean = true;
  private realApiKey?: string;

  constructor() {
    super("stripe", "1.0.0", ["stripe:read", "stripe:write", "stripe:admin"]);

    // Initialize with default mock data
    this.initializeMockData();
  }

  private initializeMockData(): void {
    // Default customers
    this.customers.set("cus_mock123", {
      id: "cus_mock123",
      email: "test@example.com",
      name: "Test Customer",
      metadata: {},
      created: Date.now() / 1000,
    });

    // Default payment intents
    this.paymentIntents.set("pi_mock123", {
      id: "pi_mock123",
      amount: 2000, // $20.00
      currency: "usd",
      status: "succeeded",
      customer: "cus_mock123",
      metadata: { order_id: "order_123" },
      created: Date.now() / 1000,
    });
  }

  protected async executeMock(call: ToolCall): Promise<any> {
    await this.simulateDelay();

    switch (call.tool) {
      case "stripe.create_payment_intent":
        return this.createPaymentIntentMock(call);
      case "stripe.retrieve_payment_intent":
        return this.retrievePaymentIntentMock(call);
      case "stripe.confirm_payment_intent":
        return this.confirmPaymentIntentMock(call);
      case "stripe.create_customer":
        return this.createCustomerMock(call);
      case "stripe.retrieve_customer":
        return this.retrieveCustomerMock(call);
      default:
        throw new Error(`Unknown Stripe tool: ${call.tool}`);
    }
  }

  protected async executeReal(call: ToolCall): Promise<any> {
    if (!this.realApiKey) {
      throw new Error("Real API key not configured");
    }

    // Real Stripe API integration
    const stripe = require("stripe")(this.realApiKey);

    try {
      switch (call.tool) {
        case "stripe.create_payment_intent":
          return await stripe.paymentIntents.create(call.parameters);
        case "stripe.retrieve_payment_intent":
          return await stripe.paymentIntents.retrieve(call.parameters.id);
        case "stripe.confirm_payment_intent":
          return await stripe.paymentIntents.confirm(call.parameters.id, call.parameters);
        case "stripe.create_customer":
          return await stripe.customers.create(call.parameters);
        case "stripe.retrieve_customer":
          return await stripe.customers.retrieve(call.parameters.id);
        default:
          throw new Error(`Unknown Stripe tool: ${call.tool}`);
      }
    } catch (error: any) {
      throw new Error(`Stripe API error: ${error.message}`);
    }
  }

  protected async executeHybrid(call: ToolCall): Promise<any> {
    // Hybrid mode: use real for payment operations, mock for customer operations
    const realOperations = ["stripe.create_payment_intent", "stripe.confirm_payment_intent"];

    if (realOperations.includes(call.tool) && this.realApiKey) {
      return this.executeReal(call);
    } else {
      return this.executeMock(call);
    }
  }

  private async createPaymentIntentMock(call: ToolCall): Promise<any> {
    const { amount, currency = "usd", customer, metadata = {} } = call.parameters;

    if (!amount || amount <= 0) {
      throw new Error("Amount must be positive");
    }

    const paymentIntent: StripePaymentIntent = {
      id: `pi_mock_${this.generateId()}`,
      amount,
      currency,
      status: "requires_payment_method",
      customer,
      metadata,
      created: Date.now() / 1000,
    };

    this.paymentIntents.set(paymentIntent.id, paymentIntent);

    return {
      id: paymentIntent.id,
      object: "payment_intent",
      amount: paymentIntent.amount,
      currency: paymentIntent.currency,
      status: paymentIntent.status,
      customer: paymentIntent.customer,
      metadata: paymentIntent.metadata,
      created: paymentIntent.created,
      client_secret: `pi_${paymentIntent.id}_secret_${this.generateId()}`,
    };
  }

  private async retrievePaymentIntentMock(call: ToolCall): Promise<any> {
    const { id } = call.parameters;

    if (!this.paymentIntents.has(id)) {
      throw new Error(`Payment intent ${id} not found`);
    }

    const paymentIntent = this.paymentIntents.get(id)!;

    return {
      id: paymentIntent.id,
      object: "payment_intent",
      amount: paymentIntent.amount,
      currency: paymentIntent.currency,
      status: paymentIntent.status,
      customer: paymentIntent.customer,
      metadata: paymentIntent.metadata,
      created: paymentIntent.created,
    };
  }

  private async confirmPaymentIntentMock(call: ToolCall): Promise<any> {
    const { id, payment_method } = call.parameters;

    if (!this.paymentIntents.has(id)) {
      throw new Error(`Payment intent ${id} not found`);
    }

    const paymentIntent = this.paymentIntents.get(id)!;

    // Simulate payment confirmation
    paymentIntent.status = "succeeded";
    this.paymentIntents.set(id, paymentIntent);

    return {
      id: paymentIntent.id,
      object: "payment_intent",
      amount: paymentIntent.amount,
      currency: paymentIntent.currency,
      status: paymentIntent.status,
      customer: paymentIntent.customer,
      metadata: paymentIntent.metadata,
      created: paymentIntent.created,
    };
  }

  private async createCustomerMock(call: ToolCall): Promise<any> {
    const { email, name, phone, metadata = {} } = call.parameters;

    if (!email) {
      throw new Error("Email is required");
    }

    const customer: StripeCustomer = {
      id: `cus_mock_${this.generateId()}`,
      email,
      name,
      phone,
      metadata,
      created: Date.now() / 1000,
    };

    this.customers.set(customer.id, customer);

    return {
      id: customer.id,
      object: "customer",
      email: customer.email,
      name: customer.name,
      phone: customer.phone,
      metadata: customer.metadata,
      created: customer.created,
    };
  }

  private async retrieveCustomerMock(call: ToolCall): Promise<any> {
    const { id } = call.parameters;

    if (!this.customers.has(id)) {
      throw new Error(`Customer ${id} not found`);
    }

    const customer = this.customers.get(id)!;

    return {
      id: customer.id,
      object: "customer",
      email: customer.email,
      name: customer.name,
      phone: customer.phone,
      metadata: customer.metadata,
      created: customer.created,
    };
  }

  // Override configure to handle Stripe-specific configuration
  async configure(config: ToolEmulatorConfig): Promise<void> {
    await super.configure(config);

    // Handle Stripe-specific configuration
    if (config.mode === "real" || config.mode === "hybrid") {
      const apiKey = process.env.STRIPE_TEST_KEY || process.env.STRIPE_SECRET_KEY;
      if (!apiKey) {
        throw new Error("Stripe API key required for real mode");
      }
      this.realApiKey = apiKey;
      this.testMode = apiKey.startsWith("sk_test_");
    }
  }

  // Override setMockData to handle Stripe-specific data
  setMockData(data: any): void {
    super.setMockData(data);

    if (data.customers) {
      data.customers.forEach((customer: StripeCustomer) => {
        this.customers.set(customer.id, customer);
      });
    }

    if (data.paymentIntents) {
      data.paymentIntents.forEach((pi: StripePaymentIntent) => {
        this.paymentIntents.set(pi.id, pi);
      });
    }
  }

  // Get test mode status
  isTestMode(): boolean {
    return this.testMode;
  }

  // Get real API key status
  hasRealApiKey(): boolean {
    return !!this.realApiKey;
  }
}
