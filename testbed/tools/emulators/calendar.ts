import { createHash } from "crypto";
import { z } from "zod";

// Calendar emulator for TB-08
// Provides deterministic, seeded mocks with real mode capabilities

export const CalendarEventSchema = z.object({
  id: z.string().optional(),
  title: z.string().min(1).max(200),
  description: z.string().optional(),
  start_time: z.string().datetime(),
  end_time: z.string().datetime(),
  location: z.string().optional(),
  attendees: z.array(z.string().email()).optional(),
  tenant: z.string().min(1),
  capability_token: z.string().min(1),
  enforce: z.boolean().default(true),
});

export const CalendarResponseSchema = z.object({
  success: z.boolean(),
  event_id: z.string(),
  created_at: z.string(),
  event: CalendarEventSchema,
  metadata: z.object({
    tenant: z.string(),
    capability_token: z.string(),
    enforce_mode: z.boolean(),
    processing_time_ms: z.number(),
  }),
  error: z.string().optional(),
});

export type CalendarEvent = z.infer<typeof CalendarEventSchema>;
export type CalendarResponse = z.infer<typeof CalendarResponseSchema>;

// Calendar availability interface
export interface TimeSlot {
  start: string;
  end: string;
  available: boolean;
  reason?: string;
}

// Mock calendar configuration
export interface MockCalendarConfig {
  seed: string;
  booking_delay_ms: number;
  failure_rate: number;
  max_events_per_day: number;
  max_attendees_per_event: number;
  business_hours: {
    start: string; // HH:MM
    end: string; // HH:MM
    timezone: string;
  };
}

export class CalendarEmulator {
  private readonly seed: string;
  private readonly enforceMode: boolean;
  private readonly capabilityToken: string;
  private readonly tenant: string;
  private readonly mockConfig: MockCalendarConfig;
  private readonly events: Map<string, CalendarEvent> = new Map();
  private readonly availabilityCache: Map<string, TimeSlot[]> = new Map();

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

    // Initialize with some sample events
    this.initializeSampleEvents();
  }

  private initializeMockConfig(seed: string): MockCalendarConfig {
    const hash = createHash("sha256").update(seed).digest("hex");

    return {
      seed,
      booking_delay_ms: (parseInt(hash.slice(0, 8), 16) % 3000) + 200, // 200-3200ms
      failure_rate: (parseInt(hash.slice(8, 16), 16) % 100) / 1000, // 0-10%
      max_events_per_day: (parseInt(hash.slice(16, 24), 16) % 20) + 5, // 5-25
      max_attendees_per_event: (parseInt(hash.slice(24, 32), 16) % 50) + 1, // 1-51
      business_hours: {
        start: "09:00",
        end: "17:00",
        timezone: "UTC",
      },
    };
  }

  private initializeSampleEvents(): void {
    const sampleEvents: CalendarEvent[] = [
      {
        title: "Team Standup",
        description: "Daily team synchronization meeting",
        start_time: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(), // Tomorrow
        end_time: new Date(Date.now() + 24 * 60 * 60 * 1000 + 30 * 60 * 1000).toISOString(),
        location: "Conference Room A",
        attendees: ["team@acme.com", "manager@acme.com"],
        tenant: "acme",
        capability_token: "sample_token",
        enforce: false,
      },
      {
        title: "Client Meeting",
        description: "Quarterly review with key client",
        start_time: new Date(Date.now() + 2 * 24 * 60 * 60 * 1000).toISOString(), // Day after tomorrow
        end_time: new Date(Date.now() + 2 * 24 * 60 * 60 * 1000 + 60 * 60 * 1000).toISOString(),
        location: "Virtual",
        attendees: ["client@example.com", "sales@acme.com"],
        tenant: "acme",
        capability_token: "sample_token",
        enforce: false,
      },
    ];

    sampleEvents.forEach((event) => {
      const eventId = this.generateEventId(event);
      this.events.set(eventId, { ...event, id: eventId });
    });
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
      .update(`${this.tenant}:calendar:${operation}`)
      .digest("hex");

    return capabilityToken === expectedHash;
  }

  // Check business hours
  private isWithinBusinessHours(startTime: string, endTime: string): boolean {
    const start = new Date(startTime);
    const end = new Date(endTime);

    const startHour = start.getUTCHours();
    const endHour = end.getUTCHours();

    const businessStart = parseInt(this.mockConfig.business_hours.start.split(":")[0]);
    const businessEnd = parseInt(this.mockConfig.business_hours.end.split(":")[0]);

    return startHour >= businessStart && endHour <= businessEnd;
  }

  // Check event conflicts
  private hasEventConflict(event: CalendarEvent): boolean {
    const eventStart = new Date(event.start_time);
    const eventEnd = new Date(event.end_time);

    for (const existingEvent of this.events.values()) {
      if (existingEvent.tenant !== event.tenant) continue;

      const existingStart = new Date(existingEvent.start_time);
      const existingEnd = new Date(existingEvent.end_time);

      // Check for overlap
      if (eventStart < existingEnd && eventEnd > existingStart) {
        return true;
      }
    }

    return false;
  }

  // Create calendar event
  async createEvent(event: CalendarEvent): Promise<CalendarResponse> {
    const startTime = Date.now();

    try {
      // Validate request schema
      const validatedEvent = CalendarEventSchema.parse(event);

      // Validate capability if in enforce mode
      if (this.enforceMode && !this.validateCapability(validatedEvent.capability_token, "create")) {
        return {
          success: false,
          event_id: "",
          created_at: new Date().toISOString(),
          event: validatedEvent,
          metadata: {
            tenant: validatedEvent.tenant,
            capability_token: validatedEvent.capability_token,
            enforce_mode: this.enforceMode,
            processing_time_ms: Date.now() - startTime,
          },
          error: "CAP_MISS: Missing or invalid capability token for calendar event creation",
        };
      }

      // Check business hours
      if (!this.isWithinBusinessHours(validatedEvent.start_time, validatedEvent.end_time)) {
        return {
          success: false,
          event_id: "",
          created_at: new Date().toISOString(),
          event: validatedEvent,
          metadata: {
            tenant: validatedEvent.tenant,
            capability_token: validatedEvent.capability_token,
            enforce_mode: this.enforceMode,
            processing_time_ms: Date.now() - startTime,
          },
          error: "BUSINESS_HOURS_VIOLATION: Event outside business hours",
        };
      }

      // Check attendee limits
      if (
        validatedEvent.attendees &&
        validatedEvent.attendees.length > this.mockConfig.max_attendees_per_event
      ) {
        return {
          success: false,
          event_id: "",
          created_at: new Date().toISOString(),
          event: validatedEvent,
          metadata: {
            tenant: validatedEvent.tenant,
            capability_token: validatedEvent.capability_token,
            enforce_mode: this.enforceMode,
            processing_time_ms: Date.now() - startTime,
          },
          error: `ATTENDEE_LIMIT_EXCEEDED: Maximum ${this.mockConfig.max_attendees_per_event} attendees allowed`,
        };
      }

      // Check event conflicts
      if (this.hasEventConflict(validatedEvent)) {
        return {
          success: false,
          event_id: "",
          created_at: new Date().toISOString(),
          event: validatedEvent,
          metadata: {
            tenant: validatedEvent.tenant,
            capability_token: validatedEvent.capability_token,
            enforce_mode: this.enforceMode,
            processing_time_ms: Date.now() - startTime,
          },
          error: "EVENT_CONFLICT: Time slot conflicts with existing event",
        };
      }

      // Simulate booking delay
      await this.simulateBookingDelay();

      // Simulate potential failure
      if (Math.random() < this.mockConfig.failure_rate) {
        throw new Error("Simulated calendar booking failure");
      }

      // Generate event ID
      const eventId = this.generateEventId(validatedEvent);

      // Store event
      this.events.set(eventId, { ...validatedEvent, id: eventId });

      const response: CalendarResponse = {
        success: true,
        event_id: eventId,
        created_at: new Date().toISOString(),
        event: { ...validatedEvent, id: eventId },
        metadata: {
          tenant: validatedEvent.tenant,
          capability_token: validatedEvent.capability_token,
          enforce_mode: this.enforceMode,
          processing_time_ms: Date.now() - startTime,
        },
      };

      return response;
    } catch (error) {
      return {
        success: false,
        event_id: "",
        created_at: new Date().toISOString(),
        event: event,
        metadata: {
          tenant: event.tenant || "unknown",
          capability_token: event.capability_token || "",
          enforce_mode: this.enforceMode,
          processing_time_ms: Date.now() - startTime,
        },
        error: error instanceof Error ? error.message : "Unknown error",
      };
    }
  }

  // Get event by ID
  async getEvent(eventId: string, capabilityToken: string): Promise<CalendarResponse | null> {
    const startTime = Date.now();

    // Validate capability if in enforce mode
    if (this.enforceMode && !this.validateCapability(capabilityToken, "read")) {
      return {
        success: false,
        event_id: eventId,
        created_at: new Date().toISOString(),
        event: {} as CalendarEvent,
        metadata: {
          tenant: "unknown",
          capability_token: capabilityToken,
          enforce_mode: this.enforceMode,
          processing_time_ms: Date.now() - startTime,
        },
        error: "CAP_MISS: Missing or invalid capability token for calendar event reading",
      };
    }

    const event = this.events.get(eventId);
    if (!event) {
      return null;
    }

    return {
      success: true,
      event_id: eventId,
      created_at: new Date().toISOString(),
      event,
      metadata: {
        tenant: event.tenant,
        capability_token: capabilityToken,
        enforce_mode: this.enforceMode,
        processing_time_ms: Date.now() - startTime,
      },
    };
  }

  // List events for a tenant
  async listEvents(
    tenant: string,
    capabilityToken: string,
    startDate?: string,
    endDate?: string,
  ): Promise<CalendarEvent[]> {
    // Validate capability if in enforce mode
    if (this.enforceMode && !this.validateCapability(capabilityToken, "read")) {
      throw new Error("CAP_MISS: Missing or invalid capability token for calendar event listing");
    }

    let events = Array.from(this.events.values()).filter((event) => event.tenant === tenant);

    // Filter by date range if provided
    if (startDate && endDate) {
      const start = new Date(startDate);
      const end = new Date(endDate);

      events = events.filter((event) => {
        const eventStart = new Date(event.start_time);
        return eventStart >= start && eventStart <= end;
      });
    }

    return events;
  }

  // Check availability for a time slot
  async checkAvailability(
    tenant: string,
    startTime: string,
    endTime: string,
    capabilityToken: string,
  ): Promise<TimeSlot[]> {
    // Validate capability if in enforce mode
    if (this.enforceMode && !this.validateCapability(capabilityToken, "read")) {
      throw new Error("CAP_MISS: Missing or invalid capability token for availability checking");
    }

    const start = new Date(startTime);
    const end = new Date(endTime);
    const slots: TimeSlot[] = [];

    // Generate 30-minute slots for the requested time range
    let current = new Date(start);
    while (current < end) {
      const slotEnd = new Date(current.getTime() + 30 * 60 * 1000);

      // Check if this slot conflicts with existing events
      let available = true;
      let reason = undefined;

      for (const event of this.events.values()) {
        if (event.tenant !== tenant) continue;

        const eventStart = new Date(event.start_time);
        const eventEnd = new Date(event.end_time);

        if (current < eventEnd && slotEnd > eventStart) {
          available = false;
          reason = `Conflicts with: ${event.title}`;
          break;
        }
      }

      // Check business hours
      if (!this.isWithinBusinessHours(current.toISOString(), slotEnd.toISOString())) {
        available = false;
        reason = "Outside business hours";
      }

      slots.push({
        start: current.toISOString(),
        end: slotEnd.toISOString(),
        available,
        reason,
      });

      current = slotEnd;
    }

    return slots;
  }

  // Generate deterministic event ID
  private generateEventId(event: CalendarEvent): string {
    const data = `${this.seed}:${event.title}:${event.start_time}:${event.tenant}:${Date.now()}`;
    return createHash("sha256").update(data).digest("hex").slice(0, 16);
  }

  // Simulate booking delay
  private async simulateBookingDelay(): Promise<void> {
    return new Promise((resolve) => {
      setTimeout(resolve, this.mockConfig.booking_delay_ms);
    });
  }

  // Get mock configuration
  getMockConfig(): MockCalendarConfig {
    return { ...this.mockConfig };
  }

  // Reset emulator state
  reset(): void {
    this.events.clear();
    this.availabilityCache.clear();
    this.initializeSampleEvents();
  }

  // Switch to real mode (placeholder for real calendar service integration)
  async switchToRealMode(apiKey: string, serviceConfig: any): Promise<void> {
    if (this.enforceMode) {
      throw new Error("Cannot switch to real mode while enforce mode is enabled");
    }

    // In a real implementation, this would initialize a real calendar service
    // For now, we'll just log the intention
    console.log("Switching to real calendar service mode");
    console.log("API Key:", apiKey ? "***" + apiKey.slice(-4) : "none");
    console.log("Service Config:", serviceConfig);
  }
}

// Export factory function for easy instantiation
export const createCalendarEmulator = (
  seed: string = "default",
  enforceMode: boolean = true,
  capabilityToken: string = "",
  tenant: string = "default",
): CalendarEmulator => {
  return new CalendarEmulator(seed, enforceMode, capabilityToken, tenant);
};

// Export default instance
export const defaultCalendarEmulator = createCalendarEmulator();
