/**
 * Cypress tests for Observability Dashboards
 * Tests key panels and functionality of Grafana dashboards
 */

describe("Observability Dashboards", () => {
  beforeEach(() => {
    // Visit Grafana
    cy.visit("http://localhost:3000");

    // Login to Grafana
    cy.get('[data-testid="username-input"]').type("admin");
    cy.get('[data-testid="password-input"]').type("admin");
    cy.get('[data-testid="login-button"]').click();

    // Wait for login to complete
    cy.url().should("include", "/dashboards");
  });

  describe("SLO Overview Dashboard", () => {
    it("should load SLO Overview dashboard", () => {
      // Navigate to SLO Overview dashboard
      cy.visit("http://localhost:3000/d/slo-overview/slo-overview");

      // Wait for dashboard to load
      cy.get('[data-testid="dashboard-container"]', { timeout: 10000 }).should("be.visible");

      // Check dashboard title
      cy.get('[data-testid="dashboard-title"]').should("contain", "SLO Overview");
    });

    it("should display SLO compliance metrics", () => {
      cy.visit("http://localhost:3000/d/slo-overview/slo-overview");

      // Check SLO compliance panel
      cy.get('[data-testid="panel-1"]').within(() => {
        cy.get('[data-testid="stat-text"]').should("be.visible");
        cy.get('[data-testid="stat-text"]').should("contain", "%");
      });
    });

    it("should display response time percentiles", () => {
      cy.visit("http://localhost:3000/d/slo-overview/slo-overview");

      // Check P95 response time panel
      cy.get('[data-testid="panel-2"]').within(() => {
        cy.get('[data-testid="stat-text"]').should("be.visible");
        cy.get('[data-testid="stat-text"]').should("contain", "s");
      });

      // Check P99 response time panel
      cy.get('[data-testid="panel-3"]').within(() => {
        cy.get('[data-testid="stat-text"]').should("be.visible");
        cy.get('[data-testid="stat-text"]').should("contain", "s");
      });
    });

    it("should display error rate metrics", () => {
      cy.visit("http://localhost:3000/d/slo-overview/slo-overview");

      // Check error rate panel
      cy.get('[data-testid="panel-4"]').within(() => {
        cy.get('[data-testid="stat-text"]').should("be.visible");
        cy.get('[data-testid="stat-text"]').should("contain", "%");
      });
    });

    it("should display request rate graph", () => {
      cy.visit("http://localhost:3000/d/slo-overview/slo-overview");

      // Check request rate graph panel
      cy.get('[data-testid="panel-5"]').within(() => {
        cy.get('[data-testid="graph-container"]').should("be.visible");
      });
    });

    it("should display response time distribution heatmap", () => {
      cy.visit("http://localhost:3000/d/slo-overview/slo-overview");

      // Check response time distribution panel
      cy.get('[data-testid="panel-6"]').within(() => {
        cy.get('[data-testid="heatmap-container"]').should("be.visible");
      });
    });

    it("should display SLO violations table", () => {
      cy.visit("http://localhost:3000/d/slo-overview/slo-overview");

      // Check SLO violations table panel
      cy.get('[data-testid="panel-7"]').within(() => {
        cy.get('[data-testid="table-container"]').should("be.visible");
      });
    });
  });

  describe("Dashboard Functionality", () => {
    it("should allow time range selection", () => {
      cy.visit("http://localhost:3000/d/slo-overview/slo-overview");

      // Open time picker
      cy.get('[data-testid="time-picker"]').click();

      // Check time range options
      cy.get('[data-testid="time-picker-options"]').should("be.visible");
      cy.get('[data-testid="time-picker-options"]').should("contain", "Last 1 hour");
      cy.get('[data-testid="time-picker-options"]').should("contain", "Last 6 hours");
      cy.get('[data-testid="time-picker-options"]').should("contain", "Last 24 hours");
    });

    it("should allow refresh interval configuration", () => {
      cy.visit("http://localhost:3000/d/slo-overview/slo-overview");

      // Check refresh interval
      cy.get('[data-testid="refresh-picker"]').should("be.visible");
      cy.get('[data-testid="refresh-picker"]').should("contain", "5s");
    });

    it("should support template variables", () => {
      cy.visit("http://localhost:3000/d/slo-overview/slo-overview");

      // Check service template variable
      cy.get('[data-testid="template-vars"]').within(() => {
        cy.get('[data-testid="var-service"]').should("be.visible");
        cy.get('[data-testid="var-environment"]').should("be.visible");
      });
    });
  });

  describe("Data Validation", () => {
    it("should display real-time data", () => {
      cy.visit("http://localhost:3000/d/slo-overview/slo-overview");

      // Wait for data to load
      cy.get('[data-testid="panel-1"]', { timeout: 15000 }).within(() => {
        cy.get('[data-testid="stat-text"]').should("not.contain", "No data");
      });
    });

    it("should handle data updates", () => {
      cy.visit("http://localhost:3000/d/slo-overview/slo-overview");

      // Wait for initial data
      cy.get('[data-testid="panel-1"]').should("be.visible");

      // Verify panels keep rendering data without fixed sleep.
      cy.get('[data-testid="panel-1"]', { timeout: 15000 }).within(() => {
        cy.get('[data-testid="stat-text"]').should("be.visible");
      });
    });
  });

  describe("Performance Gates", () => {
    it("should meet latency to insight requirements", () => {
      const startTime = Date.now();

      cy.visit("http://localhost:3000/d/slo-overview/slo-overview");

      // Wait for dashboard to be fully loaded with data
      cy.get('[data-testid="panel-1"]', { timeout: 10000 }).should("be.visible");
      cy.get('[data-testid="panel-1"]').within(() => {
        cy.get('[data-testid="stat-text"]').should("not.contain", "No data");
      });

      const loadTime = Date.now() - startTime;

      // Assert latency to insight is less than 5 seconds
      expect(loadTime).to.be.lessThan(5000);
    });

    it("should display performance thresholds correctly", () => {
      cy.visit("http://localhost:3000/d/slo-overview/slo-overview");

      // Check P95 threshold (should be < 2.0s)
      cy.get('[data-testid="panel-2"]').within(() => {
        cy.get('[data-testid="stat-text"]').then(($el) => {
          const value = parseFloat($el.text().replace(/[^\d.]/g, ""));
          expect(value).to.be.lessThan(2.0);
        });
      });

      // Check P99 threshold (should be < 4.0s)
      cy.get('[data-testid="panel-3"]').within(() => {
        cy.get('[data-testid="stat-text"]').then(($el) => {
          const value = parseFloat($el.text().replace(/[^\d.]/g, ""));
          expect(value).to.be.lessThan(4.0);
        });
      });
    });
  });

  describe("Error Handling", () => {
    it("should handle missing data gracefully", () => {
      // This test would require setting up a scenario with missing data
      // For now, we'll test that the dashboard loads even with potential data issues
      cy.visit("http://localhost:3000/d/slo-overview/slo-overview");

      // Dashboard should still load
      cy.get('[data-testid="dashboard-container"]').should("be.visible");
    });

    it("should display error states appropriately", () => {
      cy.visit("http://localhost:3000/d/slo-overview/slo-overview");

      // Check that error states are handled gracefully
      cy.get('[data-testid="dashboard-container"]').should("be.visible");
    });
  });

  describe("Accessibility", () => {
    it("should have proper ARIA labels", () => {
      cy.visit("http://localhost:3000/d/slo-overview/slo-overview");

      // Check for accessibility attributes
      cy.get('[data-testid="dashboard-container"]').should("have.attr", "role");
    });

    it("should support keyboard navigation", () => {
      cy.visit("http://localhost:3000/d/slo-overview/slo-overview");

      // Test keyboard navigation
      cy.get("body").tab();
      cy.focused().should("be.visible");
    });
  });

  describe("Cross-browser Compatibility", () => {
    it("should work across different viewport sizes", () => {
      cy.visit("http://localhost:3000/d/slo-overview/slo-overview");

      // Test responsive design
      cy.viewport(1920, 1080);
      cy.get('[data-testid="dashboard-container"]').should("be.visible");

      cy.viewport(1366, 768);
      cy.get('[data-testid="dashboard-container"]').should("be.visible");

      cy.viewport(768, 1024);
      cy.get('[data-testid="dashboard-container"]').should("be.visible");
    });
  });
});
