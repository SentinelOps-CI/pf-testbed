#!/usr/bin/env node

import express from "express";
import cors from "cors";
import { createServer } from "http";
import { ApolloServer } from "apollo-server-express";
import { gql } from "apollo-server-express";

// Simple in-memory storage for risk scores
const riskScores = new Map<string, number>();

// GraphQL schema
const typeDefs = gql`
  type Capsule {
    hash: ID!
    riskScore: Float!
    reason: String
  }

  type Query {
    capsule(hash: ID!): Capsule
  }
`;

// Resolvers
const resolvers = {
  Query: {
    capsule: (parent: any, { hash }: { hash: string }) => {
      // For testing purposes, return a high risk score for known test hashes
      const testHash =
        "sha256:test1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

      if (hash === testHash) {
        return {
          hash,
          riskScore: 0.95, // High risk score for test cases
          reason: "Test attack case detected",
        };
      }

      // Default risk score for unknown hashes
      return {
        hash,
        riskScore: riskScores.get(hash) || 0.1,
        reason: "Standard risk assessment",
      };
    },
  },
};

async function startServer() {
  const app = express();

  // Middleware
  app.use(cors());
  app.use(express.json());

  // Health check endpoint
  app.get("/health", (req, res) => {
    res.json({ status: "healthy", timestamp: new Date().toISOString() });
  });

  // Create Apollo Server
  const server = new ApolloServer({
    typeDefs,
    resolvers,
    introspection: true,
    playground: true,
  });

  await server.start();
  server.applyMiddleware({ app, path: "/graphql" });

  const httpServer = createServer(app);
  const PORT = process.env.LEDGER_PORT || 3002;

  httpServer.listen(PORT, "0.0.0.0", () => {
    console.log(`🚀 Ledger service running on port ${PORT}`);
    console.log(`📊 GraphQL endpoint: http://localhost:${PORT}/graphql`);
    console.log(`🏥 Health check: http://localhost:${PORT}/health`);
  });
}

startServer().catch(console.error);
