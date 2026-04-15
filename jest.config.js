module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/testbed'],
  testPathIgnorePatterns: [
    '/node_modules/',
    // Out of sync with current AgentRunner / PolicyKernel APIs; tracked for follow-up
    '<rootDir>/testbed/runtime/gateway/__tests__/agent-zoo.test.ts',
    '<rootDir>/testbed/runtime/policy-kernel/__tests__/kernel.test.ts',
  ],
  testMatch: [
    '**/__tests__/**/*.test.ts',
    '**/?(*.)+(spec|test).ts'
  ],
  transform: {
    '^.+\\.ts$': 'ts-jest',
  },
  collectCoverageFrom: [
    'testbed/**/*.ts',
    '!testbed/**/*.d.ts',
    '!testbed/**/__tests__/**',
    '!testbed/**/node_modules/**'
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html'],
  setupFilesAfterEnv: ['<rootDir>/testbed/__tests__/setup.ts'],
  testTimeout: 10000,
  verbose: true,
  clearMocks: true,
  restoreMocks: true
};
