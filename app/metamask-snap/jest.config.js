module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src', '<rootDir>/tests'],
  testMatch: ['**/__tests__/**/*.ts', '**/?(*.)+(spec|test).ts'],
  transform: {
    '^.+\\.ts$': ['ts-jest', {
      tsconfig: 'tsconfig.json',
    }],
  },
  transformIgnorePatterns: [
    'node_modules/(?!(@noble|@metamask|@remote-signer)/)', // Transform these modules
  ],
  moduleNameMapper: {
    '^@remote-signer/client$': '<rootDir>/../../pkg/js-client/dist/index.js',
  },
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
  ],
  testTimeout: 60000, // 60 seconds for e2e tests
  // Mock snap global
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],
};
