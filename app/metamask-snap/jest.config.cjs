module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src', '<rootDir>/tests'],
  testMatch: ['**/__tests__/**/*.ts', '**/?(*.)+(spec|test).ts'],
  transform: {
    '^.+\\.ts$': ['ts-jest', {
      tsconfig: {
        target: 'ES2020',
        module: 'commonjs',
        esModuleInterop: true,
      },
    }],
    '^.+\\.js$': 'babel-jest',
  },
  transformIgnorePatterns: [
    'node_modules/(?!(@noble|@metamask|@remote-signer|@babel)/)', // Transform these modules
  ],
  moduleNameMapper: {
    // Use source during tests to avoid depending on prebuilt artifacts.
    '^@remote-signer/client$': '<rootDir>/../../pkg/js-client/src/index.ts',
  },
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
  ],
  testTimeout: 60000, // 60 seconds for e2e tests
  // Mock snap global
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],
};
