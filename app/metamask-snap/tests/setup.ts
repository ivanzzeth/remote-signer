/**
 * Jest setup file for MetaMask Snap tests
 *
 * This file sets up the mock snap environment before tests run
 */

// Mock snap global object (will be overridden in individual tests)
(global as any).snap = {
  request: jest.fn(),
};
