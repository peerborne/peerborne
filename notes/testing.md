> Historical note: this document predates the Peerborne rename and no longer reflects current package names, commands, or test counts. Use `AGENTS.md` and `CONTRIBUTING.md` for current instructions.

## Running Tests

### Unit Tests

To run unit tests from the root directory, use:
```bash
yarn workspace {workspace_name} test
```

Examples:
```bash
yarn workspace @swarmbase/collabswarm test
yarn workspace @swarmbase/collabswarm-yjs test
yarn workspace @swarmbase/collabswarm-react test
```

### End-to-End Tests

To run E2E tests with Playwright:
```bash
yarn test:e2e
```

This will:
1. Start the browser-test example using Docker Compose
2. Run Playwright tests simulating multiple users
3. Generate an HTML report

For more details, see `e2e/README.md`.

## Test Coverage Summary

### Core Package (@swarmbase/collabswarm) - 32 tests
- Unit tests for JSON serialization/deserialization
- Unit tests for authentication (sign/verify, encrypt/decrypt)
- Unit tests for utility functions (arrays, promises, crypto keys)
- Integration tests for multi-user crypto scenarios

### Yjs Package (@swarmbase/collabswarm-yjs) - 7 tests
- Yjs document creation and management
- Base64 serialization utilities
- Document arrays and structures
- Multi-document independence

### React Package (@swarmbase/collabswarm-react) - 2 tests
- React context creation and functionality
- Provider and Consumer component verification

### Example Apps
- password-manager: Basic smoke test
- browser-test: Basic smoke test
- wiki-swarm: Basic smoke test

### End-to-End Tests (Playwright) - 4 tests
- Multi-user connectivity (2 concurrent users)
- Multiple browser instances (3 concurrent users)
- Application loading without errors
- Console error monitoring

**Total: 45 tests across 8 test suites - All Passing**

## Test Structure
- Use table-driven testing approach for comprehensive coverage
- Reference: https://dev.to/flyingdot/data-driven-unit-tests-with-jest-26bh

## Testing Approach

### Unit Tests
- Test individual modules and functions in isolation
- Use mock implementations where needed
- Focus on edge cases and error handling
- Avoid complex imports that require full dependency resolution

### Integration Tests
- Test multi-user scenarios
- Verify encryption/signing across different keys
- Validate data sharing with shared document keys

### Example Tests
- Basic smoke tests to ensure apps render without crashing
- Can be extended with more comprehensive UI tests as needed

### End-to-End Tests
- Use Playwright for browser automation
- Test multi-user scenarios with Docker Compose
- Simulate 2-3 concurrent users connecting to the same application
- Verify connectivity, isolation, and stability
- Run automatically in CI/CD pipeline

## CI/CD Integration

All tests run automatically on GitHub Actions:

### Unit Tests Workflow (`.github/workflows/test.yml`)
- Runs on every push and pull request
- Tests @swarmbase/collabswarm, collabswarm-yjs, and collabswarm-react
- Ensures code changes don't break existing functionality

### E2E Tests Workflow (`.github/workflows/e2e.yml`)
- Runs on every push and pull request
- Uses Docker Compose to start the browser-test example
- Runs Playwright tests simulating multiple concurrent users
- Uploads test reports as artifacts

### TypeScript Compilation (`.github/workflows/tsc.yml`)
- Verifies all packages compile without errors
- Catches type errors before they reach production

## Dependencies
- **jest**: Testing framework (^29.2.5)
- **ts-jest**: TypeScript support for Jest (^29.2.5)
- **@testing-library/react**: React component testing (^16.0.1)
- **@testing-library/jest-dom**: Custom matchers for DOM assertions (^6.5.0)
- **@peculiar/webcrypto**: Crypto API polyfill for Node.js tests (^1.4.6)
- **jest-environment-jsdom**: DOM environment for React tests (^29.2.5)
- **@playwright/test**: Browser automation for E2E tests (^1.48.0)

## Notes
- All packages use Jest with TypeScript support for unit tests
- Crypto tests require @peculiar/webcrypto for Node.js environment
- React tests require jsdom environment
- Tests are configured to ignore node_modules and use ts-jest transformer
- E2E tests use Playwright with Docker Compose for realistic multi-user scenarios
- See `e2e/README.md` for detailed E2E testing documentation
