# End-to-End Tests

This directory contains end-to-end tests for peerborne using Playwright. These tests simulate real user interactions and multi-user connectivity scenarios.

## Overview

The e2e tests use:
- **Playwright**: For browser automation and testing
- **Docker Compose**: For running the applications in isolated environments
- **Multiple Browser Contexts**: To simulate different users connecting simultaneously

## Running Tests Locally

### Prerequisites

1. Install dependencies:
   ```bash
   yarn install
   ```

2. Install Playwright browsers:
   ```bash
   npx playwright install chromium
   ```

### Run Tests

#### With Docker Compose (Recommended)
This will automatically start the services using Docker Compose:

```bash
yarn test:e2e
```

#### Manual Setup
If you want to run the application manually:

1. Start the browser-test example:
   ```bash
   docker compose up browser-test
   ```

2. In another terminal, run the tests:
   ```bash
   yarn test:e2e
   ```

## Test Structure

### Multi-User Tests (`multi-user.spec.ts`)

Tests multi-user connectivity scenarios:
- **Multiple users connecting**: Simulates 2-3 users connecting to the same application
- **Concurrent initialization**: Verifies multiple browser instances can initialize without errors
- **Basic functionality**: Ensures the application loads and renders correctly

### What the Tests Validate

1. **Connectivity**: Multiple browser contexts can connect to the application
2. **Isolation**: Each user operates in an isolated browser context
3. **Stability**: The application doesn't crash with multiple concurrent users
4. **Console Errors**: Monitors for critical JavaScript errors

## CI/CD Integration

The e2e tests run automatically on GitHub Actions via the `.github/workflows/e2e.yml` workflow:

1. Sets up the environment with Node.js and Yarn
2. Installs Playwright browsers
3. Builds all required packages
4. Starts Docker Compose services
5. Runs the Playwright tests
6. Uploads test reports as artifacts

## Writing New Tests

To add a new e2e test:

1. Create a new `.spec.ts` file in the `e2e/` directory
2. Import Playwright test utilities:
   ```typescript
   import { test, expect } from '@playwright/test';
   ```

3. Write your test:
   ```typescript
   test('my test description', async ({ page }) => {
     await page.goto('http://localhost:3001');
     // ... your test code
   });
   ```

### Multi-User Test Pattern

To test multi-user scenarios:

```typescript
test('multi-user test', async ({ browser }) => {
  // Create separate contexts for each user
  const context1 = await browser.newContext();
  const context2 = await browser.newContext();
  
  const page1 = await context1.newPage();
  const page2 = await context2.newPage();
  
  // Navigate both users
  await page1.goto('http://localhost:3001');
  await page2.goto('http://localhost:3001');
  
  // Test interactions
  // ...
  
  // Cleanup
  await context1.close();
  await context2.close();
});
```

## Debugging

### View Test Reports
After running tests, view the HTML report:
```bash
npx playwright show-report
```

### Run Tests in UI Mode
For interactive debugging:
```bash
npx playwright test --ui
```

### Run Tests in Debug Mode
```bash
npx playwright test --debug
```

### View Docker Logs
If tests fail, check the application logs:
```bash
docker compose logs browser-test
```

## Configuration

Test configuration is in `playwright.config.ts`:
- Test directory: `./e2e`
- Browser: Chromium
- Timeout: Standard Playwright defaults
- Retries: 2 retries on CI, 0 locally

## Troubleshooting

### Port Already in Use
If port 3001 is already in use:
```bash
docker compose down
```

### Tests Timeout
Increase timeout in the test:
```typescript
test.setTimeout(60000); // 60 seconds
```

### Application Not Starting
Check Docker logs and ensure all dependencies are built:
```bash
yarn workspace @peerborne/core tsc
yarn workspace @peerborne/automerge tsc
docker compose logs browser-test
```
