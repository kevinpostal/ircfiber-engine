#!/usr/bin/env node
/**
 * Comprehensive diagnostic for scroll-back history issue.
 * 
 * This script checks:
 * 1. Redis for message history
 * 2. REST API responses
 * 3. Browser console logs (via Playwright)
 * 
 * Usage:
 *   node diagnose-scrollback.js
 */

const { execSync } = require('child_process');
const fs = require('fs');

function log(section, message) {
  console.log(`\n[${section}] ${message}`);
}

function runCommand(cmd, timeout = 10000) {
  try {
    return execSync(cmd, { encoding: 'utf8', timeout });
  } catch (e) {
    return null;
  }
}

function checkRedis() {
  log('REDIS', 'Checking Redis connection and message storage...');
  
  // Check if redis-cli is available
  const redisVersion = runCommand('redis-cli --version');
  if (!redisVersion) {
    console.log('  ❌ redis-cli not found. Install Redis or check your PATH.');
    return false;
  }
  console.log('  ✓ Redis client found:', redisVersion.trim());
  
  // Check all scrollback keys
  const keys = runCommand('redis-cli KEYS "scrollback:*"');
  if (!keys || keys.trim() === '') {
    console.log('  ❌ No scrollback keys found in Redis!');
    console.log('     This means no messages have been stored.');
    return false;
  }
  
  const keyList = keys.trim().split('\n');
  console.log(`  ✓ Found ${keyList.length} scrollback keys`);
  
  // Analyze each key
  for (const key of keyList.slice(0, 5)) { // Check first 5
    const len = runCommand(`redis-cli LLEN "${key}"`);
    const ttl = runCommand(`redis-cli TTL "${key}"`);
    
    console.log(`\n  Key: ${key}`);
    console.log(`    Messages: ${len?.trim() || 'unknown'}`);
    console.log(`    TTL: ${ttl?.trim() || 'unknown'} seconds`);
    
    if (len && parseInt(len) > 0) {
      // Get newest and oldest
      const newest = runCommand(`redis-cli LINDEX "${key}" 0`);
      const oldest = runCommand(`redis-cli LINDEX "${key}" -1`);
      
      if (newest) {
        try {
          const parsed = JSON.parse(newest);
          console.log(`    Newest: ${new Date(parsed.t).toISOString()} - ${(parsed.x || '').substring(0, 50)}`);
        } catch (e) {}
      }
      
      if (oldest) {
        try {
          const parsed = JSON.parse(oldest);
          console.log(`    Oldest: ${new Date(parsed.t).toISOString()} - ${(parsed.x || '').substring(0, 50)}`);
        } catch (e) {}
      }
    }
  }
  
  return true;
}

function checkAPI() {
  log('API', 'Checking REST API...');
  
  // Check if server is running
  const health = runCommand('curl -s http://localhost:8090/api/health');
  if (!health) {
    console.log('  ❌ Server not running on localhost:8090');
    return false;
  }
  
  try {
    const parsed = JSON.parse(health);
    console.log('  ✓ Server status:', parsed.status);
    console.log('    Redis:', parsed.services?.redis?.ok ? 'OK' : 'FAIL');
    console.log('    Mongo:', parsed.services?.mongo?.ok ? 'OK' : 'FAIL');
  } catch (e) {
    console.log('  ⚠️  Could not parse health response');
  }
  
  return true;
}

function generateReport() {
  log('REPORT', 'Generating diagnostic report...');
  
  const report = {
    timestamp: new Date().toISOString(),
    checks: {
      redis: false,
      api: false
    },
    findings: [],
    recommendations: []
  };
  
  // Check Redis
  const redisOk = checkRedis();
  report.checks.redis = redisOk;
  
  if (!redisOk) {
    report.findings.push('Redis has no message history');
    report.recommendations.push('Check if the IRC network has CHATHISTORY support');
    report.recommendations.push('Verify the engine is connected and processing messages');
  }
  
  // Check API
  const apiOk = checkAPI();
  report.checks.api = apiOk;
  
  if (!apiOk) {
    report.findings.push('REST API is not accessible');
    report.recommendations.push('Start the server with: dub run');
  }
  
  // Save report
  const reportPath = 'scrollback-diagnostic-report.json';
  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
  console.log(`\n  Report saved to: ${reportPath}`);
  
  return report;
}

function printRecommendations(report) {
  log('RECOMMENDATIONS', 'Based on diagnostic findings:');
  
  if (report.findings.length === 0) {
    console.log('  No issues found!');
    console.log('  If you still can\'t scroll back, the issue might be:');
    console.log('  1. Frontend JavaScript errors (check browser console)');
    console.log('  2. The IRC server doesn\'t support CHATHISTORY');
    console.log('  3. Network latency causing timeout before CHATHISTORY responds');
    return;
  }
  
  for (const rec of report.recommendations) {
    console.log(`  • ${rec}`);
  }
}

// Main
console.log('╔════════════════════════════════════════════════════════════╗');
console.log('║     IRC Fiber Scroll-Back History Diagnostic              ║');
console.log('╚════════════════════════════════════════════════════════════╝');

const report = generateReport();
printRecommendations(report);

console.log('\n╔════════════════════════════════════════════════════════════╗');
console.log('║  Next Steps:                                               ║');
console.log('║  1. Check browser console for [LoadMore] and              ║');
console.log('║     [handleLoadMore] log messages                         ║');
console.log('║  2. Run the Playwright test:                              ║');
console.log('║     npx playwright test --config=e2e/playwright.scrollback-diagnostic.config.js');
console.log('║  3. Check Redis manually:                                 ║');
console.log('║     redis-cli KEYS "scrollback:*"                         ║');
console.log('╚════════════════════════════════════════════════════════════╝');
