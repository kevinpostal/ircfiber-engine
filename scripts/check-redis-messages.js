#!/usr/bin/env node
/**
 * Redis diagnostic script for IRC Fiber message history.
 * 
 * Usage:
 *   node check-redis-messages.js <networkId> <channel>
 * 
 * Example:
 *   node check-redis-messages.js 4958d7f1-3e50-46cd-bf59-3a4a99d9a3e1 #test
 */

const { execSync } = require('child_process');

function runRedisCommand(cmd) {
  try {
    const result = execSync(`redis-cli ${cmd}`, { encoding: 'utf8', timeout: 5000 });
    return result.trim();
  } catch (e) {
    console.error('Redis command failed:', e.message);
    return null;
  }
}

function checkRedisMessages(networkId, channel) {
  console.log(`Checking Redis for network=${networkId}, channel=${channel}\n`);
  
  // Try both namespaced and non-namespaced keys
  const keys = [
    `scrollback:${networkId}:${channel}`,
    `scrollback:server1:${networkId}:${channel}`,
    `scrollback:default:${networkId}:${channel}`
  ];
  
  let foundKey = null;
  let messageCount = 0;
  
  for (const key of keys) {
    const len = runRedisCommand(`LLEN "${key}"`);
    if (len && parseInt(len) > 0) {
      console.log(`✓ Found key: ${key} (${len} messages)`);
      foundKey = key;
      messageCount = parseInt(len);
    } else {
      console.log(`✗ Key not found: ${key}`);
    }
  }
  
  if (!foundKey) {
    console.log('\n❌ No messages found in Redis for this channel!');
    console.log('   Possible causes:');
    console.log('   1. Channel has no message history');
    console.log('   2. Redis key uses different naming format');
    console.log('   3. Messages were evicted (TTL expired)');
    return;
  }
  
  console.log(`\n=== Message Analysis ===`);
  console.log(`Total messages: ${messageCount}`);
  
  // Get first (newest) message
  const firstMsg = runRedisCommand(`LINDEX "${foundKey}" 0`);
  if (firstMsg) {
    try {
      const parsed = JSON.parse(firstMsg);
      console.log('\nNewest message:');
      console.log(`  Time: ${new Date(parsed.t).toISOString()}`);
      console.log(`  Text: ${(parsed.x || '').substring(0, 100)}`);
      console.log(`  Nick: ${parsed.n || 'N/A'}`);
      console.log(`  Command: ${parsed.c || 'N/A'}`);
    } catch (e) {
      console.log('  Failed to parse newest message');
    }
  }
  
  // Get last (oldest) message
  const lastMsg = runRedisCommand(`LINDEX "${foundKey}" -1`);
  if (lastMsg) {
    try {
      const parsed = JSON.parse(lastMsg);
      console.log('\nOldest message:');
      console.log(`  Time: ${new Date(parsed.t).toISOString()}`);
      console.log(`  Text: ${(parsed.x || '').substring(0, 100)}`);
      console.log(`  Nick: ${parsed.n || 'N/A'}`);
      console.log(`  Command: ${parsed.c || 'N/A'}`);
    } catch (e) {
      console.log('  Failed to parse oldest message');
    }
  }
  
  // Check message distribution over time
  console.log('\n=== Time Distribution ===');
  const samples = [0, 50, 100, 200, 300, 400, -1];
  for (const idx of samples) {
    if (idx >= messageCount) continue;
    const msg = runRedisCommand(`LINDEX "${foundKey}" ${idx}`);
    if (msg) {
      try {
        const parsed = JSON.parse(msg);
        const date = new Date(parsed.t);
        const label = idx === 0 ? 'Newest' : idx === -1 ? 'Oldest' : `Index ${idx}`;
        console.log(`  ${label}: ${date.toISOString()} (${date.toLocaleDateString()})`);
      } catch (e) {}
    }
  }
  
  // Check TTL
  const ttl = runRedisCommand(`TTL "${foundKey}"`);
  if (ttl) {
    const ttlHours = Math.floor(parseInt(ttl) / 3600);
    console.log(`\nKey TTL: ${ttl} seconds (${ttlHours} hours)`);
  }
  
  // Check if yesterday's messages exist
  console.log('\n=== Yesterday Check ===');
  const yesterday = new Date();
  yesterday.setDate(yesterday.getDate() - 1);
  yesterday.setHours(0, 0, 0, 0);
  const yesterdayMs = yesterday.getTime();
  
  // Binary search for yesterday's messages
  let left = 0;
  let right = messageCount - 1;
  let foundYesterday = false;
  
  while (left <= right) {
    const mid = Math.floor((left + right) / 2);
    const msg = runRedisCommand(`LINDEX "${foundKey}" ${mid}`);
    if (!msg) break;
    
    try {
      const parsed = JSON.parse(msg);
      const msgTime = parsed.t;
      
      if (msgTime < yesterdayMs) {
        // Message is older than yesterday, look newer
        right = mid - 1;
      } else if (msgTime >= yesterdayMs && msgTime < yesterdayMs + 86400000) {
        // Found a message from yesterday!
        foundYesterday = true;
        console.log(`✓ Found message from yesterday at index ${mid}`);
        console.log(`  Time: ${new Date(msgTime).toISOString()}`);
        break;
      } else {
        // Message is newer than yesterday, look older
        left = mid + 1;
      }
    } catch (e) {
      break;
    }
  }
  
  if (!foundYesterday) {
    console.log('❌ No messages from yesterday found in Redis buffer');
    console.log('   This means either:');
    console.log('   1. No messages were sent yesterday');
    console.log('   2. Messages were evicted (buffer limited to 500)');
    console.log('   3. Redis TTL expired');
  }
  
  // Check all Redis keys matching this network
  console.log('\n=== All Redis Keys ===');
  const allKeys = runRedisCommand(`KEYS "scrollback:*${networkId}*"`);
  if (allKeys) {
    const keys = allKeys.split('\n').filter(k => k.trim());
    console.log(`Found ${keys.length} keys:`);
    keys.forEach(k => console.log(`  - ${k}`));
  }
}

// Main
const networkId = process.argv[2];
const channel = process.argv[3];

if (!networkId || !channel) {
  console.log('Usage: node check-redis-messages.js <networkId> <channel>');
  console.log('');
  console.log('To find your network ID:');
  console.log('  1. Open the app');
  console.log('  2. Look at the URL when clicking a channel: /irc/NetworkName/channel/#test');
  console.log('  3. Or check the API: curl http://localhost:8090/api/networks');
  process.exit(1);
}

checkRedisMessages(networkId, channel);
