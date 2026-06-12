/**
 * Debug script - run in browser console (F12)
 * This version doesn't rely on ircState global
 */

(async function debugAPI() {
  const rows = document.querySelectorAll('#messages .row.messageRow');
  if (rows.length === 0) {
    console.log('❌ No messages');
    return;
  }
  
  const oldest = rows[0];
  const msgid = oldest.dataset.msgid;
  const time = oldest.dataset.time;
  
  console.log('Oldest msgid:', msgid);
  console.log('Oldest time:', time, new Date(parseInt(time)).toISOString());
  
  // Get network ID from DOM
  const networkEl = document.querySelector('[data-network-id]');
  let networkId = networkEl?.dataset.networkId;
  
  // Fallback: extract from URL or network header
  if (!networkId) {
    const networkHeader = document.querySelector('.network-header');
    if (networkHeader) {
      // Try to get it from the onclick or data attributes
      networkId = networkHeader.closest('[data-network-id]')?.dataset.networkId;
    }
  }
  
  // Another fallback: check all elements with data attributes
  if (!networkId) {
    const allDataEls = document.querySelectorAll('[data-network-id]');
    if (allDataEls.length > 0) {
      networkId = allDataEls[0].dataset.networkId;
    }
  }
  
  // Get channel from URL or active state
  const path = window.location.pathname;
  const channelMatch = path.match(/\/channel\/(.+)/);
  let channelName = channelMatch ? '#' + decodeURIComponent(channelMatch[1]) : null;
  
  // If not in URL, try to find active channel
  if (!channelName) {
    const activeChannel = document.querySelector('.channel-name.active, .channel-name.current');
    if (activeChannel) {
      channelName = activeChannel.textContent.trim();
    }
  }
  
  console.log('Network ID:', networkId || 'NOT FOUND');
  console.log('Channel:', channelName || 'NOT FOUND');
  
  if (!networkId || !channelName) {
    console.log('❌ Cannot determine network/channel');
    console.log('Please provide manually:');
    console.log('  Network ID: _____________');
    console.log('  Channel: _____________');
    return;
  }
  
  // Test 1: Get all messages
  console.log('\n=== Test 1: All messages (count=500) ===');
  try {
    const r1 = await fetch(`/api/channels/${encodeURIComponent(networkId)}/${encodeURIComponent(channelName)}/messages?count=500`);
    const all = await r1.json();
    console.log('Total returned:', all.length);
    
    if (all.length > 0) {
      console.log('First (newest):', new Date(all[0].t).toISOString());
      console.log('Last (oldest):', new Date(all[all.length-1].t).toISOString());
      
      // Find our msgid
      const idx = all.findIndex(m => m.m === msgid || m.msgid === msgid);
      console.log('\nOur msgid position:', idx);
      
      if (idx >= 0) {
        console.log('✅ Msgid found in Redis');
        console.log('Messages before ours:', idx);
        console.log('Messages after ours:', all.length - idx - 1);
        console.log('Would return with beforeMsgid:', Math.min(100, idx));
      } else {
        console.log('❌ Our msgid NOT in Redis!');
        console.log('Sample msgids from Redis:', all.slice(0, 5).map(m => m.m || m.msgid || 'NO_MSGID'));
      }
    }
  } catch (e) {
    console.error('Test 1 error:', e);
  }
  
  // Test 2: With beforeMsgid
  if (msgid) {
    console.log('\n=== Test 2: With beforeMsgid ===');
    try {
      const r2 = await fetch(`/api/channels/${encodeURIComponent(networkId)}/${encodeURIComponent(channelName)}/messages?count=100&before_msgid=${msgid}`);
      const d2 = await r2.json();
      console.log('Returned:', d2.length);
      if (d2.length > 0) {
        console.log('First:', new Date(d2[0].t).toISOString());
        console.log('Last:', new Date(d2[d2.length-1].t).toISOString());
      }
    } catch (e) {
      console.error('Test 2 error:', e);
    }
  }
  
  // Test 3: With before timestamp
  if (time) {
    console.log('\n=== Test 3: With before timestamp ===');
    try {
      const r3 = await fetch(`/api/channels/${encodeURIComponent(networkId)}/${encodeURIComponent(channelName)}/messages?count=100&before=${time}`);
      const d3 = await r3.json();
      console.log('Returned:', d3.length);
      if (d3.length > 0) {
        console.log('First:', new Date(d3[0].t).toISOString());
        console.log('Last:', new Date(d3[d3.length-1].t).toISOString());
      }
    } catch (e) {
      console.error('Test 3 error:', e);
    }
  }
  
  console.log('\n=== Summary ===');
  console.log('If Test 1 shows your msgid at index 437 with 62 messages before it,');
  console.log('but Test 2 returns 0, the backend msgid filtering is broken.');
  console.log('If Test 3 returns messages but Test 2 returns 0, same issue.');
  console.log('If all tests return 0, the Redis buffer is truly empty for this cursor.');
  
})();
