/**
 * Properly test API with URL encoding
 * Run in browser console (F12)
 */

(async () => {
  // Get current channel from URL
  const path = window.location.pathname;
  const networkMatch = path.match(/\/irc\/([^\/]+)/);
  const channelMatch = path.match(/\/channel\/(.+)/);
  
  const networkName = networkMatch ? decodeURIComponent(networkMatch[1]) : 'unknown';
  const channelName = channelMatch ? '#' + decodeURIComponent(channelMatch[1]) : '_server';
  
  console.log('Current URL path:', path);
  console.log('Network name:', networkName);
  console.log('Channel name:', channelName);
  
  // Get network ID from page
  const networks = await (await fetch('/api/networks')).json();
  const net = networks.find(n => n.name === networkName);
  
  if (!net) {
    console.log('❌ Network not found:', networkName);
    console.log('Available networks:', networks.map(n => n.name));
    return;
  }
  
  const networkId = net.id || net.networkId;
  console.log('\nNetwork ID:', networkId);
  
  // PROPERLY ENCODE channel name (the # must be %23)
  const encodedChannel = encodeURIComponent(channelName);
  console.log('Encoded channel:', encodedChannel);
  
  // Get oldest visible message
  const rows = document.querySelectorAll('#messages .row.messageRow');
  const oldest = rows[0];
  const msgid = oldest?.dataset?.msgid;
  const time = oldest?.dataset?.time;
  
  console.log('\n=== Current State ===');
  console.log('Visible messages:', rows.length);
  console.log('Oldest msgid:', msgid);
  console.log('Oldest time:', time, new Date(parseInt(time)).toISOString());
  
  // Test 1: Get newest 100
  console.log('\n=== Test 1: Newest 100 ===');
  const url1 = `/api/channels/${networkId}/${encodedChannel}/messages?count=100`;
  console.log('URL:', url1);
  
  const r1 = await fetch(url1);
  if (!r1.ok) {
    console.log('❌ Error:', r1.status, r1.statusText);
    return;
  }
  
  const newest = await r1.json();
  console.log('Returned:', newest.length);
  
  if (newest.length > 0) {
    console.log('First (newest):', new Date(newest[0].t).toISOString());
    console.log('Last (oldest of 100):', new Date(newest[newest.length-1].t).toISOString());
    
    // Test 2: Get ALL messages (count=500)
    console.log('\n=== Test 2: ALL messages (count=500) ===');
    const url2 = `/api/channels/${networkId}/${encodedChannel}/messages?count=500`;
    const r2 = await fetch(url2);
    const all = await r2.json();
    
    console.log('Total in Redis:', all.length);
    
    if (all.length > 0) {
      console.log('Date range:');
      console.log('  Newest:', new Date(all[0].t).toISOString());
      console.log('  Oldest:', new Date(all[all.length-1].t).toISOString());
      
      // Find our msgid
      const idx = all.findIndex(m => m.m === msgid || m.msgid === msgid);
      console.log('\nOur msgid position:', idx);
      
      if (idx >= 0) {
        console.log('Messages before ours:', idx);
        console.log('Messages after ours:', all.length - idx - 1);
        
        if (idx > 0) {
          // Test 3: With beforeMsgid
          console.log('\n=== Test 3: With beforeMsgid ===');
          const url3 = `/api/channels/${networkId}/${encodedChannel}/messages?count=100&before_msgid=${msgid}`;
          const r3 = await fetch(url3);
          const withMsgid = await r3.json();
          console.log('Returned:', withMsgid.length);
          
          if (withMsgid.length === 0) {
            console.log('❌ BUG: beforeMsgid returns 0 but there are', idx, 'older messages!');
          }
          
          // Test 4: With before timestamp
          console.log('\n=== Test 4: With before timestamp ===');
          const url4 = `/api/channels/${networkId}/${encodedChannel}/messages?count=100&before=${time}`;
          const r4 = await fetch(url4);
          const withTime = await r4.json();
          console.log('Returned:', withTime.length);
          
          if (withTime.length > 0 && withMsgid.length === 0) {
            console.log('❌ CONFIRMED BUG: timestamp works but msgid does not!');
          }
        } else {
          console.log('✅ No older messages - you have loaded everything from Redis!');
        }
      } else {
        console.log('❌ Our msgid not found in Redis (might be a new message)');
      }
    }
  }
  
  console.log('\n=== Summary ===');
  console.log('If Test 2 shows messages from multiple days but Test 3 returns 0,');
  console.log('there is a bug in the backend msgid filtering.');
  console.log('If Test 2 shows only today\'s messages, then there genuinely');
  console.log('is no older history in Redis for this channel.');
})();
