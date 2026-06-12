/**
 * Simple API debug - no dependencies
 * Run this in browser console (F12)
 */

(async function simpleDebug() {
  // Get network ID from any element with data attribute
  const els = document.querySelectorAll('[data-network-id], [id^="network-"]');
  let networkId = null;
  for (const el of els) {
    if (el.dataset.networkId) {
      networkId = el.dataset.networkId;
      break;
    }
  }
  
  // Or from URL path
  if (!networkId) {
    const match = window.location.pathname.match(/\/irc\/([^\/]+)/);
    if (match) {
      // It might be a name, try to find the UUID
      const networkName = decodeURIComponent(match[1]);
      console.log('Network name from URL:', networkName);
    }
  }
  
  // Get channel from URL
  const channelMatch = window.location.pathname.match(/\/channel\/(.+)/);
  const channelName = channelMatch ? '#' + decodeURIComponent(channelMatch[1]) : null;
  
  console.log('Network ID:', networkId || 'NEED TO FIND');
  console.log('Channel:', channelName || 'NEED TO FIND');
  
  if (!networkId || !channelName) {
    console.log('\n❌ Need network ID and channel name');
    console.log('Find them and replace in the fetch calls below:');
    console.log('  Network ID: Look for data-network-id attribute');
    console.log('  Channel: Check URL path after /channel/');
    return;
  }
  
  // Get oldest message
  const rows = document.querySelectorAll('#messages .row.messageRow');
  const oldest = rows[0];
  const msgid = oldest?.dataset?.msgid;
  const time = oldest?.dataset?.time;
  
  console.log('\nOldest msgid:', msgid);
  console.log('Oldest time:', time);
  
  // Try ALL messages
  console.log('\n=== Fetching all messages ===');
  const url = `/api/channels/${encodeURIComponent(networkId)}/${encodeURIComponent(channelName)}/messages?count=500`;
  console.log('URL:', url);
  
  const r = await fetch(url);
  const data = await r.json();
  console.log('Returned:', data.length, 'messages');
  
  if (data.length > 0 && msgid) {
    const idx = data.findIndex(m => m.m === msgid || m.msgid === msgid);
    console.log('Our msgid at index:', idx);
    
    if (idx > 0) {
      console.log('Messages before ours:', idx);
      
      // Now try with beforeMsgid
      console.log('\n=== With beforeMsgid ===');
      const url2 = `/api/channels/${encodeURIComponent(networkId)}/${encodeURIComponent(channelName)}/messages?count=100&before_msgid=${msgid}`;
      const r2 = await fetch(url2);
      const d2 = await r2.json();
      console.log('Returned:', d2.length);
      
      if (d2.length === 0 && idx > 0) {
        console.log('❌ BUG: API returns 0 but there are', idx, 'older messages!');
      }
    }
  }
  
})();
