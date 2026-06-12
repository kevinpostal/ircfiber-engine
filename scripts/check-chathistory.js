/**
 * Check CHATHISTORY support
 * Run in browser console
 */

(async () => {
  // Get network info
  const networks = await (await fetch('/api/networks')).json();
  
  console.log('=== Network Capabilities ===\n');
  networks.forEach(net => {
    console.log(`Network: ${net.name}`);
    console.log(`  Connected: ${net.connected}`);
    console.log(`  Capabilities: ${net.caps?.length || 0}`);
    
    if (net.caps) {
      const hasChathistory = net.caps.some(c => c.toLowerCase().includes('chathistory'));
      console.log(`  Has CHATHISTORY: ${hasChathistory}`);
      
      if (hasChathistory) {
        console.log('  ✅ Server supports CHATHISTORY');
      } else {
        console.log('  ❌ Server does NOT support CHATHISTORY');
        console.log('  Available caps:', net.caps.join(', '));
      }
    }
  });
  
  console.log('\n=== Current Buffer ===');
  const path = window.location.pathname;
  const channelMatch = path.match(/\/channel\/(.+)/);
  const channelName = channelMatch ? '#' + decodeURIComponent(channelMatch[1]) : null;
  
  if (channelName) {
    console.log(`Channel: ${channelName}`);
    
    // Check if we have server-side history available
    const rows = document.querySelectorAll('#messages .row.messageRow');
    console.log(`Loaded messages: ${rows.length}`);
    
    if (rows.length > 0) {
      const oldest = rows[0];
      const time = parseInt(oldest.dataset.time);
      const age = (Date.now() - time) / (1000 * 60 * 60); // hours
      console.log(`Oldest message age: ${age.toFixed(1)} hours`);
      
      if (age < 24) {
        console.log('⚠️  Only recent messages - buffer limit reached');
      }
    }
  }
  
  console.log('\n=== Solution ===');
  console.log('If CHATHISTORY is NOT supported:');
  console.log('  - Increase Redis buffer size (currently 500)');
  console.log('  - Implement MongoDB for long-term storage');
  console.log('  - Use a different IRC server that supports CHATHISTORY');
  console.log('');
  console.log('If CHATHISTORY IS supported:');
  console.log('  - Check why CHATHISTORY requests are not returning older messages');
  console.log('  - Verify the IRC server actually has older history');
})();
