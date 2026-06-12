/**
 * Check server ID mismatch
 * Run in browser console
 */

(async () => {
  // Get network ID from URL
  const path = window.location.pathname;
  const networkMatch = path.match(/\/irc\/([^\/]+)/);
  const networkName = networkMatch ? decodeURIComponent(networkMatch[1]) : null;
  
  console.log('Network name from URL:', networkName);
  
  // Get network info from API
  const networks = await (await fetch('/api/networks')).json();
  console.log('\nNetworks from API:');
  networks.forEach(n => {
    console.log(`  ${n.name} (${n.id || n.networkId})`);
    console.log(`    Server ID: ${n.serverId || 'NOT SET'}`);
  });
  
  // Find our network
  const net = networks.find(n => n.name === networkName);
  if (net) {
    console.log('\nOur network:', net.name);
    console.log('Network ID:', net.id || net.networkId);
    console.log('Server ID from API:', net.serverId);
    
    // Check Redis keys
    console.log('\n=== Checking Redis ===');
    const networkId = net.id || net.networkId;
    const serverId = net.serverId;
    
    if (serverId) {
      const channel = path.match(/\/channel\/(.+)/)?.[1] || '';
      const key1 = `scrollback:${serverId}:${networkId}:#${channel}`;
      const key2 = `scrollback:${networkId}:#${channel}`;
      
      console.log('Expected Redis key (with serverId):', key1);
      console.log('Legacy Redis key (no serverId):', key2);
      
      // We can't directly check Redis from browser, but we can infer
      // If the API returns 0 but Redis has messages, it's a serverId mismatch
    }
  }
  
  console.log('\n=== Test API directly ===');
  if (net) {
    const networkId = net.id || net.networkId;
    const channel = '#' + (path.match(/\/channel\/(.+)/)?.[1] || '');
    
    // Get messages without cursor
    const all = await (await fetch(`/api/channels/${networkId}/${channel}/messages?count=100`)).json();
    console.log('API returns:', all.length, 'messages');
    
    if (all.length === 0) {
      console.log('❌ API returns 0 messages even without cursor!');
      console.log('This means the server ID is wrong or Redis key is different.');
    }
  }
})();
