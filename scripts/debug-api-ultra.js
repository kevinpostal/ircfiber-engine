/**
 * Ultra-simple API test - just copy/paste and run
 */

(async () => {
  // Hardcode these if needed:
  const networkId = 'bf8f49f8-0cca-4df2-a23a-8b0b5919acb3'; // Replace with yours
  const channel = '#blackhole'; // Replace with yours
  
  // Or auto-detect from URL
  // const path = window.location.pathname;
  // const networkId = path.match(/\/irc\/([^\/]+)/)?.[1];
  // const channel = '#' + (path.match(/\/channel\/(.+)/)?.[1] || '');
  
  console.log('Testing:', networkId, channel);
  
  // Get oldest msgid from DOM
  const oldest = document.querySelector('#messages .row.messageRow');
  const msgid = oldest?.dataset?.msgid;
  const time = oldest?.dataset?.time;
  
  console.log('Oldest msgid:', msgid);
  console.log('Oldest time:', time);
  
  // Fetch all
  const all = await (await fetch(`/api/channels/${networkId}/${channel}/messages?count=500`)).json();
  console.log('\nTotal in Redis:', all.length);
  
  if (all.length > 0) {
    const idx = all.findIndex(m => m.m === msgid || m.msgid === msgid);
    console.log('Our msgid at index:', idx);
    console.log('Messages before ours:', idx > 0 ? idx : 0);
    
    // Test with msgid
    if (msgid) {
      const withMsgid = await (await fetch(`/api/channels/${networkId}/${channel}/messages?count=100&before_msgid=${msgid}`)).json();
      console.log('\nWith beforeMsgid:', withMsgid.length);
    }
    
    // Test with time
    if (time) {
      const withTime = await (await fetch(`/api/channels/${networkId}/${channel}/messages?count=100&before=${time}`)).json();
      console.log('With before time:', withTime.length);
    }
  }
})();
