/**
 * Manual scrollback test - run this in the browser console
 * 
 * Usage:
 * 1. Open your app in the browser
 * 2. Open DevTools (F12)
 * 3. Go to Console tab
 * 4. Paste this script and press Enter
 */

(async function testScrollback() {
  console.log('=== Scrollback Test ===\n');
  
  // 1. Check current state
  const container = document.getElementById('messages');
  if (!container) {
    console.log('❌ No messages container found');
    return;
  }
  
  const rows = container.querySelectorAll('.row.messageRow');
  console.log(`Current messages: ${rows.length}`);
  
  if (rows.length === 0) {
    console.log('❌ No messages visible');
    return;
  }
  
  // 2. Check oldest message
  const oldest = rows[0];
  console.log('\nOldest visible message:');
  console.log(`  Time: ${new Date(parseInt(oldest.dataset.time)).toISOString()}`);
  console.log(`  Msgid: ${oldest.dataset.msgid || 'NO_MSGID'}`);
  console.log(`  Text: ${oldest.textContent?.substring(0, 60)}`);
  
  // 3. Check LoadMore button
  const loadButton = document.querySelector('button:has-text("Load older messages")');
  console.log(`\nLoad button visible: ${!!loadButton}`);
  
  // 4. Try clicking the button
  if (loadButton) {
    console.log('\nClicking "Load older messages"...');
    loadButton.click();
    
    // Wait 3 seconds
    await new Promise(r => setTimeout(r, 3000));
    
    const newRows = container.querySelectorAll('.row.messageRow');
    console.log(`Messages after click: ${newRows.length}`);
    
    if (newRows.length > rows.length) {
      console.log(`✅ SUCCESS: Loaded ${newRows.length - rows.length} more messages!`);
      
      const newOldest = newRows[0];
      console.log('\nNew oldest message:');
      console.log(`  Time: ${new Date(parseInt(newOldest.dataset.time)).toISOString()}`);
      console.log(`  Text: ${newOldest.textContent?.substring(0, 60)}`);
    } else {
      console.log('❌ No new messages loaded');
    }
  }
  
  // 5. Test scroll-based loading
  console.log('\n=== Testing scroll-based loading ===');
  const initialCount = rows.length;
  
  for (let i = 0; i < 5; i++) {
    container.scrollTop = 0;
    await new Promise(r => setTimeout(r, 2000));
    
    const currentCount = container.querySelectorAll('.row.messageRow').length;
    console.log(`Scroll attempt ${i + 1}: ${currentCount} messages`);
    
    if (currentCount > initialCount) {
      console.log(`✅ Scroll loaded ${currentCount - initialCount} messages!`);
      break;
    }
  }
  
  // 6. Check API directly
  console.log('\n=== Checking API ===');
  try {
    // Get active buffer info from URL or state
    const networkId = window.location.pathname.match(/\/irc\/([^\/]+)/)?.[1];
    const channel = window.location.pathname.match(/\/channel\/(.+)/)?.[1];
    
    if (networkId && channel) {
      console.log(`Network: ${networkId}, Channel: ${channel}`);
      
      // Get oldest message info
      const oldestMsgid = oldest.dataset.msgid;
      const oldestTime = oldest.dataset.time;
      
      if (oldestMsgid) {
        console.log(`Testing API with beforeMsgid=${oldestMsgid}...`);
        const response = await fetch(`/api/channels/${encodeURIComponent(networkId)}/${encodeURIComponent(channel)}/messages?count=100&before_msgid=${oldestMsgid}`);
        const data = await response.json();
        console.log(`API returned: ${data.length} messages`);
        
        if (data.length > 0) {
          console.log(`  First: ${new Date(data[0].t).toISOString()}`);
          console.log(`  Last: ${new Date(data[data.length - 1].t).toISOString()}`);
        }
      }
    }
  } catch (e) {
    console.error('API check failed:', e);
  }
  
  console.log('\n=== Test Complete ===');
})();
