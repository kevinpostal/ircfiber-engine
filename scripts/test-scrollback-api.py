#!/usr/bin/env python3
"""
Simulate the backend API behavior for scrollback loading.

This reads Redis data and simulates what the API would return
for different cursor values.
"""

import json
import subprocess
from datetime import datetime

def redis_lrange(key, start, end):
    """Get messages from Redis."""
    result = subprocess.run(
        ['docker', 'exec', 'irc_redis_test', 'redis-cli', 'LRANGE', key, str(start), str(end)],
        capture_output=True, text=True
    )
    messages = []
    for line in result.stdout.strip().split('\n'):
        line = line.strip()
        if not line or line == 'nil':
            continue
        try:
            messages.append(json.loads(line))
        except:
            pass
    return messages

def simulate_api_call(key, count=100, before_msgid=None, before_ts=None):
    """Simulate the backend API behavior."""
    messages = redis_lrange(key, 0, 499)
    
    print(f"\n=== API Simulation ===")
    print(f"Key: {key}")
    print(f"Total messages in Redis: {len(messages)}")
    print(f"Requested count: {count}")
    
    if before_msgid:
        print(f"Cursor: beforeMsgid={before_msgid}")
        
        # Find index of message with matching msgid
        before_idx = -1
        before_ts_found = None
        for idx, msg in enumerate(messages):
            if msg.get('m') == before_msgid:
                before_idx = idx
                before_ts_found = msg.get('t')
                break
        
        if before_idx < 0:
            print(f"❌ Msgid not found!")
            return []
        
        print(f"Found msgid at index: {before_idx}")
        print(f"Message timestamp: {datetime.fromtimestamp(before_ts_found/1000).isoformat() if before_ts_found else 'N/A'}")
        
        # Skip messages at or before this index, keep older ones (higher index)
        # Since Redis index 0 is newest, higher indices are older
        result = []
        for idx, msg in enumerate(messages):
            if idx <= before_idx:
                continue
            result.append(msg)
            if len(result) >= count:
                break
        
        # Reverse to get oldest first
        result.reverse()
        
    elif before_ts:
        print(f"Cursor: before={before_ts}")
        
        # Keep messages with ts < before_ts
        result = []
        for msg in messages:
            ts = msg.get('t', 0)
            if ts >= before_ts:
                continue
            result.append(msg)
            if len(result) >= count:
                break
        
        # Reverse to get oldest first
        result.reverse()
        
    else:
        print("No cursor - returning newest messages")
        # Return newest messages (first in Redis list)
        result = messages[:count]
        result.reverse()  # Oldest first
    
    print(f"Returned: {len(result)} messages")
    if result:
        newest = result[-1]
        oldest = result[0]
        print(f"  Range: {datetime.fromtimestamp(oldest.get('t',0)/1000).isoformat()} to {datetime.fromtimestamp(newest.get('t',0)/1000).isoformat()}")
    
    return result

def test_scrollback_scenario():
    """Test a typical scrollback scenario."""
    key = "scrollback:localengine:bf8f49f8-0cca-4df2-a23a-8b0b5919acb3:#blackhole"
    
    print("=" * 60)
    print("SCROLLBACK SCENARIO TEST")
    print("=" * 60)
    
    # Step 1: Initial load (no cursor)
    print("\n--- Step 1: Initial load ---")
    initial = simulate_api_call(key, count=100)
    
    if not initial:
        print("❌ No initial messages!")
        return
    
    # Step 2: Find oldest message
    oldest = initial[0]  # First in array = oldest since we reversed
    oldest_msgid = oldest.get('m')
    oldest_ts = oldest.get('t')
    
    print(f"\nOldest loaded message:")
    print(f"  Timestamp: {datetime.fromtimestamp(oldest_ts/1000).isoformat() if oldest_ts else 'N/A'}")
    print(f"  Msgid: {oldest_msgid or 'NO_MSGID'}")
    print(f"  Text: {oldest.get('x', '')[:60]}")
    
    # Step 3: Load more with cursor
    print("\n--- Step 2: Load more ---")
    if oldest_msgid:
        more = simulate_api_call(key, count=100, before_msgid=oldest_msgid)
    else:
        more = simulate_api_call(key, count=100, before_ts=oldest_ts)
    
    if more:
        print(f"✅ Successfully loaded {len(more)} more messages!")
        new_oldest = more[0]
        print(f"New oldest: {datetime.fromtimestamp(new_oldest.get('t',0)/1000).isoformat()}")
    else:
        print("❌ No more messages returned!")
        print("\nPossible reasons:")
        print("1. This is the oldest message in Redis (buffer limit reached)")
        print("2. The msgid/timestamp cursor is incorrect")
        print("3. All messages share the same timestamp")
        
        # Let's check if there are actually older messages
        all_msgs = redis_lrange(key, 0, 499)
        if all_msgs:
            very_oldest = all_msgs[-1]
            print(f"\nActual oldest in Redis: {datetime.fromtimestamp(very_oldest.get('t',0)/1000).isoformat()}")
            print(f"Your oldest loaded: {datetime.fromtimestamp(oldest_ts/1000).isoformat() if oldest_ts else 'N/A'}")
            
            if very_oldest.get('t') == oldest_ts:
                print("\n✓ You've reached the end of Redis buffer!")
            else:
                print("\n❌ There are older messages but the API didn't return them!")
                print("This is a BUG in the API logic.")

if __name__ == "__main__":
    test_scrollback_scenario()
