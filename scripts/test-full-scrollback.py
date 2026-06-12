#!/usr/bin/env python3
"""
Test multiple scrollback loads to see if we can reach yesterday's messages.
"""

import json
import subprocess
from datetime import datetime

def redis_lrange(key, start, end):
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

def simulate_load_more(key, cursor_msgid=None, cursor_ts=None):
    messages = redis_lrange(key, 0, 499)
    
    if cursor_msgid:
        before_idx = -1
        for idx, msg in enumerate(messages):
            if msg.get('m') == cursor_msgid:
                before_idx = idx
                break
        
        if before_idx < 0:
            return []
        
        result = []
        for idx, msg in enumerate(messages):
            if idx <= before_idx:
                continue
            result.append(msg)
            if len(result) >= 100:
                break
        result.reverse()
        
    elif cursor_ts:
        result = []
        for msg in messages:
            ts = msg.get('t', 0)
            if ts >= cursor_ts:
                continue
            result.append(msg)
            if len(result) >= 100:
                break
        result.reverse()
    else:
        result = messages[:100]
        result.reverse()
    
    return result

def test_full_scrollback():
    key = "scrollback:localengine:bf8f49f8-0cca-4df2-a23a-8b0b5919acb3:#blackhole"
    all_loaded = []
    
    print("Testing full scrollback loading...\n")
    
    # Initial load
    batch = simulate_load_more(key)
    if not batch:
        print("❌ No initial messages")
        return
    
    all_loaded.extend(batch)
    print(f"Load 1: {len(batch)} messages")
    print(f"  Oldest: {datetime.fromtimestamp(batch[0].get('t',0)/1000).isoformat()}")
    print(f"  Newest: {datetime.fromtimestamp(batch[-1].get('t',0)/1000).isoformat()}")
    
    # Keep loading until empty
    load_num = 2
    while True:
        oldest = all_loaded[0]
        cursor_msgid = oldest.get('m')
        cursor_ts = oldest.get('t')
        
        if cursor_msgid:
            batch = simulate_load_more(key, cursor_msgid=cursor_msgid)
        else:
            batch = simulate_load_more(key, cursor_ts=cursor_ts)
        
        if not batch:
            print(f"\n✅ Load {load_num-1}: No more messages (reached end of Redis)")
            break
        
        # Check for duplicates
        existing_ids = {m.get('m') or m.get('t') for m in all_loaded}
        new_batch = [m for m in batch if (m.get('m') or m.get('t')) not in existing_ids]
        
        if not new_batch:
            print(f"\n⚠️  Load {load_num}: All returned messages are duplicates!")
            print("This means the cursor is not advancing.")
            break
        
        all_loaded = new_batch + all_loaded
        
        print(f"\nLoad {load_num}: {len(new_batch)} new messages (total: {len(all_loaded)})")
        print(f"  Oldest: {datetime.fromtimestamp(new_batch[0].get('t',0)/1000).isoformat()}")
        print(f"  Newest: {datetime.fromtimestamp(new_batch[-1].get('t',0)/1000).isoformat()}")
        
        load_num += 1
        
        if load_num > 20:  # Safety limit
            print("\n⚠️  Reached safety limit")
            break
    
    # Summary
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    print(f"Total loaded: {len(all_loaded)} messages")
    if all_loaded:
        oldest = all_loaded[0]
        newest = all_loaded[-1]
        print(f"Date range: {datetime.fromtimestamp(oldest.get('t',0)/1000).isoformat()} to {datetime.fromtimestamp(newest.get('t',0)/1000).isoformat()}")
        
        # Count per day
        from collections import Counter
        dates = Counter()
        for m in all_loaded:
            ts = m.get('t', 0)
            if ts:
                date = datetime.fromtimestamp(ts/1000).strftime('%Y-%m-%d')
                dates[date] += 1
        
        print("\nMessages per day:")
        for date in sorted(dates.keys()):
            print(f"  {date}: {dates[date]} messages")

if __name__ == "__main__":
    test_full_scrollback()
