TODO
- dont accelerate packets with TCP flags
- sync stats:
  1. reserve skb on module load
  2. for now use we iterate over all entries in hashtable using `xfe_hash_for_each`
  3. every second put all current connections into skb and send sync message
  4. xdp uses normal hash lookup to find each entry and puts stats into skb,
     then resets entry stats to 0 (we only keep stats for one sync duration)
  5. back in kmod sync to conntrack
  6. we sync stats on delete as well
- handle collisions (for 10 loop) (low priority)
