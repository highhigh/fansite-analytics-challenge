### Feature 1: 
List the top 10 most active host/IP addresses that have accessed the site. 

 - generate a host count map
 - use a min-heap of size 10 to get top 10 most active hosts

runtime complexity: O(n), n is the number of lines in the log.txt
space complexity: O(m), m is the number of various hosts/IP addresses, could be n in worst case

### Feature 2: 
Identify the 10 resources that consume the most bandwidth on the site.

 - generate a resource bandwidth map
 - use a min-heap of size 10 to get top 10 resources that consume the most bandwidth

runtime complexity: O(n), n is the number of lines in the log.txt
space complexity: O(m), m is the number of various resources, could be n in worst case

### Feature 3:
List the top 10 busiest (or most frequently visited) 60-minute periods.

 - maintain a queue that represents 60-min time window, elements in the queue are (timestamp, num_visits on this timestamp) 
 - maintain a variable total_visits that represents the total number of visits of all elements in the queue
 - on adding elements (timestamp, num_visits) to the queue, we pop earlier elements that is older than 60min ago out of the queue
 - on each pop, record the total_visits corresponding to that timestamp and insert to the min-heap
 - after exhausting the input log, pop remaining elements out of the queue and update min-heap accordingly

runtime complexity: O(n), n is the number of lines in the log.txt
space complexity: O(1) if not consider the input space complexity, as both the queue and min-heap are const size

### Feature 4: 
Detect patterns of three failed login attempts from the same IP address over 20 seconds so that all further attempts to the site can be blocked for 5 minutes. Log those possible security breaches.

 - maintain a map: host ==> (blocked_timestamp, 1st_fail_timestamp, 2nd_fail_timestamp)
 - please refer to source code documentation for implementation details

runtime complexity: O(n), n is the number of lines in the log.txt (assume input file are sorted on timestamp)
space complexity: O(m), m is the number of various hosts/IP addresses, could be n in worst case

### Note:
This implementation bundles the processing of feature 1-4 together in each input-line’s processing. The benefit is that we don’t have to save the input log file for each individual pass of feature 1-4. Therefore, it’s easy to apply small modification to the algorithm to let it handle realtime input stream and realize realtime/online updating of feature 1-4. This would become a significant advantage in some use cases.
