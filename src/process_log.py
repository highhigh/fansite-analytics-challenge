from collections import deque
from datetime import datetime, timedelta
from heapq import heappush, heappop, nsmallest
from operator import itemgetter
import re, sys

input_file, hosts_file, hours_file, resources_file, blocked_file = sys.argv[1:]

def update_host_count_map(host, host_count_map):
	host_count_map[host] = host_count_map.get(host, 0) + 1

# Assume host_count_map contains more than 10 entries
# Tie breaker: lexicographical of host name/IP
def get_10_most_active_hosts(host_count_map):
	heap = [(-value, key) for key, value in host_count_map.items()]
	largest = nsmallest(10, heap, key = itemgetter(0,1))
	largest = [(key, -value) for value, key in largest]
	with open(hosts_file, 'w') as output:
		for host, count in largest:
			host_info = host + ',' + str(count)
			output.write('%s\n' % host_info)

# Update the map of resource (key) to aggregated bandwidth (value)
def update_resource_bandwidth_map(resource, bandwidth, resource_bandwidth_map):
	resource_bandwidth_map[resource] = resource_bandwidth_map.get(resource, 0) + bandwidth

# Assume resource_bandwidth_map contains more than 10 entries
# Tie breaker: lexicographical of resource name
def get_10_most_bandwidth_intensive_resources(resource_bandwidth_map):
	heap = [(-value, key) for key, value in resource_bandwidth_map.items()]
	largest = nsmallest(10, heap, key = itemgetter(0,1))
	largest = [(key, -value) for value, key in largest]
	with open(resources_file, 'w') as output:
		for resource, bandwidth in largest:
			output.write("%s\n" % resource)

'''
Time_to_add: the next timestamp to be added.

Q: a queue which maintains a list of timestamps in order.
The earliest(leftmost) and latest(rightmost) timestamps in this
queue are within 60-min time window. To add a later timestamp
which goes beyond the 60-min window with the leftmost timestamp,
one or more timestamps on the left have to be popped, until the 
leftmost timestamp and the newly added timestamp are within 60-min.
e.g. [1min 2min 67min] is not possible under this setting, 
the add of 67min will cause the left two elements being popped.
The element in the queue is a list of two elements: [timestamp, count].

Total_visits: the aggregated count of number of visits for each
timestamp currently in the queue. total_visits is updated when the 
timestamp is added to and popped from the queue.
Note that total_visits is a one-element list to mimic passing by
reference.

Heap: a min-heap keeps the top 10 busiest time periods.
On each pop of leftmost timestamps, we update the heap with the tuple
(timestamp, total_visits) to see if it is one of the top 10 busiest 
time window.
'''
def update_10_busiest_time_periods(time_to_add, q, total_visits, heap):
	if not q:
		q.append([time_to_add,1])
		total_visits[0] = 1
		return
	if time_to_add == q[-1][0]:
		q[-1][1] = q[-1][1] + 1
		total_visits[0] = total_visits[0] + 1
		return
	time_to_pop = q[0][0]
	timediff = time_to_add - time_to_pop
	while q and timediff.seconds > 3600:
		# Pop time_to_pop, add it with total_visits to heap, update total_visits
		if len(heap) < 10:
			heappush(heap, (total_visits[0], time_to_pop))
		elif total_visits[0] > heap[0][0]:
			heappop(heap)
			heappush(heap, (total_visits[0], time_to_pop)) 
		total_visits[0] = total_visits[0] - q[0][1] 	
		q.popleft()
		if q:
			time_to_pop = q[0][0]
			timediff = time_to_add - time_to_pop
	q.append([time_to_add, 1])
	total_visits[0] = total_visits[0] + 1

# Pop the remaining timestamps out of queue, update heap accordingly
# and write the results.
def get_10_busiest_time_periods(q, total_visits, heap):
	while q:
		if len(heap) < 10:
			heappush(heap, (total_visits[0], q[0][0]))
		elif total_visits[0] > heap[0][0]:
			heappop(heap)
			heappush(heap, (total_visits[0], q[0][0]))
		total_visits[0] = total_visits[0] - q[0][1]
		q.popleft()
	# Extra sort O(nlogn) instead of popping the heap one by one O(n)
	# is to break ties in lexicographical order.
	heap.sort( key = lambda x: (-x[0],x[1]))
	with open(hours_file, 'w') as output:
		for num_visits, time in heap:
			output.write('%s,%d\n' % (time.strftime('%d/%b/%Y:%H:%M:%S %z'), num_visits))

'''
This algorithm only requires one pass to log.txt. The runtime is O(n) under the assumption 
that the log entries are sorted in ascending order of visiting time. This is a rational 
assumption considering the way the log is written. However, in case the log is merged from
distributed system and the entries are not perfectly sorted by its time, this algorithm 
would require extra O(nlogn) to sort the entries by time. The sort is not included in this
algorithm as we made the assumption here.
The space complexity is O(m), m is the number of host names/IPs.
 
Status: a map mapping host to its login attempts. 
Three timestamps are used to represent login attempts.
1. block_timestamp: If a new entry's timestamp is <= block_timestamp, the entry is blocked.
				  This timestamp is initialized to t-1s, where t is the time of the host's
				  first visit. After a host's 3 consecutive failed login within 20s, 
				  block_timestamp will be updated to the time of the 3rd fail + 5min.
				  Future visits from the same host with a visit time <= block_timestamp
				  are thus blocked.
2. 1st_fail_timestamp: This indicates a new cycle of detection. It could be cleared after
					 the same host's successful login or a fail attempt after 20s.
3. 2nd_fail_timestamp: This records the time of the 2nd failed login of this cycle. It could
					 be cleared after the same host's successful login or a fail attempt 
					 after 20s.
If the new attempt is a login fail and from a host which had already failed twice in this 
cycle, the 3rd_fail_timestamp will be compared with the 1st and the 2nd. Only when the 1st 
and the 3rd are within 20s, a block session will start. O.w., only 2nd and 3rd timestamp
are kept as fail_timestamp if they are within 20s, or, only 3rd timestamp is kept.
Thus, status is a map of host ==> [block_ts, 1st_fail_ts, 2nd_fail_ts], and the list
could have only contained block_ts, or, block_ts and 1st_fail_ts.
'''
def record_potential_breaches(status, host, resource, time_in, http_reply_code, line):
	# Initialize block_timestamp for this host
	if host not in status:
		status[host] = [time_in - timedelta(seconds = 1)]
		if resource.find('login') != -1 and http_reply_code == '401':
			status[host].append(time_in)
		return
	# time_in <= block_timestamp and we log the line
	if time_in <= status[host][0]:
		with open(blocked_file, 'a') as output:
			output.write(line)
		return
	# A non-blocked successful login clears 1st and 2nd_fail_ts
	if resource.find('login') != -1 and http_reply_code == '200':
		while len(status[host]) > 1:
			status[host].pop()
	# Handles non-blocked failed login
	if resource.find('/login') != -1 and http_reply_code == '401':
		# This would be the 1st_fail_ts of a new block session
		if len(status[host]) == 1:
			status[host].append(time_in)
		# 1st_fail_ts already exists for this host
		elif len(status[host]) == 2:
			timediff = time_in - status[host][1]
			if timediff.seconds <= 20:
				status[host].append(time_in)
			else:
				# time_in replaces the existing 1st_fail_ts
				status[host][1] = time_in
		# 2nd_fail_ts already exists for this host
		elif len(status[host]) == 3:
			if (time_in - status[host][2]).seconds > 20:
				status[host].pop()
				status[host].pop()
				status[host].append(time_in)
			elif (time_in - status[host][1]).seconds > 20:
				status[host][1] = status[host][2]
				status[host][2] = time_in
			else:
				# Start a block session by updating the block_timestamp.
				status[host][0] = time_in + timedelta(seconds = 300)

def parse(line):
	pattern = '(.*) - - \[(.*)\] "(.*)" (\d+) (.*)'
	record = re.match(pattern, line)
	host = record.group(1)
	timestamp_str = record.group(2)
	request = record.group(3)
	http_reply_code = record.group(4)
	size_str = record.group(5)
	if len(request.split()) == 1:
		resource = request
	else:
		resource = request.split()[1]	
	size = 0 if size_str == '-' else int(size_str)	
	timestamp = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
	return (host, timestamp, resource, http_reply_code, size)	

if __name__ == "__main__":
	# For feature 1
	host_count_map = {}
	# For feature 2
	resource_bandwidth_map = {}
	# For feature 3
	time_window_queue = deque()
	total_visits_of_current_time_period = [0]
	busiest_time_window_heap = []
	# For feature 4
	host_login_attempts_map = {}
	with open(input_file, 'r', errors = 'ignore') as input:
		for line in input:
			(host, timestamp, resource, http_reply_code, size) = parse(line)
			update_host_count_map(host, host_count_map)
			update_resource_bandwidth_map(resource, size, resource_bandwidth_map)
			update_10_busiest_time_periods(timestamp, time_window_queue, total_visits_of_current_time_period, 
										   busiest_time_window_heap)
			record_potential_breaches(host_login_attempts_map, host, resource, timestamp, http_reply_code, line)
	get_10_most_active_hosts(host_count_map)
	get_10_most_bandwidth_intensive_resources(resource_bandwidth_map)
	get_10_busiest_time_periods(time_window_queue, total_visits_of_current_time_period, busiest_time_window_heap)
