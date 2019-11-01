import os
import socket
import time
import threading
from HashTable import HashTable
from PacketFormatter import PacketFormatter

pf = PacketFormatter()
hs = HashTable()
keyList = []
portWhiteList = []
fanOutRateDict = {}

def sniffer():
    
	while stop_threads == False:
		packets = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
		ethernet_data, address = packets.recvfrom(65536)
		dest_mac, src_mac, protocol, ip_data = pf.ethernet_dissect(ethernet_data)
		#allow ICMP packets if their type is 0.
		if protocol == 8:
			ip_protocol, src_ip, dest_ip, transport_data = pf.ipv4_dissect(ip_data)
			if ip_protocol == 6:
				src_port, dest_port = pf.tcp_dissect(transport_data)
				'''
				if src_ip.split('.')[0] == "10":
					drop("private ip range")
				elif src_ip.split('.')[0] == "192" and src_ip.split('.')[1] == "168":
					drop("private ip range")
				elif src_ip == "0.0.0.0":
					drop("invalid ip range")
				elif src_ip.split('.')[0] == "127" and src_ip.split('.')[1] == "0":
					drop("invalid ip range")
				elif src_ip == pf.get_host_ip():
					drop("'Ping of death' attack.")
				elif src_port == "23":
					drop("Telnet")
				else:
				'''
				recordConnection(src_ip, dest_port)

def drop(reason):
	print("packet dropped for: ", reason)

# either adds to hash table, or increments the fanOut count
def recordConnection(src_ip, dest_port):
    if hs.find(src_ip):
        #print("Record already in dictionary")
        incrementFanOutDict(src_ip, time.time())
    else:
        hs.insert(src_ip, [dest_port, time.time()])
        keyList.append(src_ip)
        #print("Record added successfully")

def incrementFanOutDict(src_ip, ts):
	if fanOutRateDict.get(src_ip):
		calculateFanOut(src_ip)
	else:
		# this dictionary is the timestamp, total hits in the last second, and then the running average of hits per second. The the same thing for hits per minute, and hits per five minutes. 
		fanOutRateDict[src_ip] = [ts, 0, 0, ts, 0, 0, ts, 0]

def calculateFanOut(src_ip):
	if src_ip in fanOutRateDict.keys():
		value = fanOutRateDict.get(src_ip)
		if time.time() - value[0] < 1:
			value[1] += 1
		else:
			value[0] = time.time()
			value[2] = (value[1] + value[2])/2
			value[1] = 0
		
		if time.time() - value[3] < 59:
			value[4] += 1
		else:
			value[3] = time.time()
			value[5] = (value[4] + value[5])/2
			value[4] = 0
		
		if time.time() - value[6] < 299:
			value[7] += 1
			fanOutRateDict[src_ip] = value
		#elif time.time() - value[6] > 300:
			
			#calculateAverageFanoutRate(src_ip, value)
			# this is leftover from homework 3. I think this is where I will call functionality to log and block this IP address if it qualifies as malicious.
			#del(destinationDict[dest_ip])
			#fanOutRateDict[src_ip] = value

def printAverage():
	ts = time.time()
	
	while stop_threads == False:
		if time.time() - ts >= 60:
			ts = time.time()
			for ip in fanOutRateDict:
				if testFanout(ip):
					v = fanOutRateDict.get(ip)
					print("Portscanner detected on source ip ", ip)
					print(" Average fanout per sec: ", v[2], ", per min: ", v[5], ", per 5 min: ", v[7], "/5m")           
           
def testFanout(ip):

	v = fanOutRateDict.get(ip)
	
	if v[2] > 5:
		return True
	if v[5] > 100:
		return True
	if v[7] > 300:
		return True
		
	return False

def deleteOldRecords():
	while stop_threads == False:
		if hs.size > 0:
			for item in keyList:
				if hs.removeOld(item) == True:
					keyList.remove(item)
					print("Old item deleted")
					break


stop_threads = False
snifferThread = threading.Thread(name='sniffer', target=sniffer)
deleteThread = threading.Thread(name='deleteOldRecords', target=deleteOldRecords)
printAverageThread = threading.Thread(name='printAverage', target=printAverage)
snifferThread.start()
deleteThread.start()
printAverageThread.start()
print("running...")
	
while stop_threads == False:
	userInput = input("Type 'quit' to stop Port Scanner Detector.")
	if userInput.lower() == "quit":
		stop_threads = True
	
snifferThread.join()
deleteThread.join()
printAverageThread.join()

print("Goodbye!")
