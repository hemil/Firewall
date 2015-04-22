#!/usr/bin/python

# need root privileges to run

#import struct
import sys
import time
import os
from socket import AF_INET, AF_INET6, inet_ntoa
import socket
sys.path.append('python')
sys.path.append('build/python')

import nfqueue
import iptc

sys.path.append('dpkt-1.6')
from dpkt import ip

protocol = {"1":"ICMP","6":"TCP","17":"UDP","41":"IPv6","62":"CFTP"}

count = 0		#total
countH = 0		#http (dport=80)
countHS = 0		#https (dport = 443)
countO = 0		#others (Not TCP )
countWP = 0		#TCp but wrong dport
countP = 0 		#No of Pings
#error log
logf = open("error.txt", "w")
countE = 0		#error count



class default:
	def __init__(self):
		#adds the NFqueue to the iptables
		print "Default"
		print "Initializing."
		os.system("iptables -F")
		os.system("iptables -A OUTPUT -j NFQUEUE --queue-num 0")
		q = nfqueue.queue()
		
		print "setting callback"
		q.set_callback(self.cb)
		
		print "open"
		q.fast_open(0, AF_INET)

		q.set_queue_maxlen(50000)

		print "trying to run"
		try:
			q.try_run()
		except KeyboardInterrupt, e:
			print "interrupted"
		
		print "|---------------------------------------------------------------------------|"
		print "|Total Packets|HTTP Packets|HTTPS Packets| TCP,Wrong Port | Not TCP | Errors|"
		print "|   ",count,"   |   ",countH,"   |    ",countHS,"    |    ",countWP,"    |    ",countO,"    |    ",countE,"    |"
		print "|---------------------------------------------------------------------------|"
		
		print "\nunbind"
		q.unbind(AF_INET)

		print "close"
		os.system("iptables -F")
		q.close()

	def cb(self,i, payload):
		global count
		global countH
		global countHS
		global countWP
		global countO
		global countE

		print "\n\n========================Packet Detected========================"
		count += 1
		data = payload.get_data()
		pkt = ip.IP(data)
		try:
			print "|-----------------------------------------------------------------|"
			print "| length | protocol |  Source IP : Port  |  Destination IP : Port |"
			print "|   %s   |    %s   |%s:%s|%s:%s|" % (str(payload.get_length()),protocol[str(pkt.p)],inet_ntoa(pkt.src),pkt.tcp.sport,inet_ntoa(pkt.dst),pkt.tcp.dport)
			print "|-----------------------------------------------------------------|"
		except:
			countE += 1
			e = sys.exc_info()[0]
			logf.write("%d) Error.\n DateTime: %s"" \n Error: %s \n" % (str(countE), str(time.asctime(time.localtime(time.time()))), str(e) ))
		
		if str(pkt.p) == "6":
			print "========================TCP/IP Detected========================"
			if str(pkt.tcp.dport) == "80":
				#HTTP port
				countH += 1
				print "========================HTTP==============ACCEPTED=========="
				payload.set_verdict(nfqueue.NF_ACCEPT)
			elif str(pkt.tcp.dport) == "443":
				#HTTPS
				countHS += 1
				print "========================HTTPS============ACCEPTED============"
				payload.set_verdict(nfqueue.NF_ACCEPT)
			else:
				countWP += 1
				print "\n========================ERROR!!!!!TCP on %s. Dropping Packet========================\n" % (str(pkt.tcp.dport))
				#print "TCP on %s. Dropping Packet" % (str(pkt.tcp.dport))
				payload.set_verdict(nfqueue.NF_DROP)
		else:
			countO += 1
			print "\n========================NOT TCP. DROPPED========================\n"
		if str(inet_ntoa(pkt.dst)) == "10.100.99.32":
			print "\n\n\n\n================================================"
			print "Connecting to Abhijit? Naughty Naughty."
			print "404-ing you for your own good. CLOSE DOWN. NOW!"
			print "\n\n\n\n================================================"
			payload.set_verdict(nfqueue.NF_DROP)
			return 1
		sys.stdout.flush()
		return 1

class BlockPing:
	def __init__(self):
		os.system("iptables -F")
		#os.system("iptables -A OUTPUT -j NFQUEUE --queue-num 0")
		chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
		rule = iptc.Rule()
		rule.out_interface = "eth+"
		rule.protocol = "icmp"
		rule.target = iptc.Target(rule,"DROP")
		chain.insert_rule(rule)
		while True:
			try:
				print "Scanning and Dropping all ICMP requests"
				
			except KeyboardInterrupt:
				print "Shutting down Scan."
				print "Restoring ICMP capability\n\n\n\n"
				os.system("iptables -F")
				break
		
		
'''
		global count
		global countP
		global MyIP
		#adds the NFqueue to the iptables
		print "Blocking the Ping"
		print "Initializing."
		os.system("iptables -F")
		os.system("iptables -A OUTPUT -j NFQUEUE --queue-num 0")
		q = nfqueue.queue()
		
		print "setting callback"
		q.set_callback(self.cb)
		
		print "open"
		q.fast_open(0, AF_INET)

		q.set_queue_maxlen(50000)

		print "trying to run"
		try:
			q.try_run()
		except KeyboardInterrupt, e:
			print "interrupted"
		
		print "|----------------------------------------|"
		print "| Total Packets |    No. Pings   |"
		print "|   ",count,"   |   ",countP,"   |"
		print "|----------------------------------------|"
		
		print "\nunbind"
		q.unbind(AF_INET)

		print "close"
		os.system("iptables -F")
		q.close()

	def cb(self,i, payload):
		global count
		global countP
		print "\n\n========================Packet Detected========================"
		
		

		count += 1
		data = payload.get_data()
		pkt = ip.IP(data)
		#protocol[str(pkt.p)],inet_ntoa(pkt.src),pkt.tcp.sport,inet_ntoa(pkt.dst),pkt.tcp.dport)
		
		if protocol[str(pkt.p)] == "ICMP":
			#ICMP Protocol
			print "========================ICMP Detected========================"
			if str(inet_ntoa(pkt.dst)) == MyIP:
			#I'm the destination of the packet.
				countP += 1
				payload.set_verdict(nfqueue.NF_DROP)
			else:
				print "========================ICMP But not for me========================"
		else:
			print "========================ACCEPTED Protocol========================"
			payload.set_verdict(nfqueue.NF_ACCEPT)
		'''
class BlockDPort:
	def __init__(self, port):
		chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), 'INPUT')
		rule = iptc.Rule()
		rule.in_interface = 'eth+'
		rule.protocol = 'tcp'
		match = rule.create_match('tcp')
		match.dport = port
		rule.target = iptc.Target(rule, 'DROP')
		chain.insert_rule(rule)
		while True:
			try:
				print "Scanning and Dropping all packets to port: ",port
				
			except KeyboardInterrupt:
				print "Shutting down Scan."
				print "Restoring capability\n\n\n\n"
				os.system("iptables -F INPUT")
				break

class BlockHTTP:
	def __init__(self):
		#adds the NFqueue to the iptables
		print "Default"
		print "Initializing."
		os.system("iptables -F")
		os.system("iptables -A OUTPUT -j NFQUEUE --queue-num 0")
		q = nfqueue.queue()
		
		print "setting callback"
		q.set_callback(self.cb)
		
		print "open"
		q.fast_open(0, AF_INET)

		q.set_queue_maxlen(50000)

		print "trying to run"
		try:
			q.try_run()
		except KeyboardInterrupt, e:
			print "interrupted"
		
		print "|---------------------------------------------------------------------------|"
		print "|Total Packets|HTTP Packets|| TCP,Wrong Port | Not TCP | Errors|"
		print "|   ",count,"   |   ",countH,"   |    ",countWP,"    |    ",countO,"    |    ",countE,"    |"
		print "|---------------------------------------------------------------------------|"
		
		print "\nunbind"
		q.unbind(AF_INET)

		print "close"
		os.system("iptables -F")
		q.close()

	def cb(self,i, payload):
		global count
		global countH
		global countHS
		global countWP
		global countO
		global countE

		print "\n\n========================Packet Detected========================"
		count += 1
		data = payload.get_data()
		pkt = ip.IP(data)
		try:
			print "|-----------------------------------------------------------------|"
			print "| length | protocol |  Source IP : Port  |  Destination IP : Port |"
			print "|   %s   |    %s   |%s:%s|%s:%s|" % (str(payload.get_length()),protocol[str(pkt.p)],inet_ntoa(pkt.src),pkt.tcp.sport,inet_ntoa(pkt.dst),pkt.tcp.dport)
			print "|-----------------------------------------------------------------|"
		except:
			countE += 1
			e = sys.exc_info()[0]
			logf.write("%d) Error.\n DateTime: %s"" \n Error: %s \n" % (str(countE), str(time.asctime(time.localtime(time.time()))), str(e) ))
		
		if str(pkt.p) == "6":
			print "========================TCP/IP Detected========================"
			if str(pkt.tcp.dport) == "80":
				#HTTP port
				countH += 1
				print "========================HTTP==============DROPPED=========="
				payload.set_verdict(nfqueue.NF_DROP)
			else:
				countWP += 1
				print "\n========================TCP on %s. Accept Packet========================\n" % (str(pkt.tcp.dport))
				#print "TCP on %s. Dropping Packet" % (str(pkt.tcp.dport))
				payload.set_verdict(nfqueue.NF_ACCEPT)
		else:
			countO += 1
			print "\n========================NOT TCP. DROPPED========================\n"
		if str(inet_ntoa(pkt.dst)) == "10.100.99.32":
			print "\n\n\n\n================================================"
			print "Connecting to Abhijit? Naughty Naughty."
			print "404-ing you for your own good. CLOSE DOWN. NOW!"
			print "\n\n\n\n================================================"
			payload.set_verdict(nfqueue.NF_DROP)
			return 1
		sys.stdout.flush()
		return 1

class BlockHTTPS:
	def __init__(self):
		#adds the NFqueue to the iptables
		print "Default"
		print "Initializing."
		os.system("iptables -F")
		os.system("iptables -A OUTPUT -j NFQUEUE --queue-num 0")
		q = nfqueue.queue()
		
		print "setting callback"
		q.set_callback(self.cb)
		
		print "open"
		q.fast_open(0, AF_INET)

		q.set_queue_maxlen(50000)

		print "trying to run"
		try:
			q.try_run()
		except KeyboardInterrupt, e:
			print "interrupted"
		
		print "|---------------------------------------------------------------------------|"
		print "|Total Packets|HTTP Packets|| TCP,Wrong Port | Not TCP | Errors|"
		print "|   ",count,"   |   ",countH,"   |    ",countWP,"    |    ",countO,"    |    ",countE,"    |"
		print "|---------------------------------------------------------------------------|"
		
		print "\nunbind"
		q.unbind(AF_INET)

		print "close"
		os.system("iptables -F")
		q.close()

	def cb(self,i, payload):
		global count
		global countH
		global countHS
		global countWP
		global countO
		global countE

		print "\n\n========================Packet Detected========================"
		count += 1
		data = payload.get_data()
		pkt = ip.IP(data)
		try:
			print "|-----------------------------------------------------------------|"
			print "| length | protocol |  Source IP : Port  |  Destination IP : Port |"
			print "|   %s   |    %s   |%s:%s|%s:%s|" % (str(payload.get_length()),protocol[str(pkt.p)],inet_ntoa(pkt.src),pkt.tcp.sport,inet_ntoa(pkt.dst),pkt.tcp.dport)
			print "|-----------------------------------------------------------------|"
		except:
			countE += 1
			e = sys.exc_info()[0]
			logf.write("%d) Error.\n DateTime: %s"" \n Error: %s \n" % (str(countE), str(time.asctime(time.localtime(time.time()))), str(e) ))
		
		if str(pkt.p) == "6":
			print "========================TCP/IP Detected========================"
			if str(pkt.tcp.dport) == "443":
				#HTTP port
				countH += 1
				print "========================HTTPS==============Dropped=========="
				payload.set_verdict(nfqueue.NF_DROP)
			else:
				countWP += 1
				print "\n========================TCP on %s. ACCEPTING Packet========================\n" % (str(pkt.tcp.dport))
				#print "TCP on %s. Dropping Packet" % (str(pkt.tcp.dport))
				payload.set_verdict(nfqueue.NF_ACCEPT)
		else:
			countO += 1
			print "\n========================NOT TCP. DROPPED========================\n"
		if str(inet_ntoa(pkt.dst)) == "10.100.99.32":
			print "\n\n\n\n================================================"
			print "Connecting to Abhijit? Naughty Naughty."
			print "404-ing you for your own good. CLOSE DOWN. NOW!"
			print "\n\n\n\n================================================"
			payload.set_verdict(nfqueue.NF_DROP)
			return 1
		sys.stdout.flush()
		return 1


class BlockDIP:
	def __init__(self, ip):
		global count
		global countP
		global MyIP
		#adds the NFqueue to the iptables
		print "Blocking the Ping"
		print "Initializing."
		os.system("iptables -F")
		os.system("iptables -A OUTPUT -j NFQUEUE --queue-num 0")
		q = nfqueue.queue()
		
		print "setting callback"
		q.set_callback(self.cb)
		
		print "open"
		q.fast_open(0, AF_INET)

		q.set_queue_maxlen(50000)

		print "trying to run"
		try:
			q.try_run()
		except KeyboardInterrupt, e:
			print "interrupted"
		
		print "|----------------------------------------|"
		print "| Total Packets |    No. Pings   |"
		print "|   ",count,"   |   ",countP,"   |"
		print "|----------------------------------------|"
		
		print "\nunbind"
		q.unbind(AF_INET)

		print "close"
		os.system("iptables -F")
		q.close()

	def cb(self,i, payload):
		global count
		global countP
		print "\n\n========================Packet Detected========================"
		
		

		count += 1
		data = payload.get_data()
		pkt = ip.IP(data)
		#protocol[str(pkt.p)],inet_ntoa(pkt.src),pkt.tcp.sport,inet_ntoa(pkt.dst),pkt.tcp.dport)
		
		if inet_ntoa(pkt.dst) == str(ip) or str(pkt.tcp.dport) == "80":
			#ICMP Protocol
			print "========================Dest ",inet_ntoa(pkt.dst)," Detected========================"
			print "========================DROPPED========================"
			payload.set_verdict(nfqueue.NF_DROP)
		else:
			print "========================ACCEPTED========================"
			payload.set_verdict(nfqueue.NF_ACCEPT)

class BlockSrc:
	def __init__(self):
		os.system("iptables -F OUTPUT")
		os.system("iptables -A OUTPUT -m state --state ESTABLISHED -j ACCEPT")
		os.system("iptables -A OUTPUT -j REJECT")
		while True:
			try:
				print "\n\n========================Blocking all new Out Connection========================"
				print "press Ctrl+C to exit and restore connections"
			except KeyboardInterrupt, e:
				print "Shutting down Scan."
				print "Restoring capability\n\n\n\n"
				os.system("iptables -F OUTPUT")
				break

class BlockDNS:
	def __init__(self):
		os.system("iptables -F INPUT")
		chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), 'INPUT')
		rule = iptc.Rule()
		rule.in_interface = 'eth+'
		rule.protocol = 'udp'
		match = iptc.Match(rule, "udp")
		match.sport = "53"		#DNS port
		rule.add_match(match)
		rule.target = iptc.Target(rule, 'DROP')
		chain.insert_rule(rule)
		print "========================Initiating BLocking========================"

		while True:
			try:
				print "========================BLOCKING DNS========================"
				print "========================Press Ctrl+C to exit and restore========================"
			except KeyboardInterrupt:
				break
				
		print "========================Restoring DNS ACCESs========================"
		#os.system("sudo iptables -D INPUT -p udp -m udp --sport 53 -j DROP")
		chain.delete_rule(rule)

class start:
	def __init__(self):
		print "10.100.56.55 - portal"
		print "10.100.56.13 - intranet"
		print 'Default action to allow only HTTP/S'
        print 'Default  			-  1'
        print 'Block Incoming Pings     	-  2'
        #print 'Block Destination Port    	-  3'
        print 'Block HTTP/S 				-3'
        print 'Block Destination IP    	-  4'
        print 'Block all My Traffic 		-  5'
        print 'Block DNS Resolution 		-  6'
        print 'Exit     			-  7'
        choices = raw_input('Enter choice: ').split(',')
        for action in choices:
            if action == "1":
                c = default()
                break
            elif action == "2":
                BlockPing()
                break
            elif action == "3":
            	a = raw_input("1 - Block HTTP \n 2- Block HTTPS")
            	if a == "1":
            		BlockHTTP()
            	elif a=="2":
            		BlockHTTPS()
            	else:
            		print "Input not recognized"
            	#OutPort = raw_input("\nEnter the Port Number:\n")
                #OutP = BlockDPort(OutPort)
                break
            elif action == "4":
            	DIP = raw_input("\nEnter the IP:\n")
                outIP = BlockDIP(DIP)
                break
            elif action =="5":
            	BlockAllSrc = BlockSrc()
            elif action == "6":
            	BlockDNS()
            else:
            	print "Error in Input. Try Again."
                continue
#s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#s.connect(('google.com', 0))
#MyIP = s.getsockname()[0]
start()
