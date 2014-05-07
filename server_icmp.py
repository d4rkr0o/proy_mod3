import socket
import re
import os, sys, socket, struct, select, time , threading
from Crypto.Cipher import AES
#HOST = socket.gethostbyname(socket.gethostname())


class ServerICMP:



	ICMP_ECHO_REQUEST = 8
	def __init__	(self):
		ip = raw_input("Enter the destination IP: ")
		delay = 1
		if len(sys.argv)==1:
			while 1:
					texto = raw_input("Ingresa tu texto>")
					
					if texto == "quit":
							break
					else:
							textocifrado=self.cifrar(texto)
							self.do_one(ip,delay,textocifrado)
							print("Enviando paquete ICMP....\n")
							self.startlistening()
		else:
			#try:
			#	f=open(argv[1],'rb')
			#	while 1:
			#		contenido=f.read()
			#	textocifrado=self.cifrar(contenido)
			#	for i in range(0..len(textocifrado))
					
					#do_one(ip,delay,)
			#except IOError as e:
			#	print "I/O error({0}): {1}".format(e.errno, e.strerror)
			pass	
			
	
	def checksum(self,source_string):
	   
		sum = 0
		countTo = (len(source_string)/2)*2
		count = 0
		while count<countTo:
			thisVal = ord(source_string[count + 1])*256 + ord(source_string[count])
			sum = sum + thisVal
			sum = sum & 0xffffffff
			count = count + 2
	 
		if countTo<len(source_string):
			sum = sum + ord(source_string[len(source_string) - 1])
			sum = sum & 0xffffffff
	 
		sum = (sum >> 16)  +  (sum & 0xffff)
		sum = sum + (sum >> 16)
		answer = ~sum
		answer = answer & 0xffff
			# Swap bytes.
		answer = answer >> 8 | (answer << 8 & 0xff00)
		return answer
	 
	 
	def send_one_ping(self,my_socket, dest_addr, ID, onlydata):
		#global ICMP_ECHO_REQUEST
		data = "$$"+onlydata
		dest_addr  =  socket.gethostbyname(dest_addr)
		my_checksum = 0
		header = struct.pack("bbHHh", self.ICMP_ECHO_REQUEST, 0, my_checksum, ID, 1)
		bytesInDouble = struct.calcsize("d")
		my_checksum = self.checksum(header + data)
		header = struct.pack(
			"bbHHh", self.ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), ID, 1
		)
		packet = header + data
		my_socket.sendto(packet, (dest_addr, 1)) # Don't know about the 1
	 
	def cifrar(self,texto):
		key_size = 32 #AES256
		key=''
		try:
			f=open('C:\Users\darkroo\Desktop\key.txt','rb')
			key=f.read()
		except IOError as e:
			print "I/O error({0}): {1}".format(e.errno, e.strerror)
			
		secret=texto

		length = 16 - (len(secret) % 16) #PKCS7 adds bytes of the length of padding
		secret += chr(length) * length 

		#salt = Random.new().read(key_size) #salt the hash
		iv='e8b919894198be5f8e4b1be784d0e471'.decode('hex')	#Random.new().read(AES.block_size)
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
			my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
		except socket.error, (errno, msg):
			if errno == 1:
				# Operation not permitted
				msg = msg + (
				   
				)
				raise socket.error(msg)
			raise # raise the original error
	 
		my_ID = os.getpid() & 0xFFFF
	 
		self.send_one_ping(my_socket, dest_addr, my_ID,payload)
		my_socket.close()
		#return delay
	
	def startlistening(self):
			HOST = '192.168.30.30'
			s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
			s.bind((HOST, 0))
			s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
			print "A la escucha....."
			while 1:
					data = s.recvfrom(65565)
					d1 = str(data[0])
					d2 = str(data[1])

					#print "Imprimiendo d1 y d2"+d1
					data1 = re.search('$$(.*)', d1)
					print data1
					datapart = data1.group(0)
					print datapart
					#writer(datapart)
					#command = data1.group(0)
					#cmd = command[2:]
					#ip = d2[2:-5]
					#print command
					#print ip
					#print data
					#print reader()
	#thread.start_new_thread(startsniffing,())
	
	
servericmp=ServerICMP()
	