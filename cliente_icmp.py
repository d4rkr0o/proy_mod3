import os, sys, socket, struct, select, time , threading ,re, base64
from Crypto.Cipher import AES

class ClientICMP:
	ICMP_ECHO_REQUEST = 8
	key_size = 32 #AES256
	reconstruccion=""
	wa=1
	ip='192.168.30.30'
	archivoFinal=""
	nombrearch=""
	count=0
	count2=0

	def __init__(self):
		HOST = raw_input("Ingresa la ip para hacer el bind: ")
		s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)#Creacion socket
		s.bind((HOST, 0))
		s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
		s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)  #Se enciende modo promiscuo en la tarjeta de red
		print "Cliente a la escucha......"
		while 1:
			print "A la escucha..."
			self.count2=0
			data=""
			data = s.recvfrom(65565)
			data=str(data)
			print "nombrearch:"+self.nombrearch
			print "Llevamos la cuenta: "+str(self.count)
			if re.search("@{2}[a-z]{7}(.*)",data) and self.count==0:
				self.reconstruccion=""
				data1=re.sub("^@{2}[a-z]{7}","",str(re.search("@{2}[a-z]{7}(.*)",data).group()).replace("\\n",""),flags=re.IGNORECASE)
				if re.search("192.168.30.20",data1):
					continue
				print "Primer data 1:"+data1
				data1=data1[0:-24]
				descifrado=self.descifrar(data1)
				print re.search("\\d+",descifrado).group()
				print re.search("\.(.*)",descifrado).group()
				cantpaquetes=re.search("\\d+",descifrado).group()
				self.nombrearch=re.search("\.(.*)",descifrado).group()
				#time.sleep(100)
				self.count=1
				data1=""
				
			elif self.nombrearch!="" and self.count==1:
				print "Dentro de cuando archivo no esta vacio y count es 1"
				data1= re.sub("^@{2}","",str(re.search("@{2}(.*)",data).group()).replace("\\n",""),flags=re.IGNORECASE)
				if re.search("192.168.30.20(.*)",data1) or re.search("^[a-z]{7}(.*)",data1):
					continue
				#print data1
				data1=data1[0:-24]
				#print data1
				#print "Longitud de cadena b64: "+str(len(data1))
				
				#print data1
				#print self.descifrar(data1)
				self.reconstruccion+=self.descifrar(data1)
				#print self.reconstruccion
				print "\n\n\n\n\n\n\nAqui esta reconstruccion y cant paquetes"+str(self.cut_string(self.reconstruccion))+"..."+str(cantpaquetes)
				if str(self.cut_string(self.reconstruccion))==str(cantpaquetes):
					try:
						self.archivoFinal=open(self.nombrearch,'wb')
						self.archivoFinal.write(self.reconstruccion)
						self.archivoFinal.close()
					except IOError as e:
						print "I/O error({0}): {1}".format(e.errno, e.strerror)
					time.sleep(2)
					self.do_one(self.ip,self.wa,self.cifrar('Done'))
					print "Dentro de if archivo"
					data=""
					self.count=0
					self.nombrearch=""
					continue
				else:
					continue
			#Entra aqui cuando el nombre del archivo este vacio y contador 2 sea igual a 0
			elif self.nombrearch=="" and self.count2==0:
				data1= re.sub("^@{2}","",str(re.search("@{2}(.*)",data).group()).replace("\\n",""), flags=re.IGNORECASE)
				data1=data1[0:-24]
				#Muestra la cadena codificada
				print "Raw data: "+data1
				#Muestra el descifrado
				print "Descifrado: "+self.descifrar(data1)
				time.sleep(10)
				self.do_one(self.ip,self.wa,self.cifrar('Done'))
				print "Cadena cifrada done: "+self.cifrar('Done')
				print len(self.cifrar('Done'))
				data=""
				#print data
				self.count2=1
				continue
			else:
				continue
		s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
			
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
		
	def crafting_packet(self,my_socket,dest_addr,ID,data_send):
		data = "@@@"+data_send
		dest_addr  =  socket.gethostbyname(dest_addr)
		# Cabecera tipo (8), codigo (8), checksum (16), id (16), sequencia (16)
		my_checksum = 0
		#Realiza una cabecera con checksum 0
		header = struct.pack("bbHHh", self.ICMP_ECHO_REQUEST, 0, my_checksum, ID, 1)
		# Calcula el checksum del packete y la cabecera
		my_checksum = self.checksum(header + data)
		header = struct.pack("bbHHh", self.ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), ID, 1)
		packet = header + data
		my_socket.sendto(packet, (dest_addr, 1))
		#Realiza el cifrado tomando la llave de un archivo		
	def cifrar(self,texto):
		try:
			f=open('C:\Users\darkroo\Desktop\key.txt','rb')
			key=f.readline()
		except IOError as e:
			print "I/O error({0}): {1}".format(e.errno, e.strerror)
			
		secret=texto
		#Hace que la cadena sea multiplo de 16
		length = 16 - (len(secret) % 16)
		secret += chr(length) * length 

		
		
		iv='e8b919894198be5f8e4b1be784d0e471'.decode('hex')
		
		cipher = AES.new(key, AES.MODE_CBC, iv)
		encodedtext = iv + cipher.encrypt(secret)
		encodedtext=encodedtext.encode('base64','strict')
		return encodedtext
	
	#Realiza el descifrado igualmente tomando la llave del archivo y haciendo uso del mismo vector de inicializacion
	def descifrar(self,textocifrado):
		key_size = 32 #AES256
		key=''
		try:
			f=open('C:\Users\darkroo\Desktop\key.txt','rb')
			key=f.read()
		except IOError as e:
			print "I/O error({0}): {1}".format(e.errno, e.strerror)
			
		print key
		iv='e8b919894198be5f8e4b1be784d0e471'.decode('hex')
		cipher = AES.new(key, AES.MODE_CBC, iv)
		print len(textocifrado)
		encodedtext=textocifrado.decode('base64','strict')
		print len(encodedtext)
		print encodedtext
		decodedtext = str(cipher.decrypt(encodedtext))
		decodedtext=decodedtext[16:-ord(decodedtext[-1])] #quita el iv y le recorrido
		#print decodedtext
		return decodedtext
	
	def do_one(self,dest_addr, timeout,payload):
		icmp = socket.getprotobyname("icmp")
		try:
			my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)   #Define que sera icmp y debe ser del tipo raw
		except socket.error, (errno, msg):
			if errno == 1:
				# Operacion no permitida
				msg = msg + (
				   
				)
				raise socket.error(msg)
			raise # muestra la excepcion original
	 
		my_ID = os.getpid() & 0xFFFF
	 
		self.crafting_packet(my_socket, dest_addr, my_ID,payload)
		my_socket.close()
		#return delay	
		#corta la cadena para saber cuantos pedazos tiene y verificar que envio todos los pedazos
	def cut_string(self,cadenita):
		chunk=[]
		#tamaño maximo de datos para viajar en el paquete icmp
		interval=1500-32
		for n in range(0,len(cadenita),interval):
			chunk.append(cadenita[n:n + interval])
		return len(chunk)
		 
		
cliente=ClientICMP()