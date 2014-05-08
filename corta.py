import struct
import zlib

#se abre el archivo en modo binario
image = file("C:\Python27\hola.py","rb").read()
chunk = []
cacho2=''
#se decide que en cuantos cachos se va a dividir
interval = 1500 - 20 - 8 - 4
for n in range(0, len(image), interval):
    chunk.append(image[n:n + interval])
#for n in range(len(chunk)):	 
#	chunk[n] = struct.pack(">I", n) + chunk[n] 
print "R=",chunk[2],zlib.crc32(chunk[2]),"R2=\n",chunk[1],zlib.crc32(chunk[1])
for n in range(len(chunk)):
	cacho2=cacho2+chunk[n]
print "Este es cacho: ", cacho2
archi=open("C:\Python27\hola2.txt", 'wb')
archi.write(cacho2)
archi.close()
print "esta realizado"
