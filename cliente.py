import socket
# Protocolos
socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Puertos
socket_client.connect(("4.tcp.ngrok.io",17795))

#Variables no mutables Importantes para todo el PPP
flag = "01111110"
address = "11111111"
control = "00000011"
protocolo = "1100000000100001"
FCS = "1111111111111111" 
escape = "01111101"
protoPAP = "1100000000100011"
usuario = "Dandelion"
contrasena = "cornerstone13"
protoNet = "1000000000100001"


#Funcion para obtener texto de cadena binaria
def bin2str(mensaje):
	#String vacio para ir almacenando los caracteres
    str_data = ''
   
    # Cortamos cada 8 caracteres para hacer un byte, luego transformarlo a int y luego a string
    for i in range(0, len(mensaje), 8):
      
        # vamos almacenando lo cortado en temp_data
        temp_data = mensaje[i:i + 8]
       
        # obtenemos el valor decimal para el binario recortado
        decimal_data = int(temp_data, 2)
       
        # Transformamos a caracter usando la funcion chr() que nos regresa un valor ASCII por cada caracter
        str_data = str_data + chr(decimal_data)
        #print("caracter",chr(decimal_data))
    return str_data


#Se hace Configure Request
message = address + control + protocolo + "01000000" + FCS

# Hace el byte-stuffing del mensaje:
stuffed = (message.replace(escape, escape+escape)).replace(flag,escape+flag)

#Ponemos banderas
configureRequest = flag+stuffed+flag
socket_client.send(bytes(configureRequest,'utf-8'))

#Recibiendo Configure ack
configureAck = socket_client.recv(1024)
#print(configureAck)
configureAck = configureAck.decode('utf-8')
unstuffed = (configureAck.replace(escape+escape, escape)).replace(escape+flag,flag)
print(unstuffed)
obCode = unstuffed[8+8+8+16:8+8+8+16+8]
print(obCode)
if obCode == "00000010":
	#Enviando Authenticate Request
	userName = (''.join(format(ord(x), '08b') for x in usuario)) #Pasando a bits el username
	password = (''.join(format(ord(x), '08b') for x in contrasena)) #Pasando a bits el password
		
	userSize = format(len(userName),'08b')
	passSize = format(len(password),'08b')

	length = 8 + 8 + 16 + 8 + len(userName) + 8 + len(password)
	length = format(length,'08b')

	while len(length)<16:
		length = "0" + length

	payload = "00000001" + "00000001" + length + userSize + userName + passSize + password
	message = address + control + protoPAP + payload + FCS
	print(payload)
	print(message)
	# Hace el byte-stuffing del mensaje:
	stuffed = (message.replace(escape, escape+escape)).replace(flag,escape+flag)

	#Ponemos banderas
	authenticateRequest = flag+stuffed+flag
	socket_client.send(bytes(authenticateRequest,'utf-8'))

	#Recibiendo authenticateAck
	authenticateAck = socket_client.recv(1024)
	authenticateAck = authenticateAck.decode('utf-8')
	unstuffed = (authenticateAck.replace(escape+escape, escape)).replace(escape+flag,flag)
	obCode = unstuffed[8+8+8+16:8+8+8+16+8]
	if obCode == "00000010":

		#Enviando Configure request
		length = 8 + 8 + 16 + 8
		length = format(length,'08b')
		while len(length)<16:
			length = "0" + length
		print("se imprime la length")
		print(length)
		payload = "00000001" + "00000001" + length + "00001111"
		message = address + control + protoNet + payload + FCS
		#print(payload)
		#print(message)
		# Hace el byte-stuffing del mensaje:
		stuffed = (message.replace(escape, escape+escape)).replace(flag,escape+flag)
		#Ponemos banderas
		configureRequest = flag+stuffed+flag
		#print(configureRequest)
		socket_client.send(bytes(configureRequest,'utf-8'))
		print("Se envia configureRequest")
		#Recibiendo configureAck
		configureRequest = socket_client.recv(1024)
		configureRequest = configureRequest.decode('utf-8')
		unstuffed = (configureRequest.replace(escape+escape, escape)).replace(escape+flag,flag)
		obCode = unstuffed[8+8+8+16:8+8+8+16+8]
		if obCode == "00000010":
			#Aqui inicia la transferencia de datos
			#Mensaje
			while True:
				info = input('> ')
				if info == "quit":
					break
				info = (''.join(format(ord(x), '08b') for x in info))
				length = 8 + 8 + 16 + len(info)
				length = format(length,'08b')

				while len(length)<16:
					length = "0" + length

				payload = "00001001" + "00000001" + length + info
				message = address + control + protocolo + payload + FCS
				# Hace el byte-stuffing del mensaje:
				stuffed = (message.replace(escape, escape+escape)).replace(flag,escape+flag)
				#Ponemos banderas
				mensaje = flag+stuffed+flag
				socket_client.send(bytes(mensaje,'utf-8'))
				print("Mensaje enviado")
				echo = socket_client.recv(1024)
				echo = echo.decode('utf-8')
				unstuffed = (echo.replace(escape+escape, escape)).replace(escape+flag,flag)
				obCode = unstuffed[8+8+8+16:8+8+8+16+8]
				if obCode == "00000101":
				#Proceso de TERMINATE por peticion de servidor
					length = 8 + 8 + 16 + len(info)
					length = format(length,'08b')

					while len(length)<16:
						length = "0" + length

					payload = "00000110" + "00000001" + length + info
					message = address + control + protocolo + payload + FCS
					# Hace el byte-stuffing del mensaje:
					stuffed = (message.replace(escape, escape+escape)).replace(flag,escape+flag)
					#Ponemos banderas
					terminateAck = flag+stuffed+flag
					socket_client.send(bytes(terminateAck,'utf-8'))
					socket_client.close()
					quit()
				else:
					obLength = unstuffed[8+8+8+16+8+8:8+8+8+16+8+8+16]
					info = unstuffed[8+8+8+16+8+8+16:8+8+8+16+int(obLength,2)]
					info = bin2str(info)
					print(info)
				pass
			#Inicia proceso de TERMINATE por peticion de cliente
			info = (''.join(format(ord(x), '08b') for x in info))
			length = 8 + 8 + 16 + len(info)
			length = format(length,'08b')

			while len(length)<16:
				length = "0" + length

			payload = "00000101" + "00000001" + length + info
			message = address + control + protocolo + payload + FCS
			# Hace el byte-stuffing del mensaje:
			stuffed = (message.replace(escape, escape+escape)).replace(flag,escape+flag)
			#Ponemos banderas
			mensaje = flag+stuffed+flag
			socket_client.send(bytes(mensaje,'utf-8'))

			#Recibiendo TERMINATE ack
			terminateAck = socket_client.recv(1024)
			terminateAck = terminateAck.decode('utf-8')
			unstuffed = (terminateAck.replace(escape+escape, escape)).replace(escape+flag,flag)
			obCode = unstuffed[8+8+8+16:8+8+8+16+8]
			if obCode == "00000110":
				socket_client.close()
			else:
				print("Error")
	else:
		#Se ha recibido un nak
		socket_client.close()
