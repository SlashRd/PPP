import socket
# un socket = (dir IP, dir TCP)
# creando un socket: que protocolos
socket_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Definiendo puertos:
socket_server.bind(("localhost", 9999))
# Cuantos hosts se van a comunicar con el servidor
socket_server.listen(1) # Esta función también pone al servidor en modo de escucha, esperando una petición
# Aceptando la petición. Se crea el cliente
socket_client, (remote_client_ip, remote_client_tcp) = socket_server.accept()
print ("ip client: ", remote_client_ip)
print ("tcp client: ", remote_client_tcp)

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

#Recibiendo Configure Request
configureRequest = socket_client.recv(1024)
configureRequest = configureRequest.decode('utf-8')
unstuffed = (configureRequest.replace(escape+escape, escape)).replace(escape+flag,flag)

if unstuffed[0:8]==flag and unstuffed[-8:]==flag:
	#Armando Configure Ack
	message = address + control + protocolo + "00000010" + FCS
###################----------------------------------------------Primera mod
	# Hace el byte-stuffing del mensaje:
	stuffed = (message.replace(escape, escape+escape)).replace(flag,escape+flag)

	#Ponemos banderas
	configureAck = flag+stuffed+flag
	socket_client.send(bytes(configureAck,'utf-8'))

	authenticateRequest = socket_client.recv(1024)
	authenticateRequest = authenticateRequest.decode('utf-8')

	#print(authenticateRequest)

	#Comprobando el authenticateRequest
	#Haciendo unstuffing
	unstuffed = (authenticateRequest.replace(escape+escape, escape)).replace(escape+flag,flag)
	obLength = int(unstuffed[8+8+8+16+8+8:8+8+8+16+8+8+16],2)
	obUlength = int(unstuffed[8+8+8+16+8+8+16:8+8+8+16+8+8+16+8],2)
	obUserName = unstuffed[8+8+8+16+8+8+16+8:8+8+8+16+8+8+16+8+obUlength]
	obPassword = unstuffed[8+8+8+16+8+8+16+8+obUlength+8:8+8+8+16+obLength]
	recieveUsername = bin2str(obUserName)
	recievePassword = bin2str(obPassword)
	#print(obLength)
	#print(obUlength)
	#print(recieveUsername)
	#print(recievePassword)

	if recievePassword == contrasena and recieveUsername == usuario:
		#Comienza el Authenticate-ack
		userName = (''.join(format(ord(x), '08b') for x in usuario)) #Pasando a bits el username
				
		userSize = format(len(userName),'08b')

		length = 8 + 8 + 16 + 8 + len(userName)
		length = format(length,'08b')

		while len(length)<16:
			length = "0" + length

		payload = "00000010" + "00000001" + length + userSize + userName
		message = address + control + protoPAP + payload + FCS
		#print(payload)
		#print(message)
		# Hace el byte-stuffing del mensaje:
		stuffed = (message.replace(escape, escape+escape)).replace(flag,escape+flag)

		#Ponemos banderas
		authenticateAck = flag+stuffed+flag
		socket_client.send(bytes(authenticateAck,'utf-8'))
		#print(authenticateAck)

		###Recibiendo ConfigureRequest
		configureRequest = socket_client.recv(1024)
		configureRequest = configureRequest.decode('utf-8')
		unstuffed = (configureRequest.replace(escape+escape, escape)).replace(escape+flag,flag)
		print(unstuffed)
		obIPCP = unstuffed[8+8+8+16+8+16+8:8+8+8+16+8+16+8+8]
		###------------------SEGUNDA MOD
		print(obIPCP)
		if obIPCP == "00001111":
			##Construyendo el Configure-Ack
			length = 8 + 8 + 16
			length = format(length,'08b')

			while len(length)<16:
				length = "0" + length

			payload = "00000010" + "00000001" + length
			message = address + control + protoNet + payload + FCS
			#print(payload)
			#print(message)
			# Hace el byte-stuffing del mensaje:
			stuffed = (message.replace(escape, escape+escape)).replace(flag,escape+flag)

			#Ponemos banderas
			configureAck = flag+stuffed+flag
			socket_client.send(bytes(configureAck,'utf-8'))

			#Inicia transferencia de Datos
			while True:
				mensaje=socket_client.recv(1024)
				mensaje = mensaje.decode('utf-8')
				unstuffed = (mensaje.replace(escape+escape, escape)).replace(escape+flag,flag)
				obCode = unstuffed[8+8+8+16:8+8+8+16+8]
				if obCode == "00000101":
					#Proceso de TERMINATE por peticion de cliente
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
				obLength = unstuffed[8+8+8+16+8+8:8+8+8+16+8+8+16]
				info = unstuffed[8+8+8+16+8+8+16:8+8+8+16+int(obLength,2)]
				info = bin2str(info)
				print(info)
				info = input('> ')
				if info == "quit":
					break
				else:
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
				pass
			#Inicia proceso de TERMINATE por peticion de servidor
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
			socket_client.close()
			socket_server.close()

		else:
			print("termina proceso con nak")

	else:
		#Comienza el Authenticate-nak
		userName = (''.join(format(ord(x), '08b') for x in usuario)) #Pasando a bits el username
				
		userSize = format(len(userName),'08b')

		length = 8 + 8 + 16 + 8 + len(userName)
		length = format(length,'08b')

		while len(length)<16:
			length = "0" + length

		payload = "00000011" + "00000001" + length + userSize + userName
		message = address + control + protoPAP + payload + FCS
		#print(payload)
		#print(message)
		# Hace el byte-stuffing del mensaje:
		stuffed = (message.replace(escape, escape+escape)).replace(flag,escape+flag)

		#Ponemos banderas
		authenticateNak = flag+stuffed+flag
		#print(authenticateNak)
		socket_client.close()
		socket_server.close()

else:
	print("Request Fallido")