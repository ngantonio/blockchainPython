#BlockChain.py

"""
	El siguiente codigo modela de forma simple un bloque de BlockChain...
	* Un bloque de blockChain contiene 3 elementos, La data de ese bloque, el hash del bloque anterior
	y una referencia al bloque anterior.
	
"""
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

# Tipo de dato compuesto
class someClass:
	string = None
	num = 1264378
	def __init__(self, mystring):
		self.string = mystring
	def __repr__(self):
		return self.string + str(self.num)

# Clase que modela a un bloque
class CBlock:

	# Contiene el hash del bloque anterior
	previousHash = None
	# Al bloque anterior
	previousBlock = None
	# y los datos de este bloque
	data = None

	# constructor
	def __init__(self, data, previousBlock):
		self.data = data
		self.previousBlock = previousBlock

		# Calculamos de una vez el hash anterior...
		# caso borde para el bloque root, no tiene un bloque anterior
		if previousBlock is not None:
			self.previousHash = previousBlock.computeHash()

	
	# funcion encargada de calcular el hash para este bloque
	# El hash de este bloque es una composicion del hash del bloque anterior + los datos        
	def computeHash(self):
		digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
		digest.update(bytes(str(self.data), 'utf-8'))
		digest.update(bytes(str(self.previousHash), 'utf-8'))
		return digest.finalize()

	# funcion encargada de comprobar si un determinado bloque es valido..
	# Un bloque es valido si al calcular nuevamente el hash del bloque anterior, el resultado
	# es igual al hash anterior almacenado en este bloque como previusHash
	def is_valid(self):
		if self.previousBlock is None:
			return True					#si es el primer bloque, es valido
		return self.previousBlock.computeHash() == self.previousHash





################## BLOQUE MAIN ############################

if __name__ == '__main__':

	#creamos la primera instancia de la cadena de bloques (root) 
	# cuyos datos seran el mensaje, y no tendrpa un hasta anterior
	root  = CBlock(b'I am root', None)

	#Creamos la seguna instancia, el hijo
	B1 = CBlock('Im a child!', root)


	#Agregamos mas bloques a la cadena:
	#agregamos a B2 como hijo de root
	#agregamos a B3 como hijo de B1
	#agregamos a B4 como hijo de B3
	#B5 como hijo de B4
	#B6 como hijo de B5

	B2 = CBlock('Im a brother', root)        
	B3 = CBlock(b'I contiain bytes', B1)
	B4 = CBlock(12354, B3)
	B5 = CBlock(someClass('Hi there!'), B4)
	B6 = CBlock("child of B5", B5)


	""" debemos preguntar si el hash de el bloque actual (B1 coincide con 
		el hash del bloque anterior (root).
		Para ello calculamos el hash del bloque anterior y lo igualamos con
		el elemento previousHash de B1, el cual deberia de contener el hash de root
	"""

	#Ahora, necesitamos hacer la comprobacion de hashes para cada bloque que se agregue
	# Creamos una lista de tuplas para almacenar el bloque y su nombre
	
	for b,name in [(B1,'B1'), (B2,'B2'), (B3,'B3'), (B4,'B4'), (B5,'B5')]:
		if b.previousBlock.computeHash() == b.previousHash:
			print("Success! "+name+" hash matches")
		else:
			print("ERROR! " +name+" hash does not match")

################################################################################# 

	print("\n\n############# ATTACK ATTEMPT ###############\n\n")

	"""
		Intentemos comportarnos como un atacante manipulando el contenido
		de los datos del Bloque 4...	
	"""

	# cambiamos los datos de B4
	B4.data = 12345

	print("Datos del bloque anterior a B4 (bloque B3)")
	print(B4.previousBlock.data)

	""" 
		Se pregunta siempre por el anterior, desde el bloque siguiente..
		B5.previousBlock.computeHash() calcula nuevamente el hash para B4 (datos + hash anterior (b3)),
		el cual debe coincidir con B5.previousHash , variable que mantiene solo el hash de B4)
	
	"""
	if B5.previousBlock.computeHash() == B5.previousHash:
		print("ERROR! Failed to detect tamper")
	else:
		print("Success! Tampering detected.")

"""
B5.data.num = 23678
	if B6.previousBlock.computeHash() == B6.previousHash:
		print("ERROR! Failed to detect tamper")
	else:
		print("Success! Tampering detected.")
"""
	
		

	
