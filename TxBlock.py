#TxBlock

"""
    El siguiente codigo modela de forma simple una cadena bloques de transacciones de monedas en blockchain
    * Esas transacciones están protegidas por firmas digitales y la cadena de bloques 
    está asegurada por los hashes registrados.
    * Hereda de la clase CBlock
"""



from BlockChain import CBlock
from Signatures import generate_keys, sign, verify
from Transactions import Tx

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

import pickle
import time
import random

# recompensa para el minero
REWARD = 25.0
# Numero de ceros inciales para el hash
leading_zeros = 2
# 
next_char_limit = 20

class TxBlock (CBlock):

    nonce = "AAAAAAA"

    def __init__(self, previousBlock):
        super(TxBlock,self).__init__([],previousBlock)

    def addTx(self, Tx_in):
        self.data.append(Tx_in)

    ## Encargada de regresar el total de coins recibidos y retirados
    def __count_totals(self):
        total_in = 0
        total_out = 0

        #recorremos las transacciones y listas del bloque...
        for tx in self.data:
            for addr, amount in tx.inputs:
                total_in = total_in + amount
            for addr, amount in tx.outputs:
                total_out = total_out + amount

        return total_in,total_out


    # Encargada de evaluar si un bloque de transacciones es valido.
    # Un bloque de transacciones es valido, si cada una de las transacciones son validas
    # y el bloque tambien lo es

    def is_valid(self):
        
        # Se verifican las transacciones
        for tx in self.data:
            if not tx.is_valid():
                return False

        #se verifica el hash del bloque
        if not super(TxBlock, self).is_valid():
            return False

        # Se verifica si un usuario quiere retirar mas monedas
        # de las que existen + una tasa de recompensa para el minero de 25 coins
        total_in, total_out = self.__count_totals()

        # eliminamos el error de punto flotante de python
        if total_out - total_in - REWARD > 0.000000000001:
            return False
            
        return True

    # Encargada de hacer la prueba del algorimo de nonce, algoritmo de los ceros inciales 
    # en el hash con el que funciona bitcoin
    def good_nonce(self):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(bytes(str(self.data),'utf8'))
        digest.update(bytes(str(self.previousHash),'utf8'))
        digest.update(bytes(str(self.nonce),'utf8'))
        this_hash = digest.finalize()

        # Pregunta si los n primeros caracterers del hash son distintos a una lista de n caracteres iguales
        # si son distintos, retorna falso
        if this_hash[:leading_zeros] != bytes(''.join([ '\x4f' for i in range(leading_zeros)]),'utf8'):
            return False

        # retorna el booleano resultante de preguntar si el caracter siguiente del hash es menor al 
        # limite establecido
        return int(this_hash[leading_zeros]) < next_char_limit


    #####################################
    def find_nonce(self):
        for i in range(1000000):
            self.nonce = ''.join([ 
                   chr(random.randint(0,255)) for i in range(10*leading_zeros)])
            if self.good_nonce():
                return self.nonce
        return None


################## BLOQUE MAIN ############################

if __name__ == "__main__":
    pr1, pu1 = generate_keys()
    pr2, pu2 = generate_keys()
    pr3, pu3 = generate_keys()

    Tx1 = Tx()
    Tx1.add_input(pu1, 1)
    Tx1.add_output(pu2, 1)
    Tx1.sign(pr1)


    if Tx1.is_valid():
        print("Success! Tx1 is valid")


    ## Almacenando la transaccion...
    savefile = open("tx.dat","wb")
    pickle.dump(Tx1,savefile)
    savefile.close()


    ## cargando la transaccion
    loadfile = open("tx.dat", "rb")
    newTx = pickle.load(loadfile)

    ## comprobamos si la transaccion es valida
    if newTx.is_valid():
        print("Sucess! Loaded newTx is valid")
    loadfile.close()

##############################################################

    ## Comencemos a crear bloques de transacciones

    #Creamos el primer bloque de transacciones,tiene un antecesor nulo, tx1 es hijo de root
    root = TxBlock(None)
    root.addTx(Tx1)

    # Creamos y agregamos la Transaccion 2 como hijo de root
    Tx2 = Tx()
    Tx2.add_input(pu2,1.1)
    Tx2.add_output(pu3, 1)
    Tx2.sign(pr2)
    root.addTx(Tx2)

    # Comenzamos a crear la cadena de bloques, el bloque root tiene una transaccion hija
    B1 = TxBlock(root)

    # Creamos Transaccion 3 y agregamos al bloque
    Tx3 = Tx()
    Tx3.add_input(pu3,1.1)
    Tx3.add_output(pu1, 1)
    Tx3.sign(pr3)
    B1.addTx(Tx3)
    
    #Creamos una transaccon de custodia y la agregamos al bloque
    Tx4 = Tx()
    Tx4.add_input(pu1,1)
    Tx4.add_output(pu2, 1)
    Tx4.add_reqd(pu3)
    Tx4.sign(pr1)
    Tx4.sign(pr3)
    B1.addTx(Tx4)

    ###################### BUSCANDO NONCE PARA B1 ################################
    start = time.time()
    print(B1.find_nonce())

    # tiempo que tarda "minando"
    elapsed = time.time() - start
    print("elapsed time: " + str(elapsed) + " s.")
    
    if elapsed < 60:
        print("ERROR! Mining is too fast")
    if B1.good_nonce():
        print("Success! Nonce is good!")
    else:
        print("ERROR! Bad nonce")

    ################################################################################


    #Abramos un archivo para guardar el bloque
    savefile = open("block.dat", "wb")
    pickle.dump(B1, savefile)
    savefile.close()

    #como prueba de la integridad de los datos, leeremos del mismo archivo el bloque
    loadfile = open("block.dat" ,"rb")
    load_B1 = pickle.load(loadfile)

    #Imprime los objetos transaccion
    #print(bytes(str(load_B1.data),"utf-8"))

    #comprobemos si el bloque antes de guardar y luego de guardar son validos.
    for b,name in [(root,'root'), (B1,'B1'), (load_B1,'load_B1'), (load_B1.previousBlock,'load_B1.previousBlock')]:
        if b.is_valid():
            print("Success! "+name+" Valid Block")
        else:
            print("ERROR! "+name+" Bad block")


    if B1.good_nonce():
        print("Success! Nonce is good after save and load!")
    else:
        print("ERROR! Bad nonce after load")


    ## Crearemos un bloque que contenga una transaccion erronea donde el usuario 1
    ## quiera obtener más monedas de las que puede obtener por su recompensa
    ## B2 es hijo de B1
    B2 = TxBlock(B1)

    Tx5 = Tx()
    Tx5.add_input(pu3, 1)
    Tx5.add_output(pu1, 100)
    Tx5.sign(pr3)
    B2.addTx(Tx5)

    # vamos a modificar el bloque B1, agregando una repeticion de la transaccion Tx4
    # a pesar de que es una copia exacta de Tx4, el hash es distinto y no coincide
    load_B1.previousBlock.addTx(Tx4)

    #ambos bloques deberian ser invalidos... B1 porque se modificó, y B2 porque
    #contiene una transaccion erronea
    for b in [B2, load_B1]:
        if b.is_valid():
            print ("ERROR! Bad block verified.")
        else:
            print ("Success! Bad blocks detected")  
    
  

    


    ################# Pruebas con recompensa para mineros ################    

    #vamos a agregar a un usuario más
    pr4, pu4 = generate_keys()

    #agregamos un bloque, y añadimos las transacciones validas anteriores
    B3 = TxBlock(B2)
    B3.addTx(Tx2)
    B3.addTx(Tx3)
    B3.addTx(Tx4)
    # añadimos una nueva transaccion, el minero quiere hacer na transaccion para
    # retirar su recompensa con 25 coins, la coloca en la lista de salida
    Tx6 = Tx()
    Tx6.add_output(pu4,25)
    B3.addTx(Tx6)

    #verificamos si es valida
    if B3.is_valid():
        print ("Success! Block reward succeeds")
    else:
        print("ERROR! Block reward fail")

   
    #Nuevo bloque hijo de B3 con transacciones validas
    B4 = TxBlock(B3)
    B4.addTx(Tx2)
    B4.addTx(Tx3)
    B4.addTx(Tx4)

    #nueva transaccion del minero, quiere retirar 25.2 coins
    # se coloca en la lista de salida y se agrega al bloque
    Tx7 = Tx()
    Tx7.add_output(pu4,25.2)
    B4.addTx(Tx7)

    #se comprueba si el bloque es valido
    if B4.is_valid():
        print ("Success! Tx fees succeeds")
    else:
        print("ERROR! Tx fees fail")

   
    #Nuevo bloque de minero codiciosa
    #Greedy miner
    B5 = TxBlock(B4)
    B5.addTx(Tx2)
    B5.addTx(Tx3)
    B5.addTx(Tx4)

    #nueva transaccion, el minero quiere retirar una moneda más
    Tx8 = Tx()
    Tx8.add_output(pu4,26.2)
    B5.addTx(Tx8)
    if not B5.is_valid():
        print ("Success! Greedy miner detected")
    else:
        print("ERROR! Greedy miner not detected")       
    

    
    
"""

TEORIA:::

¿PORQUE ESTA CLASE?

Podríamos haber utilizado la clase CBlock y haber seguido poniendo Tx's como datos. 

La clase TxBlock es agradable porque usamos convenientemente agregar (y, más tarde, eliminar) 
Tx's e imponer algunos requisitos para nuestro cryptocoin. 

Por ejemplo, un poco más tarde, vamos a requerir que cada bloque cree no más de 25 monedas. 
Eso significa recorrer la lista de transacciones y sumar el total de monedas dentro y fuera, 
luego asegurarse de que las entradas + 25 <= salidas. Es más fácil hacerlo en una clase especializada.

Tenga en cuenta, por supuesto, que TxBlock "hereda" de CBlock, 
lo que significa que mantiene toda la funcionalidad de CBlock, luego agrega algunas funciones especializadas para un TxBlock.

"""