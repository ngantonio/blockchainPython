#Transaction.py
"""
    El siguiente codigo modela una Transaccion de Blockchain, una transaccion es una forma de
    enviar monedas a otro usuario.
    * Una moneda se envia, utilizando la Clave publica del usuario que quiere enviarla (Usuario A), esa clave
    es su direccion, a continuancion, la clave se coloca en una lista de entrada junto al monto que se quiere enviar.
    * El usuario que quiere recibir la moneda (usuario B), debe colocar su clave publica en una lista de salida, junto al
    monto que quiere retirar.
    * Para que una transaccion sea valida, debe estar firmada digitalmente por el usuario A o el conjunto de usuarios que
    inicien la transaccion, la firma digital se realiza con la clave privada del Usuario A.
    * En ocasiones una transaccion necesita la ayuda de un tercero, tal que este debe validar que ambas partes cumplan.
    se conoce como transacciones multi-firma. El tercero firma la transaccion con su clave privada
"""

import Signatures


#Clase que modela una transaccion
class Tx:

    #Lista de direcciones de entrada
    inputs = None
    #Lista de direcciones de salida
    outputs =None
    #Lista de firmas
    sigs = None
    #Lista de firmas que no son entradas (transacciones custodiadas por terceros)
    reqd = None

    #Constructor
    def __init__(self):
        # es más preciso que estas tres sean una lista de tuplas...
        # la tupla será, la direccion de la persona que hara la transaccion y el monto
        self.inputs = []
        self.outputs = []
        self.sigs = []
        self.reqd = []

    # Encargada de añadir una entrada adicional a la lista,
    # requiere la direccion origen y la cantidad
    def add_input(self, from_addr, amount):
        self.inputs.append((from_addr, amount))

    # Encargada de añadir una direccion de salida a la lista,
    # requiere la direccion destino y la cantidad
    def add_output(self, to_addr, amount):
        self.outputs.append((to_addr, amount))

    # Encargada de añadir una direccion de custodia a la lista
    def add_reqd(self, addr):
        self.reqd.append(addr)

    # Encargada de Firmar (aprobar) una transaccion, aqui comprobamos si
    # la clave privada enviada es valida
    def sign(self, private):
        message = self.__gather()
        newsig = Signatures.sign(message, private)
        self.sigs.append(newsig) 

    # Encargada de comprobar si un transaccion actual es valida o no
    # si es valida, se preocesa
    def is_valid(self):
        total_in = 0
        total_out = 0
        message = self.__gather()

        # debemos verificar que todas las entradas en la lista de entrada sean correctas
        # que todas las personas en la lista de inputs, hayan firmado y la firma sea valida

        for address,amount in self.inputs:
            found = False
            # recorremos la lista de firmas
            for sign in self.sigs:
                #para comprobar si la firma es valida, Enviamos el mensaje, la firma y la direccion (llave publica)
                if Signatures.verify(message, sign, address) :
                    found = True

            #si revisamos todas las firmas de una dirección en particular y no la encontramos, eso es falso.
            if not found:
                return False
            if amount < 0:
                return False

            # acumulamos el total de las monedas que seran enviadas
            total_in = total_in + amount

        
        # Ahora debemos comprobar que las firmas de los arbitros (transacciones de garantia)
        # sean validas
        for addr in self.reqd:
            found = False
            for s in self.sigs:
                if Signatures.verify(message, s, addr) :
                    found = True
            if not found:
                return False

        # Comprueba si las cantidades en la lista de salidas son menores a 0
        # Una persona no puede retirar monedas si no existen
        for addr,amount in self.outputs:
            if amount < 0:
                return False
            total_out = total_out + amount

        return True

    # los datos necesarios para realizar la firma, son la recopilacion
    # de las 3 listas involucradas en una transaccion, asi que unimos las tres listas
    # en una sola
    def __gather(self):
        data=[]
        data.append(self.inputs)
        data.append(self.outputs)
        data.append(self.reqd)
        return data
    
    ## Encargada de representar las transacciones de forma legible
    def __repr__(self):
        reprstr = "\nINPUTS:\n"
        for addr, amt in self.inputs:
            reprstr = reprstr + str(amt) + " FROM " + str(addr) + "\n"
        reprstr = reprstr + "\nOUTPUTS:\n"
        for addr, amt in self.outputs:
            reprstr = reprstr + str(amt) + " TO " + str(addr) + "\n"
        reprstr = reprstr + "\nREQD:\n"
        for r in self.reqd:
            reprstr = reprstr + str(r) + "\n"
        reprstr = reprstr + "\nSIGS:\n"
        for s in self.sigs:
            reprstr = reprstr + str(s) + "\n"
        reprstr = reprstr + "END\n\n"
        return reprstr
     
        
####################### MAIN CODE ##################################


if __name__ == "__main__":

    # Creamos 4 pares de claves publicas y privadas para simular 4 usuarios
    pr1, pu1 = Signatures.generate_keys()
    pr2, pu2 = Signatures.generate_keys()
    pr3, pu3 = Signatures.generate_keys()
    pr4, pu4 = Signatures.generate_keys()

    #Creamos una transaccion simple para trabajar con el primer
    #par de claves
    Tx1 = Tx()

    """
        Queremos enviar una moneda a la persona de la clave2, 
        añadimos nuestra clave publica a la lista de entrada de transaccion
        y la clave publica de la persona de la clave 2 a la lista de salida...
        Posteriormente, firmamos la transaccion
    """
    Tx1.add_input(pu1, 1)
    Tx1.add_output(pu2, 1)
    Tx1.sign(pr1)


    ######### Transaccion 2 #########
    #Transaccion multiple, mas de una entrada y mas de una salida

    """
        Queremos enviar 2 monedas, las colocamos dos entradas
        en la lista con la misma direccion, las personas 2 y 3  desean retirar 1 y se colocan
        sus llaves publicas en la lista de salida..
        se firma la transaccion con nuestra llave privada (llave privada de 1)
    """

    Tx2 = Tx()
    Tx2.add_input(pu1, 2)
    Tx2.add_output(pu2, 1)
    Tx2.add_output(pu3, 1)
    Tx2.sign(pr1)

    ######### Transaccion 3, transaccion asistida o de garantia #########

    """
        La persona 3, coloca una moneda con valor de 1.2, la persona 1
        retira 1.1 (el 0.1 restante se la asigna a p4 como pago por el favor).
        -Entra p4 y coloca su llave publica en la lista de custodia
    """

    Tx3 = Tx()
    Tx3.add_input(pu3, 1.2)
    Tx3.add_output(pu1, 1.1)
    Tx3.add_reqd(pu4)
    # p3 y p4 Firman la transaccion con su llave privada
    Tx3.sign(pr3)
    Tx3.sign(pr4)


    # Comprobamos la validez de todas las transacciones
    for t,name in [(Tx1,'Tx1'),( Tx2,'Tx2'), (Tx3,'Tx3')]:
        if t.is_valid():
            print("Success! "+name+" Is Valid \n")
        else:
            print("ERROR! "+name+" Is invalid \n")


    ######### Transaccion 4, intentando firmar con llave equivocada #########

    """     
        Digamos que el número dos lo firmará y se enviará las monedas a sí mismo.
        Nuestro malvado usuario número dos dirá: oh, sí, el usuario 1 definitivamente me enviará una moneda.
        pero será su firma por lo que debería ser inválida desde nuestra perspectiva.
    """
    # Wrong signatures, la persona 2 quiere intentar firmar
    Tx4 = Tx()
    Tx4.add_input(pu1, 1)
    Tx4.add_output(pu2, 1)
    Tx4.sign(pr2)

    ######### Transaccion 5, transaccion en custodia no firmada por el arbitro #########

    """     
        No valido porque no ha sido firmado por todas las partes requeridas
    """
    # Escrow Tx not signed by the arbiter
    Tx5 = Tx()
    Tx5.add_input(pu3, 1.2)
    Tx5.add_output(pu1, 1.1)
    Tx5.add_reqd(pu4)
    Tx5.sign(pr3)

    ######### Transaccion 6, Dos direcciones de entrada, pero solo una de ellas firma #########

    """     
        Todas las personas involucradas en una transaccion de entrada (direcciones diferentes) deben firmar
    """
    # Two input addrs, signed by one
    Tx6 = Tx()
    Tx6.add_input(pu3, 1)
    Tx6.add_input(pu4, 0.1)
    Tx6.add_output(pu1, 1.1)
    Tx6.sign(pr3)

    ######### Transaccion 7, transaccion donde la cantidad de salida excede la entrada #########

    """     
        El usuario 4 solo ha colocado 1.2, se está intentandoo retirar 3, aunque el usuario 4
        firme la transaccion, es invalida
    """
    # Outputs exceed inputs
    Tx7 = Tx()
    Tx7.add_input(pu4, 1.2)
    Tx7.add_output(pu1, 1)
    Tx7.add_output(pu2, 2)
    Tx7.sign(pr4)

    ######### Transaccion 8, transaccion con valores negativos #########

    # Negative values
    Tx8 = Tx()
    Tx8.add_input(pu2, -1)
    Tx8.add_output(pu1, -1)
    Tx8.sign(pr2)

    ######### Transaccion 9, transaccion manipulada #########

    """     
        una vez que esto haya sido firmado, lo cambiaremos para enviar la moneda a pu3 en lugar de pu2, 
        nos referiremos al primer elemento de esa tupla que vamos a reemplazar con pu3.
        Esto es una cosa desagradable de pu3 que hacer. Así que vamos a ver si Tx9 se detecta con éxito.
    """
    # Modified Tx
    Tx9 = Tx()
    Tx9.add_input(pu1, 1)
    Tx9.add_output(pu2, 1)
    Tx9.sign(pr1)
    # outputs = [(pu2,1)]
    # change to [(pu3,1)]
    Tx9.outputs[0] = (pu3,1)    #reemplazamos la tupla de la lista
    
  

    #Comprobanmdo la invalidez
    print("Invalidez... \n")
    for t, name in [(Tx4,'Tx4'), (Tx5,'Tx5'), (Tx6,'Tx6'), (Tx7,'Tx7'), (Tx8,'Tx8'), (Tx9,'Tx9')]:
        if t.is_valid():
            print("ERROR! Bad "+name+" Is Valid \n")
        else:
            print("Success! Bad "+name+" is invalid\n")
