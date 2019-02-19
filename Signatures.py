#Signatures.py

"""
    El siguiente codigo modela una Firma digital...
    Las firms digitales son escenciales para comprobar si un bloque o una transaccion es valida
    Se utilizan distinatas librerias de Criptography apara obtener la serializacion, los hashes
    y los distintos algoritmos de encriptado
"""
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

# Es la encargada de generar un par de llaves publicas y privadas
def generate_keys():
    private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )    
    #se genera la clave publica a partir de la privada
    public = private.public_key()

    # serializamos la clave publica, es nercesario serializar con RSA para que no este en formato hexadecimal...
    # y pase a bytes, retornamos esa clave serializada
    pu_ser = public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )    
    return private, pu_ser

# Es la encargada de firmar digitalmente (encriptar) datos dada una clave privada
def sign(message, private):
    message = bytes(str(message), 'utf-8')
    sig = private.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return sig

# Es la encargada de verificar si los datos enviados no han sido alterados, dada una firma
# y una clave publica, la clave publica debe ser de la misma persona que los encripto
def verify(message, sig, pu_ser):

	# para verificar la firma, debemos enviar la clave publica serializada
	# y en estas lineas la deserializamos, convertimos de nuevo a bytes
    public = serialization.load_pem_public_key(
        pu_ser,
        backend=default_backend()
    )
    
    message = bytes(str(message), 'utf-8')
    try:
        public.verify(
            sig,
            message,
            padding.PSS(
              mgf=padding.MGF1(hashes.SHA256()),
              salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except:
        print("Error executing public_key.verify")
        return False
    

################## BLOQUE MAIN ############################

if __name__ == '__main__':

    #generamos un par de claves
    pr,pu = generate_keys()

    print(pr)
    print(pu)

    #Generamos un mensaje
    message = "This is a secret message"

    #Firmamos el mensaje con nuestra clave privada
    sig = sign(message, pr)
    print(sig)

    #Verificamos si el mensage es verdadero
    correct = verify(message, sig, pu)
    print(correct)

    if correct:
        print("Success! Good sig")
    else:
        print ("ERROR! Signature is bad")

    # Hacemos el paso anterior pero verificando el mensaje con la primera clave publica
    
    pr2, pu2 = generate_keys()
    sig2 = sign(message, pr2)
    correct= verify(message, sig2, pu)

    if correct:
        print("ERROR! Bad signature checks out!")
    else:
        print("Success! Bad sig detected")

   # Intentamos cambiar el mensaje

    badmess = message + "Q"
    correct= verify(badmess, sig, pu)
    if correct:
        print("ERROR! Tampered message checks out!")
    else:
        print("Success! Tampering detected")