"""
* Implementar un programa para cifrar y descifrar archivos de cualquier taman~o (hay un límite de 64GB) mediante AES-GCM

// El profesor hará la parte de cifrado, tu trabajo consiste en hacer el descifrado (en el código compartido)

// El programa recibe un password (para la derivación de llave), la ruta del archivo de entrada, la ruta del archivo de salida y la operación que se desea ejecutar (cifrar o descifrar)
"""
from xml.etree.ElementInclude import default_loader
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
import argparse
import getpass
import sys
import os


def generar_llave(salt: bytes, password: str):
    password = password.encode("utf-8")
    KDF = Scrypt(salt=salt, length=32,
                 n=2**14, r=8, p=1,
                 backend=default_backend())
    return KDF.derive(password)


def cifrar(path_entrada, path_salida, password):
    # // Generar salt
    salt = os.urandom(16)
    iv = os.urandom(12)
    llave_aes = generar_llave(salt, password)
    datos_adicionales = iv + salt
    encryptor = Cipher(algorithms.AES(llave_aes),
                       modes.GCM(iv),
                       backend=default_backend()).encryptor()
    # // Comprobación de datos adicionales IV y SALT
    encryptor.authenticate_additional_data(datos_adicionales)
    # //Iterando en el archivo
    salida_archivo = open(path_salida, "wb")
    for buffer in open(path_entrada, "rb"):
        datos_cifrados = encryptor.update(buffer)
        salida_archivo.write(datos_cifrados)
    encryptor.finalize()
    tag = encryptor.tag
    print("IV", iv, "\n")
    print("SALT", salt, "\n")
    print("TAG", tag, "\n")
    print("Llave AES", llave_aes, "\n")
    # //Añadiendo datos de comprobación
    salida_archivo.write(iv+salt+tag)  # * 12,16,16 bytes
    salida_archivo.close()


def descifrar(path_entrada, path_salida, password):
    with open(path_entrada, "rb") as datos_cifrados:
        datos = datos_cifrados.read()
        datos_importantes = datos[-44:]
        iv = datos_importantes[:12]
        salt = datos_importantes[12:28]
        tag = datos_importantes[28:]
        llave_aes = generar_llave(salt, password)
    print("IV", iv, "\n")
    print("SALT", salt, "\n")
    print("TAG", tag, "\n")
    print("Llave AES", llave_aes, "\n")
    datos_importantes = iv + salt
    decryptor = Cipher(algorithms.AES(llave_aes),
                       modes.GCM(iv, tag),
                       backend=default_backend()).decryptor()
    decryptor.authenticate_additional_data(datos_importantes)
    salida_archivo = open(path_salida, "wb")
    for datos_cifrados in open(path_entrada, "rb"):
        datos_descifrados = decryptor.update(datos_cifrados)
        salida_archivo.write(datos_descifrados)
    salida_archivo.close()
    try:
        decryptor.finalize_with_tag
        print('Pasó la verificación de tag, todo OK')
    except:
        print('No pasó la verificación de tag, integridad comprometida')


if __name__ == '__main__':
    all_args = argparse.ArgumentParser()
    all_args.add_argument("-p",
                          "--Operacion",
                          help="Aplicar operación,cifrar/descifrar")
    all_args.add_argument("-i",
                          "--input",
                          help="Archivo de entrada",
                          required=True)
    all_args.add_argument("-o",
                          "--output",
                          help="Archivo de salida",
                          required=True)
    args = vars(all_args.parse_args())
    operacion = args['Operacion']
    # // Obtener contraseña
    password = getpass.getpass(prompt='Password> ')

    if operacion == "cifrar":
        cifrar(args['input'], args['output'], password)
    elif operacion == 'descifrar':
        descifrar(args['input'], args['output'], password)
    else:
        print("Error")
        exit(1)
"""
* Ejecución
python3 AES_GSM.py -p cifrar -i aes-gcm.org -o aes-gcm.org_cif
python3 AES_GSM.py -p descifrar -i aes-gcm.org_cif -o aes_prueba.org
"""
