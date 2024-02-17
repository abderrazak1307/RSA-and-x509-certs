import argparse
from CertificationAuthority import CertificationAuthority
from RSA import RSA

custom_formatter = lambda prog: argparse.HelpFormatter(prog, max_help_position=40)

# create the top-level parser
parser = argparse.ArgumentParser(prog='myRSA', formatter_class=custom_formatter)
subparsers = parser.add_subparsers(title="actions", help='description', metavar="action", dest="action", required=True)

# create the parser for the "genKey" command
parser_genKey = subparsers.add_parser('genKey', help='generate an RSA keypair', formatter_class=custom_formatter)
parser_genKey.add_argument('-b', '--bits', default=2048, help='number of bits') # if specified, generate n bits key, default 2048
parser_genKey.add_argument('-s', '--secret', required=True, help='secret key save path') # save private key to this path
parser_genKey.add_argument('-p', '--public', required=True, help='public key save path') # save public key to this path

# create the parser for the "genCert" command
parser_genCert = subparsers.add_parser('genCert', help='generate an X.509 cert', formatter_class=custom_formatter)
parser_genCert.add_argument('-s', '--secret', required=True, help='secret key load path') # if specified, use this key
parser_genCert.add_argument('-c', '--cert', required=True, help='certificate save path')

# create the parser for the "validateCert" command
parser_validateCert = subparsers.add_parser('chkCert', help='check if an X.509 cert is valid', formatter_class=custom_formatter)
parser_validateCert.add_argument('-c', '--cert', required=True, help='certificate load path')

# create the parser for the "encFile" command
parser_encFile = subparsers.add_parser('encFile', help='encrypt a file using RSA', formatter_class=custom_formatter)
parser_encFile.add_argument('-p', '--public', required=True,  help='secret key path')
parser_encFile.add_argument('-i', '--src', required=True, help='src file path')
parser_encFile.add_argument('-o', '--dest', required=True,  help='dest file path')

# create the parser for the "decFile" command
parser_decFile = subparsers.add_parser('decFile', help='decrypt a file using RSA', formatter_class=custom_formatter)
parser_decFile.add_argument('-s', '--secret', help='secret key path')
parser_decFile.add_argument('-i', '--src', help='src file path')
parser_decFile.add_argument('-o', '--dest', help='dest file path')

args = vars(parser.parse_args())

# Treat different actions
if(args['action'] == "genKey"):
    print("Generating RSA KeyPair...")
    RSA_Cryptosystem = RSA()
    RSA_Cryptosystem.generate_keys(int(args['bits']))
    if(args['public']):
        RSA_Cryptosystem.save_publicKey(args['public'])
    if(args['secret']):
        RSA_Cryptosystem.save_privateKey(args['secret'])
    print("[+] Done")

elif(args['action'] == "genCert"):
    print("Generating X.509 Certificate...")
    RSA_Cryptosystem = RSA()
    CA = CertificationAuthority("SSI 22/23 USTHB", "Groupe#1 SSI", "Boulevard 5", "Babezzouar", "Algiers", "DZ")
    subject = {}
    subject['CA_CommonName'] = input("Common Name (Default: John Doe): ") or 'John Doe'
    subject['CA_OrganizationName'] = input("Organization Name (Default: -): ") or '-'
    subject['CA_StreetAddress'] = input("Street Address (Default: 32 BP EL ALIA): ") or '32 BP EL ALIA'
    subject['CA_Locality'] = input("Locality (Default: Bab Ezzouar): ") or 'Bab Ezzouar'
    subject['CA_State'] = input("State (Default: Algiers): ") or 'Algiers'
    subject['CA_CountryName'] = input("Country Code, 2 Letters (Default: DZ): ") or 'DZ'
    CA.generateCertificate(certificate_filePath=args['cert'], privateKey_filePath=args['secret'], cert_info=subject)
    print("[+] Done")

elif(args['action'] == "chkCert"):
    print("Checking if X.509 Certificate is valid...")
    validity = CertificationAuthority.verifyCertificate(certificate_filePath=args['cert'])
    if validity:
        print("[+] Certificate is valid")
    else:
        print("[-] Certificate is not valid")

elif(args['action'] == "encFile"):
    print("Encrypting file using RSA")
    RSA_Cryptosystem = RSA()
    RSA_Cryptosystem.load_publicKey(args['public'])
    f = open(args['src'], "rb")
    original = f.read()
    encrypted = RSA_Cryptosystem.encrypt(original)
    f.close()

    f2 = open(args['dest'], "wb")
    f2.write(encrypted)
    f2.close()
    print(f"[+] Done Encrypting '{args['src']}' into '{args['dest']}'")

elif(args['action'] == "decFile"):
    print("Decrypting file using RSA")
    RSA_Cryptosystem = RSA()
    RSA_Cryptosystem.load_privateKey(args['secret'])
    f = open(args['src'], "rb")
    original = f.read()
    decrypted = RSA_Cryptosystem.decrypt(original)
    f.close()

    f2 = open(args['dest'], "wb")
    f2.write(decrypted)
    f2.close()
    print(f"[+] Done Decrypting '{args['src']}' into '{args['dest']}'")
