from datetime import datetime
import random
from RSA import RSA
import asn1tools
import base64

PKCS1_ENCODER = asn1tools.compile_files('specifications/pkcs1.asn', 'ber')
X509_ENCODER = asn1tools.compile_files('specifications/rfc5280.asn', 'der')

class CertificationAuthority:
    def __init__(self, CA_CommonName, CA_OrganizationName, CA_StreetAddress, CA_Locality, CA_State, CA_CountryName):
        self.CA_CommonName = CA_CommonName
        self.CA_OrganizationName = CA_OrganizationName
        self.CA_StreetAddress = CA_StreetAddress
        self.CA_Locality = CA_Locality
        self.CA_State = CA_State
        self.CA_CountryName = CA_CountryName

    def generateCertificate(self, certificate_filePath, privateKey_filePath, cert_info):
        # Generate Public-Private Key-Pair
        RSA_Cryptosystem = RSA()
        RSA_Cryptosystem.generate_keys(2048)
        RSA_Cryptosystem.save_privateKey(privateKey_filePath)
        public_key = RSA_Cryptosystem.getPublicKeyPKCS1()

        # Generate CertificateTBS
        issuer = (
            'rdnSequence', [
                [{'type':'2.5.4.3',  'value': self.CA_CommonName}],
                [{'type':'2.5.4.10', 'value': self.CA_OrganizationName}],
                [{'type':'2.5.4.9',  'value': self.CA_StreetAddress}],
                [{'type':'2.5.4.7',  'value': self.CA_Locality}],
                [{'type':'2.5.4.8',  'value': self.CA_State}],
                [{'type':'2.5.4.6',  'value': self.CA_CountryName}]
            ]
        )
        subject = (
            'rdnSequence', [
                [{'type':'2.5.4.3', 'value': cert_info['CA_CommonName']}],
                [{'type':'2.5.4.10','value': cert_info['CA_OrganizationName']}],
                [{'type':'2.5.4.9', 'value': cert_info['CA_StreetAddress']}],
                [{'type':'2.5.4.7', 'value': cert_info['CA_Locality']}],
                [{'type':'2.5.4.8', 'value': cert_info['CA_State']}],
                [{'type':'2.5.4.6', 'value': cert_info['CA_CountryName']}]
            ]
        )
        tbsCertificate = {
            'version' : 2,
            'serialNumber' : random.randrange(2**127, 2**128-1),
            'signature' : {'algorithm': "1.2.840.113549.1.1.11", 'parameters': None},
            'issuer' : issuer,
            'validity' : {
                'notBefore' : ('utcTime', datetime.today()),
                'notAfter' : ('utcTime', datetime.today().replace(year = datetime.today().year+1))
            } ,
            'subject' : subject,
            'subjectPublicKeyInfo' : {
                'algorithm' : {'algorithm': '1.2.840.113549.1.1.1', 'parameters': None},
                'subjectPublicKey': (public_key, 8*len(public_key))
            }
        }
        certificate_tbs_DER = X509_ENCODER.encode("TBSCertificate", tbsCertificate) # DER encoding of certificat_tbs
        signature = RSA_Cryptosystem.sign(certificate_tbs_DER)

        # Sign Certificat TBS (use sign)
        certificate = {'tbsCertificate' : tbsCertificate} # create certificate containing tbsCertificate
        certificate['signatureAlgorithm'] = {'algorithm': "1.2.840.113549.1.1.11", 'parameters': None} # add signature algorithm
        certificate['signature'] = (signature, len(signature) * 8) # add signature

        # Obj -> ASN1, DER
        certificate_der = X509_ENCODER.encode("Certificate", certificate) # DER encoding of certificate

        # DER (ASN1) -> Base64
        certificate_base64 = base64.b64encode(certificate_der).decode('utf-8')
        certificate_base64 = [certificate_base64[i:i+64] for i in range(0, len(certificate_base64), 64)]
        certificate_base64 = "\n".join(certificate_base64)

        # Write to File
        f = open(certificate_filePath,'w')
        f.write('-----BEGIN CERTIFICATE-----\n')
        f.write(certificate_base64+'\n')
        f.write('-----END CERTIFICATE-----')
        f.close()
    
    @staticmethod
    def verifyCertificate(certificate_filePath):
        # Decode certificate and get
        f= open(certificate_filePath, "rb")
        certificate_base64 = b"".join(f.read().splitlines()[1:-1])
        f.close()
        certificate = base64.b64decode(certificate_base64)
        certificate = X509_ENCODER.decode("Certificate", certificate)

        # Get certificate_tbs and signature
        certificate_tbs = X509_ENCODER.encode("TBSCertificate", certificate['tbsCertificate'])
        signature = (certificate['signature'])[0]

        # Extract public key from certificate
        public_key_ber = (((certificate['tbsCertificate'])['subjectPublicKeyInfo'])['subjectPublicKey'])[0]
        public_key = PKCS1_ENCODER.decode('RSAPublicKey', public_key_ber)
        RSA_Cryptosystem = RSA()
        RSA_Cryptosystem.setPublicKey(public_key['modulus'], public_key['publicExponent'])

        return RSA_Cryptosystem.verifySignature(certificate_tbs, signature)
        
