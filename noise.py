import pynacl as nacl

class Party(staticKey = None, ephemeralKey= None, remoteStaticKey = None, remoteEphemeralKey = None, handshakeHash : str, chainingKey : str, encryptionKey = None, nonce : int): 
    def __init__(self):
        self.staticKey = staticKey
        self.emphemeralKey = emphemeralKey
        self.remoteStaticKey = remoteStaticKey
        self.remoteEphemeralKey = remoteEphemeralKey
        self.handshakeHash = handshakeHash
        self.chainingKey = chainingKey
        self.encryptionKey = encryptionKey
        self.nonce = nonce

class Message(payload):
    def __init__(self):
        if payload < 65535:
            self.payload = payload
        else:
            Exception("payload too large. Expected 65535 bytes")
        self.ad = None

class HandshakeMessage(payload):
    def __init__(self):
        self.public_keys = None
        self.payload = payload

class DiffieHellman():
    DHLEN = 0
    def generate_keypair():
        keypair = b""
        return keypair
    def diffie_hellman(key_pair, public_key):
        output = b""
        return output

class Cipher():
    def encrypt(encryptionKey, nonce, authenticationData, plainText):
        cipherText = b""
        return cipherText
    def decrypt(encryptionKey, nonce, authenticationData, cipherText):
        plainText = ""
        return plainText

class Hash():
    HASHLEN = 0
    BLOCKLEN = 0
    def hash(data):
        output = b""
        return output
    def hmac_hash(key, data):
        output = b""
        return output
    def hkdf(chainingKey, inputKeyMaterial):
        tempKey = hmac_hash(chainingKey, inputMaterial)
        output1 = hmac_hash(tempKey, byte(0x01))
        output2 = hmac_hash(tempKey, output1 + byte(0x02))
        return (output1, output2)

class CipherState(encryptionKey = None, nonce):
    def __init__(self):
        self.encryptionKey = encryptionKey
        self.nonce = nonce
        self.cipher = Cipher()

    def initializeKey(key):
        self.encryptionKey = key
        self.nonce = 0

    def hasKey():
        if self.encryptionKey is not None:
            return True
        else:
            return False

    def encryptWithAd(authenticationData, plainText):
        if self.hasKey():
            return self.cipher.encrypt(self.encryptionKey, self.nonce, authenticationData, plainText)
        else:
            return plainText

    def decryptWithAd(authenticationData, cipherText):
        if self.hasKey():
            plainText = self.cipher.decrypt(self.encryptionKey, self.nonce, authenticationData, cipherText)
            self.nonce += 1
            return plainText
        else:
            return cipherText

def SymmetricState(chainingKey, handshakeHash):
    def __init__(self):
        self.chainingKey = chainingKey
        self.handshakeHash = handshakeHash
        self.cipherState = CipherState(None, 0)

    def initializeSymmetric(protocolName):
        self.handshakeHash = Hash().hash(protocol_name)
        self.chainingKey = self.handshakeHash
        self.cipherState = CipherState.initializeKey(None)

    def mixKey(input_key_material):
        self.chainingKey, tempKey = Hash().hkdf(self.chainingKey, input_key_material)
        if Hash().HASHLEN == 64:
            tempKey = tempKey[:32]
        self.cipherState = CipherState.initializeKey(tempKey)

    def mixHash(data):
        self.handshakeHash = Hash().hash(self.handshakeHash + data)

    def encryptAndHash(plainText):
        cipherText = self.cipherState.encryptWithAd(self.handshakeHash, plainText)
        mixHash(cipherText)
        return cipherText

    def decryptAndHash(cipherText):
        plainText = self.cipherState.decryptWithAd(authenticationData, cipherText):
        mixHash(cipherText)
        return plainText

    def split():
        tempKey1, tempKey2 = Hash().hkdf(self.chainingKey, zerolen)
        if Hash().HASHLEN == 64:
            tempKey1 = tempKey1[:32]
            tempKey2 = tempKey2[:32]
        c1, c2 = CipherState(), CipherState()
        c1.initializeKey(tempKey1)
        c2.initializeKey(tempKey2)
        return c1, c2

def
