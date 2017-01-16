import pynacl as nacl
from enum import Enum


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

class DiffieHellman:
    def __init__(self, DHLEN = 64):
        DHLEN = DHLEN

    @staticmethod
    def generate_keypair():
        public_key = b""
        private_key = b""
        keypair = public_key, private_key
        return keypair

    @staticmethod
    def diffie_hellman(key_pair, public_key):
        output = b""
        return output

class Cipher:

    @staticmethod
    def encrypt(encryptionKey, nonce, authenticationData, plainText):
        cipherText = b""
        return cipherText

    @staticmethod
    def decrypt(encryptionKey, nonce, authenticationData, cipherText):
        plainText = ""
        return plainText

class Hash:
    HASHLEN = 0
    BLOCKLEN = 0

    @staticmethod
    def hash(data):
        output = b""
        return output

    @staticmethod
    def hmac_hash(key, data):
        output = b""
        return output

    @staticmethod
    def hkdf(chainingKey, inputKeyMaterial):
        tempKey = hmac_hash(chainingKey, inputMaterial)
        output1 = hmac_hash(tempKey, byte(0x01))
        output2 = hmac_hash(tempKey, output1 + byte(0x02))
        return (output1, output2)

class CipherState():
    def __init__(self,encryptionKey = None, nonce):
        self.encryptionKey = encryptionKey
        self.nonce = nonce
        self.cipher = Cipher

    def initializeKey(self,key):
        self.encryptionKey = key
        self.nonce = 0

    def hasKey():
        if self.encryptionKey is not None:
            return True
        else:
            return False

    def encryptWithAd(self,authenticationData, plainText):
        if self.hasKey():
            return self.cipher.encrypt(self.encryptionKey, self.nonce, authenticationData, plainText)
        else:
            return plainText

    def decryptWithAd(self,authenticationData, cipherText):
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

    def initializeSymmetric(self,protocolName):
        self.handshakeHash = Hash().hash(protocol_name)
        self.chainingKey = self.handshakeHash
        self.cipherState = CipherState.initializeKey(None)

    def mixKey(self,input_key_material):
        self.chainingKey, tempKey = Hash().hkdf(self.chainingKey, input_key_material)
        if Hash().HASHLEN == 64:
            tempKey = tempKey[:32]
        self.cipherState = CipherState.initializeKey(tempKey)

    def mixHash(self,data):
        self.handshakeHash = Hash().hash(self.handshakeHash + data)

    def encryptAndHash(self,plainText):
        cipherText = self.cipherState.encryptWithAd(self.handshakeHash, plainText)
        mixHash(cipherText)
        return cipherText

    def decryptAndHash(self,cipherText):
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

def HandshakeState():

    def __init__(self,localStaticKey = None, localEmphemeralKey = None, remoteStaticKey = None, remoteEmpheralKey = None):
        self.localStaticKey = localStaticKey
        self.localEmphemeralKey = localEmphemeralKey
        self.remoteStaticKey = remoteStaticKey
        self.remoteEphemeralKey = remoteEphemeralKey
        self.initiator = False
        self.message_patterns = []
        protocol_name = generate_protocol_name(self.message_patterns)
        self.SymmetricState = SymmetricState().initializeSymmetric(protocol_name)

    def initialize(handshakePattern, initiator, prologue, localStaticKey, localEmphemeralKey, remoteStaticKey, remoteEphemeralKey):
        protocol_name = generate_protocol_name(self.handshakePattern)
        self.SymmetricState = SymmetricState().initializeSymmetric(protocol_name)
        self.SymmetricState.mixHash(self.prologue)
        self.message_patterns = handshakePattern
        self.initiator = initiator
        self.prologue = prologue
        self.localStaticKey = localStaticKey
        self.localEmphemeralKey = localEmphemeralKey
        self.remoteStaticKey = remoteStaticKey
        self.remoteEphemeralKey = remoteEphemeralKey

    def writeMessage(self, payload, message_buffer):
        for pattern in self.message_patterns:
            if pattern == 'e':
                self.localEmphemeralKey = DiffieHellman().generate_keypair()
                message_buffer.write(self.localEmphemeralKey)
                self.SymmetricState.mixHash(self.localEmphemeralKey)
            elif pattern == 's':
                eh = self.SymmetricState.encryptAndHash(self.localStaticKey)
                message_buffer.write()
            elif pattern == 'xy':
                if initiator:
                    dh = diffie_hellman(localStaticKey, remoteEphemeralKey)
                else:
                    dh = diffie_hellman(localEmphemeralKey, remoteStaticKey)
                self.SymmetricState.mixKey(dh)
        message_buffer.write(encryptAndHash(payload))
        return self.SymmetricState.split()

    def readMessage(self, message, payload_buffer):
        chunks = range(0, len(message), Hash.DHLEN)
        idx = 0
        for pattern in self.message_patterns:
            if pattern == 'e':
                re = message[chunks[idx]:chunks[idx+1]]
                self.SymmetricState.mixHash(re)
                idx += 1
            elif pattern == 's':
                if self.SymmetricState.CipherState.hasKey():
                    temp = message[chunks[idx]:chunks[idx+1] + 16]
                else:
                    temp = message[chunks[idx]:chunks[idx+1]]
                rs = self.SymmetricState.decryptAndHash(temp)
                idx += 1
            elif pattern == 'xy':
                if initiator:
                    dh = diffie_hellman(localStaticKey, remoteEphemeralKey)
                else:
                    dh = diffie_hellman(localEmphemeralKey, remoteStaticKey)
                self.SymmetricState.mixKey(dh)
        payload_buffer.write(self.SymmetricState.decryptAndHash(message[chunks[idx]:]))
        return self.SymmetericState.split()

class MessagePatterns(Enum):
    e = "e"
    s = "s"
    ee = "ee"
    es = "es"
    se = "se"
    ss = "ss"

class PreMessagePatterns(Enum):
    e = "e"
    s = "s"
    es = "e, s"
    Empty = None

InitatorPreMessagePatterns = PreMessagePatterns
ResponderPreMessagePatterns = PreMessagePatterns

HandShakePatterns = (InitatorPreMessagePatterns, ResponderPreMessagePatterns, ListOfMessagePatterns)
