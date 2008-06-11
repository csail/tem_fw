package edu.mit.csail.tc;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/**
 * TEM cryptographic engine.
 * @author Victor Costan
 * 
 * The TEM cryptographic engine exposes a uniform interface on top of the
 * cryptographic accelerator inside the TEM implementation. Its duties include
 * generating, using, and importing/exporting cryptographic keys, and computing
 * message digests.
 */
class TEMCrypto {
	/** The number of entries in the keys file. */
	public static final short NUM_KEYS = 8;
	/** The size of a key authorization secret. */
	public static final short AUTH_SIZE = 20;
	/** Invalid key ID. */
	public static final byte INVALID_KEY = (byte)-1;
	
	/** The identifier for symmetric keys. */
	public static final byte SYMMETRIC_KEY = (byte)0x99;
	/** The identifier for the public component of an asymmetric key. */
	public static final byte ASYMMETRIC_PUBKEY = (byte)0xAA;
	/** The identifier for the private component of an asymmetric key. */
	public static final byte ASYMMETRIC_PRIVKEY = (byte)0x55;
	
	/** The cipher to be used for symmetric key encryption/decryption. */
	private static final byte sksCipherID = Cipher.ALG_AES_BLOCK_128_ECB_NOPAD;	
	/** The cipher to be used for PKS encryption/decryption. */
	// Use this when JCOP supports OAEP padding according to PKCS#1 v2.0
	// private static final byte pksCipherID = Cipher.ALG_RSA_PKCS1_OAEP;
	// PKCS#1 v1.5 padding
	private static final byte pksCipherID = Cipher.ALG_RSA_PKCS1;
	/** The number of padding bytes needed for PKS encryption/decryption. */
	// Padding size: 11 for PKCS#1 v1.5, 41 for PKCS#1 v2.0
	// (according to http://www.openssl.org/docs/crypto/RSA_public_encrypt.html)
	// Our tests: 11 works for v1.5, but 41 fails for v2.0; so we use 42
	// private static final short pksCipherPadding = 42;
	private static final short pksCipherPadding = 11;
	
	/** The size of the generic key TEM header. */
	private static final short KEY_HEADER_BYTES = 1;
	
	/** Message digest instance. Made static because the dynamic version leaks memory. */
	private static MessageDigest digest;	
	/** Symmetric / asymmetric cipher instances. Made static because the dynamic version leaks memory. */
	private static Cipher symCipher, asymCipher;	
	/** Symmetric / asymmetric signature instances. Made static because the dynamic version leaks memory. */	
	private static Signature symSignature, asymSignature;
	/** Randomizer instance. Made static because the dynamic version leaks memory. */	
	private static RandomData randomizer;
	
	/** Holds random material for creating symmetric keys. */
	private static byte[] randomMaterial;
	
	/** The key file (parallel: register file). */
	private static Key[] keys;	
	/** The key authorizations. */
	private static byte[] authorizations;
	/**
	 * Indicates which keys are persistent.
	 * 
	 * Persistent keys are retained after the proc that created them finishes.
	 * A key becomes persistent when its authorization value is set. 
	 */
	private static boolean[] persistent;
	
	/**
	 * Initializes the TEM cryptographic engine.
	 * Called when the TEM is activated.
	 */
	public static void init() {
		keys = new Key[NUM_KEYS];
		authorizations = new byte[(short)(NUM_KEYS * AUTH_SIZE)];
		persistent = new boolean[NUM_KEYS];
		for(short i = 0; i < persistent.length; i++)
			persistent[i] = false;

		symCipher = Cipher.getInstance(sksCipherID, false);
		asymCipher = Cipher.getInstance(pksCipherID, false);
		digest = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
		digest.reset();		
		randomizer = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		symSignature = Signature.getInstance(Signature.ALG_AES_MAC_128_NOPAD, false);
		asymSignature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
		randomMaterial = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);
	}
	
	/**
	 * Releases all the resources held by the TEM cryptographic engine.
	 * Called when the TEM is de-activated.
	 */
	public static void deinit() {
		for(short i = 0; i < keys.length; i++) {
			if(keys[i] != null)
				keys[i].clearKey();
		}
		keys = null;
		authorizations = null;
		persistent = null;
		
		symCipher = null; asymCipher = null;
		digest = null; randomizer = null;
		symSignature = null; asymSignature = null;
		randomMaterial = null;
	}
	
	/**
	 * Identifies an available key slot.
	 * This does not mark the slot busy (allocation), it merely identifies it.
	 * @return a key slot that is available, or -1 if all the slots are taken 
	 */
	private static byte findFreeKeySlot() {
		for(byte i = (byte)0; i < (byte)keys.length; i++) {
			if(keys[i] == null)
				return i;
		}
		return (byte)-1;
	}
	/**
	 * Generates an encryption key (or key pair, for PKS).
	 * @param pks <code>true</code> to obtain a PKS key, <code>false</code> for a symmetric key
	 * @return a tuple (slot of private key, slot of public key / zero for symmetric keys) packaged in a short
	 */
	public static short generateKey(boolean pks) {
		byte privKeyIndex = findFreeKeySlot();
		byte pubKeyIndex = privKeyIndex;
		if(privKeyIndex == (byte)-1 || pubKeyIndex == (byte)-1) return (short)-1;

		if(pks) {
			// PKS key pair			
			KeyPair newKP = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_2048);
			newKP.genKeyPair();
			keys[privKeyIndex] = newKP.getPrivate();
			pubKeyIndex = findFreeKeySlot();
			JCSystem.requestObjectDeletion();			
			if(pubKeyIndex == (byte)-1) {
				keys[privKeyIndex] = null;
				newKP.getPrivate().clearKey();
				newKP.getPublic().clearKey();
				return (short)-1;
			}
			keys[pubKeyIndex] = newKP.getPublic();
		}
		else {
			// symmetric key
			AESKey key = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
			short keySize = (short)(key.getSize() / (short)4);			
			random(randomMaterial, (short)0, keySize);
			key.setKey(randomMaterial, (short)0);
			keys[privKeyIndex] = key;
		}
		return Util.makeShort(privKeyIndex, pubKeyIndex);		
	}
	private static RSAPublicKey loadPublicKey(byte[] buffer, short offset) {
		RSAPublicKey pubKey = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC,
				KeyBuilder.LENGTH_RSA_2048, false);
		short readOffset = (short)(offset + (short)4);
		short length = Util.getShort(buffer, offset);
		pubKey.setExponent(buffer, readOffset, length); readOffset += length;
		length = Util.getShort(buffer, (short)(offset + (short)2));		
		pubKey.setModulus(buffer, readOffset, length);
		return pubKey;	
	}	
	private static AESKey loadSymmetricKey(byte[] buffer, short offset) {
		AESKey sksKey = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
		sksKey.setKey(buffer, offset);
		return sksKey;
	}
	private static RSAPrivateCrtKey loadPrivateKey(byte[] buffer, short offset) {
		RSAPrivateCrtKey privKey = (RSAPrivateCrtKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_CRT_PRIVATE,
				KeyBuilder.LENGTH_RSA_2048, false);
		short readOffset = (short)(offset + (short)10);

		short length = Util.getShort(buffer, offset);
		privKey.setP(buffer, readOffset, length); readOffset += length;
		length = Util.getShort(buffer, (short)(offset + (short)2));		
		privKey.setQ(buffer, readOffset, length); readOffset += length;
		length = Util.getShort(buffer, (short)(offset + (short)4));		
		privKey.setDP1(buffer, readOffset, length); readOffset += length;
		length = Util.getShort(buffer, (short)(offset + (short)6));		
		privKey.setDQ1(buffer, readOffset, length); readOffset += length;
		length = Util.getShort(buffer, (short)(offset + (short)8));		
		privKey.setPQ(buffer, readOffset, length); readOffset += length;
		return privKey;
	}
	public static byte loadKey(byte[] buffer, short offset) {		
		byte keyIndex = findFreeKeySlot();
		if(keyIndex == -1) return keyIndex;

		if(buffer[offset] == ASYMMETRIC_PRIVKEY) {
			// RSA private key
			keys[keyIndex] = loadPrivateKey(buffer, (short)(offset + (short)1));
		}
		else if(buffer[offset] == ASYMMETRIC_PUBKEY) {
			// RSA public key
			keys[keyIndex] = loadPublicKey(buffer, (short)(offset + (short)1));
		}
		else if(buffer[offset] == SYMMETRIC_KEY) {
			// symmetric encryption key
			keys[keyIndex] = loadSymmetricKey(buffer, (short)(offset + (short)1));
		}
		else
			return (byte)-1;
		return keyIndex;
	}	
	public static void releaseKey(byte keyIndex) {
		keys[keyIndex].clearKey();
		keys[keyIndex] = null;
		persistent[keyIndex] = false;
		JCSystem.requestObjectDeletion();
	}
	
	/**
	 * Releases all non-persistent keys.
	 */
	public static void releaseVolatileKeys() {
		for(byte i = 0; i < persistent.length; i++) {
			if(persistent[i] == false && keys[i] != null)
				releaseKey(i);
		}
	}
	
	public static short getKeyLength(byte keyIndex) {
		if(keys[keyIndex] instanceof RSAPrivateCrtKey) {
			// Private key has 5 numbers half the public key's size = 5 * # of bytes / 2
			// plus 10 bytes for header (size of the 5 numbers)
			return (short)((keys[keyIndex].getSize() / (short)16) * (short)5 + (short)10 + KEY_HEADER_BYTES);
		}
		else if(keys[keyIndex] instanceof RSAPublicKey) {
			// Public key has (e, m) so it's # of bytes * 2 = # of bits / 4
			// plus 4 bytes for header (size of the 2 numbers)
			return (short)(keys[keyIndex].getSize() / (short)4 + (short)4 + KEY_HEADER_BYTES);			
		}
		else if (keys[keyIndex] instanceof AESKey) {
			// AES keys are so much more straightforward...
			return keys[keyIndex].getSize();
		}
			
		else
			return 0;		
	}
	
	private static short savePublicKey(RSAPublicKey key, byte[] buffer, short offset) {		
		short writeOffset = (short)((short)offset + (short)4);

		// the public exponent E -- e in OpenSSL
		short expSize = key.getExponent(buffer, writeOffset); writeOffset += expSize;
		Util.setShort(buffer, offset, expSize);
		// the public modulus N -- n in OpenSSL
		short modSize = key.getModulus(buffer, writeOffset); writeOffset += modSize;
		Util.setShort(buffer, (short)(offset + (short)2), modSize);
		return (short)(writeOffset - offset);
	}
	private static short savePrivateKey(RSAPrivateCrtKey key, byte[] buffer, short offset) {
		short writeOffset = (short)((short)offset + (short)10);
		
		// P, Q are the secret prime factors (N = PQ)
		// D is the private exponent

		// secret prime factor P
		short pSize = key.getP(buffer, writeOffset); writeOffset += pSize;
		Util.setShort(buffer, (short)(offset + (short)0), pSize);
		// secret prime factor Q
		short qSize = key.getQ(buffer, writeOffset); writeOffset += qSize;
		Util.setShort(buffer, (short)(offset + (short)2), qSize);
		// D mod (P-1) -- dmp1 in OpenSSL
		short dp1Size = key.getDP1(buffer, writeOffset); writeOffset += dp1Size;
		Util.setShort(buffer, (short)(offset + (short)4), dp1Size);
		// D mod (Q-1) -- dmq1 in OpenSSL
		short dq1Size = key.getDQ1(buffer, writeOffset); writeOffset += dq1Size;
		Util.setShort(buffer, (short)(offset + (short)6), dq1Size);		
		// Q^(-1) mod P -- iqmp in OpenSSL
		short pqSize = key.getPQ(buffer, writeOffset); writeOffset += pqSize;
		Util.setShort(buffer, (short)(offset + (short)8), pqSize);
		
		return (short)(writeOffset - offset);
	}
	private static short saveSymmetricKey(AESKey key, byte[] buffer, short offset) {
		return (short)key.getKey(buffer, offset);
	}
	private static byte getKeyType(Key key) {
		if(key instanceof RSAPrivateCrtKey)
			return ASYMMETRIC_PRIVKEY;
		else if(key instanceof RSAPublicKey)
			return ASYMMETRIC_PUBKEY;
		else if(key instanceof AESKey)
			return SYMMETRIC_KEY;
		return INVALID_KEY;
	}
	public static short saveKey(byte keyIndex, byte[] buffer, short offset) {
		short writeOffset = (short)(offset + KEY_HEADER_BYTES);
		buffer[offset] = getKeyType(keys[keyIndex]);
		if(keys[keyIndex] instanceof RSAPrivateCrtKey)
			writeOffset = savePrivateKey((RSAPrivateCrtKey)keys[keyIndex], buffer, writeOffset);			
		else if(keys[keyIndex] instanceof RSAPublicKey)
			writeOffset = savePublicKey((RSAPublicKey)keys[keyIndex], buffer, writeOffset);			
		else if(keys[keyIndex] instanceof AESKey)
			writeOffset = saveSymmetricKey((AESKey)keys[keyIndex], buffer, writeOffset);
		return (short)(writeOffset + KEY_HEADER_BYTES);
	}
	
	public static short getEncryptedBlockSize(byte keyIndex, short plainBlockSize) {
		Key pk = (Key)keys[keyIndex];
		short oneBlockSize = (short)(pk.getSize() / (short)8);
		short oneInputSize = (pk instanceof AESKey) ? oneBlockSize : (short)(oneBlockSize - (short)pksCipherPadding);
		return (short)((short)((short)((short)(plainBlockSize + oneInputSize) - (short)1) / oneInputSize) * oneBlockSize);
	}
	 
	/**
	 * Performs encryption / decryption.
	 * When using asymmetric keys, decryption should be performed using the pair of the key used for encryption. 
	 * @param keyIndex the ID of the key to be used for encryption / decryption
	 * @param sourceBuffer the buffer containing the data to be encrypted / decrypted
	 * @param sourceOffset the offset of the first byte in sourceBuffer that contains the data to be encrypted / decrypted
	 * @param sourceLength the number of bytes to be encrypted / decrypted
	 * @param outBuffer the buffer that will receive the encrypted / decrypted result
	 * @param outOffset the offset of the first byte in outBuffer that will receive the encrypted / decrypted result
	 * @param doEncrypt <code>true</code> to indicate encryption, or <code>false</code> for decryption
	 * @return the number of bytes written to outBuffer
	 */
	public static short cryptWithKey(byte keyIndex, byte[] sourceBuffer, short sourceOffset, short sourceLength, byte[] outBuffer, short outOffset, boolean doEncrypt) {
		Key cryptKey = keys[keyIndex];
		Cipher cipher;		
		short outBlockSize, inBlockSize;
		if(cryptKey instanceof AESKey) {
			// symmetric encryption setup
			cipher = symCipher;
			inBlockSize = outBlockSize = (short)(cryptKey.getSize() / (short)8);
		}
		else {
			// asymmetric encryption setup
			cipher = asymCipher;
			if(doEncrypt) {
				outBlockSize = (short)(cryptKey.getSize() / (short)8);
				inBlockSize = (short)(outBlockSize - (short)pksCipherPadding);
			}
			else {
				inBlockSize = (short)(cryptKey.getSize() / (short)8);
				outBlockSize = (short)(inBlockSize - (short)pksCipherPadding);			
			}
		}
		cipher.init(cryptKey, doEncrypt ? Cipher.MODE_ENCRYPT : Cipher.MODE_DECRYPT);
		
		short stopOffset = (short)(sourceOffset + sourceLength);
		short writeOffset = outOffset;
		for(; sourceOffset < stopOffset; sourceOffset += inBlockSize) {
			short blockSize = ((short)(stopOffset - sourceOffset) >= inBlockSize) ? inBlockSize : (short)(stopOffset - sourceOffset);
			writeOffset += cipher.doFinal(sourceBuffer, sourceOffset, blockSize, outBuffer, writeOffset);
		}
		return (short)(writeOffset - outOffset);
	}
	
	/**
	 * Performs a signature operaion (sign / verify).
	 * When using asymmetric keys, verification should be performed using the pair of the key used for signing. 
	 * @param keyIndex the ID of the key to be used for signing / verification
	 * @param sourceBuffer the buffer containing the data to be signed / that was signed
	 * @param sourceOffset the offset of the first byte in sourceBuffer that contains the data to be signed / that was signed
	 * @param sourceLength the number of bytes to be signed / that were signed
	 * @param outBuffer the buffer that will receive the signature / contains the signature to be verified
	 * @param outOffset the offset of the first byte in outBuffer that will receive the signature / contains the signature to be verified
	 * @param doSign <code>true</code> to indicate signing, or <code>false</code> for signature verification
	 * @return the number of bytes written to outBuffer, when in signing mode; 0 (fail) or 1 (pass) in verification mode
	 */
	public static short signWithKey(short keyIndex, byte[] sourceBuffer, short sourceOffset, short sourceLength, byte[] outBuffer, short outOffset, boolean doSign) {
		Key cryptKey = keys[keyIndex];
		Signature signature;
		short signatureSize;

		if(cryptKey instanceof AESKey) {
			// HMAC setup
			signature = symSignature;
		}
		else {
			// PKS signing setup
			signature = asymSignature;			
		}
		signatureSize = (short)(cryptKey.getSize() / (short)8);
		signature.init(cryptKey, doSign ? Signature.MODE_SIGN : Signature.MODE_VERIFY);
		
		if(doSign)
			return signature.sign(sourceBuffer, sourceOffset, sourceLength, outBuffer, outOffset);
		else
			return signature.verify(sourceBuffer, sourceOffset, sourceLength, outBuffer, outOffset, signatureSize) ? (short)0x01: (short)0x00;			
	}
	
	/**
	 * Sets the authorization value for a key.
	 * @param keyIndex the ID of the key
	 * @param buffer the buffer containing the authorization value
	 * @param offset the byte offset of the authorization value in the given buffer
	 */
	public static void setKeyAuth(byte keyIndex, byte[] buffer, short offset) {
		short authOffset = (short)(keyIndex * AUTH_SIZE);
		Util.arrayCopyNonAtomic(buffer, offset, authorizations, authOffset, AUTH_SIZE);
		persistent[keyIndex] = true;
	}
	
	/**
	 * Verifies the authorization value for a key.
	 * @param keyIndex the ID of the key
	 * @param buffer the buffer containing the authorization value to be verified
	 * @param offset the byte offset of the authorization value in the given buffer
	 */
	public static boolean verifyKeyAuth(byte keyIndex, byte[] buffer, short offset) {
		if(persistent[keyIndex] == false)
			return false;
		short authOffset = (short)(keyIndex * AUTH_SIZE);
		return Util.arrayCompare(buffer, offset, authorizations, authOffset, AUTH_SIZE) == 0;
	}
	
	public static short digest(byte[] sourceBuffer, short sourceOffset, short sourceLength, byte[] outBuffer, short outOffset) {
		digest.reset();
		return digest.doFinal(sourceBuffer, sourceOffset, sourceLength, outBuffer, outOffset);
	}
	public static short digest2(byte[] sourceBuffer1, short sourceOffset1, short sourceLength1, byte[] sourceBuffer2, short sourceOffset2, short sourceLength2, byte[] outBuffer, short outOffset) {
		digest.reset();
		digest.update(sourceBuffer1, sourceOffset1, sourceLength1);
		return digest.doFinal(sourceBuffer2, sourceOffset2, sourceLength2, outBuffer, outOffset);		
	}
	public static short getDigestLength() {
		return (short)digest.getLength();
	}
	public static short getDigestBlockLength() {
		// dunno how to get message digest block lengths from crypto 
		return 20;
	}	
	
	public static void random(byte[] buffer, short offset, short length) {		
		randomizer.generateData(buffer, offset, length);
	}
	
	/**
	 * Dumps the state of the TEM cryptographic engine.
	 * @param output the buffer that will receive the stat results
	 * @param outputOffset the offset of the first byte in the output buffer that will receive the stat results
	 * @return the number of bytes written to the output buffer
	 */
	public static short stat(byte[] output, short outputOffset) {
		short o = outputOffset;
		
		// status for each key
		for(byte i = 0; i < NUM_KEYS; i++) {
			if(keys[i] == null)
				continue;
			output[o] = i; o++;
			output[o] = getKeyType(keys[i]); o++;
			Util.setShort(output, o, keys[i].getSize()); o += 2;
		}
		
		return (short)(o - outputOffset);
	}	
}