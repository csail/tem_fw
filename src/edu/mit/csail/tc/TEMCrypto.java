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
  /** Invalid pair of key IDs. */
  public static final short INVALID_KEY_PAIR = (short)-1;
	
	/** The identifier for symmetric keys. */
	public static final byte SYMMETRIC_KEY = (byte)0x99;
	/** The identifier for the public component of an asymmetric key. */
	public static final byte ASYMMETRIC_PUBKEY = (byte)0xAA;
	/** The identifier for the private component of an asymmetric key. */
	public static final byte ASYMMETRIC_PRIVKEY = (byte)0x55;
	
	/** The cipher to be used for symmetric key encryption/decryption. */
	private static final byte SKS_CIPHER_ID = Cipher.ALG_AES_BLOCK_128_CBC_NOPAD;	
	/** The cipher to be used for PKS encryption/decryption. */
	// Use this when JCOP supports OAEP padding according to PKCS#1 v2.0
	// private static final byte pksCipherID = Cipher.ALG_RSA_PKCS1_OAEP;
	// PKCS#1 v1.5 padding
	private static final byte PKS_CIPHER_ID = Cipher.ALG_RSA_PKCS1;
	/** The number of padding bytes needed for PKS encryption/decryption. */
	// Padding size: 11 for PKCS#1 v1.5, 41 for PKCS#1 v2.0
	// (according to http://www.openssl.org/docs/crypto/RSA_public_encrypt.html)
	// Our tests: 11 works for v1.5, but 41 fails for v2.0; so we use 42
	// private static final short pksCipherPadding = 42;
	private static final short pksCipherPadding = 11;
	
	/** The size of the generic key TEM header. */
	private static final short KEY_HEADER_BYTES = 1;
	
	/** 
	 * Message digest instance.
	 * 
	 * Static because the dynamic version leaks memory.
	 */
	private static MessageDigest digest;	
	/** 
	 * Symmetric / asymmetric cipher instances.
	 * 
	 * Static because the dynamic versions leak memory.
	 */
	private static Cipher symCipher, asymCipher;	
	/** 
	 * Symmetric / asymmetric signature instances.
	 * 
	 * Static because the dynamic versions leak memory.
	 */	
	private static Signature symSignature, asymSignature;
	/**
	 * Randomizer instance.
	 * 
	 * Static because the dynamic version leaks memory.
	 */	
	private static RandomData randomizer;
	
	/** Holds random material for creating symmetric keys. */
	private static byte[] randomMaterial;
	
	/** The key file (parallel: register file). */
	private static Key[] keys;	
	/** The key authorization secrets. */
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
	 * 
	 * Called when the TEM is activated.
	 */
	public static final void init() {
		keys = new Key[NUM_KEYS];
		authorizations = new byte[(short)(NUM_KEYS * AUTH_SIZE)];
		persistent = new boolean[NUM_KEYS];
		for (short i = 0; i < persistent.length; i++)
			persistent[i] = false;

		symCipher = Cipher.getInstance(SKS_CIPHER_ID, false);
		asymCipher = Cipher.getInstance(PKS_CIPHER_ID, false);
		digest = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
		digest.reset();		
		randomizer = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		symSignature = Signature.getInstance(Signature.ALG_AES_MAC_128_NOPAD,
		                                     false);
		asymSignature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
		randomMaterial = JCSystem.makeTransientByteArray((short)16,
        JCSystem.CLEAR_ON_DESELECT);
	}
	
	/**
	 * Releases all the resources held by the TEM cryptographic engine.
	 * 
	 * Called when the TEM is de-activated.
	 */
	public static final void deinit() {
		for (short i = 0; i < keys.length; i++) {
			if (keys[i] != null)
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
	private static final byte findFreeKeySlot() {
		for (byte i = (byte)0; i < keys.length; i++) {
			if (keys[i] == null)
				return i;
		}
		return INVALID_KEY;
	}
	/**
	 * Generates an encryption key (or key pair, for PKS).
	 * @param keyIsAsymmetric <code>true</code> to obtain a PKS key, or
	 *                        <code>false</code> for a symmetric key
	 * @return a tuple (slot of private key, slot of public key / zero for
	 *         symmetric keys) packaged in a short
	 */
	public static final short generateKey(boolean keyIsAsymmetric) {
		byte privKeyIndex = findFreeKeySlot();
		byte pubKeyIndex = privKeyIndex;
		if (privKeyIndex == INVALID_KEY)
		  return INVALID_KEY_PAIR;

		if (keyIsAsymmetric) {
			// Asymmetric key pair.
			KeyPair newKP = new KeyPair(KeyPair.ALG_RSA_CRT,
			                            KeyBuilder.LENGTH_RSA_2048);
			newKP.genKeyPair();
			keys[privKeyIndex] = newKP.getPrivate();
			pubKeyIndex = findFreeKeySlot();
			JCSystem.requestObjectDeletion();			
			if (pubKeyIndex == INVALID_KEY) {
				keys[privKeyIndex] = null;
				newKP.getPrivate().clearKey();
				newKP.getPublic().clearKey();
				return INVALID_KEY_PAIR;
			}
			keys[pubKeyIndex] = newKP.getPublic();
		}
		else {
			// Symmetric key.
			AESKey key = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES,
			                                         KeyBuilder.LENGTH_AES_128,
			                                         false);
			short keySize = (short)(key.getSize() / 8);
			random(randomMaterial, (short)0, keySize);
			key.setKey(randomMaterial, (short)0);
			keys[privKeyIndex] = key;
			pubKeyIndex = INVALID_KEY;
		}
		return Util.makeShort(privKeyIndex, pubKeyIndex);		
	}
	private static final RSAPublicKey loadPublicKey(byte[] buffer, short offset) {
		RSAPublicKey pubKey = (RSAPublicKey)KeyBuilder.buildKey(
		    KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_2048, false);
		short readOffset = (short)(offset + 4);
		short length = Util.getShort(buffer, offset);
		pubKey.setExponent(buffer, readOffset, length); readOffset += length;
		length = Util.getShort(buffer, (short)(offset + 2));		
		pubKey.setModulus(buffer, readOffset, length);
		return pubKey;	
	}	
	private static final AESKey loadSymmetricKey(byte[] buffer, short offset) {
		AESKey sksKey = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES,
		                                            KeyBuilder.LENGTH_AES_128,
		                                            false);
		sksKey.setKey(buffer, offset);
		return sksKey;
	}
	private static final RSAPrivateCrtKey loadPrivateKey(byte[] buffer,
	                                                     short offset) {
		RSAPrivateCrtKey privKey = (RSAPrivateCrtKey)KeyBuilder.buildKey(
		    KeyBuilder.TYPE_RSA_CRT_PRIVATE, KeyBuilder.LENGTH_RSA_2048, false);
		short readOffset = (short)(offset + 10);

		short length = Util.getShort(buffer, offset);
		privKey.setP(buffer, readOffset, length); readOffset += length;
		length = Util.getShort(buffer, (short)(offset + 2));		
		privKey.setQ(buffer, readOffset, length); readOffset += length;
		length = Util.getShort(buffer, (short)(offset + 4));		
		privKey.setDP1(buffer, readOffset, length); readOffset += length;
		length = Util.getShort(buffer, (short)(offset + 6));		
		privKey.setDQ1(buffer, readOffset, length); readOffset += length;
		length = Util.getShort(buffer, (short)(offset + 8));		
		privKey.setPQ(buffer, readOffset, length); readOffset += length;
		return privKey;
	}
	public static final byte loadKey(byte[] buffer, short offset) {		
		byte keyIndex = findFreeKeySlot();
		if(keyIndex == -1) return keyIndex;

		if(buffer[offset] == ASYMMETRIC_PRIVKEY) {
			// RSA private key
			keys[keyIndex] = loadPrivateKey(buffer, (short)(offset + 1));
		}
		else if(buffer[offset] == ASYMMETRIC_PUBKEY) {
			// RSA public key
			keys[keyIndex] = loadPublicKey(buffer, (short)(offset + 1));
		}
		else if(buffer[offset] == SYMMETRIC_KEY) {
			// Symmetric encryption key
			keys[keyIndex] = loadSymmetricKey(buffer, (short)(offset + 1));
		}
		else
			return INVALID_KEY;
		return keyIndex;
	}	
	public static final void releaseKey(byte keyIndex) {
		keys[keyIndex].clearKey();
		keys[keyIndex] = null;
		persistent[keyIndex] = false;
		JCSystem.requestObjectDeletion();
	}
	
	/**
	 * Releases all non-persistent keys.
	 */
	public static final void releaseVolatileKeys() {
		for (byte i = 0; i < persistent.length; i++) {
			if (persistent[i] == false && keys[i] != null)
				releaseKey(i);
		}
	}
	
	public static final short getKeyLength(byte keyIndex) {
	  Key key = keys[keyIndex];
		if (key instanceof RSAPrivateCrtKey) {
			// Private key has 5 numbers half the public key's size =
		  // 5 * # of bytes / 2 plus 10 bytes for header (5 shorts)
			return (short)((key.getSize() >> 4) * 5 + 10 + KEY_HEADER_BYTES);
		}
		else if (key instanceof RSAPublicKey) {
			// Public key has (e, m) so it's # of bytes * 2 = # of bits / 4
			// plus 4 bytes for header (2 numbers shorts)
			return (short)((key.getSize() >> 2) + 4 + KEY_HEADER_BYTES);			
		}
		else if (key instanceof AESKey) {
			// AES keys are so much more straightforward...
			return (short)((key.getSize() >> 3) + KEY_HEADER_BYTES);
		}
		else
			return 0;		
	}
	
	private static final short savePublicKey(RSAPublicKey key, byte[] buffer,
	                                         short offset) {		
		short writeOffset = (short)(offset + 4);

		// The public exponent E -- e in OpenSSL
		short expSize = key.getExponent(buffer, writeOffset);
		writeOffset += expSize;
		Util.setShort(buffer, offset, expSize);
		// The public modulus N -- n in OpenSSL
		short modSize = key.getModulus(buffer, writeOffset); writeOffset += modSize;
		Util.setShort(buffer, (short)(offset + 2), modSize);
		return (short)(writeOffset - offset);
	}
	private static final short savePrivateKey(RSAPrivateCrtKey key, byte[] buffer,
	                                          short offset) {
		short writeOffset = (short)(offset + 10);
		
		// P, Q are the secret prime factors (N = PQ)
		// D is the private exponent

		// Secret prime factor P
		short pSize = key.getP(buffer, writeOffset); writeOffset += pSize;
		Util.setShort(buffer, (short)(offset + 0), pSize);
		// Secret prime factor Q
		short qSize = key.getQ(buffer, writeOffset); writeOffset += qSize;
		Util.setShort(buffer, (short)(offset + 2), qSize);
		// D mod (P-1) -- dmp1 in OpenSSL
		short dp1Size = key.getDP1(buffer, writeOffset); writeOffset += dp1Size;
		Util.setShort(buffer, (short)(offset + 4), dp1Size);
		// D mod (Q-1) -- dmq1 in OpenSSL
		short dq1Size = key.getDQ1(buffer, writeOffset); writeOffset += dq1Size;
		Util.setShort(buffer, (short)(offset + 6), dq1Size);		
		// Q^(-1) mod P -- iqmp in OpenSSL
		short pqSize = key.getPQ(buffer, writeOffset); writeOffset += pqSize;
		Util.setShort(buffer, (short)(offset + 8), pqSize);
		
		return (short)(writeOffset - offset);
	}
	private static final short saveSymmetricKey(AESKey key, byte[] buffer,
	                                            short offset) {
		return key.getKey(buffer, offset);
	}
	private static final byte getKeyType(Key key) {
		if (key instanceof RSAPrivateCrtKey)
			return ASYMMETRIC_PRIVKEY;
		else if (key instanceof RSAPublicKey)
			return ASYMMETRIC_PUBKEY;
		else if (key instanceof AESKey)
			return SYMMETRIC_KEY;
		return INVALID_KEY;
	}
	public static final short saveKey(byte keyIndex, byte[] buffer,
	                                  short offset) {
		short writeOffset = (short)(offset + KEY_HEADER_BYTES);
		Key key = keys[keyIndex];
		
		buffer[offset] = getKeyType(key);
		if (key instanceof RSAPrivateCrtKey)
			writeOffset = savePrivateKey((RSAPrivateCrtKey)key, buffer, writeOffset);			
		else if (key instanceof RSAPublicKey)
			writeOffset = savePublicKey((RSAPublicKey)key, buffer, writeOffset);			
		else if (key instanceof AESKey)
			writeOffset = saveSymmetricKey((AESKey)key, buffer, writeOffset);
		return (short)(writeOffset + KEY_HEADER_BYTES);
	}
	
	/** Computes the maximum size of the result of encrypting some data.
	 * 
	 * @param keyIndex the entry in the key file pointing to the encryption key
	 * @param plainBytes the number of bytes be encrypted
	 * @return the maximum size of the result of using the given key to encrypt
	 *         plainBytes bytes of data
	 */
	public static final short getEncryptedDataSize(byte keyIndex,
	                                                short plainBytes) {
		Key pk = keys[keyIndex];
		short outBlockSize = (short)(pk.getSize() >> 3);
		short inBlockSize = (pk instanceof AESKey) ? outBlockSize :
		  (short)(outBlockSize - pksCipherPadding);
		return (short)((plainBytes + inBlockSize - 1) / inBlockSize * outBlockSize);
	}
	 
	/**
	 * Performs encryption / decryption.
	 * 
	 * When using asymmetric keys, decryption should be performed using the pair
	 * of the key used for encryption. 
	 * 
	 * @param keyIndex the ID of the key to be used for *cryption
	 * @param sourceBuffer the buffer containing the data to be *crypted
	 * @param sourceOffset the offset of the first byte in sourceBuffer that
	 *                     contains the data to be *crypted
	 * @param sourceLength the number of bytes to be *crypted
	 * @param outBuffer the buffer that will receive the *crypted result
	 * @param outOffset the offset of the first byte in outBuffer that will
	 *                  receive the *crypted result
	 * @param doEncrypt <code>true</code> to indicate encryption, or
	 *                  <code>false</code> for decryption
	 * @return the number of bytes written to outBuffer
	 */
	public static final short cryptWithKey(byte keyIndex, byte[] sourceBuffer,
	                                       short sourceOffset, short sourceLength,
	                                       byte[] outBuffer, short outOffset,
	                                       boolean doEncrypt) {
		Key cryptKey = keys[keyIndex];
		Cipher cipher;		
		short outBlockSize, inBlockSize;
		if (cryptKey instanceof AESKey) {
			// Prepare for symmetric encryption
			cipher = symCipher;
			inBlockSize = outBlockSize = sourceLength;
		}
		else {
			// Prepare for asymmetric encryption
			cipher = asymCipher;
			if (doEncrypt) {
				outBlockSize = (short)(cryptKey.getSize() >> 3);
				inBlockSize = (short)(outBlockSize - pksCipherPadding);
			}
			else {
				inBlockSize = (short)(cryptKey.getSize() >> 3);
				outBlockSize = (short)(inBlockSize - pksCipherPadding);			
			}
		}
		cipher.init(cryptKey,
		            doEncrypt ? Cipher.MODE_ENCRYPT : Cipher.MODE_DECRYPT);
		
		short stopOffset = (short)(sourceOffset + sourceLength);
		short writeOffset = outOffset;
		for(; sourceOffset < stopOffset; sourceOffset += inBlockSize) {
			short blockSize = (stopOffset - sourceOffset >= inBlockSize) ? inBlockSize
			                  : (short)(stopOffset - sourceOffset);
			writeOffset += cipher.doFinal(sourceBuffer, sourceOffset, blockSize,
			                              outBuffer, writeOffset);
		}
		return (short)(writeOffset - outOffset);
	}
	
	/**
	 * Performs a signature operaion (sign / verify).
	 * 
	 * When using asymmetric keys, verification should be performed using the pair
	 * of the key used for signing.
	 * 
	 * @param keyIndex the ID of the key to be used for signing / verification
	 * @param dataBuffer the buffer containing the data to be signed / that was
	 *                   signed
	 * @param dataOffset the offset of the first byte in dataBuffer
	 *                   that contains the data to be signed / that was signed
	 * @param dataLength the number of bytes to be signed / that were signed
	 * @param signBuffer the buffer that will receive the signature / contains the
	 *                   signature to be verified
	 * @param signOffset the offset of the first byte in outBuffer that will
	 *                   receive the signature / contains the signature to be
	 *                   verified
	 * @param doSign <code>true</code> to indicate signing, or <code>false</code>
	 *               for signature verification
	 * @return the number of bytes written to signBuffer, when in signing mode;
	 *         0 (fail) or 1 (pass) in verification mode
	 */
	public static final short signWithKey(short keyIndex, byte[] dataBuffer,
	                                      short dataOffset, short dataLength,
	                                      byte[] signBuffer, short signOffset,
	                                      boolean doSign) {
		Key signKey = keys[keyIndex];
		Signature signature;
		short signatureSize;

		if (signKey instanceof AESKey) {
			// HMAC setup
			signature = symSignature;
		}
		else {
			// PKS signing setup
			signature = asymSignature;			
		}
		signatureSize = (short)(signKey.getSize() >> 3);
		signature.init(signKey,
		               doSign ? Signature.MODE_SIGN : Signature.MODE_VERIFY);
		
		if (doSign) {
			return signature.sign(dataBuffer, dataOffset, dataLength, signBuffer,
			                      signOffset);
		}
		return (short)(signature.verify(dataBuffer, dataOffset, dataLength,
		                                signBuffer, signOffset, signatureSize) ?
			               0x01 : 0x00);
	}
	
	/**
	 * Sets the authorization secret for a key.
	 * 
	 * @param keyIndex the ID of the key
	 * @param buffer the buffer containing the authorization secret
	 * @param offset the offset of the first byte of the authorization secret in
	 *               the given buffer
	 */
	public static final void setKeyAuth(byte keyIndex, byte[] buffer,
	                                    short offset) {
		short authOffset = (short)(keyIndex * AUTH_SIZE);
		Util.arrayCopyNonAtomic(buffer, offset, authorizations, authOffset,
		                        AUTH_SIZE);
		persistent[keyIndex] = true;
	}
	
	/**
	 * Verifies the authorization secret for a key.
	 * 
	 * @param keyIndex the ID of the key
	 * @param buffer the buffer containing the authorization secret to be verified
	 * @param offset the offset of the first byte of the authorization secret in
	 *               the given buffer
	 * @return <code>true</code> if the given secret matches the key's
	 *         authorization secret, <code>false</code> otherwise
	 */
	public static final boolean verifyKeyAuth(byte keyIndex, byte[] buffer,
	                                          short offset) {
		if (persistent[keyIndex] == false)
			return false;
		short authOffset = (short)(keyIndex * AUTH_SIZE);
		return Util.arrayCompare(buffer, offset, authorizations, authOffset,
		                         AUTH_SIZE) == 0;
	}
	
	public static final short digest(byte[] sourceBuffer, short sourceOffset,
	                                 short sourceLength, byte[] outBuffer,
	                                 short outOffset) {
		digest.reset();
		return digest.doFinal(sourceBuffer, sourceOffset, sourceLength, outBuffer,
		                      outOffset);
	}
	public static final short digest2(byte[] sourceBuffer1, short sourceOffset1,
	                                  short sourceLength1, byte[] sourceBuffer2,
	                                  short sourceOffset2, short sourceLength2,
	                                  byte[] outBuffer, short outOffset) {
		digest.reset();
		digest.update(sourceBuffer1, sourceOffset1, sourceLength1);
		return digest.doFinal(sourceBuffer2, sourceOffset2, sourceLength2,
		                      outBuffer, outOffset);		
	}
	public static final short getDigestLength() {
		return digest.getLength();
	}
	public static final short getDigestBlockLength() {
		// dunno how to get message digest block lengths from crypto 
		return (short)20;
	}	
	
	public static final void random(byte[] buffer, short offset, short length) {		
		randomizer.generateData(buffer, offset, length);
	}
	
	/**
	 * Dumps the state of the TEM cryptographic engine.
	 * 
	 * @param output the buffer that will receive the stat results
	 * @param outputOffset the offset of the first byte in the output buffer that
	 *                     will receive the stat results
	 * @return the number of bytes written to the output buffer
	 */
	public static final short stat(byte[] output, short outputOffset) {
		short o = outputOffset;
		
		// status for each key
		for (byte i = 0; i < NUM_KEYS; i++) {
			if (keys[i] == null)
				continue;
			output[o] = i; o++;
			output[o] = getKeyType(keys[i]); o++;
			Util.setShort(output, o, keys[i].getSize()); o += 2;
		}
		
		return (short)(o - outputOffset);
	}	
}
