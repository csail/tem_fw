package edu.mit.csail.tc;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * TEM communication module.
 * @author Victor Costan
 *
 * For this TEM implementation, the communication module is the JavaCard Applet.
 * The communication module processes commands from the outside, and converts
 * them into calls to the appropriate modules.
 * 
 * In the JavaCard world, commands are APDUs (we don't use the JavaCard RMI
 * mechanism).
 * 
 * This implementation provides "test points" for the crypto engine. While the
 * test points help development a lot, they should be removed from production
 * implementations.
 */
public class TEMApplet extends Applet {
  /** The firmware version. */
  public static final short FIRMWARE_VER = 0x0110;
  
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new TEMApplet()
				.register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}
	
	/**
	 * Empty constructor.
	 * 
	 * This is called when the applet is installed, and we don't need to do
	 * anything useful at that point.
	 * The real initialization happens when the activate APDU is received.
	 */
	public TEMApplet() { }
	
	private static void sendSuccess(APDU apdu) {
		apdu.setOutgoingAndSend((short)0, (short)0);
	}
	
	private static void sendSuccessAndByte(APDU apdu, byte byteValue) {
		byte[] buf = apdu.getBuffer();
		buf[0] = byteValue;
		apdu.setOutgoingAndSend((short)0, (short)1);
	}
		
	private static void sendSuccessAndShort(APDU apdu, short shortValue) {
		byte[] buf = apdu.getBuffer();
		Util.setShort(buf, (short)0, shortValue);
		apdu.setOutgoingAndSend((short)0, (short)2);
	}

	private static void sendSuccessAndByteShort(APDU apdu, byte byteValue,
	                                            short shortValue) {
		byte[] buf = apdu.getBuffer();
		buf[0] = byteValue;
		Util.setShort(buf, (short)1, shortValue);
		apdu.setOutgoingAndSend((short)0, (short)3);
	}

  public void process(APDU apdu) {
		// Good practice: Return 9000 on SELECT
		if (selectingApplet()) {
			return;
		}

		byte[] buf = apdu.getBuffer();
		
		byte[] temBuffer; byte bufferIndex; short bufferSize;
		byte[] outBuffer; byte outBufferIndex; short outputLength;
		short counterIndex;
		byte keyIndex;
		
		switch (buf[ISO7816.OFFSET_INS]) {
///////////////// LIFECYCLE ///////////////////////////			
		case 0x10:
			/**
			 * 	INS 0x10 -- Activate TEM
			 * Parameters:
			 * 	none
			 * Returns:
			 * 	nothing
			 * Throws:
			 *  69 86 (command not allowed) -- if the tag has not been set
			 * Remarks:
			 *  this should be called in the factory to initialize the TEM
			 */			
			if (TEMBuffers.init() == false)
				ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
			TEMTag.init();
			TEMCrypto.init();
			TEMStore.init();
			TEMExecution.init();
			TEMBuffers.layout();
			JCSystem.requestObjectDeletion();			
			TEMApplet.sendSuccess(apdu);
			break;
		case 0x11:
			/**
			 * 	INS 0x11 -- Kill TEM
			 * Parameters:
			 * 	none
			 * Returns:
			 * 	nothing
			 * Throws:
			 *  69 86 (command not allowed) -- if the tag has not been set
			 * Remarks:
			 *  this renders a TEM useless and requires re-issuing
			 *  the TEM applet can be uninstalled once this is called
			 */
			if (TEMBuffers.deinit() == false)
				ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
			TEMExecution.deinit();
			TEMStore.deinit();
			TEMCrypto.deinit();
			TEMTag.deinit();
			JCSystem.requestObjectDeletion();			
			TEMApplet.sendSuccess(apdu);
			break;
		case 0x12:
		  /**
		   *  INS 0x12 -- Retrieve TEM firmware version
		   * Parameters:
		   *  none:
		   * Returns:
		   *  
		   */
		  TEMApplet.sendSuccessAndShort(apdu, TEMApplet.FIRMWARE_VER);
		  break;

///////////////// RESOURCE MANAGEMENT ///////////////////////////			

		case 0x20:
			/**
			 * 	INS 0x20 -- Allocate buffer
			 * Parameters:
			 * 	(P1, P2) -- buffer size
			 * Returns:
			 * 	byte -- buffer ID (0xFF for failure)
			 * Throws:
			 *  6A 84 (file full) -- if there's not enough memory for the buffer
			 */			
			bufferSize = Util.getShort(buf, ISO7816.OFFSET_P1);
			bufferIndex = TEMBuffers.create(bufferSize);
			if (bufferIndex == TEMBuffers.INVALID_BUFFER)
				ISOException.throwIt(ISO7816.SW_FILE_FULL);

			TEMApplet.sendSuccessAndByte(apdu, bufferIndex);
			break;
			
		case 0x21:
			/**
			 * 	INS 0x21 -- Release buffer
			 * Parameters:
			 * 	P1 -- buffer ID
			 * Returns:
			 * 	nothing
			 * Throws:
			 *  nothing -- an invalid buffer ID is a NOP
			 */
			bufferIndex = buf[ISO7816.OFFSET_P1];			
			TEMBuffers.release(bufferIndex);
			TEMApplet.sendSuccess(apdu);
			break;

		case 0x22:
			/**
			 * 	INS 0x22 -- Get buffer length
			 * Parameters:
			 * 	P1 -- buffer ID
			 * Returns:
			 * 	short -- buffer length
			 * Throws:
			 *  6A 86 (incorrect P1P2) -- if given an invalid buffer ID
			 */			
			bufferIndex = buf[ISO7816.OFFSET_P1];
			if (!TEMBuffers.isPublic(bufferIndex) ||
			    TEMBuffers.pin(bufferIndex) == false)
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			TEMApplet.sendSuccessAndShort(apdu, TEMBuffers.size(bufferIndex));
			TEMBuffers.unpin(bufferIndex);
			break;
		
		case 0x23:
			/**
			 * 	INS 0x23 -- Read buffer chunk
			 * Parameters:
			 * 	P1 -- buffer ID
			 *  P2 -- chunk number (0-based, each chunk is TEMBuffers.chunkSize bytes)
			 * Returns:
			 * 	? bytes -- the requested chunk (exactly TEMBuffers.chunkSize bytes,
			 *                                  unless this is the last chunk)
			 * Throws:
			 *  6A 86 (incorrect P1P2) -- if the buffer ID or chunk number is invalid
			 * Remarks:
			 *  it is possible to get a 0 bytes return if the buffer fits in N chunks
			 *  and P2 == N; this facilitates reading the buffer w/o needing to query
			 *  its length separately
			 */			
		
			bufferIndex = buf[ISO7816.OFFSET_P1];
			short bufferOffset = (short)(buf[ISO7816.OFFSET_P2] *
			                             TEMBuffers.chunkSize);
			
			temBuffer = (TEMBuffers.isPublic(bufferIndex) && TEMBuffers.pin(
			    bufferIndex)) ? TEMBuffers.get(bufferIndex) : null;
			bufferSize = TEMBuffers.size(bufferIndex);
			if (temBuffer == null || bufferOffset > bufferSize)
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

			apdu.setOutgoing();
			outputLength = (bufferSize - bufferOffset >= TEMBuffers.chunkSize) ?
				  TEMBuffers.chunkSize : (short)(bufferSize - bufferOffset);
			apdu.setOutgoingLength(outputLength);
			apdu.sendBytesLong(temBuffer, bufferOffset, outputLength);
			TEMBuffers.unpin(bufferIndex);
			break;
			
		case 0x24:
			/**
			 * 	INS 0x24 -- Write buffer chunk
			 * Parameters:
			 * 	P1 -- buffer ID
			 *  P2 -- chunk number (0-based, each chunk is TEMBuffers.chunkSize bytes)
			 *  Lc -- number of bytes to write to the chunk (should be
			 *        TEMBuffers.chunkSize, unless this is the last last chunk)
			 *  Lc bytes -- the chunk data
			 * Returns:
			 *  nothing
			 * Throws:
			 *  6A 86 (incorrect P1P2) -- if the buffer ID or chunk number is invalid
			 */			
			bufferIndex = buf[ISO7816.OFFSET_P1];
			bufferOffset = (short)(buf[ISO7816.OFFSET_P2] * TEMBuffers.chunkSize);			
			bufferSize = apdu.setIncomingAndReceive();
			
			temBuffer = (TEMBuffers.isPublic(bufferIndex) && TEMBuffers.pin(
			    bufferIndex)) ? TEMBuffers.get(bufferIndex) : null;
			if (temBuffer == null ||
			    (bufferOffset + bufferSize > TEMBuffers.size(bufferIndex)))
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA,
			                        temBuffer, bufferOffset, bufferSize);
			TEMBuffers.unpin(bufferIndex);
			TEMApplet.sendSuccess(apdu);
			break;
			
		case 0x25:
			/**
			 * INS 0x25 -- Reset and get buffer chunk length.
			 * Parameters:
			 *  none
			 * Returns:
			 *  short -- the length, in bytes, of a buffer chunk
			 */
			TEMBuffers.guessChunkSize();
			TEMApplet.sendSuccessAndShort(apdu, TEMBuffers.chunkSize);
			break;
			
		case 0x26:
			/**
			 * INS 0x26 -- Releases all the TEM buffers.
			 * Parameters:
			 *  none
			 * Returns:
			 *  nothing
			 */
			TEMBuffers.releaseAll();
			TEMApplet.sendSuccess(apdu);
			break;			

		case 0x27:
			/**
			 * INS 0x27 -- Stat the TEM keys or buffers.
			 * Parameters:
			 *  P1 -- 0 for buffers, 1 for keys
			 * Returns:
			 *  the state of the TEM buffers
			 *    3 shorts - available memory
			 *               (PERMANENT, CLEAR_ON_RESET, CLEAR_ON_DESELECT)
			 *    4 bytes for each buffer entry
			 *      byte - buffer type
			 *        0: NOT_A_TRANSIENT_OBJECT 
			 *        1: CLEAR_ON_RESET
			 *        2: CLEAR_ON_DESELECT
			 *        0x40: set if the buffer is taken
			 *        0x80: set if the buffer is pinned
			 *      short - requested buffer length (bytes)
			 *      short - buffer length (bytes)
			 *  the state of the TEM keys
			 *    4 bytes for each allocated key
			 *      byte - key ID
			 *      byte - key type
			 *        0x99: SYMMETRIC_KEY 
			 *        0x55: ASYMMETRIC_PUBKEY
			 *        0xAA: ASYMMETRIC_PRIVKEY
			 *      short - key length (bits)
			 */
			if (buf[ISO7816.OFFSET_P1] == 0)
				bufferSize = TEMBuffers.stat(buf, (short)0);
			else
				bufferSize = TEMCrypto.stat(buf, (short)0);
			apdu.setOutgoingAndSend((short)0, bufferSize);
			break;
			
    case 0x28:
      /**
       *  INS 0x28 -- Release key
       * Parameters:
       *  P1 -- key ID
       * Returns:
       *  nothing
       * Throws:
       *  nothing -- an invalid key ID is a NOP
       */
      // NOTE: this key-related method must be implemented on production TEMs to
      //       prevent SEClosure DOSing by filling the key store 
      keyIndex = buf[ISO7816.OFFSET_P1];
      TEMCrypto.releaseKey(keyIndex);
      TEMApplet.sendSuccess(apdu);
      break;			

///////////////// TAG ///////////////////////////
			
		case 0x30:
			/**
			 * 	INS 0x30 -- Set tag
			 * Parameters:
			 * 	P1 -- buffer ID of the buffer containing the tag data
			 * Returns:
			 * 	nothing
			 * Throws:
			 *  69 86 (command not allowed) -- the tag has already been set
			 *  6A 84 (file full) -- there is not enough memory for the tag
			 */			
			bufferIndex = buf[ISO7816.OFFSET_P1];
			if (!TEMBuffers.isPublic(bufferIndex) ||
			    TEMBuffers.pin(bufferIndex) == false)
				ISOException.throwIt(ISO7816.SW_FILE_FULL);
			temBuffer = TEMBuffers.get(bufferIndex);
			TEMTag.set(temBuffer, (short)0, TEMBuffers.size(bufferIndex));
			TEMBuffers.unpin(bufferIndex);
				
			TEMApplet.sendSuccess(apdu);
			break;
			
		case 0x31:
			/**
			 * 	INS 0x31 -- Get tag length
			 * Parameters:
			 * 	none
			 * Returns:
			 * 	short -- tag length
			 * Throws:
			 *  69 86 (command not allowed) -- the tag has not been set yet
			 */			
			if (TEMTag.tag != null)
				TEMApplet.sendSuccessAndShort(apdu, (short)TEMTag.tag.length);
			else
				ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
			break;
		
		case 0x32:
			/**
			 * 	INS 0x23 -- Read tag data
			 * Parameters:
			 * 	P1 -- buffer ID of the buffer which receives data
			 *  P2 -- blank
			 *  LC -- 4
			 *  DATA --
			 *  	2 bytes: byte offset of the read operation
			 *  	2 bytes: length (bytes) of the read operation
			 * Returns:
			 * 	nothing
			 * Throws:
			 *  69 86 (command not allowed) -- if the tag has not been set
			 *  6A 86 (incorrect P1P2) -- if given an invalid buffer ID
			 * Remarks:
			 *  it is possible to get a 0 bytes return if the buffer fits in N chunks
			 *  and P2 == N; this facilitates reading the buffer w/o needing to query
			 *  its length separately
			 */
		
			if (TEMTag.tag == null)
				ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
			
			bufferIndex = buf[ISO7816.OFFSET_P1];
			bufferOffset = Util.getShort(buf, ISO7816.OFFSET_CDATA);
			bufferSize = Util.getShort(buf, (short)(ISO7816.OFFSET_CDATA + (short)2));
			
			temBuffer = (TEMBuffers.isPublic(bufferIndex) && TEMBuffers.pin(
			    bufferIndex)) ? TEMBuffers.get(bufferIndex) : null;
			if(temBuffer == null || (bufferSize > TEMBuffers.size(bufferIndex)))
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			
			Util.arrayCopyNonAtomic(TEMTag.tag, bufferOffset,
			                        temBuffer, (short)0, bufferSize);
			TEMBuffers.unpin(bufferIndex);
			TEMApplet.sendSuccess(apdu);
			break;			

///////////////// SEC EXECUTION ///////////////////////////			

		case 0x50:			
			/**
			 * 	INS 0x50 -- Load SECpack
			 * Parameters:
			 * 	P1 -- buffer ID of the buffer containing the SECpack
			 *  P2 -- ID of the key that can decrypt the SECpack
			 *        (ignored for unencrypted SECpacks)
			 * Returns:
			 *  byte -- 1 if the SECpack is accepted, 0 otherwise
			 * Throws:
			 *  6A 86 (incorrect P1P2) -- if given an invalid buffer ID
			 */			

			if (TEMExecution.status != TEMExecution.STATUS_NOSEC)
				TEMExecution.unbindSec();

			bufferIndex = buf[ISO7816.OFFSET_P1];
			keyIndex = buf[ISO7816.OFFSET_P2];
			if (TEMBuffers.pin(bufferIndex) == false)
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			
			TEMExecution.bindSecPack(keyIndex, bufferIndex);
			TEMBuffers.unpin(bufferIndex);
			if (TEMExecution.status != TEMExecution.STATUS_READY)
				TEMBuffers.release(bufferIndex);
			TEMApplet.sendSuccessAndByte(apdu, ((TEMExecution.status ==
			  TEMExecution.STATUS_READY) ? (byte)1 : (byte)0));
			break;
			
		case 0x51:
			/**
			 * 	INS 0x51 -- Unbind SEC
			 * Parameters:
			 *  none
			 * Returns:
			 *  if the SEC executed succesfully 
			 *   byte -- buffer ID of a buffer containing the SEC output
			 *   short -- number of bytes in the SEC output
			 *            (the buffer might be bigger, and padded w/ garbage)
			 *  else
			 *   nothing
			 * Throws:
			 *  69 86 (command not allowed) -- execution engine not in the right state
			 * Remarks:
			 *  the buffer containing the SEC is released before the SEC is executed
			 */			
			keyIndex = TEMExecution.status; // abusing keyIndex to mean secStatus
			outBufferIndex = TEMExecution.outBufferIndex;
			outputLength = TEMExecution.outLength;
			TEMExecution.unbindSec();
			if (keyIndex == TEMExecution.STATUS_SUCCESS)
				TEMApplet.sendSuccessAndByteShort(apdu, outBufferIndex, outputLength);
			else
				TEMApplet.sendSuccess(apdu);
			break;
			
		case 0x52:
			/**
			 * 	INS 0x52 -- Execute bound SEC
			 * Parameters:
			 *  none
			 * Returns:
			 *  byte -- status of the execution engine after the SEC execution
			 * Throws:
			 *  6A 86 (incorrect P1P2) -- invalid buffer ID
			 *  69 86 (command not allowed) -- execution engine not in the right state
			 */			
			if (TEMExecution.status != TEMExecution.STATUS_READY ||
			    TEMBuffers.pin(TEMExecution.i_secBufferIndex) == false)
				ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
			
			TEMExecution.execute();
			TEMBuffers.unpin(TEMExecution.i_secBufferIndex);
			TEMApplet.sendSuccessAndByte(apdu, TEMExecution.status);
			break;

		case 0x53:
			/**
			 * 	INS 0x53 -- Solve Persistent Store fault
			 * Parameters:
			 *  short -- the next cell to be used by psnew
			 * Returns:
			 *  nothing
			 * Throws:
			 *  69 86 (command not allowed) -- execution engine not in the right state
			 * Remarks:
			 *  this is a no-op if the SECpack containing the SEC isn't appropriately
			 *  flagged; this command is only implemented on dev TEMs
			 */			
			if (TEMExecution.status != TEMExecution.STATUS_PSFAULT)
				ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

		  // abusing outputLength to mean nextCell
			outputLength = Util.getShort(buf, ISO7816.OFFSET_P1);
			
			TEMExecution.solvePStoreFault(outputLength);
			TEMApplet.sendSuccess(apdu);
			break;

		case (byte)0x54:
			/**
			 * 	INS 0x54 -- Stat the execution engine
			 * Parameters:
			 *  nothing
			 * Returns:
			 *  the trace (may be empty if the SECpack doesn't allow tracing)
			 * Throws:
			 *  6A 86 (incorrect P1P2) -- if given an invalid buffer ID
			 *  69 86 (command not allowed) -- if the execution engine is not in the right state
			 * Remarks:
			 *  this is a no-op if the SECpack containing the SEC isn't appropriately flagged
			 *  this command is only implemented on dev TEMs
			 */
			bufferSize = TEMExecution.devTrace(buf, (short)0);
			apdu.setOutgoingAndSend((short)0, bufferSize);
			break;
						
///////////////// CRYPTO DEBUGGING HOOKS ///////////////////////////			
						
		case 0x40:
			/**
			 * 	INS 0x40 -- Generate Key or Key Pair
			 * Parameters:
			 * 	P1 -- key type (0x00 PKS key pair, 0x80 symmetric key)
			 * Returns:
			 *  byte -- key ID of private key
			 *  byte -- key ID of public key (0 for symmetric keys)
			 * Throws:
			 *  6A 84 (file full) -- if there's not enough memory for the keys
			 */			
			
			// generate key pair
			counterIndex = TEMCrypto.generateKey(buf[ISO7816.OFFSET_P1] == 0x00);
			// counterIndex is abused to hold (privKeyIndex, pubKeyIndex)			
			TEMApplet.sendSuccessAndShort(apdu, counterIndex);
			break;
			
		case 0x41:
			/**
			 * 	INS 0x41 -- Load key
			 * Parameters:
			 * 	P1 -- buffer ID of the buffer containing key data
			 * Returns:
			 * 	byte - key ID of the loaded key
			 * Throws:
			 *  6A 86 (incorrect P1P2) -- if given an invalid buffer ID
			 *  6A 84 (file full) -- if there's not enough memory for the key
			 */
			bufferIndex = buf[ISO7816.OFFSET_P1];
			if (TEMBuffers.pin(bufferIndex) == false)
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);			
			temBuffer = TEMBuffers.get(bufferIndex);
			keyIndex = TEMCrypto.loadKey(temBuffer, (short)0);
			TEMApplet.sendSuccessAndByte(apdu, keyIndex);
			break;
			
		case 0x42:
			/**
			 * 	INS 0x42 -- Save key
			 * Parameters:
			 * 	P1 -- key ID of the key to be saved
			 * Returns:
			 * 	byte - buffer ID of buffer containing key material
			 *  short - number of bytes in the output key
			 *          (the buffer may be bigger, and padded w/ garbage)
			 * Throws:
			 *  6A 86 (incorrect P1P2) -- if given an invalid key ID
			 *  6A 84 (file full) -- if there's not enough memory for the buffer
			 */
			keyIndex = buf[ISO7816.OFFSET_P1];	
			bufferSize = TEMCrypto.getKeyLength(keyIndex);
			bufferIndex = TEMBuffers.create(bufferSize);
			if (TEMBuffers.pin(bufferIndex) == false)
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);			
			temBuffer = TEMBuffers.get(bufferIndex);
			outputLength = TEMCrypto.saveKey(keyIndex, temBuffer, (short)0);
			TEMApplet.sendSuccessAndByteShort(apdu, bufferIndex, outputLength);
			break;
			
		case 0x43:
			/**
			 * 	INS 0x43 -- Encrypt data
			 * Parameters:
			 * 	P1 -- key ID of the encryption key
			 *  P2 -- buffer ID of the buffer containing the data to be encrypted
			 * Returns:
			 * 	byte - buffer ID of buffer containing encrypted data
			 *  short -- number of bytes in the encrypted output
			 *           (the buffer may be bigger, padded w/ garbage) 
			 * Throws:
			 *  6A 86 (incorrect P1P2) -- if given an invalid key ID or buffer ID
			 *  6A 84 (file full) -- if there's not enough memory for the buffer
			 * Remarks:
			 *  the input buffer is not released automatically
			 */
		case 0x44:
			/**
			 * 	INS 0x44 -- Decrypt data
			 * Parameters:
			 * 	P1 -- key ID of the encryption key
			 *  P2 -- buffer ID of the buffer containing the data to be decrypted
			 * Returns:
			 * 	byte - buffer ID of buffer containing decrypted data
			 *  short -- number of bytes in the decrypted output
			 *           (the buffer may be bigger, amd padded w/ garbage) 
			 * Throws:
			 *  6A 86 (incorrect P1P2) -- if given an invalid key ID or buffer ID
			 *  6A 84 (file full) -- if there's not enough memory for the buffer
			 * Remarks:
			 *  the input buffer is not released automatically
			 */
			keyIndex = buf[ISO7816.OFFSET_P1];
			bufferIndex = buf[ISO7816.OFFSET_P2];
			if (TEMBuffers.pin(bufferIndex) == false)
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);			
			temBuffer = TEMBuffers.get(bufferIndex);
			
			boolean encrypting = (buf[ISO7816.OFFSET_INS] == 0x43);
			bufferSize = TEMBuffers.size(bufferIndex);
			outputLength = (encrypting) ?
			    TEMCrypto.getEncryptedDataSize(keyIndex, bufferSize) : bufferSize;
			outBufferIndex = TEMBuffers.create(outputLength);
			TEMBuffers.pin(outBufferIndex);
			outBuffer = TEMBuffers.get(outBufferIndex);
			if (outBuffer == null)
				ISOException.throwIt(ISO7816.SW_FILE_FULL);
			outputLength = TEMCrypto.cryptWithKey(keyIndex, temBuffer, (short)0,
			                                      bufferSize, outBuffer, (short)0,
			                                      encrypting);
			TEMBuffers.unpin(outBufferIndex);
			TEMBuffers.unpin(bufferIndex);
			TEMApplet.sendSuccessAndByteShort(apdu, outBufferIndex, outputLength);
			break;
		default:
			// good practice: If you don't know the INStruction, say so:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
}
