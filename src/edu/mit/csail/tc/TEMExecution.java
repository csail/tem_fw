package edu.mit.csail.tc;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * TEM execution engine.
 * 
 * This module is responsible for executing SECs (Security-Enhanced Closures).
 * 
 * @author Victor Costan
 */
class TEMExecution {
	/** No SEC is loaded into the execution engine. */
	public static final byte STATUS_NOSEC = 0;
	/** A SEC is loaded and ready to be executed. */
	public static final byte STATUS_READY = 1;
	/** The SEC has been successfully executed. */
	public static final byte STATUS_SUCCESS = 2;
	/** An exception has occurred while the SEC was executed. */
	public static final byte STATUS_EXCEPTION = 3;
	/** A permanent store fault has occurred while the SEC was executed. */
	public static final byte STATUS_PSFAULT = 4;	
	
	/** The length of the last SEC's output. */
	public static short outLength;	
	/** The ID of the buffer holding the current SEC's output. */
	public static byte outBufferIndex;
	/** The status of the last proc's execution. */
	public static byte status;
	
	/** The SEC buffer to be used when {@link #execute()} is called. */
	public static byte i_secBufferIndex;
	/** The initial IP value to be used when {@link #execute()} is called. */
	private static short i_secIP;
	/** The initial SP value to be used when {@link #execute()} is called. */
	private static short i_secSP;
	/** IF <code>true</code>, the loaded SEC allows development hooks. */
	private static boolean i_devhooks;
	
	/** Keeps track of the keys authorized for use by the bound SEC. */
	private static boolean[] authorizedKeys;
	
	/** The test hash used by the SECpack loader. */
	private static byte[] testHash;

	/** Special value indicating an empty Persistent Store fault register. */
	private static short PS_INVALID = (short)-1;
	/** Persistent Store fault register: the next slot to be used by psnew. */
	private static short i_nextPSCell;
				
	/**
	 * Initializes the TEM execution engine.
	 * Called when the TEM is activated.
	 */
	public static void init() {
		status = STATUS_NOSEC;
		outBufferIndex = TEMBuffers.INVALID_BUFFER;
		i_secBufferIndex = TEMBuffers.INVALID_BUFFER;
		testHash = JCSystem.makeTransientByteArray(TEMCrypto.getDigestLength(),
		    JCSystem.CLEAR_ON_DESELECT);			
		authorizedKeys = JCSystem.makeTransientBooleanArray(TEMCrypto.NUM_KEYS,
        JCSystem.CLEAR_ON_DESELECT);
		// authorizedKeys should start out false
	}
	
	/**
	 * Releases all the resources held by the TEM execution module.
	 * Called when the TEM is deactivated.
	 */	
	public static void deinit() {
		if (status != STATUS_NOSEC) {
			status = STATUS_NOSEC;
			// no need to release buffers, TEMBuffers.deinit() will be called later
			outBufferIndex = TEMBuffers.INVALID_BUFFER;
			i_secBufferIndex = TEMBuffers.INVALID_BUFFER;
		}
		authorizedKeys = null;
		testHash = null;
	}

	/**
	 * Executes the currently bound SEC.
	 * 
	 * For correct functionality, the engine's status should be
	 * {@link #STATUS_READY}.
	 */
	public static void execute() {
		// ASSERT: status == STATUS_READY		
		
		// resume execution
		short sp = TEMExecution.i_secSP;
		short ip = TEMExecution.i_secIP;
		byte[] pBuffer = TEMBuffers.get(TEMExecution.i_secBufferIndex);		
		byte[] outBuffer;
		if (TEMExecution.outBufferIndex == TEMBuffers.INVALID_BUFFER)
			outBuffer = null;
		else {
			TEMBuffers.pin(TEMExecution.outBufferIndex);			
			outBuffer = TEMBuffers.get(TEMExecution.outBufferIndex);			
		}
		short outOffset = TEMExecution.outLength;
		
		// registers
		short opcode;
		short operand1 = (short)0, operand2, operand3, operand4, result;
		boolean condition;
		
		// execute
		try {
			while (true) {
				// vm block
				opcode = pBuffer[ip];
				ip++;
				switch (opcode) {
				
        /**** Arithmetics ****/
				
				case 0x10: // add
        case 0x11: // sub
        case 0x12: // mul
        case 0x13: // div
        case 0x14: // mod
        case 0x15: // available (rotational shift left?)
        case 0x16: // available (rotational shift right?)
        case 0x17: // available (xor?)
					sp -= 2; operand2 = Util.getShort(pBuffer, sp);
					sp -= 2; operand1 = Util.getShort(pBuffer, sp);
					switch(opcode & 0x07) {
					case 0x00: 
						result = (short)(operand1 + operand2); break;
					case 0x01: // sub
						result = (short)(operand1 - operand2); break;
					case 0x02: // mul
						result = (short)(operand1 * operand2); break;
					case 0x03: // div
						result = (short)(operand1 / operand2); break;
					case 0x04: // mod
						result = (short)(operand1 % operand2); break;
					default:   // undefined op
						result = 0;
					}
					Util.setShort(pBuffer, sp, result); sp += 2;
					break;

			  
        /**** Complex memory stream operations ****/
					
        case 0x18: // mdfxb (message digest w/ fixed buffers)
        case 0x19: // mdvb  (message digest w/ variable buffers)
        case 0x1A: // mcmpfxb (memory-compare fixed buffers)
        case 0x1B: // mcmpvb  (memory-compare variable buffers)
        case 0x1C: // mcfxb (memory-copy fixed buffers)
        case 0x1D: // mcvb  (memory-copy variable buffers)
          if ((opcode & 1) != 0) {
            sp -= 2; operand3 = Util.getShort(pBuffer, sp);
            sp -= 2; operand2 = Util.getShort(pBuffer, sp);
            sp -= 2; operand1 = Util.getShort(pBuffer, sp);
          }
          else {
            operand1 = Util.getShort(pBuffer, ip); ip += 2;
            operand2 = Util.getShort(pBuffer, ip); ip += 2;
            operand3 = Util.getShort(pBuffer, ip); ip += 2;
          }
          if ((opcode & 4) != 0) {
            Util.arrayCopyNonAtomic(pBuffer, operand2,
                                    pBuffer, operand3, operand1);
            result = operand1;
          }
          else if ((opcode & 2) != 0) {
              result = Util.arrayCompare(pBuffer, operand2,
                                         pBuffer, operand3, operand1);
          }
          else {
            if (operand3 == -1) {
              result = TEMCrypto.digest(pBuffer, operand2, operand1,
                                        outBuffer, outOffset);
              outOffset += result;
            }
            else
              result = TEMCrypto.digest(pBuffer, operand2, operand1,
                                        pBuffer, operand3);
          }
          Util.setShort(pBuffer, sp, result); sp += 2;          
          break;
          
        case 0x1E: // rnd (generate random data)
          sp -= 2; operand2 = Util.getShort(pBuffer, sp);
          sp -= 2; operand1 = Util.getShort(pBuffer, sp);
          if (operand2 == -1) {
            TEMCrypto.random(outBuffer, outOffset, operand1);
            outOffset += operand1;
          }
          else
            TEMCrypto.random(pBuffer, operand2, operand1);
          break;        
        
        case 0x1F: // unallocated
          break;

          
        /**** Flow control ****/
          
        case 0x21: // jz, je  (jump if zero / equal)
        case 0x22: // ja, jg  (if above zero / greater)
        case 0x23: // jae, jge  (if above or equal to zero / greater or equal)
        case 0x24: // jb, jl  (if below zero / less)
        case 0x25: // jbe, jle  (if below or equal to zero / less or equal)
        case 0x26: // jnz, jne  (if non-zero / equal)
        case 0x27: // jmp (unconditional jump)          
  				if (opcode != 0x27) {
  					// jmp doesn't pop a stack value, everything else does
  					sp -= 2; operand1 = Util.getShort(pBuffer, sp);
  				}
  				operand2 = Util.getShort(pBuffer, ip); ip += 2;
  				condition = false;
  				if ((opcode & 0x01) != 0)
  					condition |= (operand1 == 0);
  				if ((opcode & 0x02) != 0)
  					condition |= (operand1 > 0);
  				if ((opcode & 0x04) != 0)
  					condition |= (operand1 < 0);					
  				if (condition)
  					ip += operand2;
  				break;
  				

  		  /**** Memory access ****/
  				
				case 0x30: // ldbc (load byte constant)
				case 0x31: // ldwc	(load word constant)
				case 0x32: // ldb	(load byte)
				case 0x33: // ldw  (load word)
				case 0x36: // ldbv (load byte from variable address)
				case 0x37: // ldwv (load word from variable address) 
					if ((opcode & 0x02) != 0) { // memory load
						if ((opcode & 0x04) != 0) { // from variable address
							sp -= 2; operand2 = Util.getShort(pBuffer, sp); 
						}
						else { // from fixed address
							operand2 = Util.getShort(pBuffer, ip); ip += 2;
						}						
					}
					else { // constant load
						// NOTE: this relies on the fact that the b0 = 0 for byte and 1 for short
						operand2 = ip; ip += 1 + (opcode & 0x01);
					}							
					if((opcode & 1) != 0)
						result = Util.getShort(pBuffer, operand2);
					else
						result = pBuffer[operand2];
					Util.setShort(pBuffer, sp, result); sp += 2;
					break;
										
				case 0x38:	// stb (store byte)
				case 0x39:	// stw (store word)
				case 0x3A:	// stbv (store byte at variable address)
				case 0x3B:	// stwv (store word at variable address)					
					sp -= 2; operand1 = Util.getShort(pBuffer, sp);
					if ((opcode & 2) != 0) { // variable address
						sp -= 2; operand2 = Util.getShort(pBuffer, sp);
					}
					else { // fixed address
						operand2 = Util.getShort(pBuffer, ip); ip += 2;
					}
					if ((opcode & 1) != 0)
						Util.setShort(pBuffer, operand2, operand1);
					else
						pBuffer[operand2] = (byte)operand1;
					break;
					
				case 0x34:	// pop
					sp -= 2; break;
				case 0x35:	// popn
					operand1 = (short)(pBuffer[ip] << 1); ip++;
					sp -= operand1; break;
				case 0x3C:	// dupn
					operand1 = (short)(pBuffer[ip] << 1); ip++;
					Util.arrayCopyNonAtomic(pBuffer, (short)(sp - operand1),
					                        pBuffer, sp, operand1);
					sp += operand1; break;
				case 0x3D:	// flipn
					operand1 = (short)(pBuffer[ip] << 1); ip++;
					
					operand2 = (short)(sp - 2);
					operand1 = (short)(sp - operand1);
					for (; operand1 < operand2; operand1 += 2, operand2 -= 2) {
						operand3 = Util.getShort(pBuffer, operand1);
						operand4 = Util.getShort(pBuffer, operand2);
						Util.setShort(pBuffer, operand1, operand4);
						Util.setShort(pBuffer, operand2, operand3);
					}
					break;
					
					
				/**** Flow control 2: procedure calls. ****/
				case 0x3E:  // call (call procedure)
          operand1 = Util.getShort(pBuffer, ip); ip += 2;
          Util.setShort(pBuffer, sp, ip); sp += 2;
          ip += operand1;
          break;				  
				case 0x3F:  // ret (return from procedure)
				  sp -= 2; ip = Util.getShort(pBuffer, sp);
				  break;


        /**** Data output ****/
					
				case 0x40:	// outfxb (output fixed buffer)
				case 0x41:	// outvlb (output variable-length buffer)
				case 0x43:	// outvb  (output variable buffer)
					if ((opcode & 1) != 0) {
						if ((opcode & 2) != 0) {
							sp -= 2; operand2 = Util.getShort(pBuffer, sp);						
						}
						else {
							operand2 = Util.getShort(pBuffer, ip); ip += 2;
						}
						sp -= 2; operand1 = Util.getShort(pBuffer, sp);						
					}
					else {
						operand1 = Util.getShort(pBuffer, ip); ip += 2;
						operand2 = Util.getShort(pBuffer, ip); ip += 2;
					}
					Util.arrayCopyNonAtomic(pBuffer, operand2,
					                        outBuffer, outOffset, operand1);
					outOffset += operand1;
					break;
				case 0x42:	// outnew (allocate output buffer)
					sp -= 2; operand1 = Util.getShort(pBuffer, sp);
					TEMExecution.outBufferIndex = TEMBuffers.create(operand1);
					// handler to catch running out of buffer memory
					if (TEMExecution.outBufferIndex == TEMBuffers.INVALID_BUFFER)
						ISOException.throwIt(ISO7816.SW_FILE_FULL);
					TEMBuffers.pin(TEMExecution.outBufferIndex);
					outBuffer = TEMBuffers.get(TEMExecution.outBufferIndex);
					break;
				case 0x44:	// outb	(output byte) 
          sp -= 2; operand1 = Util.getShort(pBuffer, sp);
          outBuffer[outOffset] = (byte)operand1;
          outOffset++;
          break;
				case 0x45:  // outw (output short)
          sp -= 2; operand1 = Util.getShort(pBuffer, sp);
  				Util.setShort(outBuffer, outOffset, operand1);
	  			outOffset += 2;
					break;
				case 0x46:	// halt
					// save the results and exit
					TEMBuffers.unpin(outBufferIndex);
					TEMExecution.outLength = outOffset;
					TEMExecution.status = STATUS_SUCCESS;
					return;
				case 0x47: // psrm (remove persistent store location)
					sp -= 2; operand1 = Util.getShort(pBuffer, sp);
					TEMStore.releaseCell(pBuffer, operand1);
					break;
					
 
				/**** Persistent store operations ****/
					
				case 0x48: // psupfxb (update persistent store, fixed buffers)
				case 0x49: // psupvb  (update persistent store, variable buffers)
				case 0x4A: // pswrfxb (write persistent store, fixed buffers)
				case 0x4B: // pswrvb  (write persistent store, variable buffers)					
				case 0x4C: // psrdfxb (read persistent store, fixed buffers)
				case 0x4D: // psrdvb  (read persistent store, variable buffers)
					if ((opcode & 0x01) != 0) {
						 sp -= 2; operand2 = Util.getShort(pBuffer, sp);
						 sp -= 2; operand1 = Util.getShort(pBuffer, sp);
					}
					else {
						operand1 = Util.getShort(pBuffer, ip); ip += 2;
						operand2 = Util.getShort(pBuffer, ip); ip += 2;
					}
					if ((opcode & 0x04) != 0 && operand2 == -1) {
						condition = TEMStore.readOrWrite(pBuffer, operand1,
						                                 outBuffer, outOffset,
						                                 (opcode & 4) != 0,
						                                 (opcode & 2) != 0);					
						result = condition ? TEMStore.VALUE_SIZE : (short)0;
						outOffset += result;
					}
					else {
						condition = TEMStore.readOrWrite(pBuffer, operand1,
						                                 pBuffer, operand2,
						                                 (opcode & 4) != 0,
						                                 (opcode & 2) != 0);
						result = condition ? TEMStore.VALUE_SIZE : (short)0;						
					}
					if (condition == false) {
						// Abort execution if reading or updating blank cell, or
					  // creating but the pstore is full.
						ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);							
					}
					Util.setShort(pBuffer, sp, result); sp += 2;						
					break;
				case 0x4E: // pshkfxb (persistent store has key, fixed buffers)
				case 0x4F: // pshkvb  (persistent store has key, variable buffers)
					if ((opcode & 0x01) != 0) {
						 sp -= 2; operand1 = Util.getShort(pBuffer, sp);
					}
					else {
						operand1 = Util.getShort(pBuffer, ip); ip += 2;
					}
					result = (short)((TEMStore.findCell(pBuffer, operand1) !=
					                 TEMStore.INVALID_CELL) ? 1 : 0);
					Util.setShort(pBuffer, sp, result); sp += 2;
					break;
					
				
	      /**** Crypto ****/					
					
				case 0x50: // kefxb (key-encrypt with fixed buffers)
				case 0x51: // kevb (key-encrypt with variable buffers)
				case 0x52: // kdfxb (key-decrypt with fixed buffers)
				case 0x53: // kdvb (key-decrypt with variable buffers)
				case 0x54: // ksfxb (key-sign with fixed buffers)
				case 0x55: // ksvb (key-sign with variable buffers)
				case 0x56: // kvsfxb (key-verify signature with fixed buffers)
				case 0x57: // kvsvb (key-verify signature with variable buffers)
					if((opcode & 1) != 0) {
						 sp -= 2; operand3 = Util.getShort(pBuffer, sp);
						 sp -= 2; operand2 = Util.getShort(pBuffer, sp);
						 sp -= 2; operand1 = Util.getShort(pBuffer, sp);
					}
					else {
						operand1 = Util.getShort(pBuffer, ip); ip += 2;
						operand2 = Util.getShort(pBuffer, ip); ip += 2;
						operand3 = Util.getShort(pBuffer, ip); ip += 2;
					}
					sp -= 2; operand4 = Util.getShort(pBuffer, sp);
					if (authorizedKeys[operand4] == false)
						ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);						
					if (operand3 == -1) {
						if ((opcode & 0x04) == 0)
							result = TEMCrypto.cryptWithKey((byte)operand4, pBuffer,
							                                operand2, operand1, outBuffer,
							                                outOffset, ((opcode & 2) == 0));
						else
							result = TEMCrypto.signWithKey((byte)operand4, pBuffer,
							                               operand2, operand1, outBuffer,
							                               outOffset, ((opcode & 2) == 0));
						outOffset += result;
					}
					else {
						if ((opcode & 0x04) == 0)							
							result = TEMCrypto.cryptWithKey((byte)operand4, pBuffer,
							                                operand2, operand1, pBuffer,
							                                operand3, ((opcode & 2) == 0));
						else
							result = TEMCrypto.signWithKey((byte)operand4, pBuffer,
							                               operand2, operand1, pBuffer,
							                               operand3, ((opcode & 2) == 0));
					}
					Util.setShort(pBuffer, sp, result); sp += 2;
					break;
				case 0x5A: // rdk  (read key) 
					sp -= 2; operand1 = Util.getShort(pBuffer, sp);
					result = TEMCrypto.loadKey(pBuffer, operand1);
					if(result != TEMCrypto.INVALID_KEY)
						authorizedKeys[result] = true;
					Util.setShort(pBuffer, sp, result); sp += 2;
					break;
				case 0x5B: // stk (store key)
					sp -= 2; operand2 = Util.getShort(pBuffer, sp);
					sp -= 2; operand1 = Util.getShort(pBuffer, sp);
					if(authorizedKeys[operand1] == false)
						ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
					if(operand2 == (short)-1) {
						result = TEMCrypto.saveKey((byte)operand1, outBuffer, outOffset);
						outOffset += result;						
					}
					else
						result = TEMCrypto.saveKey((byte)operand1, pBuffer, operand2);
					Util.setShort(pBuffer, sp, result); sp += 2;
					break;
				case 0x5C: // relk (release key)
					sp -= 2; operand1 = Util.getShort(pBuffer, sp);
					if(authorizedKeys[operand1] == false)
						ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
					TEMCrypto.releaseKey((byte)operand1);
					break;
				case 0x5D: // ldkl (load key length)
					sp -= 2; operand1 = Util.getShort(pBuffer, sp);
					if(authorizedKeys[operand1] == false)
						ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
					result = TEMCrypto.getKeyLength((byte)operand1);
					Util.setShort(pBuffer, sp, result); sp += 2;
					break;
				case 0x5E: // genkp (generate key pair)
					operand1 = pBuffer[ip]; ip++;
					result = TEMCrypto.generateKey(operand1 == 0);
					operand2 = (short)(result >> 8);
					operand3 = (short)(result & 0xff);
					if(operand2 != TEMCrypto.INVALID_KEY)
						authorizedKeys[operand2] = true;
					if(operand3 != TEMCrypto.INVALID_KEY)
						authorizedKeys[operand3] = true;
												
					Util.setShort(pBuffer, sp, operand2); sp += 2;
					Util.setShort(pBuffer, sp, operand3); sp += 2;
					break;
				case 0x5F: // authk (authorize key)
					sp -= 2; operand1 = Util.getShort(pBuffer, sp);
					operand2 = Util.getShort(pBuffer, ip); ip += 2;
					
					if(authorizedKeys[operand1]) {
						// key already authorized, SEC can set/change its authorization
						TEMCrypto.setKeyAuth((byte)operand1, pBuffer, operand2);
						result = operand1;							
					}
					else {
						// SEC trying to get authorization to use key
						if(TEMCrypto.verifyKeyAuth((byte)operand1, pBuffer, operand2)) {
							authorizedKeys[operand1] = true;
							result = operand1;	
						}
						else
							result = (short)-1;
					}
					Util.setShort(pBuffer, sp, result); sp += 2;
					break;
				}
			}
		}
		catch (Exception e) { // developer "production" mode
//		catch(APDUException e) { // DEBUG MODE -- trick that invalidates this line and traps the debugger
			status = STATUS_EXCEPTION;
			
			// for developers: save the SEC trace (production TEMs don't need this)
			TEMExecution.i_secIP = ip;
			TEMExecution.i_secSP = sp;
			TEMExecution.outLength = outOffset;
		}
	}
	
	/**
	 * Binds the SEC contained in a SECpack to the execution engine.
	 * 
	 * After this call succeeds, the SEC can be executed by calling 
	 * {@link #execute()}. For correct functionality,
	 * {@link #bindSecPack(byte, byte)} should only be called when the engine's
	 * status is {@link #STATUS_NOSEC}.
	 * 
	 * The SECpack is decoded in-place, so the buffer received should be large
	 * enough to hold the decoded SECpack. 
	 * 
	 * @param keyIndex the ID of a key that can decrypt the SECpack
	 * @param secPackIndex the ID of the buffer containing the SECpack whose SEC
	 *                     will be decrypted and bound
	 * @return <code>true</code> if unpacking succeeded, or <code>false</code> if
	 *         the SECpack unpacking failed (perhaps
	 */
	public static boolean bindSecPack(byte keyIndex, byte secPackIndex) {
		// ASSERT: status == STATUS_NOSEC
				
		byte[] secPack = TEMBuffers.get(secPackIndex);
		short secPackLength = TEMBuffers.size(secPackIndex);

		// Refuse SECpacks using incompatible formats.
		if (secPack[0] != (byte)1)
			return false;
		
		// Pick up the header parts that are interesting.
		TEMExecution.i_secSP = Util.getShort(secPack, (short)8);
		TEMExecution.i_secIP = Util.getShort(secPack, (short)10);
		TEMExecution.i_devhooks = (byte)(secPack[1] & (byte)1) != (byte)0;		
		
		// Compute sizes for all SECimage parts.
		short headerSize = TEMCrypto.getDigestBlockLength();
		short frozenSize = Util.getShort(secPack, (short)2);
		short privateSize = Util.getShort(secPack, (short)4);
		short zerosSize = Util.getShort(secPack, (short)6);
		short cryptedSize = (frozenSize != 0 || privateSize != 0) ?
		    TEMCrypto.getEncryptedDataSize(keyIndex,
        (short)(privateSize + TEMCrypto.getDigestLength())) : 0;
		short securedPackSize = (short)(frozenSize + cryptedSize + headerSize);
		short plainPackSize = (short)(secPackLength - securedPackSize); 		

		if (cryptedSize != 0) {
			// The SEC image must be able to hold the signature, since we'll be
		  // dumping it there temporarily.
			if((short)(zerosSize + plainPackSize) < TEMCrypto.getDigestLength())
				zerosSize = (short)(TEMCrypto.getDigestLength() - plainPackSize);			
		}
				
		// Save the header for signature checking.
		Util.arrayCopyNonAtomic(secPack, (short)0, testHash, (short)0, headerSize);
		// Put together the SEC image.
		Util.arrayCopyNonAtomic(secPack, headerSize, secPack, (short)0, frozenSize);
		short secOffset = frozenSize;
		if (frozenSize != 0 || privateSize != 0) {
			// Decrypt the secret part and check the signature
			TEMCrypto.cryptWithKey(keyIndex, secPack,
			                       (short)(frozenSize + headerSize), cryptedSize,
			                       secPack, frozenSize, false);
			secOffset += privateSize;
			
			TEMCrypto.digest2(testHash, (short)0, headerSize, secPack, (short)0,
			                  secOffset, testHash, (short)0);
			if (Util.arrayCompare(testHash, (short)0, secPack, secOffset,
			                      (short)testHash.length) != 0) {
				// Signature check failed.
				// TODO: set better exception checking
				return false;
			}
		}
		Util.arrayCopyNonAtomic(secPack, securedPackSize,
		                        secPack, secOffset, plainPackSize);
		Util.arrayFillNonAtomic(secPack, (short)(secOffset + plainPackSize),
		                        (short)(secPackLength - secOffset - plainPackSize),
		                        (byte)0);
		
		// Unpacking succeeded, set the SEC execution context.
		TEMExecution.i_secBufferIndex = secPackIndex;
		TEMExecution.i_nextPSCell = PS_INVALID;
		TEMExecution.outLength = 0;
		TEMExecution.status = STATUS_READY;
		
		return true;
	}

	/**
	 * Unbinds the currently bound SEC from the engine.
	 * 
	 * This releases the resources associated with the bound SEC, and prepares the
	 * engine for accepting another SECpack.
	 */
	public static void unbindSec() {
		// Drop the SEC buffer
		TEMBuffers.unpin(TEMExecution.i_secBufferIndex);
		TEMBuffers.release(TEMExecution.i_secBufferIndex);
		TEMExecution.i_secBufferIndex = TEMBuffers.INVALID_BUFFER;
		
		// Drop the volatile (non-persistent) SEC keys
		TEMCrypto.releaseVolatileKeys();
		for (short i = 0; i < authorizedKeys.length; i++)
			authorizedKeys[i] = false;
		
		if (TEMExecution.status != STATUS_SUCCESS) {
			// Since the SEC didn't execute well, discard any output.
			if (TEMExecution.outBufferIndex != TEMBuffers.INVALID_BUFFER) {
				TEMBuffers.unpin(TEMExecution.outBufferIndex);
				TEMBuffers.release(TEMExecution.outBufferIndex);
			}
		}
		TEMExecution.outBufferIndex = TEMBuffers.INVALID_BUFFER;
		TEMExecution.status = STATUS_NOSEC;
	}

	/** The version of the trace output format. */
	private static final short TRACE_VERSION = (short)0x01;
	
	/**
	 * Produces a trace of the current SEC status.
	 * 
	 * @param buffer the buffer that the trace will be written to
	 * @param offset the offset of the first byte in the buffer that will receive
	 *               the trace
	 * @return the length of the trace produced
	 */
	public static final short devTrace(byte[] buffer, short offset) {
		if (i_devhooks == false) return 0;
		
		Util.setShort(buffer, offset, TRACE_VERSION);
		Util.setShort(buffer, (short)(offset + 2), TEMExecution.i_secSP);
		Util.setShort(buffer, (short)(offset + 4), TEMExecution.i_secIP);
		Util.setShort(buffer, (short)(offset + 6), TEMExecution.outLength);
		Util.setShort(buffer, (short)(offset + 8), TEMExecution.i_nextPSCell);
		
		return (short)10;
	}
	
	/**
	 * Fixes a Persistent Store fault.
	 * 
   * This is called when the driver responds to a Persistent Store fault. The
   * fault is fixed accoding to the given instructions, and the execution engine
   * becomes ready to resume SEC execution. 
	 * 
	 * @param nextCell the next PStore cell to be used by psnew
	 * 
	 */
	public static final void solvePStoreFault(short nextCell) {
		// ASSERT: status == STATUS_PSFAULT
		TEMExecution.i_nextPSCell = nextCell;
		TEMExecution.status = STATUS_READY;
	}
}
