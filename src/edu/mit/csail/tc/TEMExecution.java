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
	/** An exception has occured while the SEC was executed. */
	public static final byte STATUS_EXCEPTION = 3;
	/** A permanent store fault has occured while the SEC was executed. */
	public static final byte STATUS_PSFAULT = 4;	
	
	/** The length of the last SEC's output. */
	public static short outLength;	
	/** The ID of the buffer holding the current SEC's output. */
	public static byte outBufferIndex;
	/** The status of the last proc's execution. */
	public static byte status;
	
	/** The SEC buffer to be used when {@link #execute(short, short, byte[])} is called. */
	public static byte i_secBufferIndex;
	/** The initial IP value to be used when {@link #execute(short, short, byte[])} is called. */
	private static short i_secIP;
	/** The initial SP value to be used when {@link #execute(short, short, byte[])} is called. */
	private static short i_secSP;
	/** IF <code>true</code>, the currently loaded SEC allows development hooks. */
	private static boolean i_devhooks;
	
	/** Keeps track of the keys authorized for use by the currently bound SEC. */
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
		testHash = JCSystem.makeTransientByteArray(TEMCrypto.getDigestLength(), JCSystem.CLEAR_ON_DESELECT);			
		authorizedKeys = JCSystem.makeTransientBooleanArray(TEMCrypto.NUM_KEYS, JCSystem.CLEAR_ON_DESELECT);
		// authorizedKeys should start out false
	}
	
	/**
	 * Releases all the resources held by the TEM execution module.
	 * Called when the TEM is de-activated.
	 */	
	public static void deinit() {
		if(status != STATUS_NOSEC) {
			status = STATUS_NOSEC;
			// no need to release buffers because TEMBuffers is getting de-initialized too
			outBufferIndex = TEMBuffers.INVALID_BUFFER;
			i_secBufferIndex = TEMBuffers.INVALID_BUFFER;
		}
		authorizedKeys = null;
		testHash = null;
	}

	/**
	 * Executes the currently bound SEC.
	 * 
	 * For correct functionality, the engine's status should be {@link #STATUS_READY}.
	 */
	public static void execute() {
		// ASSERT: status == STATUS_READY		
		
		// resume execution
		short sp = TEMExecution.i_secSP;
		short ip = TEMExecution.i_secIP;
		byte[] pBuffer = TEMBuffers.get(TEMExecution.i_secBufferIndex);		
		byte[] outBuffer;
		if(TEMExecution.outBufferIndex == TEMBuffers.INVALID_BUFFER)
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
			while(true) {
				// vm block
				opcode = pBuffer[ip];
				ip++;
				switch(opcode >> 4) {
				case 0x1:
					if((opcode & 8) == 0) {
						// binary arithmetics
						// result = operand1 OP operand2
						sp -= (short)2; operand2 = Util.getShort(pBuffer, sp);
						sp -= (short)2; operand1 = Util.getShort(pBuffer, sp);
						switch(opcode & 0x07) {
						case 0x00: // add
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
					}
					else {
						// complex memory stream operations
						switch(opcode & 0x07) {
						case 0x00: // mdfxb (message digest w/ fixed buffers)
						case 0x01: // mdvb  (message digest w/ variable buffers)
						case 0x02: // mcmpfxb (memory-compare fixed buffers)
						case 0x03: // mcmpvb  (memory-compare variable buffers)
						case 0x04: // mcfxb (memory-copy fixed buffers)
						case 0x05: // mcvb  (memory-copy variable buffers)
							if((opcode & 1) != 0) {
								 sp -= (short)2; operand3 = Util.getShort(pBuffer, sp);
								 sp -= (short)2; operand2 = Util.getShort(pBuffer, sp);
								 sp -= (short)2; operand1 = Util.getShort(pBuffer, sp);
							}
							else {
								operand1 = Util.getShort(pBuffer, ip); ip += 2;
								operand2 = Util.getShort(pBuffer, ip); ip += 2;
								operand3 = Util.getShort(pBuffer, ip); ip += 2;
							}
							if((opcode & 4) != 0) {
								Util.arrayCopyNonAtomic(pBuffer, operand2, pBuffer, operand3, operand1);
								result = operand1;
							}
							else if((opcode & 2) != 0) {
									result = (short)Util.arrayCompare(pBuffer, operand2, pBuffer, operand3, operand1);
							}
							else
								if(operand3 == (short)-1) {
									result = TEMCrypto.digest(pBuffer, operand2, operand1, outBuffer, outOffset);
									outOffset += result;
								}
								else
									result = TEMCrypto.digest(pBuffer, operand2, operand1, pBuffer, operand3);
							Util.setShort(pBuffer, sp, result); sp += 2;					
							break;
						case 0x06: // rnd (generate random data)
							sp -= (short)2; operand2 = Util.getShort(pBuffer, sp);
							sp -= (short)2; operand1 = Util.getShort(pBuffer, sp);
							if(operand2 == (short)-1) {
								TEMCrypto.random(outBuffer, outOffset, operand1);
								outOffset += operand1;
							}
							else
								TEMCrypto.random(pBuffer, operand2, operand1);
							break;						
						}
					}
					break;					
				case 0x2:
					// conditionals
					switch(opcode & 0x0f) {					
					case 0x01:	// jz, je	(jump if zero / equal)
					case 0x06:	// jnz, jne  (jump if non-zero / equal)
					case 0x02:	// ja, jg	(jump if above zero / greater)
					case 0x03:	// jae, jge	(jump if above or equal to zero / greater or equal)
					case 0x04:	// jb, jl	(jump if below zero / less)
					case 0x05:	// jbe, jle	(jump if below or equal to zero / less or equal)
					case 0x07:	// jmp	(jump)
						if(opcode != 0x27) {
							// jmp doesn't need a stack value, everything else does
							sp -= (short)2; operand1 = Util.getShort(pBuffer, sp);
						}
						operand2 = Util.getShort(pBuffer, ip); ip += 2;
						condition = false;
						if((opcode & 0x01) != 0)
							condition |= (operand1 == (short)0);
						if((opcode & 0x02) != 0)
							condition |= (operand1 > (short)0);
						if((opcode & 0x04) != 0)
							condition |= (operand1 < (short)0);					
						if(condition)
							ip += operand2;
						break;
					default:	// undefined
					}
					break;
				case 0x3:
					// memory access
					switch(opcode & 0x0f) {
					case 0x00:	// ldbc (load byte constant)
					case 0x01:	// ldwc	(load word constant)
					case 0x02:	// ldb	(load byte)
					case 0x03:	// ldw  (load word)
					case 0x06:	// ldbv (load byte from variable address)
					case 0x07:  // ldwv (load word from variable address) 
						if((opcode & 0x02) != 0) { // memory load
							if((opcode & 0x04) != 0) { // from variable address
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
							result = (short)pBuffer[operand2];
						Util.setShort(pBuffer, sp, result); sp += 2;
						break;				
					case 0x08:	// stb (store byte)
					case 0x09:	// stw (store word)
					case 0x0A:	// stbv (store byte at variable address)
					case 0x0B:	// stwv (store word at variable address)					
						sp -= (short)2; operand1 = Util.getShort(pBuffer, sp);
						if((opcode & 2) != 0) { // variable address
							sp -= 2; operand2 = Util.getShort(pBuffer, sp);
						}
						else { // fixed address
							operand2 = Util.getShort(pBuffer, ip); ip += 2;
						}
						if((opcode & 1) != 0)
							Util.setShort(pBuffer, operand2, operand1);
						else
							pBuffer[operand2] = (byte)operand1;
						break;
					case 0x04:	// pop
						sp -= (short)2; break;
					case 0x05:	// popn
						operand1 = (short)((short)pBuffer[ip] * (short)2); ip++;
						sp -= operand1; break;
					case 0x0C:	// dupn
						operand1 = (short)((short)pBuffer[ip] * (short)2); ip++;
						Util.arrayCopyNonAtomic(pBuffer, (short)(sp - operand1), pBuffer, sp, operand1);
						sp += operand1; break;
					case 0x0D:	// flipn
						operand1 = (short)((short)pBuffer[ip] * (short)2); ip++;
						
						operand2 = (short)(sp - (short)2);
						operand1 = (short)(sp - operand1);
						for(; operand1 < operand2; operand1 += (short)2, operand2 -= (short)2) {
							operand3 = Util.getShort(pBuffer, operand1);
							operand4 = Util.getShort(pBuffer, operand2);
							Util.setShort(pBuffer, operand1, operand4);
							Util.setShort(pBuffer, operand2, operand3);
						}
						break;
					default:	// invalid opcode
						break;
					}
					break;
				case 0x4:
					// output data
					switch(opcode & 0x0f) {
					case 0x00:	// outfxb (output fixed buffer)
					case 0x01:	// outvlb (output variable-length buffer)
					case 0x03:	// outvb  (output variable buffer)
						if((opcode & 1) != 0) {
							if((opcode & 2) != 0) {
								sp -= (short)2; operand2 = Util.getShort(pBuffer, sp);						
							}
							else {
								operand2 = Util.getShort(pBuffer, ip); ip += 2;
							}
							sp -= (short)2; operand1 = Util.getShort(pBuffer, sp);						
						}
						else {
							operand1 = Util.getShort(pBuffer, ip); ip += 2;
							operand2 = Util.getShort(pBuffer, ip); ip += 2;
						}
						Util.arrayCopyNonAtomic(pBuffer, operand2, outBuffer, outOffset, operand1);
						outOffset += operand1;
						break;
					case 0x02:	// outnew (allocate output buffer)
						sp -= (short)2; operand1 = Util.getShort(pBuffer, sp);
						TEMExecution.outBufferIndex = TEMBuffers.create(operand1);
						// handler to catch running out of buffer memory
						if(TEMExecution.outBufferIndex == TEMBuffers.INVALID_BUFFER)
							ISOException.throwIt(ISO7816.SW_FILE_FULL);
						TEMBuffers.pin(TEMExecution.outBufferIndex);
						outBuffer = TEMBuffers.get(TEMExecution.outBufferIndex);
						break;
					case 0x04:	// outb	(output byte) 
					case 0x05:  // outw (output short)
						sp -= (short)2; operand1 = Util.getShort(pBuffer, sp);
						if((opcode & 1) != 0) {
							Util.setShort(outBuffer, outOffset, operand1);
							outOffset += (short)2;
						}
						else {
							outBuffer[outOffset] = (byte)operand1;
							outOffset++;
						}
						break;
					case 0x06:	// halt
						// save the results and exit
						TEMBuffers.unpin(outBufferIndex);
						TEMExecution.outLength = outOffset;
						TEMExecution.status = STATUS_SUCCESS;
						return;
					case 0x07: // psrm (remove persistent store location)
						sp -= (short)2; operand1 = Util.getShort(pBuffer, sp);
						TEMStore.releaseCell(pBuffer, operand1);
						break;
					case 0x08: // psupfxb (update persistent store, fixed buffers)
					case 0x09: // psupvb  (update persistent store, variable buffers)
					case 0x0A: // pswrfxb (write persistent store, fixed buffers)
					case 0x0B: // pswrvb  (write persistent store, variable buffers)					
					case 0x0C: // psrdfxb (read persistent store, fixed buffers)
					case 0x0D: // psrdvb  (read persistent store, variable buffers)
						if((opcode & 0x01) != 0) {
							 sp -= (short)2; operand2 = Util.getShort(pBuffer, sp);
							 sp -= (short)2; operand1 = Util.getShort(pBuffer, sp);
						}
						else {
							operand1 = Util.getShort(pBuffer, ip); ip += 2;
							operand2 = Util.getShort(pBuffer, ip); ip += 2;
						}
						if((opcode & 0x04) != 0 && operand2 == (short)-1) {
							condition = TEMStore.readOrWrite(pBuffer, operand1, outBuffer, outOffset, (opcode & 4) != 0, (opcode & 2) != 0);					
							result = condition ? TEMStore.VALUE_SIZE : (short)0;
							outOffset += result;
						}
						else {
							condition = TEMStore.readOrWrite(pBuffer, operand1, pBuffer, operand2, (opcode & 4) != 0, (opcode & 2) != 0);
							result = condition ? TEMStore.VALUE_SIZE : (short)0;						
						}
						if(condition == false) {
							// abort execution if reading or updating blank cell, or creating but the pstore is full  
							ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);							
						}
						Util.setShort(pBuffer, sp, result); sp += 2;						
						break;
					case 0x0E: // pshkfxb (persistent store has key, fixed buffers)
					case 0x0F: // pshkvb  (persistent store has key, variable buffers)
						if((opcode & 0x01) != 0) {
							 sp -= (short)2; operand1 = Util.getShort(pBuffer, sp);
						}
						else {
							operand1 = Util.getShort(pBuffer, ip); ip += 2;
						}
						result = (TEMStore.findCell(pBuffer, operand1) != TEMStore.INVALID_CELL) ? (short)1 : (short)0;
						Util.setShort(pBuffer, sp, result); sp += 2;						
						break;
					/*
					case 0x0C: // psnew (new persistent store location)
						if(i_nextPSCell == PS_INVALID) {
							// generate a Persistent Store fault
							if(outBufferIndex != TEMBuffers.INVALID_BUFFER)
								TEMBuffers.unpin(outBufferIndex);
							TEMExecution.outLength = outOffset;
							TEMExecution.i_secIP = (short)(ip - (short)1);							
							TEMExecution.i_secSP = sp;
							TEMExecution.status = STATUS_PSFAULT;
							return;
						}
						
						// the Persistent Store fault has been resolved
						sp -= (short)2; operand1 = Util.getShort(pBuffer, sp);
						
						result = TEMStore.ADDRESS_SIZE;
						if(operand1 == (short)-1) {
							TEMStore.makeLocation(i_nextPSCell, outBuffer, outOffset);
							outOffset += result;
						}
						else
							TEMStore.makeLocation(i_nextPSCell, pBuffer, operand1);
						Util.setShort(pBuffer, sp, result); sp += 2;

						// set the PS cell to invalid so the next psnew will also require a load
						i_nextPSCell = PS_INVALID;
						break;
					*/
					}
					break;
				case 0x5: // crypto
					switch(opcode & 0x0f) {
					case 0x00: // kefxb (key-encrypt with fixed buffers)
					case 0x01: // kevb (key-encrypt with variable buffers)
					case 0x02: // kdfxb (key-decrypt with fixed buffers)
					case 0x03: // kdvb (key-decrypt with variable buffers)
					case 0x04: // ksfxb (key-sign with fixed buffers)
					case 0x05: // ksvb (key-sign with variable buffers)
					case 0x06: // kvsfxb (key-verify signature with fixed buffers)
					case 0x07: // kvsvb (key-verify signature with variable buffers)
						if((opcode & 1) != 0) {
							 sp -= (short)2; operand3 = Util.getShort(pBuffer, sp);
							 sp -= (short)2; operand2 = Util.getShort(pBuffer, sp);
							 sp -= (short)2; operand1 = Util.getShort(pBuffer, sp);
						}
						else {
							operand1 = Util.getShort(pBuffer, ip); ip += 2;
							operand2 = Util.getShort(pBuffer, ip); ip += 2;
							operand3 = Util.getShort(pBuffer, ip); ip += 2;
						}
						sp -= (short)2; operand4 = Util.getShort(pBuffer, sp);
						if(authorizedKeys[operand4] == false)
							ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);						
						if(operand3 == (short)-1) {
							if((opcode & 0x04) == 0)
								result = TEMCrypto.cryptWithKey((byte)operand4, pBuffer, operand2, operand1, outBuffer, outOffset, ((opcode & 2) == 0));
							else
								result = TEMCrypto.signWithKey((byte)operand4, pBuffer, operand2, operand1, outBuffer, outOffset, ((opcode & 2) == 0));
							outOffset += result;
						}
						else {
							if((opcode & 0x04) == 0)							
								result = TEMCrypto.cryptWithKey((byte)operand4, pBuffer, operand2, operand1, pBuffer, operand3, ((opcode & 2) == 0));
							else
								result = TEMCrypto.signWithKey((byte)operand4, pBuffer, operand2, operand1, pBuffer, operand3, ((opcode & 2) == 0));
						}
						Util.setShort(pBuffer, sp, result); sp += 2;
						break;
					case 0x0A: // rdk  (read key) 
						sp -= (short)2; operand1 = Util.getShort(pBuffer, sp);
						result = TEMCrypto.loadKey(pBuffer, operand1);
						if(result != TEMCrypto.INVALID_KEY)
							authorizedKeys[result] = true;
						Util.setShort(pBuffer, sp, result); sp += 2;
						break;
					case 0x0B: // stk (store key)
						sp -= (short)2; operand2 = Util.getShort(pBuffer, sp);
						sp -= (short)2; operand1 = Util.getShort(pBuffer, sp);
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
					case 0x0C: // relk (release key)
						sp -= (short)2; operand1 = Util.getShort(pBuffer, sp);
						if(authorizedKeys[operand1] == false)
							ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
						TEMCrypto.releaseKey((byte)operand1);
						break;
					case 0x0D: // ldkl (load key length)
						sp -= (short)2; operand1 = Util.getShort(pBuffer, sp);
						if(authorizedKeys[operand1] == false)
							ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
						result = TEMCrypto.getKeyLength((byte)operand1);
						Util.setShort(pBuffer, sp, result); sp += 2;
						break;
					case 0x0E: // genkp (generate key pair)
						operand1 = (short)pBuffer[ip]; ip++;
						result = TEMCrypto.generateKey(operand1 == 0);
						operand2 = (short)(result >> 8);
						operand3 = (short)(result & (short)0xff);
						if(operand2 != TEMCrypto.INVALID_KEY)
							authorizedKeys[operand2] = true;
						if(operand3 != TEMCrypto.INVALID_KEY)
							authorizedKeys[operand3] = true;
													
						Util.setShort(pBuffer, sp, operand2); sp += 2;
						Util.setShort(pBuffer, sp, operand3); sp += 2;
						break;
					case 0x0F: // authk (authorize key)
						sp -= (short)2; operand1 = Util.getShort(pBuffer, sp);
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
					}
				}
			}
		}
		catch(Exception e) { // developer "production" mode
//		catch(APDUException e) { // DEBUG MODE -- trick that invalidates this line and traps the debugger
			status = STATUS_EXCEPTION;
			
			// for developers: save the SEC trace (production TEMs don't need this)
			TEMExecution.i_secIP = ip;
			TEMExecution.i_secSP = sp;
			TEMExecution.outLength = outOffset;
		}
	}
	
	/**
	 * Binds the SEC contained in a SECpack to the engine, so the SEC can be executed.
	 * @param keyIndex the ID of the key which can decrypt the SECpack
	 * @param secPack the SECpack containing the SEC to be bound
	 * @param secPackLength the length of SECpack containing the SEC to be bound
	 * @return <code>true</code> if unpacking succeeded, or <code>false</code> if SECpack unpacking failed
	 * 
	 * For correct functionality, the engine's status should be {@link #STATUS_NOSEC}.
	 */
	public static boolean bindSecPack(byte keyIndex, byte[] secPack, short secPackLength) {
		// ASSERT: status == STATUS_NOSEC
		
		// refuse SECpacks we can't read
		if(secPack[0] != (byte)1)
			return false;
		
		// compute sizes for all SECimage parts
		short headerSize = TEMCrypto.getDigestBlockLength();
		short frozenSize = Util.getShort(secPack, (short)2);
		short privateSize = Util.getShort(secPack, (short)4);
		short zerosSize = Util.getShort(secPack, (short)6);
		short cryptedSize = (frozenSize != 0 || privateSize != 0) ? TEMCrypto.getEncryptedBlockSize(keyIndex, (short)(privateSize + TEMCrypto.getDigestLength())) : 0;
		short imageSize = (short)(secPackLength - headerSize + privateSize - cryptedSize);
		short securedPackSize = (short)(frozenSize + cryptedSize + headerSize);
		short plainPackSize = (short)(secPackLength - securedPackSize); 		

		if(cryptedSize != 0) {
			// the SEC image must be able to hold the signature, since we'll be dumping it there temporarily
			if((short)(zerosSize + plainPackSize) < TEMCrypto.getDigestLength())
				zerosSize = (short)(TEMCrypto.getDigestLength() - plainPackSize);			
		}
		
		// allocate the SEC buffer		
		byte secBufferIndex = TEMBuffers.create((short)(imageSize + zerosSize));
		if(secBufferIndex == TEMBuffers.INVALID_BUFFER) return false;
		TEMBuffers.pin(secBufferIndex);
		byte[] secBuffer = TEMBuffers.get(secBufferIndex);		
		
		// assemble the SEC image
		Util.arrayCopyNonAtomic(secPack, headerSize, secBuffer, (short)0, frozenSize);
		short secOffset = (short)frozenSize;
		if(frozenSize != 0 || privateSize != 0) {
			// decrypt and check signature
			TEMCrypto.cryptWithKey(keyIndex, secPack, (short)(frozenSize + headerSize), cryptedSize, secBuffer, frozenSize, false);
			secOffset += privateSize;
			
			TEMCrypto.digest2(secPack, (short)0, headerSize, secBuffer, (short)0, secOffset, testHash, (short)0);
			if(Util.arrayCompare(testHash, (short)0, secBuffer, secOffset, (short)testHash.length) != 0) {
				// signature check failed
				// TODO: set better exception checking
				TEMBuffers.unpin(secBufferIndex);
				TEMBuffers.release(secBufferIndex);
				return false;
			}
		}
		Util.arrayCopyNonAtomic(secPack, securedPackSize, secBuffer, secOffset, plainPackSize);
		
		// prepare for SEC execution
		TEMExecution.i_secBufferIndex = secBufferIndex;
		TEMExecution.i_secSP = Util.getShort(secPack, (short)8);
		TEMExecution.i_secIP = Util.getShort(secPack, (short)10);
		TEMExecution.i_devhooks = (byte)(secPack[1] & (byte)1) != (byte)0;
		TEMExecution.i_nextPSCell = PS_INVALID;
		TEMExecution.outLength = 0;
		TEMExecution.status = STATUS_READY;
		
		TEMBuffers.unpin(secBufferIndex);
		return true;
	}

	/**
	 * Unbinds the currently bound SEC from the engine.
	 * 
	 * This releases the resources associated with the bound SEC, and
	 * prepares the engine for accepting another SECpack.
	 */
	public static void unbindSec() {
		// drop the SEC buffer
		TEMBuffers.unpin(TEMExecution.i_secBufferIndex);
		TEMBuffers.release(TEMExecution.i_secBufferIndex);
		TEMExecution.i_secBufferIndex = TEMBuffers.INVALID_BUFFER;
		
		// drop the volatile (non-persistent) SEC keys
		TEMCrypto.releaseVolatileKeys();
		for(short i = 0; i < authorizedKeys.length; i++)
			authorizedKeys[i] = false;
		
		if(TEMExecution.status != STATUS_SUCCESS) {
			// the SEC didn't execute well; discard its output, if it exists
			if(TEMExecution.outBufferIndex != TEMBuffers.INVALID_BUFFER) {
				TEMBuffers.unpin(TEMExecution.outBufferIndex);
				TEMBuffers.release(TEMExecution.outBufferIndex);
			}
		}
		TEMExecution.outBufferIndex = TEMBuffers.INVALID_BUFFER;
		TEMExecution.status = STATUS_NOSEC;
	}
	
	/**
	 * Produces a trace of the current SEC status.
	 * @param buffer the buffer that the trace will be written to
	 * @param offset the offset of the first byte in the buffer that will receive the trace
	 * @return the length of the trace produced
	 */
	public static short devTrace(byte[] buffer, short offset) {
		if(i_devhooks == false) return 0;
		
		Util.setShort(buffer, offset, (short)0x01); // trace format version
		Util.setShort(buffer, (short)(offset + (short)2), TEMExecution.i_secSP);
		Util.setShort(buffer, (short)(offset + (short)4), TEMExecution.i_secIP);
		Util.setShort(buffer, (short)(offset + (short)6), TEMExecution.outLength);
		Util.setShort(buffer, (short)(offset + (short)8), TEMExecution.i_nextPSCell);
		
		return (short)10;
	}
	
	/**
	 * Fixes a Persistent Store fault.
	 * @param nextCell the next PStore cell to be used by psnew
	 * 
	 * This is called when the driver responds to a Persistent Store fault.
	 * The fault is fixed accoding to the given instructions, and the
	 * execution engine becomes ready to resume SEC execution. 
	 */
	public static void solvePStoreFault(short nextCell) {
		// ASSERT: status == STATUS_PSFAULT
		TEMExecution.i_nextPSCell = nextCell;
		TEMExecution.status = STATUS_READY;
	}
}
