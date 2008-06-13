package edu.mit.csail.tc;

import javacard.framework.APDU;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * TEM memory management module.
 * @author Victor Costan
 * 
 * This module manages the memories available in a Javacard chip. Its main reason of
 * existence is that normal APDUs can only carry 256 bytes of data, and TEM procs are
 * much bigger than that. The module now has versatile logic which juggles between
 * volatile and non-volatile memory. 
 */
class TEMBuffers {
	/**
	 * The buffer file (parallel: register file).
	 * Allocated as <code>CLEAR_ON_DESELECT</code> memory, since buffers are temporary in nature.
	 */
	private static Object[] buffers;
	/**
	 * The requested sizes of the buffers in the file.
	 */
	private static short[] sizes;
	/**
	 * Pinned and busy flags for each buffer.
	 * Allocated as <code>CLEAR_ON_DESELECT</code> memory, since buffers are temporary in nature.
	 */
	private static byte[] flags;
	
	/** Number of entries in the buffer file. */
	public static byte NUM_BUFFERS = 8;
	
	/** Returned by {@link #create(short)} to communicate failure. */
	public static byte INVALID_BUFFER = -1;
	
	/** The size of a buffer chunk. */
	public static short chunkSize;
	
	/**
	 * Initializes the TEM buffer module.
	 * Called when the TEM is activated.
	 * @return <code>true</code> if all is good, <code>false</code> if the TEM is already initialized
	 */
	public static boolean init() {
		// initialize the buffer file
		if(buffers != null)
			return false;
		buffers = JCSystem.makeTransientObjectArray(NUM_BUFFERS, JCSystem.CLEAR_ON_DESELECT);
		// buffers should start out null
		flags = JCSystem.makeTransientByteArray(NUM_BUFFERS, JCSystem.CLEAR_ON_DESELECT);
		// flags should start out zeroed
		sizes = JCSystem.makeTransientShortArray(NUM_BUFFERS, JCSystem.CLEAR_ON_DESELECT);
		return true;
	}
	
	/**
	 * Lays out the TEM buffers into memory.
	 * Called when the TEM is activated, after all the other modules claimed their card memory.
	 */
	public static void layout() {		
		// initial memory layout - RAM
		for(byte i = 0; i <= 1; i++) {
			short availableMemory = JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
			availableMemory -= (short)280;
			short nextSize = (i != 0) ? availableMemory : 512;
			buffers[i] = JCSystem.makeTransientByteArray(nextSize, JCSystem.CLEAR_ON_DESELECT);
		}
		
		// initial memory layout - EEPROM
		short reservedMemory = (short)(JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT) / (short)4);
		if(reservedMemory < 2560) reservedMemory = 2560;
		if(reservedMemory > 12288) reservedMemory = 12288;
		for(byte i = 5; i >= 0; i--) {
			short availableMemory = JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT);
			availableMemory -= reservedMemory;
			short nextSize = (i != 0) ? (short)(availableMemory / (short)2) : availableMemory;
			buffers[2 + i] = new byte[nextSize];
		}		
	}

	/**
	 * Refreshes the TEM's estimate of the buffer chunk size. 
	 * @param apdu the APDU used to estimate the buffer chunk size
	 * @return
	 */
	public static short guessChunkSize(APDU apdu) {
		short inSize = APDU.getInBlockSize();
		short outSize = APDU.getOutBlockSize();
		TEMBuffers.chunkSize = (short)((inSize < outSize ? inSize : outSize) - (short)7);
		if(TEMBuffers.chunkSize >= (short)256)
			TEMBuffers.chunkSize = (short)255;
		return TEMBuffers.chunkSize;
	}
	
	/**
	 * Releases all the resources held by the TEM buffer module.
	 * Called when the TEM is de-activated.
	 * @return <code>true</code> if all is good, <code>false</code> if the TEM is not initialized
	 */	
	public static boolean deinit() {
		if(buffers == null)
			return false;
		buffers = null;
		flags = null;
		sizes = null;
		return true;
	}
		
	/**
	 * Allocates a memory zone and an entry in the buffer file that references it.
	 * @param bufferSize the desired buffer size, in bytes
	 * @return the buffer file entry referencing the allocated buffer, or
	 * {@link #INVALID_BUFFER} if the buffer could not be allocated
	 */
	public static byte create(short bufferSize) {
		// TODO: better memory allocation, use the pinned flags
		
		// forward move: find the smallest buffer that fits, remember largest candidate
		byte lastFree = INVALID_BUFFER;
		for(byte i = 0; i < NUM_BUFFERS; i++) {
			// skip taken buffers
			if((byte)(flags[i] & (byte)1) != (byte)0)
				continue;
			
			// if it looks good, take it
			lastFree = i;
			if(((byte[])buffers[i]).length >= bufferSize) {
				sizes[i] = bufferSize;
				flags[i] |= (byte)1;
				return i;
			}
		}
		
		// increase the largest available buffer if it's in EEPROM
		if(JCSystem.isTransient(buffers[lastFree]) != JCSystem.MEMORY_TYPE_PERSISTENT)
			return INVALID_BUFFER;
		if(lastFree != INVALID_BUFFER) {
			buffers[lastFree] = new byte[bufferSize];
			if(JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT) < 2048)
				JCSystem.requestObjectDeletion();
			sizes[lastFree] = bufferSize;
			flags[lastFree] |= (byte)1;
		}
		return lastFree;				
	}
	
	/**
	 * Pins down the memory zone referenced by a buffer file entry.
	 * This method should be called before obtaining a buffer via {@link #get(byte)}.
	 * Its pair method, {@link #unpin(byte)}, should be called once the work on the
	 * buffer is complete.
	 * @param bufferIndex the buffer file entry whose memory zone will be pinned
	 * @return 
	 */
	public static boolean pin(byte bufferIndex) {
		if(bufferIndex < 0 || bufferIndex >= NUM_BUFFERS)
			return false;
		
		flags[bufferIndex] |= (byte)0x80;
		return true;
	}
	
	/**
	 * Un-pins a memory zone previously pinned by {@link #pin(byte)}.
	 * This method should be called after finishing all the work on a buffer
	 * which was previously pinned via {@link #pin(byte)}.
	 * @param bufferIndex the buffer file entry whose memory zone will be un-pinned
	 */
	public static boolean unpin(byte bufferIndex) {
		if(bufferIndex < 0 || bufferIndex >= NUM_BUFFERS)
			return false;
		
		flags[bufferIndex] &= (byte)0x7f;
		return true;
	}
	
	/**
	 * Returns a buffer referenced by the buffer file.
	 * The buffer must be pinned via a call to {@link #pin(byte)}, and remain
	 * pinned while it is referenced.
	 * @param bufferIndex the buffer file entry whose buffer will be returned
	 * @return the byte array that is the buffer in a buffer file
	 */
	public static byte[] get(byte bufferIndex) {
		if(bufferIndex < 0 || bufferIndex >= NUM_BUFFERS || flags[bufferIndex] >= 0)
			return null;
		else
			return (byte[])buffers[bufferIndex];
	}
	
	/**
	 * Returns the requested size of a buffer referenced by the buffer file. 
	 * @param bufferIndex the buffer file entry whose buffer size will be returned
	 * @return the requested size of the buffer
	 */
	public static short size(byte bufferIndex) {
		return sizes[bufferIndex];
	}
	
	/**
	 * Releases the memory associated with a buffer, and frees the associated buffer file entry.
	 * The buffer must not be pinned.
	 * @param bufferIndex the buffer file entry that will be cleared
	 */
	public static void release(byte bufferIndex) {
		if(bufferIndex < 0 || bufferIndex >= NUM_BUFFERS)
			return;
		Util.arrayFillNonAtomic((byte[])buffers[bufferIndex], (short)0, sizes[bufferIndex], (byte)0);
		sizes[bufferIndex] = 0;
		flags[bufferIndex] = 0;
	}
	
	/**
	 * Releases all the buffers.
	 * This is equivalent to unpinning all the pinned buffers via calls to {@link #unpin(byte)},
	 * followed by calling {@link #release(byte)} on all the buffers.
	 */
	public static void releaseAll() {
		for(byte i = 0; i < NUM_BUFFERS; i++) {
			release(i);
		}
	}
	
	/**
	 * Checks if a buffer is public, and can be accessed outside the TEM.
	 * @param bufferIndex the buffer file entry whose buffer will be checked
	 * @return <code>true</code> if the buffer is public, or <code>false</code> if it's private
	 */
	public static boolean isPublic(byte bufferIndex) {
		return bufferIndex != TEMExecution.outBufferIndex && bufferIndex != TEMExecution.i_secBufferIndex;
	}
	
	/**
	 * Dumps the state of the TEM memory management module.
	 * This is only useful for driver development / debugging. It should not be included in production versions.
	 * @param output the buffer that will receive the stat results
	 * @param outputOffset the offset of the first byte in the output buffer that will receive the stat results
	 * @return the number of bytes written to the output buffer
	 */
	public static short stat(byte[] output, short outputOffset) {
		short o = outputOffset;
		
		// header: 3 shorts indicating available memory of each type
		for(byte memoryType = JCSystem.MEMORY_TYPE_PERSISTENT; memoryType <= JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT; memoryType++) {
			Util.setShort(output, o, JCSystem.getAvailableMemory(memoryType));
			o += 2;
		}
		
		// status for each buffer
		for(byte i = 0; i < NUM_BUFFERS; i++) {
			output[o] = (byte)(JCSystem.isTransient(buffers[i]) | (byte)(flags[i] & (byte)0x80) | (byte)(flags[i] << (byte)6)); o++;
			Util.setShort(output, o, sizes[i]); o += 2;
			Util.setShort(output, o, (short)((byte[])buffers[i]).length); o += 2;
		}		
		return (short)(o - outputOffset);
	}
}
