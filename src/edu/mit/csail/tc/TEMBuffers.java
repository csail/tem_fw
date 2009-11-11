package edu.mit.csail.tc;

import javacard.framework.APDU;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * TEM memory management module.
 * @author Victor Costan
 * 
 * This module manages the memories available in a Javacard chip. Its main
 * reason of existence is that normal APDUs can only carry 256 bytes of data,
 * and TEM procs are much bigger than that. The module now has versatile logic
 * which juggles between volatile and non-volatile memory.
 */
class TEMBuffers {
	/**
	 * The buffer file (parallel: register file).
	 * Allocated as <code>CLEAR_ON_DESELECT</code> memory, since buffers are
	 * temporary in nature.
	 */
	private static Object[] buffers;
	/** The requested sizes of the buffers in the file. */
	private static short[] sizes;
	/**
	 * Pinned and busy flags for each buffer.
	 * Allocated as <code>CLEAR_ON_DESELECT</code> memory, since buffers are
	 * temporary in nature.
	 */
	private static byte[] flags;
	
	/** Number of entries in the buffer file. */
	public static final byte NUM_BUFFERS = 8;
	
	/** Returned by {@link #create(short)} to communicate failure. */
	public static final byte INVALID_BUFFER = -1;
	
	/** The size of a buffer chunk. */
	public static short chunkSize;
	
	/**
	 * Initializes the TEM buffer module.
	 * 
	 * Called when the TEM is activated.
	 * 
	 * @return <code>true</code> if all is good, <code>false</code> if the TEM is
	 *         already initialized
	 */
	public static final boolean init() {
		// Initialize the buffer file.
		if (buffers != null)
			return false;
		buffers = new Object[NUM_BUFFERS];
		
		// The buffer file is reset to an empty state (no layout, no flags) when an
		// application connects to the TEM applet.
		flags = JCSystem.makeTransientByteArray(NUM_BUFFERS,
				                                    JCSystem.CLEAR_ON_DESELECT);
		sizes = JCSystem.makeTransientShortArray(NUM_BUFFERS,
				                                     JCSystem.CLEAR_ON_DESELECT);
		return true;
	}
	
	/**
	 * Lays out the TEM buffers into memory.
	 * 
	 * Called when the TEM is activated, after all the other modules allocated
	 * their static objects.
	 */
	public static final void layout() {		
		// Partition the RAM into buffers.
		for (byte i = 0; i <= 1; i++) {
			short availableMemory = JCSystem.getAvailableMemory(
			    JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
			availableMemory -= 280;
			short nextSize = (i != 0) ? availableMemory : 512;
			buffers[i] = JCSystem.makeTransientByteArray(nextSize,
			    JCSystem.CLEAR_ON_DESELECT);
		}
		
		// Partition the EEPROM into buffers.
		short reservedMemory = (short)(
		    JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT) /
		    (short)4);
		if (reservedMemory < 2560) reservedMemory = 2560;
		if (reservedMemory > 12288) reservedMemory = 12288;
		for (byte i = 5; i >= 0; i--) {
			short availableMemory = JCSystem.getAvailableMemory(
					JCSystem.MEMORY_TYPE_PERSISTENT);
			availableMemory -= reservedMemory;
			short nextSize = (i != 0) ? (short)(availableMemory >> 1)
			                          : availableMemory;
			buffers[2 + i] = new byte[nextSize];
		}		
	}

	/**
	 * Refreshes the TEM's estimate of the buffer chunk size.
	 *  
	 * @return the newly estimated buffer chunk size
	 */
	public static final short guessChunkSize() {
		short inSize = APDU.getInBlockSize();
		short outSize = APDU.getOutBlockSize();
		TEMBuffers.chunkSize = (short)((inSize < outSize ? inSize : outSize) - 7);
		
		// If the card seems to support chunk sizes greater than 255 bytes, fall
		// back to 255, to avoid any driver issues.
		if (TEMBuffers.chunkSize >= 256)
			TEMBuffers.chunkSize = 255;
		return TEMBuffers.chunkSize;
	}
	
	/**
	 * Releases all the resources held by the TEM buffer module.
	 * 
	 * Called when the TEM is de-activated.
	 * 
	 * @return <code>true</code> if all is good, <code>false</code> if the TEM is
	 *         not initialized
	 */	
	public static final boolean deinit() {
		if (buffers == null)
			return false;
		buffers = null;
		flags = null;
		sizes = null;
		return true;
	}
	
	// Flag: a buffer file entry is allocated.
	private static final byte BUFFER_ALLOCATED = (byte)1;
	// Flag: a buffer file entry is pinned.
	private static final byte BUFFER_PINNED = (byte)0x80;
	
	/**
	 * Allocates a memory zone and an entry in the buffer file that references it.
	 * 
	 * @param bufferSize the desired buffer size, in bytes
	 * @return the buffer file entry referencing the allocated buffer, or
	 *         {@link #INVALID_BUFFER} if the buffer could not be allocated
	 */
	public static final byte create(short bufferSize) {
		// TODO: better memory allocation using the pinned flags
		
		// Find the smallest buffer that accomodates the request. Also keep track
	  // of the largest free buffer for the code below.
		byte lastFree = INVALID_BUFFER;
		for (byte i = 0; i < NUM_BUFFERS; i++) {
			if ((flags[i] & BUFFER_ALLOCATED) != 0)
				continue;
			
			lastFree = i;
			if (((byte[])buffers[i]).length >= bufferSize) {
				sizes[i] = bufferSize;
				flags[i] |= BUFFER_ALLOCATED;
				return i;
			}
		}
		
		// No buffer works. If the largest free buffer is in EEPROM, try to "resize"
		// it (release / reallocate) to fit the request.
		if (JCSystem.isTransient(buffers[lastFree]) !=
		    JCSystem.MEMORY_TYPE_PERSISTENT)
			return INVALID_BUFFER;
		if (lastFree != INVALID_BUFFER) {
			buffers[lastFree] = new byte[bufferSize];
			if (JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT) < 2048)
				JCSystem.requestObjectDeletion();
			sizes[lastFree] = bufferSize;
      flags[lastFree] |= BUFFER_ALLOCATED;
		}
		return lastFree;				
	}
	
	/**
	 * Pins down the memory zone referenced by a buffer file entry.
	 * 
	 * This method should be called before obtaining a buffer via
	 * {@link #get(byte)}. The associated method, {@link #unpin(byte)}, should be
	 * called once the work on the buffer is complete.
	 * 
	 * @param bufferIndex the buffer file entry whose memory zone will be pinned
	 * @return <code>true</code> if the pinning succeeded, or <code>false</code>
	 *         if the given buffer file entry is invalid
	 */
	public static final boolean pin(byte bufferIndex) {
		if (bufferIndex < 0 || bufferIndex >= NUM_BUFFERS)
			return false;
		
		flags[bufferIndex] |= BUFFER_PINNED;
		return true;
	}
	
	/**
	 * Un-pins a memory zone previously pinned by {@link #pin(byte)}.
	 * 
	 * This method should be called after finishing all the work on a buffer which
	 * was previously pinned via {@link #pin(byte)}.
	 * 
	 * @param bufferIndex the buffer file entry whose memory zone will be
	 *                    un-pinned
	 */
	public static final boolean unpin(byte bufferIndex) {
		if (bufferIndex < 0 || bufferIndex >= NUM_BUFFERS)
			return false;
		
		flags[bufferIndex] &= ~BUFFER_PINNED;
		return true;
	}
	
	/**
	 * The memory zone of a buffer referenced by the buffer file.
	 * 
	 * The buffer must have been pinned via a call to {@link #pin(byte)}, and it
	 * must remain pinned while it is referenced.
	 * 
	 * @param bufferIndex the buffer file entry whose buffer will be returned
	 * @return the byte array that is the buffer in a buffer file
	 */
	public static final byte[] get(byte bufferIndex) {
		if (bufferIndex < 0 || bufferIndex >= NUM_BUFFERS ||
		    flags[bufferIndex] >= 0)
			return null;
		return (byte[])buffers[bufferIndex];
	}
	
	/**
	 * The requested buffer size for a buffer file entry.
	 * 
	 * @param bufferIndex the buffer file entry whose buffer size will be returned
	 * @return the buffer size requested when the file entry was allocated
	 */
	public static final short size(byte bufferIndex) {
		return sizes[bufferIndex];
	}
	
	/**
	 * Releases a buffer's memory zone and frees the associated buffer file entry.
	 * 
	 * The buffer must not be pinned.
	 * 
	 * @param bufferIndex the buffer file entry that will be cleared
	 */
	public static final void release(byte bufferIndex) {
		if (bufferIndex < 0 || bufferIndex >= NUM_BUFFERS)
			return;
		Util.arrayFillNonAtomic((byte[])buffers[bufferIndex], (short)0,
		                        sizes[bufferIndex], (byte)0);
		sizes[bufferIndex] = 0;
		flags[bufferIndex] = 0;
	}
	
	/**
	 * Releases all the buffers.
	 * 
	 * This is equivalent to unpinning all the pinned buffers via calls to
	 * {@link #unpin(byte)}, followed by calling {@link #release(byte)} on all
	 * the buffers.
	 */
	public static final void releaseAll() {
		for (byte i = 0; i < NUM_BUFFERS; i++) {
			release(i);
		}
	}
	
	/**
	 * Checks if a buffer is public, and can be accessed outside the TEM.
	 * 
	 * @param bufferIndex the buffer file entry whose buffer will be checked
	 * @return <code>true</code> if the buffer can be accessed by the TEM's client
	 *         application, or <code>false</code> if the buffer contains sensitive
	 *         information
	 */
	public static final boolean isPublic(byte bufferIndex) {
		return bufferIndex != TEMExecution.outBufferIndex &&
		       bufferIndex != TEMExecution.i_secBufferIndex;
	}
	
	/**
	 * Dumps the state of the TEM memory management module.
	 * 
	 * This is only useful for driver development / debugging. It should not be
	 * included in production versions, because it could be used to leak secrets.
	 * 
	 * @param output the buffer that will receive the stat results
	 * @param outputOffset the offset of the first byte in the output buffer that
	 *        will receive the stat results
	 * @return the number of bytes written to the output buffer
	 */
	public static final short stat(byte[] output, short outputOffset) {
		short o = outputOffset;
		
		// Header: 3 shorts indicating available memory of each type.
		for (byte memoryType = JCSystem.MEMORY_TYPE_PERSISTENT;
		     memoryType <= JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT; memoryType++) {
			Util.setShort(output, o, JCSystem.getAvailableMemory(memoryType));
			o += 2;
		}
		
		// Status for each buffer file entry:
		//   1 byte - bit 2-0: 0 = EEPROM, 1 = clear on reset, 2 = clear on deselect
		//            bit 5: 1 = public, 0 = locked
		//            bit 6: 1 = allocated, 0 = free
		//            bit 7: 1 = pinned, 0 = unpinned
		//   2 bytes - requested buffer size
		//   2 bytes - size of actual buffer in the memory layout
		for (byte i = 0; i < NUM_BUFFERS; i++) {
			output[o] = (byte)(JCSystem.isTransient(buffers[i]) |
			                   (flags[i] & BUFFER_PINNED) | (flags[i] << 6) |
			                   (TEMBuffers.isPublic(i) ? 0x20 : 0));
			o++;
			Util.setShort(output, o, sizes[i]); o += 2;
			Util.setShort(output, o, (short)((byte[])buffers[i]).length); o += 2;
		}		
		return (short)(o - outputOffset);
	}
}
