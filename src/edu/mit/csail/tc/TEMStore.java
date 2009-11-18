package edu.mit.csail.tc;

import javacard.framework.Util;

/**
 * NVRAM-backed implementation of the TEM persistent store abstraction.
 * @author Victor Costan
 * 
 * This module implements the persistent store abstraction in the TEM
 * specification. The persistent store is an associative memory, where the
 * keys/addresses are huge (in comparison to regular addresses) integers. Huge
 * keys serve double purpose, as memory addresses and authorization values
 * (guessing a persistent store address is just as hard as guessing a symmetric
 * encryption key).
 */
public class TEMStore {
	/** The size, in bytes, of a persistent store value. */
	public static final short VALUE_SIZE = 20;
	/** The size, in bytes, of a persistent store key(address). */
	public static final short ADDRESS_SIZE = 20;
	
	/** The number of cells in the NVRAM-backed implementation. */
	public static final short NUM_CELLS = 64;
	
	/** The size of a cell in the TEM store. */
	private static final short CELL_SIZE = 40; // KEY_LENGTH + VALUE_LENGTH
	/** Special value to indicate inexistent cell. */
	public static final short INVALID_CELL = (short)-1;

	
	/**
	 * The NVRAM-backed permanent store data.
	 * 
	 * The NVRAM is partitioned into cells. Each cell backs a location, and stores
	 * the location's address (ADDRESS_SIZE bytes) and the value at the location
	 * (VALUE_SIZE bytes).
	 */
	private static byte data[];
	
	/** Bitfield indicating which entries are free in the store data. */
	private static byte free[];
	
	/**
	 * Initializes the TEM persistent store.
	 * 
	 * Called when the TEM is activated.
	 */
	public static void init() {
		data = new byte[(short)(NUM_CELLS * CELL_SIZE)];
		free = new byte[(short)(NUM_CELLS / (short)8)];
		Util.arrayFillNonAtomic(free, (short)0, (short)(NUM_CELLS / 8), (byte)0xFF);
	}
	
	/**
	 * Releases all the resources held by the TEM persistent store module.
	 * 
	 * Called when the TEM is de-activated.
	 */	
	public static void deinit() {
		data = null;		
	}
	
	/**
	 * Finds the cell containing an association for an address.
	 * 
	 * @param address the buffer containing the address to look for 
	 * @param addressOffset the position in the buffer containing the first byte
	 *                      of the address 
	 * @return the ID of a cell containing an association for the given address,
	 *         or {@link #INVALID_CELL} if no such association exists 
	 */
	public static short findCell(byte[] address, short addressOffset) {
		for (short i = 0, cellOffset = 0; i < NUM_CELLS;
		     i++, cellOffset += CELL_SIZE) {
			if ((free[i >> 3] & (1 << (i & 7))) != 0)
				continue;
			if (Util.arrayCompare(address, addressOffset, data, cellOffset,
			                      ADDRESS_SIZE) == 0)
				return i;
		}
		return INVALID_CELL;
	}
	
	/**
	 * Finds an empty cell and marks it as allocated.
	 * 
	 * @return the ID of a cell that was free before {@link #allocCell()} was
	 *         called, or {@link #INVALID_CELL} if all the cells are taken
	 */
	private static short allocCell() {
		for (short i = 0, cellOffset = 0; i < NUM_CELLS;
		     i++, cellOffset += CELL_SIZE) {
			if ((free[i >> 3] & (1 << (i & 7))) == 0)
				continue;
			free[i >> 3] ^= 1 << (i & 7);
			return i;
		}
		return INVALID_CELL;		
	}

	/** Reads/Writes a value from the TEM store. */
	public static boolean readOrWrite(byte[] address, short addressOffset,
	                                  byte[] value, short valueOffset,
	                                  boolean opIsRead, boolean create) {
		short cellNumber = findCell(address, addressOffset);
		if (cellNumber == INVALID_CELL) {
			if (create == false)
				return false;
			
			cellNumber = allocCell();
			if (cellNumber == INVALID_CELL)
				return false; // TODO: driver-managed cells or page faults
			Util.arrayCopyNonAtomic(address, addressOffset, data,
			                        (short)(CELL_SIZE * cellNumber), ADDRESS_SIZE);
		}
			
		if (opIsRead)
			Util.arrayCopyNonAtomic(data,
			                        (short)(CELL_SIZE * cellNumber + ADDRESS_SIZE),
			                        value, valueOffset, VALUE_SIZE);
		else
			Util.arrayCopyNonAtomic(value, valueOffset, data,
			                        (short)(CELL_SIZE * cellNumber + ADDRESS_SIZE),
			                        VALUE_SIZE);
		return true;
	}
		
	/** Clobbers a TEM store entry. */
	public static boolean releaseCell(byte[] address, short addressOffset) {
		short cellNumber = findCell(address, addressOffset);
		if (cellNumber == INVALID_CELL)
			return false;
		free[cellNumber >> 3] |= 1 << (cellNumber & 7);
		return true;
	}
}
