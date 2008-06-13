package edu.mit.csail.tc;

import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * TEM tag module.
 * @author Victor
 *
 * The tag includes information that assists the TEM driver.
 * This information includes: the public endorsement key,
 * endorsement certificate, and driver procs.
 * 
 * Tag information does not need to be stored securely. We just
 * store it on the TEM for convenience.
 */
public class TEMTag {
	/* The firmware version posted in the tag. */
	public static short FIRMWARE_VER = 0x010A;
	
	/**
	 * The tag information.
	 */
	public static byte[] tag;
	
	/**
	 * Initializes the TEM tag module.
	 * Called when the TEM is activated.
	 * 
	 * After this method is called, the TEM tag is not yet set.
	 */	
	public static void init() {
		tag = null;
	}
	
	/**
	 * Releases all the resources held by the TEM tag module.
	 * Called when the TEM is de-activated.
	 */		
	public static void deinit() {
		tag = null;
	}
	
	/**
	 * Sets the TEM tag. This can be only done once.
	 * @param buffer the buffer to read tag data from
	 * @param offset the byte offset at which tag data starts
	 * @param length the length of the tag data, in bytes
	 */
	public static boolean set(byte[] buffer, short offset, short length) {
		if(tag != null)
			return false;
		
		tag = new byte[length + 2];
		Util.setShort(tag, (short)0, FIRMWARE_VER);
		Util.arrayCopyNonAtomic(buffer, offset, tag, (short)2, length);
		return true;	
	}
}
