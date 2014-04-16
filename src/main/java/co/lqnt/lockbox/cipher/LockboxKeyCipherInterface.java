/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.cipher;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * The interface implemented by Lockbox key ciphers.
 */
public interface LockboxKeyCipherInterface
{
    /**
     * Initialize the cipher.
     *
     * @param forEncryption True if the cipher should be initialized for encryption, false for decryption.
     * @param parameters    The key and other data required by the cipher.
     *
     * @throws IllegalArgumentException If the parameters argument is invalid.
     */
    public void init(
        final boolean forEncryption,
        final CipherParameters parameters
    ) throws
        IllegalArgumentException;

    /**
     * Get the size of the output buffer required for an update() with an input
     * of the specified byte size.
     *
     * @param inputSize The input size in bytes.
     *
     * @return The output size in bytes.
     */
    public int getUpdateOutputSize(final int inputSize);

    /**
     * Get the size of the output buffer required for an update() plus a
     * doFinal() with an input of the specified byte size.
     *
     * @param inputSize The input size in bytes.
     *
     * @return The output size in bytes.
     */
    public int getOutputSize(final int inputSize);

    /**
     * Process a single byte, producing an output block if necessary.
     *
     * @param input        The input byte.
     * @param output       The space for any output that might be produced.
     * @param outputOffset The offset to which the output will be copied.
     *
     * @return The number of bytes produced.
     * @exception DataLengthException   If there isn't enough space in output.
     * @exception IllegalStateException If the cipher isn't initialized.
     */
    public int processByte(
        final byte input,
        final byte[] output,
        final int outputOffset
    ) throws
        DataLengthException,
        IllegalStateException;

    /**
     * Process an array of bytes, producing an output block if necessary.
     *
     * @param input        The input byte array.
     * @param inputOffset  The offset at which the input data starts.
     * @param size         The number of bytes to be read from the input array.
     * @param output       The space for any output that might be produced.
     * @param outputOffset The offset to which the output will be copied.
     *
     * @return The number of bytes produced.
     * @exception DataLengthException   If there isn't enough space in output.
     * @exception IllegalStateException If the cipher isn't initialized.
     */
    public int processBytes(
        final byte[] input,
        final int inputOffset,
        final int size,
        final byte[] output,
        final int outputOffset
    ) throws
        DataLengthException,
        IllegalStateException;

    /**
     * Process the last block in the buffer.
     *
     * @param output       The space for any output that might be produced.
     * @param outputOffset The offset to which the output will be copied.
     *
     * @return The number of bytes produced.
     * @exception DataLengthException        If there isn't enough space in output.
     * @exception IllegalStateException      If the cipher isn't initialized.
     * @exception InvalidCipherTextException If padding is expected and not found.
     */
    public int doFinal(
        final byte[] output,
        final int outputOffset
    ) throws
        DataLengthException,
        IllegalStateException,
        InvalidCipherTextException;

    /**
     * Reset the cipher to its state after the last init() call.
     */
    public void reset();
}
