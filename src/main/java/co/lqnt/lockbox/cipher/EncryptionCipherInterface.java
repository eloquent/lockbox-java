/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.cipher;

import co.lqnt.lockbox.cipher.exception.OutputSizeException;
import co.lqnt.lockbox.cipher.parameters.EncryptionCipherParametersInterface;

/**
 * The interface implemented by key encryption ciphers.
 */
public interface EncryptionCipherInterface
{
    /**
     * Initialize the cipher.
     *
     * @param parameters The parameters required by the cipher.
     */
    public void initialize(
        final EncryptionCipherParametersInterface parameters
    );

    /**
     * Get the size of the output buffer required for a process() call with an
     * input of the specified byte size.
     *
     * @param inputSize The input size in bytes.
     *
     * @return The output size in bytes.
     */
    public int processOutputSize(final int inputSize);

    /**
     * Process a single byte, producing an output block if necessary.
     *
     * @param input        The input byte.
     * @param output       The space for any output that might be produced.
     * @param outputOffset The offset to which the output will be copied.
     *
     * @return The number of bytes produced.
     * @exception IllegalStateException If the cipher isn't initialized.
     * @exception OutputSizeException   If there isn't enough space in output.
     */
    public int process(
        final byte input,
        final byte[] output,
        final int outputOffset
    ) throws
        IllegalStateException,
        OutputSizeException;

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
     * @exception IllegalStateException If the cipher isn't initialized.
     * @exception OutputSizeException   If there isn't enough space in output.
     */
    public int process(
        final byte[] input,
        final int inputOffset,
        final int size,
        final byte[] output,
        final int outputOffset
    ) throws
        IllegalStateException,
        OutputSizeException;

    /**
     * Get the size of the output buffer required for a process() call with an
     * input of the specified byte size plus a finalize() call.
     *
     * @param inputSize The input size in bytes.
     *
     * @return The output size in bytes.
     */
    public int finalOutputSize(final int inputSize);

    /**
     * Finalize the cipher output.
     *
     * @param output       The space for any output that might be produced.
     * @param outputOffset The offset to which the output will be copied.
     *
     * @return The number of bytes produced.
     * @exception IllegalStateException      If the cipher isn't initialized.
     * @exception OutputSizeException        If there isn't enough space in output.
     */
    public int finalize(final byte[] output, final int outputOffset)
        throws IllegalStateException, OutputSizeException;

    /**
     * Reset the cipher to its state after the last initialize() call.
     */
    public void reset();
}
