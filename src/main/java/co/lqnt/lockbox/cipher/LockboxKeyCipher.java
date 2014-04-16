/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.cipher;

import com.google.common.primitives.Bytes;
import java.util.Arrays;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * The key-based Lockbox cipher.
 */
public class LockboxKeyCipher extends BufferedBlockCipher implements
    LockboxKeyCipherInterface
{
    /**
     * Create a new Lockbox key cipher.
     */
    public LockboxKeyCipher()
    {
        this.internalCipher = new PaddedBufferedBlockCipher(
            new CBCBlockCipher(new AESEngine()),
            new PKCS7Padding()
        );
        this.blockMac = null;
        this.finalMac = null;
        this.isHeaderSent = false;
    }

    /**
     * Initialize the cipher.
     *
     * @param forEncryption True if the cipher should be initialized for encryption, false for decryption.
     * @param parameters    The key and other data required by the cipher.
     *
     * @throws IllegalArgumentException If the parameters argument is invalid.
     */
    @Override
    public void init(
        final boolean forEncryption,
        final CipherParameters parameters
    ) throws
        IllegalArgumentException
    {
        if (!(parameters instanceof LockboxKeyCipherParametersInterface)) {
            throw new IllegalArgumentException(
                "Parameters must be an instance of " +
                    "LockboxKeyCipherParametersInterface."
            );
        }

        LockboxKeyCipherParametersInterface lockboxParameters =
            (LockboxKeyCipherParametersInterface) parameters;

        this.iv = Bytes.toArray(lockboxParameters.iv());

        switch (lockboxParameters.key().authenticationSecretBits()) {
            case 224:
                this.blockMac = new HMac(new SHA224Digest());
                this.finalMac = new HMac(new SHA224Digest());

                break;

            case 384:
                this.blockMac = new HMac(new SHA384Digest());
                this.finalMac = new HMac(new SHA384Digest());

                break;

            case 512:
                this.blockMac = new HMac(new SHA512Digest());
                this.finalMac = new HMac(new SHA512Digest());

                break;

            default:
                this.blockMac = new HMac(new SHA256Digest());
                this.finalMac = new HMac(new SHA256Digest());
        }

        byte[] authenticationSecret = Bytes
            .toArray(lockboxParameters.key().authenticationSecret());

        this.finalMac.init(new KeyParameter(authenticationSecret));
        this.blockMac.init(new KeyParameter(authenticationSecret));

        Arrays.fill(authenticationSecret, (byte) 0);

        byte[] encryptionSecret = Bytes
            .toArray(lockboxParameters.key().encryptionSecret());

        this.internalCipher.init(
            forEncryption,
            new ParametersWithIV(new KeyParameter(encryptionSecret), this.iv)
        );

        Arrays.fill(encryptionSecret, (byte) 0);

        this.isHeaderSent = false;
    }

    /**
     * Get the size of the output buffer required for an update() with an input
     * of the specified byte size.
     *
     * @param inputSize The input size in bytes.
     *
     * @return The output size in bytes.
     */
    @Override
    public int getUpdateOutputSize(final int inputSize)
    {
        int size = this.internalCipher.getUpdateOutputSize(inputSize) / 16 * 18;

        if (size > 0 && !this.isHeaderSent) {
            size += 18;
        }

        return size;
    }

    /**
     * Get the size of the output buffer required for an update() plus a
     * doFinal() with an input of the specified byte size.
     *
     * @param inputSize The input size in bytes.
     *
     * @return The output size in bytes.
     */
    @Override
    public int getOutputSize(final int inputSize)
    {
        int size = this.internalCipher.getOutputSize(inputSize) / 16 * 18;

        if (this.isHeaderSent) {
            size += this.finalMac.getMacSize();
        } else {
            size += this.finalMac.getMacSize() + 18;
        }

        return size;
    }

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
    @Override
    public int processByte(
        final byte input,
        final byte[] output,
        final int outputOffset
    ) throws
        DataLengthException,
        IllegalStateException
    {
        return this.processBytes(new byte[]{input}, 0, 1, output, outputOffset);
    }

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
    @Override
    public int processBytes(
        final byte[] input,
        final int inputOffset,
        final int size,
        final byte[] output,
        final int outputOffset
    ) throws
        DataLengthException,
        IllegalStateException
    {
        if (null == this.iv) {
            throw new IllegalStateException("Cipher not initialized.");
        }

        int outputSize = this.getUpdateOutputSize(size);
        int ciphertextOffset = outputOffset;

        if (outputSize > 0 && !this.isHeaderSent) {
            ciphertextOffset += 18;
        }

        if (output.length < outputOffset + outputSize) {
            throw new DataLengthException();
        }

        if (outputSize > 0 && !this.isHeaderSent) {
            output[outputOffset] = output[outputOffset + 1] = 1;
            System.arraycopy(this.iv, 0, output, outputOffset + 2, 16);
            this.finalMac.update(output, outputOffset, 18);
        }

        this.internalCipher.processBytes(
            input,
            inputOffset,
            size,
            output,
            ciphertextOffset
        );

        if (outputSize > 0) {
            int ciphertextSize = outputSize;

            if (!this.isHeaderSent) {
                this.isHeaderSent = true;
                ciphertextSize -= 18;
            }

            this.authenticate(output, ciphertextOffset, ciphertextSize);
        }

        return outputSize;
    }

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
    @Override
    public int doFinal(
        final byte[] output,
        final int outputOffset
    ) throws
        DataLengthException,
        IllegalStateException,
        InvalidCipherTextException
    {
        if (null == this.iv) {
            throw new IllegalStateException("Cipher not initialized.");
        }

        int outputSize = this.getOutputSize(0);
        int ciphertextOffset = outputOffset;

        if (outputSize > 0 && !this.isHeaderSent) {
            ciphertextOffset += 18;
        }

        if (output.length < outputOffset + outputSize) {
            throw new DataLengthException();
        }

        if (outputSize > 0 && !this.isHeaderSent) {
            output[outputOffset] = output[outputOffset + 1] = 1;
            System.arraycopy(this.iv, 0, output, outputOffset + 2, 16);
            this.finalMac.update(output, outputOffset, 18);
        }

        this.internalCipher.doFinal(output, ciphertextOffset);

        int ciphertextSize;
        if (outputSize > 0) {
            ciphertextSize = outputSize - this.finalMac.getMacSize();

            if (!this.isHeaderSent) {
                this.isHeaderSent = true;
                ciphertextSize -= 18;
            }

            this.authenticate(output, ciphertextOffset, ciphertextSize);
        } else {
            ciphertextSize = 0;
        }

        byte[] mac = new byte[this.finalMac.getMacSize()];
        this.finalMac.doFinal(mac, 0);

        System.arraycopy(
            mac,
            0,
            output,
            ciphertextOffset + ciphertextSize,
            mac.length
        );

        return outputSize;
    }

    /**
     * Reset the cipher to its state after the last init() call.
     */
    @Override
    public void reset()
    {
        this.internalCipher.reset();
        this.isHeaderSent = false;
    }

    /**
     * Authenticate the supplied ciphertext.
     *
     * @param output The ciphertext to authenticate.
     * @param offset The ciphertext offset.
     * @param size   The ciphertext size in bytes.
     */
    private void authenticate(
        final byte[] output,
        final int offset,
        final int size
    ) {
        this.finalMac.update(output, offset, size / 18 * 16);

        for (int i = size / 18 - 1; i >= 0; i -= 1) {
            byte[] mac = new byte[this.blockMac.getMacSize()];

            this.blockMac.reset();
            this.blockMac.update(output, (16 * i) + offset, 16);
            this.blockMac.doFinal(mac, 0);

            System.arraycopy(mac, 0, output, (18 * i) + 16 + offset, 2);
            if (i > 0) {
                System.arraycopy(output, 16 * i, output, (18 * i) + offset, 16);
            }
        }
    }

    final private PaddedBufferedBlockCipher internalCipher;
    private byte[] iv;
    private HMac blockMac;
    private HMac finalMac;
    private boolean isHeaderSent;
}
