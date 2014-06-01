/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.cipher;

import co.lqnt.lockbox.cipher.exception.CipherFinalizedException;
import co.lqnt.lockbox.cipher.exception.CipherNotInitializedException;
import co.lqnt.lockbox.cipher.exception.CipherStateException;
import co.lqnt.lockbox.cipher.exception.OutputSizeException;
import co.lqnt.lockbox.cipher.exception.UnsupportedCipherParametersException;
import co.lqnt.lockbox.cipher.parameters.CipherParametersInterface;
import co.lqnt.lockbox.cipher.parameters.EncryptParametersInterface;
import co.lqnt.lockbox.cipher.result.CipherResultInterface;
import co.lqnt.lockbox.cipher.result.factory.CipherResultFactory;
import co.lqnt.lockbox.cipher.result.factory.CipherResultFactoryInterface;
import co.lqnt.lockbox.key.KeyInterface;
import com.google.common.base.Optional;
import com.google.common.primitives.Bytes;
import java.util.Arrays;
import org.bouncycastle.crypto.BufferedBlockCipher;
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
 * Decrypts data with a key.
 */
public class DecryptCipher implements CipherInterface
{
    /**
     * Create a new decrypt cipher.
     */
    public DecryptCipher()
    {
        this(CipherResultFactory.instance());
    }

    /**
     * Create a new decrypt cipher.
     *
     * @param resultFactory The result factory to use.
     */
    public DecryptCipher(final CipherResultFactoryInterface resultFactory)
    {
        this(
            resultFactory,
            new PaddedBufferedBlockCipher(
                new CBCBlockCipher(new AESEngine()),
                new PKCS7Padding()
            )
        );
    }

    /**
     * Get the result factory.
     *
     * @return The result factory.
     */
    public CipherResultFactoryInterface resultFactory()
    {
        return this.resultFactory;
    }

    /**
     * Returns true if this cipher is initialized.
     *
     * @return True if initialized.
     */
    public boolean isInitialized()
    {
        return this.isInitialized;
    }

    /**
     * Initialize the cipher.
     *
     * @param parameters The parameters required by the cipher.
     *
     * @throws UnsupportedCipherParametersException If unsupported parameters are supplied.
     */
    public void initialize(final CipherParametersInterface parameters)
    {
        KeyInterface key = null;

        if (parameters instanceof KeyInterface) {
            key = (KeyInterface) parameters;
        } else if (parameters instanceof EncryptParametersInterface) {
            EncryptParametersInterface encryptParameters =
                (EncryptParametersInterface) parameters;

            key = encryptParameters.key();
        } else {
            throw new UnsupportedCipherParametersException(this, parameters);
        }

        this.isInitialized = true;

        switch (key.authSecretBits()) {
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

        byte[] authSecret = Bytes.toArray(key.authSecret());
        KeyParameter authKey = new KeyParameter(authSecret);

        this.finalMac.init(authKey);
        this.blockMac.init(authKey);

        Arrays.fill(authSecret, (byte) 0);

        byte[] encryptSecret = Bytes.toArray(key.encryptSecret());

        this.cipher.init(
            true,
            new ParametersWithIV(new KeyParameter(encryptSecret), this.iv)
        );

        Arrays.fill(encryptSecret, (byte) 0);

        this.buffer = new byte[key.authSecretBytes() + 18];
        this.bufferPosition = 0;
        this.isHeaderReceived = false;
    }

    /**
     * Get the size of the output buffer required for a process() call with an
     * input of the specified byte size.
     *
     * @param inputSize The input size in bytes.
     *
     * @return The output size in bytes.
     * @throws CipherStateException If the cipher is in an invalid state.
     */
    public int processOutputSize(final int inputSize)
    {
        if (!this.isInitialized) {
            throw new CipherNotInitializedException(this);
        }
        if (this.isFinalized) {
            throw new CipherFinalizedException(this);
        }

        int ciphertextSize = inputSize +
            this.bufferPosition -
            this.finalMac.getMacSize();
        if (!this.isHeaderReceived) {
            ciphertextSize -= 18;
        }

        ciphertextSize -= Math.floor(ciphertextSize / 18) * 2;

        return this.cipher.getUpdateOutputSize(ciphertextSize);
    }

    /**
     * Process a single byte, producing an output block if necessary.
     *
     * @param input        The input byte.
     * @param output       The space for any output that might be produced.
     * @param outputOffset The offset to which the output will be copied.
     *
     * @return The number of bytes produced.
     * @throws CipherStateException If the cipher is in an invalid state.
     * @throws OutputSizeException  If there isn't enough space in output.
     */
    public int process(
        final byte input,
        final byte[] output,
        final int outputOffset
    ) {
        return this.process(new byte[]{input}, 0, 1, output, outputOffset);
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
     * @throws CipherStateException If the cipher is in an invalid state.
     * @throws OutputSizeException  If there isn't enough space in output.
     */
    public int process(
        final byte[] input,
        final int inputOffset,
        final int size,
        final byte[] output,
        final int outputOffset
    ) {
        int outputSize = this.processOutputSize(size);
        if (outputSize > output.length - outputOffset) {
            throw new OutputSizeException(
                output.length - outputOffset,
                outputSize
            );
        }

        if (size + this.bufferPosition < this.buffer.length) {
            System.arraycopy(
                input,
                inputOffset,
                this.buffer,
                this.bufferPosition,
                size
            );
            this.bufferPosition += size;

            return 0;
        } else {

        }

        return 0;
    }

    private boolean processHeader(
        final byte[] input,
        final int inputOffset,
        final int size,
        final byte[] output,
        final int outputOffset
    ) {
        if (this.isHeaderReceived) {
            return true;
        }
        if (size + this.bufferPosition < 18) {
            return false;
        }

        return true;
    }

    /**
     * Get the size of the output buffer required for a process() call with an
     * input of the specified byte size plus a finalize() call.
     *
     * @param inputSize The input size in bytes.
     *
     * @return The output size in bytes.
     * @throws CipherStateException If the cipher is in an invalid state.
     */
    public int finalOutputSize(final int inputSize)
    {
        if (!this.isInitialized) {
            throw new CipherNotInitializedException(this);
        }
        if (this.isFinalized) {
            throw new CipherFinalizedException(this);
        }

        int ciphertextSize = inputSize +
            this.bufferPosition -
            this.finalMac.getMacSize();
        if (!this.isHeaderReceived) {
            ciphertextSize -= 18;
        }

        ciphertextSize -= Math.ceil(ciphertextSize / 18) * 2;

        return this.cipher.getOutputSize(ciphertextSize);
    }

    /**
     * Finalize the cipher output.
     *
     * @param output       The space for any output that might be produced.
     * @param outputOffset The offset to which the output will be copied.
     *
     * @return The number of bytes produced.
     * @throws CipherStateException If the cipher is in an invalid state.
     * @throws OutputSizeException  If there isn't enough space in output.
     */
    public int finalize(final byte[] output, final int outputOffset)
    {
        int outputSize = this.finalOutputSize(0);
        if (outputSize > output.length - outputOffset) {
            throw new OutputSizeException(
                output.length - outputOffset,
                outputSize
            );
        }

        this.isFinalized = true;

        return 0;
    }

    /**
     * Finalize the cipher output.
     *
     * @param input        The input byte.
     * @param output       The space for any output that might be produced.
     * @param outputOffset The offset to which the output will be copied.
     *
     * @return The number of bytes produced.
     * @throws CipherStateException If the cipher is in an invalid state.
     * @throws OutputSizeException  If there isn't enough space in output.
     */
    public int finalize(
        final byte input,
        final byte[] output,
        final int outputOffset
    ) {
        return this.finalize(new byte[]{input}, 0, 1, output, outputOffset);
    }

    /**
     * Finalize the cipher output.
     *
     * @param input        The input byte array.
     * @param inputOffset  The offset at which the input data starts.
     * @param size         The number of bytes to be read from the input array.
     * @param output       The space for any output that might be produced.
     * @param outputOffset The offset to which the output will be copied.
     *
     * @return The number of bytes produced.
     * @throws CipherStateException If the cipher is in an invalid state.
     * @throws OutputSizeException  If there isn't enough space in output.
     */
    public int finalize(
        final byte[] input,
        final int inputOffset,
        final int size,
        final byte[] output,
        final int outputOffset
    ) {
        int outputSize =
            this.process(input, inputOffset, size, output, outputOffset);

        return outputSize + this.finalize(output, outputOffset + outputSize);
    }

    /**
     * Returns true if this cipher is finalized.
     *
     * @return True if finalized.
     */
    public boolean isFinalized()
    {
        return this.isFinalized;
    }

    /**
     * Get the result.
     *
     * @return The result.
     */
    public Optional<CipherResultInterface> result()
    {
        return Optional.fromNullable(this.result);
    }

    /**
     * Reset the cipher to its state after the last initialize() call.
     */
    public void reset()
    {
        this.cipher.reset();
        if (null != this.finalMac) {
            this.finalMac.reset();
        }
        if (null != this.buffer) {
            Arrays.fill(this.buffer, (byte) 0);
        }
        this.isHeaderReceived = this.isFinalized = false;
        this.result = null;
    }

    /**
     * Create a new decrypt cipher.
     *
     * @param resultFactory The result factory to use.
     * @param cipher        The internal cipher to use.
     */
    DecryptCipher(
        final CipherResultFactoryInterface resultFactory,
        final BufferedBlockCipher cipher
    ) {
        this.resultFactory = resultFactory;
        this.cipher = cipher;
        this.blockMac = this.finalMac = null;
        this.buffer = null;
        this.bufferPosition = 0;
        this.isInitialized = this.isHeaderReceived = this.isFinalized = false;
        this.result = null;
    }

    final private CipherResultFactoryInterface resultFactory;
    final private BufferedBlockCipher cipher;
    private byte[] iv;
    private HMac blockMac;
    private HMac finalMac;
    private byte[] buffer;
    private int bufferPosition;
    private boolean isInitialized;
    private boolean isHeaderReceived;
    private boolean isFinalized;
    private CipherResultInterface result;
}
