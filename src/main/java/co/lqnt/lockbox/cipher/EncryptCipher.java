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
import co.lqnt.lockbox.cipher.result.CipherResultType;
import co.lqnt.lockbox.cipher.result.factory.CipherResultFactory;
import co.lqnt.lockbox.cipher.result.factory.CipherResultFactoryInterface;
import co.lqnt.lockbox.key.KeyInterface;
import co.lqnt.lockbox.random.RandomSourceInterface;
import co.lqnt.lockbox.random.SecureRandom;
import com.google.common.base.Optional;
import com.google.common.primitives.Bytes;
import java.util.Arrays;
import org.bouncycastle.crypto.BufferedBlockCipher;
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
 * Encrypts data with a key.
 */
public class EncryptCipher implements CipherInterface
{
    /**
     * Create a new encrypt cipher.
     */
    public EncryptCipher()
    {
        this(SecureRandom.instance(), CipherResultFactory.instance());
    }

    /**
     * Create a new encrypt cipher.
     *
     * @param randomSource  The random source to use.
     * @param resultFactory The result factory to use.
     */
    public EncryptCipher(
        final RandomSourceInterface randomSource,
        final CipherResultFactoryInterface resultFactory
    ) {
        this(
            randomSource,
            resultFactory,
            new PaddedBufferedBlockCipher(
                new CBCBlockCipher(new AESEngine()),
                new PKCS7Padding()
            )
        );
    }

    /**
     * Get the random source.
     *
     * @return The random source.
     */
    public RandomSourceInterface randomSource()
    {
        return this.randomSource;
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

        if (parameters instanceof EncryptParametersInterface) {
            EncryptParametersInterface encryptParameters =
                (EncryptParametersInterface) parameters;

            key = encryptParameters.key();

            if (encryptParameters.iv().isPresent()) {
                this.iv = Bytes.toArray(encryptParameters.iv().get());
            }
        } else if (parameters instanceof KeyInterface) {
            key = (KeyInterface) parameters;
        } else {
            throw new UnsupportedCipherParametersException(this, parameters);
        }

        this.isInitialized = true;

        if (null == this.iv) {
            this.iv = Bytes.toArray(this.randomSource().generate(16));
        }

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

        this.isHeaderSent = false;
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

        int size = this.cipher.getUpdateOutputSize(inputSize) / 16 * 18;
        if (size < 0) {
            size = 0;
        }
        if (!this.isHeaderSent) {
            size += 18;
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

        int ciphertextOffset = outputOffset +
            this.handleHeader(output, outputOffset);

        this.cipher.processBytes(
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

        int size = this.cipher.getOutputSize(inputSize) / 16 * 18;

        if (this.isHeaderSent) {
            size += this.finalMac.getMacSize();
        } else {
            size += this.finalMac.getMacSize() + 18;
        }

        return size;
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

        int ciphertextOffset = outputOffset +
            this.handleHeader(output, outputOffset);

        try {
            this.cipher.doFinal(output, ciphertextOffset);
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException(e);
        }

        int ciphertextSize = outputSize - this.finalMac.getMacSize();
        if (!this.isHeaderSent) {
            this.isHeaderSent = true;
            ciphertextSize -= 18;
        }

        this.authenticate(output, ciphertextOffset, ciphertextSize);

        byte[] mac = new byte[this.finalMac.getMacSize()];
        this.finalMac.doFinal(mac, 0);

        System.arraycopy(
            mac,
            0,
            output,
            ciphertextOffset + ciphertextSize,
            mac.length
        );

        this.result = this.resultFactory()
            .createResult(CipherResultType.SUCCESS);

        return outputSize;
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
        this.isHeaderSent = this.isFinalized = false;
        this.result = null;
    }

    /**
     * Create a new encrypt cipher.
     *
     * @param randomSource  The random source to use.
     * @param resultFactory The result factory to use.
     * @param cipher        The internal cipher to use.
     */
    EncryptCipher(
        final RandomSourceInterface randomSource,
        final CipherResultFactoryInterface resultFactory,
        final BufferedBlockCipher cipher
    ) {
        this.randomSource = randomSource;
        this.resultFactory = resultFactory;
        this.cipher = cipher;
        this.blockMac = this.finalMac = null;
        this.isInitialized = this.isHeaderSent = this.isFinalized = false;
        this.result = null;
    }

    /**
     * Prepend the header to output if necessary.
     *
     * @param output       The space for any output that might be produced.
     * @param outputOffset The offset to which the output will be copied.
     *
     * @return The number of bytes of header data written.
     */
    private int handleHeader(
        final byte[] output,
        final int outputOffset
    ) {
        if (this.isHeaderSent) {
            return 0;
        }

        output[outputOffset] = output[outputOffset + 1] = 1;
        System.arraycopy(this.iv, 0, output, outputOffset + 2, 16);
        this.finalMac.update(output, outputOffset, 18);

        return 18;
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
                System.arraycopy(
                    output,
                    (16 * i) + offset,
                    output,
                    (18 * i) + offset,
                    16
                );
            }
        }
    }

    final private RandomSourceInterface randomSource;
    final private CipherResultFactoryInterface resultFactory;
    final private BufferedBlockCipher cipher;
    private byte[] iv;
    private HMac blockMac;
    private HMac finalMac;
    private boolean isInitialized;
    private boolean isHeaderSent;
    private boolean isFinalized;
    private CipherResultInterface result;
}
