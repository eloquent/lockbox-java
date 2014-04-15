/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.stream;

import co.lqnt.lockbox.key.KeyInterface;
import co.lqnt.lockbox.random.RandomSourceInterface;
import co.lqnt.lockbox.random.SecureRandom;
import com.google.common.primitives.Bytes;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Mac;
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
 * Encrypts streaming data.
 */
public class EncryptStream extends FilterOutputStream
{
    /**
     * Construct a new encrypt stream.
     *
     * @param out The target output stream to use.
     * @param key The key to use.
     */
    public EncryptStream(final OutputStream out, final KeyInterface key)
    {
        super(out);

        this.key = key;
        this.randomSource = SecureRandom.instance();
        this.cipher = new PaddedBufferedBlockCipher(
            new CBCBlockCipher(new AESEngine()),
            new PKCS7Padding()
        );

        switch (key.authenticationSecretBits()) {
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

        this.isInitialized = new AtomicBoolean();
    }

    /**
     * Construct a new encrypt stream.
     *
     * @param out          The target output stream to use.
     * @param key          The key to use.
     * @param randomSource The random source to use.
     * @param cipher       The cipher to use.
     * @param blockMac     The MAC implementation to use for block MACs.
     * @param finalMac     The MAC implementation to use for the final MAC.
     */
    public EncryptStream(
        final OutputStream out,
        final KeyInterface key,
        final RandomSourceInterface randomSource,
        final PaddedBufferedBlockCipher cipher,
        final Mac blockMac,
        final Mac finalMac
    ) {
        super(out);

        this.key = key;
        this.randomSource = randomSource;
        this.cipher = cipher;
        this.blockMac = blockMac;
        this.finalMac = finalMac;

        this.isInitialized = new AtomicBoolean();
    }

    /**
     * Get the target output stream.
     *
     * @return The output stream.
     */
    public OutputStream out()
    {
        return this.out;
    }

    /**
     * Get the key.
     *
     * @return The key.
     */
    public KeyInterface key()
    {
        return this.key;
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
     * Get the cipher.
     *
     * @return The cipher.
     */
    public PaddedBufferedBlockCipher cipher()
    {
        return this.cipher;
    }

    /**
     * Get the MAC implementation to use for block MACs.
     *
     * @return The block MAC implementation.
     */
    public Mac blockMac()
    {
        return this.blockMac;
    }

    /**
     * Get the MAC implementation to use for the final MAC.
     *
     * @return The final MAC implementation.
     */
    public Mac finalMac()
    {
        return this.finalMac;
    }

    /**
     * Write data to this stream.
     *
     * @param data The data to write.
     *
     * @throws IOException If the data cannot be written.
     */
    @Override
    public void write(final int data) throws IOException
    {
        this.write(new byte[]{(byte) data}, 0, 1);
    }

    /**
     * Write data to this stream.
     *
     * @param data   The data to write.
     * @param offset The offset to start from.
     * @param size   The data size.
     *
     * @throws IOException If the data cannot be written.
     */
    @Override
    public void write(
        final byte[] data,
        final int offset,
        final int size
    ) throws IOException
    {
        if (this.isInitialized.compareAndSet(false, true)) {
            this.initialize();
        }

        int ciphertextSize = this.cipher.getUpdateOutputSize(data.length);
        if (ciphertextSize > 0) {
            byte[] output = new byte[this.outputSize(ciphertextSize)];

            this.cipher.processBytes(data, 0, data.length, output, 0);
            this.authenticate(data, ciphertextSize);

            this.out.write(output);
        } else {
            byte[] output = new byte[0];
            this.cipher.processBytes(data, 0, data.length, output, 0);
        }
    }

    /**
     * Finalize and close this stream.
     *
     * @throws IOException If there is a problem closing the stream.
     */
    @Override
    public void close() throws IOException
    {
        if (!this.isInitialized.get()) {
            return;
        }

        int ciphertextSize = this.cipher.getOutputSize(0);
        int outputSize = this.outputSize(ciphertextSize);
        byte[] output = new byte[
            outputSize + this.key.authenticationSecretBytes()
        ];

        try {
            this.cipher.doFinal(output, 0);
        } catch (DataLengthException e) {
            throw new IOException(e);
        } catch (IllegalStateException e) {
            throw new IOException(e);
        } catch (InvalidCipherTextException e) {
            throw new IOException(e);
        }

        this.authenticate(output, ciphertextSize);
        this.finalMac.doFinal(output, outputSize);

        this.out.write(output);
        this.out.close();
    }

    /**
     * Initialize the cipher and output header data.
     */
    private void initialize() throws IOException
    {
        List<Byte> iv = this.randomSource.generate(16);
        byte[] ivArray = Bytes.toArray(iv);
        byte[] encryptionSecret = Bytes.toArray(this.key.encryptionSecret());
        byte[] authenticationSecret = Bytes
            .toArray(this.key.authenticationSecret());

        this.cipher.init(
            true,
            new ParametersWithIV(
                new KeyParameter(encryptionSecret),
                ivArray
            )
        );
        this.finalMac.init(new KeyParameter(authenticationSecret));

        byte[] header = new byte[18];
        header[0] = header[1] = 1;
        System.arraycopy(ivArray, 0, header, 2, 16);

        this.finalMac.update(header, 0, header.length);

        try {
            this.out.write(header);
        } finally {
            Collections.fill(iv, (byte) 0);
            Arrays.fill(ivArray, (byte) 0);
            Arrays.fill(encryptionSecret, (byte) 0);
            Arrays.fill(authenticationSecret, (byte) 0);
        }
    }

    /**
     * Calculate the output size for a given ciphertext size.
     *
     * @param ciphertextSize The ciphertext size.
     *
     * @return The output size.
     */
    private int outputSize(final int ciphertextSize)
    {
        return (int) (ciphertextSize * 1.125);
    }

    /**
     * Authenticate the supplied ciphertext.
     *
     * @param data The ciphertext to authenticate.
     * @param size The amount of data to authenticate.
     */
    private void authenticate(final byte[] data, final int size)
    {
        this.finalMac.update(data, 0, size);

        byte[] authenticationSecret = Bytes
            .toArray(this.key.authenticationSecret());

        for (int i = size / 16 - 1; i >= 0; i -= 1) {
            byte[] mac = new byte[this.key.authenticationSecretBytes()];

            this.blockMac.init(new KeyParameter(authenticationSecret));
            this.blockMac.update(data, 16 * i, 16);
            this.blockMac.doFinal(mac, 0);

            System.arraycopy(mac, 0, data, (18 * i) + 16, 2);
            if (i > 0) {
                System.arraycopy(data, 16 * i, data, 18 * i, 16);
            }
        }

        Arrays.fill(authenticationSecret, (byte) 0);
    }

    final private KeyInterface key;
    final private RandomSourceInterface randomSource;
    final private PaddedBufferedBlockCipher cipher;
    final private Mac blockMac;
    final private Mac finalMac;
    final private AtomicBoolean isInitialized;
}
