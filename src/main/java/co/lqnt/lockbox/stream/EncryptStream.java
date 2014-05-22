/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.stream;

import co.lqnt.lockbox.cipher.CipherInterface;
import co.lqnt.lockbox.cipher.EncryptCipher;
import co.lqnt.lockbox.cipher.parameters.EncryptParameters;
import co.lqnt.lockbox.key.KeyInterface;
import co.lqnt.lockbox.random.RandomSourceInterface;
import co.lqnt.lockbox.random.SecureRandom;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.concurrent.atomic.AtomicBoolean;

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
        this(out, key, SecureRandom.instance(), new EncryptCipher());
    }

    /**
     * Construct a new encrypt stream.
     *
     * @param out          The target output stream to use.
     * @param key          The key to use.
     * @param randomSource The random source to use.
     * @param cipher       The cipher to use.
     */
    public EncryptStream(
        final OutputStream out,
        final KeyInterface key,
        final RandomSourceInterface randomSource,
        final CipherInterface cipher
    ) {
        super(out);

        this.key = key;
        this.randomSource = randomSource;
        this.cipher = cipher;

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
    public CipherInterface cipher()
    {
        return this.cipher;
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
        this.initialize();

        int outputSize = this.cipher.processOutputSize(size);
        if (outputSize > 0) {
            byte[] output = new byte[outputSize];
            this.cipher.process(data, offset, size, output, 0);

            this.out.write(output);
        } else {
            byte[] output = new byte[0];
            this.cipher.process(data, offset, size, output, 0);
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
        this.initialize();

        int outputSize = this.cipher.finalOutputSize(0);
        byte[] output = new byte[outputSize];

        this.cipher.finalize(output, 0);

        this.out.write(output);
        this.out.flush();
        this.out.close();
    }

    /**
     * Initialize the cipher.
     */
    private void initialize()
    {
        if (this.isInitialized.compareAndSet(false, true)) {
            this.cipher.initialize(
                new EncryptParameters(this.key, this.randomSource.generate(16))
            );
        }
    }

    final private KeyInterface key;
    final private RandomSourceInterface randomSource;
    final private CipherInterface cipher;
    final private AtomicBoolean isInitialized;
}
