/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.util;

import co.lqnt.lockbox.util.exception.ErasedDataException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import org.bouncycastle.util.Arrays;

/**
 * A temporary data representation that can be erased.
 */
public class ErasableData implements ErasableDataInterface
{
    /**
     * Construct a new erasable data packet.
     *
     * @param data The data.
     */
    public ErasableData(char[] data)
    {
        this.isErased = false;
        this.data = Arrays.copyOf(data, data.length);
    }

    /**
     * Construct a new erasable data packet using UTF-8 encoding.
     *
     * @param data The data.
     */
    public ErasableData(byte[] data)
    {
        this(data, Charset.forName("UTF-8"));
    }

    /**
     * Construct a new erasable data packet.
     *
     * @param data    The data.
     * @param charset The encoding to use.
     */
    public ErasableData(byte[] data, Charset charset)
    {
        this.isErased = false;

        ByteBuffer byteBuffer = ByteBuffer.wrap(data);
        CharBuffer charBuffer = charset.decode(byteBuffer);

        this.data = Arrays.copyOf(charBuffer.array(), charBuffer.limit());

        Arrays.fill(charBuffer.array(), '\u0000');
        Arrays.fill(byteBuffer.array(), (byte) 0);
    }

    /**
     * Construct a new erasable data packet.
     *
     * @deprecated Avoid the use of strings if possible, as they cannot truly be erased.
     *
     * @param data The data.
     */
    public ErasableData(String data)
    {
        this(data.toCharArray());
    }

    /**
     * Erase the data.
     */
    public void erase()
    {
        if (!this.isErased()) {
            Arrays.fill(this.data, '\u0000');
            this.isErased = true;
        }
    }

    /**
     * Returns true if this data has been erased.
     *
     * @return True if this data has been erased.
     */
    public boolean isErased()
    {
        return this.isErased;
    }

    /**
     * Get the data as an array of characters.
     *
     * @return The data.
     * @throws ErasedDataException If this data has been erased.
     */
    public char[] characters() throws ErasedDataException
    {
        if (this.isErased()) {
            throw new ErasedDataException();
        }

        return Arrays.copyOf(this.data, this.data.length);
    }

    /**
     * Get the data as an array of bytes using UTF-8 encoding.
     *
     * @return The data.
     * @throws ErasedDataException If this data has been erased.
     */
    public byte[] bytes() throws ErasedDataException
    {
        return this.bytes(Charset.forName("UTF-8"));
    }

    /**
     * Get the data as an array of bytes using the supplied encoding.
     *
     * @param charset The encoding to use.
     *
     * @return The data.
     * @throws ErasedDataException If this data has been erased.
     */
    public byte[] bytes(final Charset charset) throws ErasedDataException
    {
        CharBuffer charBuffer = CharBuffer.wrap(this.characters());
        ByteBuffer byteBuffer = charset.encode(charBuffer);

        byte[] bytes = Arrays.copyOf(byteBuffer.array(), byteBuffer.limit());

        Arrays.fill(charBuffer.array(), '\u0000');
        Arrays.fill(byteBuffer.array(), (byte) 0);

        return bytes;
    }

    private boolean isErased;
    private char[] data;
}
