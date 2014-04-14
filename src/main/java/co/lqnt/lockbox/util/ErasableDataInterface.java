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
import java.nio.charset.Charset;

/**
 * The interface implemented by erasable data.
 */
public interface ErasableDataInterface
{
    /**
     * Erase the data.
     */
    public void erase();

    /**
     * Returns true if this data has been erased.
     *
     * @return True if this data has been erased.
     */
    public boolean isErased();

    /**
     * Get the data as an array of characters.
     *
     * @return The data.
     * @throws ErasedDataException If this data has been erased.
     */
    public char[] characters() throws ErasedDataException;

    /**
     * Get the data as an array of bytes using UTF-8 encoding.
     *
     * @return The data.
     * @throws ErasedDataException If this data has been erased.
     */
    public byte[] bytes() throws ErasedDataException;

    /**
     * Get the data as an array of bytes using the supplied encoding.
     *
     * @param charset The encoding to use.
     *
     * @return The data.
     * @throws ErasedDataException If this data has been erased.
     */
    public byte[] bytes(final Charset charset) throws ErasedDataException;
}
