/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.cipher.result;

import com.google.common.base.Optional;
import java.util.List;

/**
 * The interface implemented by cipher results.
 */
public interface CipherResultInterface
{
    /**
     * Get the result type.
     *
     * @return The result type.
     */
    public CipherResultType type();

    /**
     * Returns true if this result is successful.
     *
     * @return True if successful.
     */
    public boolean isSuccessful();

    /**
     * Set the data.
     *
     * @param data The data.
     */
    public void setData(final List<Byte> data);

    /**
     * Get the data.
     *
     * This data will not be present for unsuccessful and/or streaming results.
     *
     * @return The data, if available.
     */
    public Optional<List<Byte>> data();
}
