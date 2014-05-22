/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.cipher.parameters;

import co.lqnt.lockbox.key.KeyInterface;
import com.google.common.base.Optional;
import java.util.List;

/**
 * The interface implemented by encrypt parameters.
 */
public interface EncryptParametersInterface extends CipherParametersInterface
{
    /**
     * Get the key.
     *
     * @return The key.
     */
    public KeyInterface key();

    /**
     * Get the initialization vector.
     *
     * @return The initialization vector.
     */
    public Optional<List<Byte>> iv();
}
