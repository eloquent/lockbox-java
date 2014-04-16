/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.cipher;

import co.lqnt.lockbox.key.KeyInterface;
import java.util.List;
import org.bouncycastle.crypto.CipherParameters;

/**
 * The interface implemented by Lockbox key cipher parameters.
 */
public interface LockboxKeyCipherParametersInterface extends CipherParameters
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
    public List<Byte> iv();
}