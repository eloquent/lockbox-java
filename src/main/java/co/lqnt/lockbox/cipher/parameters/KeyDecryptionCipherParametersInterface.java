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
import org.bouncycastle.crypto.CipherParameters;

/**
 * The interface implemented by key decryption cipher parameters.
 */
public interface KeyDecryptionCipherParametersInterface extends CipherParameters
{
    /**
     * Get the key.
     *
     * @return The key.
     */
    public KeyInterface key();
}
