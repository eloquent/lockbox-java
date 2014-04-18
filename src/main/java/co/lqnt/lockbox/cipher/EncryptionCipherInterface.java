/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.cipher;

import co.lqnt.lockbox.cipher.parameters.EncryptionCipherParametersInterface;

/**
 * The interface implemented by key encryption ciphers.
 */
public interface EncryptionCipherInterface extends CipherInterface
{
    /**
     * Initialize the cipher.
     *
     * @param parameters The parameters required by the cipher.
     */
    public void initialize(
        final EncryptionCipherParametersInterface parameters
    );
}
