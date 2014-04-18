/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.cipher;

import co.lqnt.lockbox.cipher.parameters.DecryptionCipherParametersInterface;
import co.lqnt.lockbox.cipher.result.DecryptionResultInterface;
import com.google.common.base.Optional;

/**
 * The interface implemented by key decryption ciphers.
 */
public interface DecryptionCipherInterface extends CipherInterface
{
    /**
     * Initialize the cipher.
     *
     * @param parameters The parameters required by the cipher.
     */
    public void initialize(
        final DecryptionCipherParametersInterface parameters
    );
    
    /**
     * Get the decryption result.
     * 
     * @return The result, if available.
     */
    public Optional<DecryptionResultInterface> result();
}
