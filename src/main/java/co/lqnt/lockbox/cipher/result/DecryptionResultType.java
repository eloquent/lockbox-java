/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.cipher.result;

/**
 * Represents the available result types.
 */
public enum DecryptionResultType
{
    SUCCESS (true),
    
    INVALID_SIZE (false),
    INVALID_ENCODING (false),
    INVALID_MAC (false),
    UNSUPPORTED_VERSION (false),
    UNSUPPORTED_TYPE (false),
    INVALID_PADDING (false);
        
    /**
     * Returns true if this result type indicates a successful result.
     * 
     * @return True if successful.
     */
    public boolean isSuccessful()
    {
        return this.isSuccessful;
    }
    
    DecryptionResultType(final boolean isSuccessful)
    {
        this.isSuccessful = isSuccessful;
    }
    
    final private boolean isSuccessful;
}
