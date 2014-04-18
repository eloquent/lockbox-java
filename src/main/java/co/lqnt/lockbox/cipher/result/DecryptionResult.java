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
import java.util.ArrayList;
import java.util.List;

/**
 * Represents the result of an attempted decryption.
 */
public class DecryptionResult implements DecryptionResultInterface
{
    /**
     * Construct a new decryption result.
     * 
     * @param type The result type.
     */
    public DecryptionResult(final DecryptionResultType type)
    {
        this(type, null);
    }
    
    /**
     * Construct a new decryption result.
     * 
     * @param data The decrypted data.
     */
    public DecryptionResult(final List<Byte> data)
    {
        this(DecryptionResultType.SUCCESS, data);
    }
    
    /**
     * Construct a new decryption result.
     * 
     * @param type The result type.
     * @param data The decrypted data.
     */
    public DecryptionResult(
        final DecryptionResultType type,
        final List<Byte> data
    ) {
        this.type = type;
        this.data = data;
    }
    
    /**
     * Get the result type.
     * 
     * @return The result type.
     */
    public DecryptionResultType type()
    {
        return this.type;
    }
    
    /**
     * Returns true if this result is successful.
     *
     * @return True if successful.
     */
    public boolean isSuccessful()
    {
        return this.type().isSuccessful();
    }
    
    /**
     * Set the decrypted data.
     * 
     * @param data The data.
     */
    public void setData(final List<Byte> data)
    {
        this.data = data;
    }
    
    /**
     * Get the decrypted data.
     *
     * This data will not be present for unsuccessful and/or streaming results.
     * 
     * @return The data, if available.
     */
    public Optional<List<Byte>> data()
    {
        if (null == this.data) {
            return Optional.<List<Byte>>absent();
        }
        
        return Optional.<List<Byte>>of(new ArrayList<Byte>(this.data));
    }
    
    final private DecryptionResultType type;
    private List<Byte> data;
}
