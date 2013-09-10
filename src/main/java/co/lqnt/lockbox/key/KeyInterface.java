/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox.key;

import java.math.BigInteger;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public interface KeyInterface
{
    /**
     * Get the size of this key in bits.
     *
     * @return The key size.
     */
    public int size();

    /**
     * Get the modulus.
     *
     * @return The modulus.
     */
    public BigInteger modulus();

    /**
     * Get the public exponent.
     *
     * @return The public exponent.
     */
    public BigInteger publicExponent();

    /**
     * Get the generic Bouncy Castle asymmetric key parameters.
     *
     * @return The generic Bouncy Castle asymmetric key parameters.
     */
    public AsymmetricKeyParameter bcKeyParameters();

    /**
     * Get this key as a PEM formatted string.
     *
     * @return The PEM formatted key.
     */
    public String toPem();
}
