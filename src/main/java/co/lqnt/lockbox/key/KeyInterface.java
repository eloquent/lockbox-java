/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox.key;

import co.lqnt.lockbox.util.PemWriterFactoryInterface;
import co.lqnt.lockbox.util.StringWriterFactoryInterface;
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

    /**
     * Get this key as a PEM formatted string.
     *
     * @param stringWriterFactory The string writer factory to use.
     * @param pemWriterFactory    The PEM writer factory to use.
     *
     * @return The PEM formatted key.
     */
    public String toPem(
        final StringWriterFactoryInterface stringWriterFactory,
        final PemWriterFactoryInterface pemWriterFactory
    );
}
