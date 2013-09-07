/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox.util;

import java.io.Writer;
import org.bouncycastle.openssl.PEMWriter;

/**
 * The interface implemented by PEM writer factories.
 */
public interface PemWriterFactoryInterface
{
    /**
     * Create a new PEM writer.
     *
     * @param writer The inner writer;
     *
     * @return The new PEM writer.
     */
    public PEMWriter create(final Writer writer);
}
