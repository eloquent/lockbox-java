/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox.util;

import java.io.InputStream;
import org.bouncycastle.openssl.PEMParser;

/**
 * The interface implemented by PEM parser factories.
 */
public interface PemParserFactoryInterface
{
    /**
     * Create a new PEM parser.
     *
     * @param input The PEM stream to parse.
     *
     * @return A new PEM parser for the supplied stream.
     */
    public PEMParser create(final InputStream input);
}
