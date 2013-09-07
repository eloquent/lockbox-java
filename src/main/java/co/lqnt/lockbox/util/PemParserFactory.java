/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox.util;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import org.bouncycastle.openssl.PEMParser;

/**
 * Creates PEM parsers.
 */
public class PemParserFactory implements PemParserFactoryInterface
{
    /**
     * Create a new PEM parser.
     *
     * @param input The PEM stream to parse.
     *
     * @return A new PEM parser for the supplied stream.
     */
    public PEMParser create(final InputStream input)
    {
        return new PEMParser(
            new BufferedReader(
                new InputStreamReader(input, Charset.forName("US-ASCII"))
            )
        );
    }
}
