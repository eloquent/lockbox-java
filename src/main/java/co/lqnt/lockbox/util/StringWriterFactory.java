/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox.util;

import java.io.StringWriter;

/**
 * Creates string writers.
 */
public class StringWriterFactory implements StringWriterFactoryInterface
{
    /**
     * Create a new string writer.
     *
     * @return The new string writer.
     */
    public StringWriter create()
    {
        return new StringWriter();
    }
}
