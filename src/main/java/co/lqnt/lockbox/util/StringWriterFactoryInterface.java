/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.util;

import java.io.StringWriter;

/**
 * The interface implemented by string writer factories.
 */
public interface StringWriterFactoryInterface
{
    /**
     * Create a new string writer.
     *
     * @return The new string writer.
     */
    public StringWriter create();
}
