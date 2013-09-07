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
import org.testng.annotations.Test;

public class StringWriterFactoryTest
{
    @Test
    public void testFactory() throws Throwable
    {
        StringWriterFactory factory = new StringWriterFactory();

        StringWriter writer = factory.create();

        writer.close();
    }
}
