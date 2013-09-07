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
import org.bouncycastle.openssl.PEMWriter;
import org.testng.annotations.Test;

public class PemWriterFactoryTest
{
    @Test
    public void testFactory() throws Throwable
    {
        PemWriterFactory factory = new PemWriterFactory();
        StringWriter stringWriter = new StringWriter();

        PEMWriter writer = factory.create(stringWriter);

        writer.close();
        stringWriter.close();
    }
}
