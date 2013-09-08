/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox.util;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.Charset;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.testng.Assert;
import org.testng.annotations.Test;

public class PemParserFactoryTest
{
    @Test
    public void testCreate() throws Throwable
    {
        String publicKeyString = "-----BEGIN PUBLIC KEY-----\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8jsljdxzsgvboCytmlH\n" +
            "3Q03v30fPTNfMqmz2Yn0GdtkqQH01+H9y5bWWCQyeGOATvIPrELGeB9nRlQeaTb5\n" +
            "VjCl1V9PYeM6Q30PK6411fJexjYA/UbRG/9I/K+A9UBfJvUsjGVUMxZR8n8jmmSy\n" +
            "8G2eqXBbP6dEZFnO0V274TRTB3SLKD2tfYBYwMtXqT+rSbH1OyoS29A03FaUgkRk\n" +
            "1er2i3ldyNIG8vMGv7Iagup69yBrt8xo61IFj76dkocbozp1Y4SGzyjkR/ukRSLe\n" +
            "+0ejS4eMyziaH7J52XX1rDFreinZZDoE571ameu0biuM6aT8P1pk85VIqHLlqRm/\n" +
            "vQIDAQAB\n" +
            "-----END PUBLIC KEY-----\n";
        InputStream publicKeyStream = new ByteArrayInputStream(publicKeyString.getBytes(Charset.forName("US-ASCII")));

        PemParserFactoryInterface factory = new PemParserFactory();
        PEMParser parser = factory.create(publicKeyStream);

        Assert.assertSame(parser.readObject().getClass(), SubjectPublicKeyInfo.class);
    }
}
