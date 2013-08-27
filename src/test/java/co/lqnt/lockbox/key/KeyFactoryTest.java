/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox.key;

import co.lqnt.lockbox.key.exception.KeyPairReadException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.PublicKey;
import org.bouncycastle.openssl.PEMWriter;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class KeyFactoryTest
{
    @BeforeMethod
    public void setUp()
    {
        this.factory = new KeyFactory();

        this.privateKeyStringNoPassword =
            "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIIEpAIBAAKCAQEAy8jsljdxzsgvboCytmlH3Q03v30fPTNfMqmz2Yn0GdtkqQH0\n" +
            "1+H9y5bWWCQyeGOATvIPrELGeB9nRlQeaTb5VjCl1V9PYeM6Q30PK6411fJexjYA\n" +
            "/UbRG/9I/K+A9UBfJvUsjGVUMxZR8n8jmmSy8G2eqXBbP6dEZFnO0V274TRTB3SL\n" +
            "KD2tfYBYwMtXqT+rSbH1OyoS29A03FaUgkRk1er2i3ldyNIG8vMGv7Iagup69yBr\n" +
            "t8xo61IFj76dkocbozp1Y4SGzyjkR/ukRSLe+0ejS4eMyziaH7J52XX1rDFreinZ\n" +
            "ZDoE571ameu0biuM6aT8P1pk85VIqHLlqRm/vQIDAQABAoIBAAlqWyQFo8h+D1L3\n" +
            "t0oeSye3eJ/sVAkr2nYoyRp/+TtIm7oDUSC4XFWPvo+L/Jj7X+5F2NuIqkraiJcD\n" +
            "Q/RwicylqsPVB4HqUcLUgGLwRaSA8kgOLrWFFBxLC0BBi5/JPZw7L7e85ssFePvP\n" +
            "TAHSLUJWjkId4tlqDQrl61xZDFk3UHawcovZeUp4RAqULeLDXAQTQJYXE8erPjhQ\n" +
            "Y0uSWORe1S1ICaI2aqbjmIHFUzPlz45KlakzLwn4tobeiKeNaHrPw++JMXNVSlPk\n" +
            "hGxPliXbZauaoDHa/p6w3hDvr2ZjOLU7QDHgdiWZ4EUW5AQRf7aiKtE2yNPTGJQb\n" +
            "yv9QHzECgYEA/UQluesABp+UJvvDzbEmDkipgCbEu5fHyGb8C0FPZET1ys2wu0DI\n" +
            "IaYR4hiYetrv5inHzXnMSkuQSMzPa+SyBXgiGnB9J2+sBX0H9byq3QuMriTSDQPA\n" +
            "ptxZlYAXTEXRUsNYG3/VCiC75VjbufHI7QmsOStTij6w15gchTrBt+cCgYEAzfwL\n" +
            "amiGmgVblJ1xr+8zwZMv99c22j8K+Cm4PoUhQ6I6XcgqHyDj8mD65UxQU3aE8R2m\n" +
            "vbX7XW1jrpflbVwoRoJS9z8F77rm6t38yS3WJqz6kyoQ0u4W2m8D8g/WWROjeGFD\n" +
            "ljrpiwErkmzCGrNhSk4O9YTXrNUGkD5MTpVPBrsCgYBlmdgUnIy3G3+AoBFty/o7\n" +
            "UrUE3wifRQV1hLLqBPpHfE6qXBfhFtzyer/D1yAccQY6bFpmOM1WpLeuLNOtMeKk\n" +
            "xQvRVX0vu+HjlcQCtfxJjt+R4N2PMQkxJ0ac7fTquTt/GzSWW5LobDdUi3AiSTfU\n" +
            "t8Oqb5Ik7H9fDfurCuY50wKBgQDDC/wfSVTTeWlLo35oct+WV/JfA7ocFQAlFxQw\n" +
            "l011RqNv9D72dOWDuJM7FvUk4yBlVId0MmMQB6oRRCHqWQ6GHZfEKThM1bUdBxD7\n" +
            "ytxyiO9I9NczdGHNervItXhppq/vKGKgWa6VgokowLVYJS1l994wXBcBwEHTyjnl\n" +
            "W3qWSwKBgQDZo0uMMWevRBriPT6OCdEYwnOZOMvh6LdXG2wyC2wYMY+8XOMzDrZP\n" +
            "zD3i4wQYCfJg7pyhVtctBz2NQ8J878xm2EXzUpGaIxjLIXb1UVgw4XXcM7LkjFaa\n" +
            "J1iMrMTLGSX89+gW3Bg8hxS7klxZf7ZlVSzLpA2jkK3k5vdgWGVhtA==\n" +
            "-----END RSA PRIVATE KEY-----\n";
        this.publicKeyStringNoPassword = "-----BEGIN PUBLIC KEY-----\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8jsljdxzsgvboCytmlH\n" +
            "3Q03v30fPTNfMqmz2Yn0GdtkqQH01+H9y5bWWCQyeGOATvIPrELGeB9nRlQeaTb5\n" +
            "VjCl1V9PYeM6Q30PK6411fJexjYA/UbRG/9I/K+A9UBfJvUsjGVUMxZR8n8jmmSy\n" +
            "8G2eqXBbP6dEZFnO0V274TRTB3SLKD2tfYBYwMtXqT+rSbH1OyoS29A03FaUgkRk\n" +
            "1er2i3ldyNIG8vMGv7Iagup69yBrt8xo61IFj76dkocbozp1Y4SGzyjkR/ukRSLe\n" +
            "+0ejS4eMyziaH7J52XX1rDFreinZZDoE571ameu0biuM6aT8P1pk85VIqHLlqRm/\n" +
            "vQIDAQAB\n" +
            "-----END PUBLIC KEY-----\n";
    }

    @Test
    public void testCreateKeyPair() throws Throwable
    {
        KeyPair keyPair = this.factory.createKeyPair(this.stringToInputStream(this.privateKeyStringNoPassword));

        Assert.assertEquals(this.publicKeyToPemString(keyPair.getPublic()), this.publicKeyStringNoPassword);
    }

    @Test(expectedExceptions = KeyPairReadException.class)
    public void testCreateKeyPairFailureInvalidKey() throws Throwable
    {
        this.factory.createKeyPair(this.stringToInputStream("foobar"));
    }

    @Test(expectedExceptions = KeyPairReadException.class)
    public void testCreateKeyPairFailureNoEnd() throws Throwable
    {
        this.factory.createKeyPair(this.stringToInputStream("-----BEGIN RSA PRIVATE KEY-----\n"));
    }

    protected InputStream stringToInputStream(String string)
    {
        return new ByteArrayInputStream(string.getBytes(Charset.forName("US-ASCII")));
    }

    protected String publicKeyToPemString(PublicKey key)
    {
        StringWriter stringWriter = new StringWriter();
        PEMWriter pemWriter = new PEMWriter(stringWriter);

        try {
            pemWriter.writeObject(key);
            pemWriter.flush();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return stringWriter.toString();
    }

    private KeyFactory factory;
    String privateKeyStringNoPassword;
    String publicKeyStringNoPassword;
}
