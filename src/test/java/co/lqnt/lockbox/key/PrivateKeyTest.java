/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox.key;

import co.lqnt.lockbox.util.PemWriterFactory;
import co.lqnt.lockbox.util.PrivateKeyInformationFactory;
import co.lqnt.lockbox.util.StringWriterFactory;
import co.lqnt.lockbox.util.PublicKeyInformationFactory;
import java.io.IOException;
import java.io.StringWriter;
import javax.xml.bind.DatatypeConverter;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.mockito.InOrder;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.Test;

public class PrivateKeyTest
{
    public PrivateKeyTest() throws Throwable
    {
        this.factory = new KeyFactory();

        this.keyString =
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
        this.key = this.factory.createPrivateKey(this.keyString);
        this.expectedModulus =
            "AMvI7JY3cc7IL26AsrZpR90NN799Hz0zXzKps9mJ9BnbZKkB9Nfh/cuW1lgkMnhj" +
            "gE7yD6xCxngfZ0ZUHmk2+VYwpdVfT2HjOkN9DyuuNdXyXsY2AP1G0Rv/SPyvgPVA" +
            "Xyb1LIxlVDMWUfJ/I5pksvBtnqlwWz+nRGRZztFdu+E0Uwd0iyg9rX2AWMDLV6k/" +
            "q0mx9TsqEtvQNNxWlIJEZNXq9ot5XcjSBvLzBr+yGoLqevcga7fMaOtSBY++nZKH" +
            "G6M6dWOEhs8o5Ef7pEUi3vtHo0uHjMs4mh+yedl19awxa3op2WQ6BOe9WpnrtG4r" +
            "jOmk/D9aZPOVSKhy5akZv70=";
        this.expectedPublicExponent = "AQAB";
        this.expectedPrivateExponent =
            "CWpbJAWjyH4PUve3Sh5LJ7d4n+xUCSvadijJGn/5O0ibugNRILhcVY++j4v8mPtf" +
            "7kXY24iqStqIlwND9HCJzKWqw9UHgepRwtSAYvBFpIDySA4utYUUHEsLQEGLn8k9" +
            "nDsvt7zmywV4+89MAdItQlaOQh3i2WoNCuXrXFkMWTdQdrByi9l5SnhECpQt4sNc" +
            "BBNAlhcTx6s+OFBjS5JY5F7VLUgJojZqpuOYgcVTM+XPjkqVqTMvCfi2ht6Ip41o" +
            "es/D74kxc1VKU+SEbE+WJdtlq5qgMdr+nrDeEO+vZmM4tTtAMeB2JZngRRbkBBF/" +
            "tqIq0TbI09MYlBvK/1AfMQ==";
        this.expectedPrime1 =
            "AP1EJbnrAAaflCb7w82xJg5IqYAmxLuXx8hm/AtBT2RE9crNsLtAyCGmEeIYmHra" +
            "7+Ypx815zEpLkEjMz2vksgV4IhpwfSdvrAV9B/W8qt0LjK4k0g0DwKbcWZWAF0xF" +
            "0VLDWBt/1Qogu+VY27nxyO0JrDkrU4o+sNeYHIU6wbfn";
        this.expectedPrime2 =
            "AM38C2pohpoFW5Sdca/vM8GTL/fXNto/CvgpuD6FIUOiOl3IKh8g4/Jg+uVMUFN2" +
            "hPEdpr21+11tY66X5W1cKEaCUvc/Be+65urd/Mkt1ias+pMqENLuFtpvA/IP1lkT" +
            "o3hhQ5Y66YsBK5JswhqzYUpODvWE16zVBpA+TE6VTwa7";
        this.expectedPrimeExponent1 =
            "ZZnYFJyMtxt/gKARbcv6O1K1BN8In0UFdYSy6gT6R3xOqlwX4Rbc8nq/w9cgHHEG" +
            "OmxaZjjNVqS3rizTrTHipMUL0VV9L7vh45XEArX8SY7fkeDdjzEJMSdGnO306rk7" +
            "fxs0lluS6Gw3VItwIkk31LfDqm+SJOx/Xw37qwrmOdM=";
        this.expectedPrimeExponent2 =
            "AMML/B9JVNN5aUujfmhy35ZX8l8DuhwVACUXFDCXTXVGo2/0PvZ05YO4kzsW9STj" +
            "IGVUh3QyYxAHqhFEIepZDoYdl8QpOEzVtR0HEPvK3HKI70j01zN0Yc16u8i1eGmm" +
            "r+8oYqBZrpWCiSjAtVglLWX33jBcFwHAQdPKOeVbepZL";
        this.expectedCoefficient =
            "ANmjS4wxZ69EGuI9Po4J0RjCc5k4y+Hot1cbbDILbBgxj7xc4zMOtk/MPeLjBBgJ" +
            "8mDunKFW1y0HPY1DwnzvzGbYRfNSkZojGMshdvVRWDDhddwzsuSMVponWIysxMsZ" +
            "Jfz36BbcGDyHFLuSXFl/tmVVLMukDaOQreTm92BYZWG0";
    }

    @Test
    public void testConstructor()
    {
        String modulus = DatatypeConverter.printBase64Binary(this.key.modulus().toByteArray());
        String publicExponent = DatatypeConverter.printBase64Binary(this.key.publicExponent().toByteArray());
        String privateExponent = DatatypeConverter.printBase64Binary(this.key.privateExponent().toByteArray());
        String prime1 = DatatypeConverter.printBase64Binary(this.key.prime1().toByteArray());
        String prime2 = DatatypeConverter.printBase64Binary(this.key.prime2().toByteArray());
        String primeExponent1 = DatatypeConverter.printBase64Binary(this.key.primeExponent1().toByteArray());
        String primeExponent2 = DatatypeConverter.printBase64Binary(this.key.primeExponent2().toByteArray());
        String coefficient = DatatypeConverter.printBase64Binary(this.key.coefficient().toByteArray());

        Assert.assertEquals(modulus, this.expectedModulus);
        Assert.assertEquals(publicExponent, this.expectedPublicExponent);
        Assert.assertEquals(privateExponent, this.expectedPrivateExponent);
        Assert.assertEquals(prime1, this.expectedPrime1);
        Assert.assertEquals(prime2, this.expectedPrime2);
        Assert.assertEquals(primeExponent1, this.expectedPrimeExponent1);
        Assert.assertEquals(primeExponent2, this.expectedPrimeExponent2);
        Assert.assertEquals(coefficient, this.expectedCoefficient);
    }

    @Test
    public void testSize()
    {
        Assert.assertEquals(this.key.size(), 2048);
    }

    @Test
    public void testBcPrivateKeyParameters()
    {
        RSAPrivateCrtKeyParameters bcPrivateKeyParameters = this.key.bcPrivateKeyParameters();
        String modulus = DatatypeConverter.printBase64Binary(bcPrivateKeyParameters.getModulus().toByteArray());
        String publicExponent = DatatypeConverter.printBase64Binary(
            bcPrivateKeyParameters.getPublicExponent().toByteArray()
        );
        String privateExponent = DatatypeConverter.printBase64Binary(
            bcPrivateKeyParameters.getExponent().toByteArray()
        );
        String prime1 = DatatypeConverter.printBase64Binary(bcPrivateKeyParameters.getP().toByteArray());
        String prime2 = DatatypeConverter.printBase64Binary(bcPrivateKeyParameters.getQ().toByteArray());
        String primeExponent1 = DatatypeConverter.printBase64Binary(bcPrivateKeyParameters.getDP().toByteArray());
        String primeExponent2 = DatatypeConverter.printBase64Binary(bcPrivateKeyParameters.getDQ().toByteArray());
        String coefficient = DatatypeConverter.printBase64Binary(bcPrivateKeyParameters.getQInv().toByteArray());

        Assert.assertEquals(modulus, this.expectedModulus);
        Assert.assertEquals(publicExponent, this.expectedPublicExponent);
        Assert.assertEquals(privateExponent, this.expectedPrivateExponent);
        Assert.assertEquals(prime1, this.expectedPrime1);
        Assert.assertEquals(prime2, this.expectedPrime2);
        Assert.assertEquals(primeExponent1, this.expectedPrimeExponent1);
        Assert.assertEquals(primeExponent2, this.expectedPrimeExponent2);
        Assert.assertEquals(coefficient, this.expectedCoefficient);
    }

    @Test
    public void testBcKeyParameters()
    {
        RSAPrivateCrtKeyParameters bcKeyParameters = (RSAPrivateCrtKeyParameters) this.key.bcKeyParameters();
        String modulus = DatatypeConverter.printBase64Binary(bcKeyParameters.getModulus().toByteArray());
        String publicExponent = DatatypeConverter.printBase64Binary(bcKeyParameters.getPublicExponent().toByteArray());
        String privateExponent = DatatypeConverter.printBase64Binary(bcKeyParameters.getExponent().toByteArray());
        String prime1 = DatatypeConverter.printBase64Binary(bcKeyParameters.getP().toByteArray());
        String prime2 = DatatypeConverter.printBase64Binary(bcKeyParameters.getQ().toByteArray());
        String primeExponent1 = DatatypeConverter.printBase64Binary(bcKeyParameters.getDP().toByteArray());
        String primeExponent2 = DatatypeConverter.printBase64Binary(bcKeyParameters.getDQ().toByteArray());
        String coefficient = DatatypeConverter.printBase64Binary(bcKeyParameters.getQInv().toByteArray());

        Assert.assertEquals(modulus, this.expectedModulus);
        Assert.assertEquals(publicExponent, this.expectedPublicExponent);
        Assert.assertEquals(privateExponent, this.expectedPrivateExponent);
        Assert.assertEquals(prime1, this.expectedPrime1);
        Assert.assertEquals(prime2, this.expectedPrime2);
        Assert.assertEquals(primeExponent1, this.expectedPrimeExponent1);
        Assert.assertEquals(primeExponent2, this.expectedPrimeExponent2);
        Assert.assertEquals(coefficient, this.expectedCoefficient);
    }

    @Test
    public void testBcPrivateKey()
    {
        RSAPrivateKey bcPrivateKey = this.key.bcPrivateKey();
        String modulus = DatatypeConverter.printBase64Binary(bcPrivateKey.getModulus().toByteArray());
        String publicExponent = DatatypeConverter.printBase64Binary(bcPrivateKey.getPublicExponent().toByteArray());
        String privateExponent = DatatypeConverter.printBase64Binary(bcPrivateKey.getPrivateExponent().toByteArray());
        String prime1 = DatatypeConverter.printBase64Binary(bcPrivateKey.getPrime1().toByteArray());
        String prime2 = DatatypeConverter.printBase64Binary(bcPrivateKey.getPrime2().toByteArray());
        String primeExponent1 = DatatypeConverter.printBase64Binary(bcPrivateKey.getExponent1().toByteArray());
        String primeExponent2 = DatatypeConverter.printBase64Binary(bcPrivateKey.getExponent2().toByteArray());
        String coefficient = DatatypeConverter.printBase64Binary(bcPrivateKey.getCoefficient().toByteArray());

        Assert.assertEquals(modulus, this.expectedModulus);
        Assert.assertEquals(publicExponent, this.expectedPublicExponent);
        Assert.assertEquals(privateExponent, this.expectedPrivateExponent);
        Assert.assertEquals(prime1, this.expectedPrime1);
        Assert.assertEquals(prime2, this.expectedPrime2);
        Assert.assertEquals(primeExponent1, this.expectedPrimeExponent1);
        Assert.assertEquals(primeExponent2, this.expectedPrimeExponent2);
        Assert.assertEquals(coefficient, this.expectedCoefficient);
    }

    @Test
    public void testBcPrivateKeyInfo() throws Throwable
    {
        PrivateKeyInfo bcPrivateKeyInfo = this.key.bcPrivateKeyInfo();
        AsymmetricKeyParameter bcKeyParameters = PrivateKeyFactory.createKey(bcPrivateKeyInfo);
        RSAPrivateCrtKeyParameters bcPrivateKeyParameters = (RSAPrivateCrtKeyParameters) bcKeyParameters;
        String modulus = DatatypeConverter.printBase64Binary(bcPrivateKeyParameters.getModulus().toByteArray());
        String publicExponent = DatatypeConverter.printBase64Binary(
            bcPrivateKeyParameters.getPublicExponent().toByteArray()
        );
        String privateExponent = DatatypeConverter.printBase64Binary(
            bcPrivateKeyParameters.getExponent().toByteArray()
        );
        String prime1 = DatatypeConverter.printBase64Binary(bcPrivateKeyParameters.getP().toByteArray());
        String prime2 = DatatypeConverter.printBase64Binary(bcPrivateKeyParameters.getQ().toByteArray());
        String primeExponent1 = DatatypeConverter.printBase64Binary(bcPrivateKeyParameters.getDP().toByteArray());
        String primeExponent2 = DatatypeConverter.printBase64Binary(bcPrivateKeyParameters.getDQ().toByteArray());
        String coefficient = DatatypeConverter.printBase64Binary(bcPrivateKeyParameters.getQInv().toByteArray());

        Assert.assertEquals(modulus, this.expectedModulus);
        Assert.assertEquals(publicExponent, this.expectedPublicExponent);
        Assert.assertEquals(privateExponent, this.expectedPrivateExponent);
        Assert.assertEquals(prime1, this.expectedPrime1);
        Assert.assertEquals(prime2, this.expectedPrime2);
        Assert.assertEquals(primeExponent1, this.expectedPrimeExponent1);
        Assert.assertEquals(primeExponent2, this.expectedPrimeExponent2);
        Assert.assertEquals(coefficient, this.expectedCoefficient);
    }

    @Test(expectedExceptions = RuntimeException.class)
    public void testBcPrivateKeyInfoFailure() throws Throwable
    {
        PrivateKeyInformationFactory mockFactory = Mockito.mock(PrivateKeyInformationFactory.class);
        Mockito.when(mockFactory.create(Mockito.any(RSAPrivateCrtKeyParameters.class))).thenThrow(new IOException());

        this.key.bcPrivateKeyInfo(mockFactory);
    }

    @Test
    public void testJcePrivateKey() throws Throwable
    {
        java.security.PrivateKey jcePrivateKey = this.key.jcePrivateKey();
        StringWriter stringWriter = new StringWriter();
        PEMWriter pemWriter = new PEMWriter(stringWriter);
        pemWriter.writeObject(jcePrivateKey);
        pemWriter.close();
        stringWriter.close();

        Assert.assertEquals(stringWriter.toString(), this.keyString);
    }

    @Test(expectedExceptions = RuntimeException.class)
    public void testJcePublicKeyFailure() throws Throwable
    {
        JcaPEMKeyConverter mockConverter = Mockito.mock(JcaPEMKeyConverter.class);
        Mockito.when(mockConverter.getPrivateKey(Mockito.any(PrivateKeyInfo.class)))
            .thenThrow(new PEMException(""));

        this.key.jcePrivateKey(mockConverter);
    }

    @Test
    public void testToPem()
    {
        Assert.assertEquals(this.key.toPem(), this.keyString);
    }

    @Test(expectedExceptions = RuntimeException.class)
    public void testToPemFailure() throws Throwable
    {
        StringWriter stringWriter = Mockito.mock(StringWriter.class);
        PEMWriter pemWriter = Mockito.mock(PEMWriter.class);
        StringWriterFactory stringWriterFactory = Mockito.mock(StringWriterFactory.class);
        PemWriterFactory pemWriterFactory = Mockito.mock(PemWriterFactory.class);
        Mockito.when(stringWriterFactory.create()).thenReturn(stringWriter);
        Mockito.when(pemWriterFactory.create(stringWriter)).thenReturn(pemWriter);
        Mockito.doThrow(new IOException()).when(pemWriter).writeObject(Mockito.any(SubjectPublicKeyInfo.class));

        try {
            this.key.toPem(stringWriterFactory, pemWriterFactory);
        } finally {
            InOrder inOrder = Mockito.inOrder(stringWriter, pemWriter);
            inOrder.verify(pemWriter).close();
            inOrder.verify(stringWriter).close();
        }
    }

    @Test(expectedExceptions = RuntimeException.class)
    public void testToPemFailureClosePemWriter() throws Throwable
    {
        StringWriter stringWriter = Mockito.mock(StringWriter.class);
        PEMWriter pemWriter = Mockito.mock(PEMWriter.class);
        StringWriterFactory stringWriterFactory = Mockito.mock(StringWriterFactory.class);
        PemWriterFactory pemWriterFactory = Mockito.mock(PemWriterFactory.class);
        Mockito.when(stringWriterFactory.create()).thenReturn(stringWriter);
        Mockito.when(pemWriterFactory.create(stringWriter)).thenReturn(pemWriter);
        Mockito.doThrow(new IOException()).when(pemWriter).close();

        try {
            this.key.toPem(stringWriterFactory, pemWriterFactory);
        } finally {
            InOrder inOrder = Mockito.inOrder(stringWriter, pemWriter);
            inOrder.verify(pemWriter).close();
            inOrder.verify(stringWriter).close();
        }
    }

    @Test(expectedExceptions = RuntimeException.class)
    public void testToPemFailureWriteAndClosePemWriter() throws Throwable
    {
        StringWriter stringWriter = Mockito.mock(StringWriter.class);
        PEMWriter pemWriter = Mockito.mock(PEMWriter.class);
        StringWriterFactory stringWriterFactory = Mockito.mock(StringWriterFactory.class);
        PemWriterFactory pemWriterFactory = Mockito.mock(PemWriterFactory.class);
        Mockito.when(stringWriterFactory.create()).thenReturn(stringWriter);
        Mockito.when(pemWriterFactory.create(stringWriter)).thenReturn(pemWriter);
        Mockito.doThrow(new IOException()).when(pemWriter).writeObject(Mockito.any(SubjectPublicKeyInfo.class));
        Mockito.doThrow(new IOException()).when(pemWriter).close();

        try {
            this.key.toPem(stringWriterFactory, pemWriterFactory);
        } finally {
            InOrder inOrder = Mockito.inOrder(stringWriter, pemWriter);
            inOrder.verify(pemWriter).close();
            inOrder.verify(stringWriter).close();
        }
    }

    @Test(expectedExceptions = RuntimeException.class)
    public void testToPemFailureCloseStringWriter() throws Throwable
    {
        StringWriter stringWriter = Mockito.mock(StringWriter.class);
        PEMWriter pemWriter = Mockito.mock(PEMWriter.class);
        StringWriterFactory stringWriterFactory = Mockito.mock(StringWriterFactory.class);
        PemWriterFactory pemWriterFactory = Mockito.mock(PemWriterFactory.class);
        Mockito.when(stringWriterFactory.create()).thenReturn(stringWriter);
        Mockito.when(pemWriterFactory.create(stringWriter)).thenReturn(pemWriter);
        Mockito.doThrow(new IOException()).when(stringWriter).close();

        try {
            this.key.toPem(stringWriterFactory, pemWriterFactory);
        } finally {
            InOrder inOrder = Mockito.inOrder(stringWriter, pemWriter);
            inOrder.verify(pemWriter).close();
            inOrder.verify(stringWriter).close();
        }
    }

    @Test(expectedExceptions = RuntimeException.class)
    public void testToPemFailureWriteAndCloseStringWriterAndClosePemWriter() throws Throwable
    {
        StringWriter stringWriter = Mockito.mock(StringWriter.class);
        PEMWriter pemWriter = Mockito.mock(PEMWriter.class);
        StringWriterFactory stringWriterFactory = Mockito.mock(StringWriterFactory.class);
        PemWriterFactory pemWriterFactory = Mockito.mock(PemWriterFactory.class);
        Mockito.when(stringWriterFactory.create()).thenReturn(stringWriter);
        Mockito.when(pemWriterFactory.create(stringWriter)).thenReturn(pemWriter);
        Mockito.doThrow(new IOException()).when(pemWriter).writeObject(Mockito.any(SubjectPublicKeyInfo.class));
        Mockito.doThrow(new IOException()).when(pemWriter).close();
        Mockito.doThrow(new IOException()).when(stringWriter).close();

        try {
            this.key.toPem(stringWriterFactory, pemWriterFactory);
        } finally {
            InOrder inOrder = Mockito.inOrder(stringWriter, pemWriter);
            inOrder.verify(pemWriter).close();
            inOrder.verify(stringWriter).close();
        }
    }

    @Test
    public void testToString()
    {
        Assert.assertEquals(this.key.toString(), this.keyString);
    }

    private KeyFactory factory;
    private String keyString;
    private PrivateKey key;
    private String expectedModulus;
    private String expectedPublicExponent;
    private String expectedPrivateExponent;
    private String expectedPrime1;
    private String expectedPrime2;
    private String expectedPrimeExponent1;
    private String expectedPrimeExponent2;
    private String expectedCoefficient;
}
