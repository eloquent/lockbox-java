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
import co.lqnt.lockbox.util.StringWriterFactory;
import co.lqnt.lockbox.util.PublicKeyInformationFactory;
import java.io.IOException;
import java.io.StringWriter;
import javax.xml.bind.DatatypeConverter;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.mockito.InOrder;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.Test;

public class PublicKeyTest
{
    public PublicKeyTest() throws Throwable
    {
        this.factory = new KeyFactory();

        this.keyString =
            "-----BEGIN PUBLIC KEY-----\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8jsljdxzsgvboCytmlH\n" +
            "3Q03v30fPTNfMqmz2Yn0GdtkqQH01+H9y5bWWCQyeGOATvIPrELGeB9nRlQeaTb5\n" +
            "VjCl1V9PYeM6Q30PK6411fJexjYA/UbRG/9I/K+A9UBfJvUsjGVUMxZR8n8jmmSy\n" +
            "8G2eqXBbP6dEZFnO0V274TRTB3SLKD2tfYBYwMtXqT+rSbH1OyoS29A03FaUgkRk\n" +
            "1er2i3ldyNIG8vMGv7Iagup69yBrt8xo61IFj76dkocbozp1Y4SGzyjkR/ukRSLe\n" +
            "+0ejS4eMyziaH7J52XX1rDFreinZZDoE571ameu0biuM6aT8P1pk85VIqHLlqRm/\n" +
            "vQIDAQAB\n" +
            "-----END PUBLIC KEY-----\n";
        this.key = this.factory.createPublicKey(this.keyString);
        this.expectedModulus =
            "AMvI7JY3cc7IL26AsrZpR90NN799Hz0z" +
            "XzKps9mJ9BnbZKkB9Nfh/cuW1lgkMnhj" +
            "gE7yD6xCxngfZ0ZUHmk2+VYwpdVfT2Hj" +
            "OkN9DyuuNdXyXsY2AP1G0Rv/SPyvgPVA" +
            "Xyb1LIxlVDMWUfJ/I5pksvBtnqlwWz+n" +
            "RGRZztFdu+E0Uwd0iyg9rX2AWMDLV6k/" +
            "q0mx9TsqEtvQNNxWlIJEZNXq9ot5XcjS" +
            "BvLzBr+yGoLqevcga7fMaOtSBY++nZKH" +
            "G6M6dWOEhs8o5Ef7pEUi3vtHo0uHjMs4" +
            "mh+yedl19awxa3op2WQ6BOe9WpnrtG4r" +
            "jOmk/D9aZPOVSKhy5akZv70=";
        this.expectedPublicExponent = "AQAB";
    }

    @Test
    public void testConstructor()
    {
        String modulus = DatatypeConverter.printBase64Binary(this.key.modulus().toByteArray());
        String publicExponent = DatatypeConverter.printBase64Binary(this.key.publicExponent().toByteArray());

        Assert.assertEquals(modulus, this.expectedModulus);
        Assert.assertEquals(publicExponent, this.expectedPublicExponent);
    }

    @Test
    public void testSize()
    {
        Assert.assertEquals(this.key.size(), 2048);
    }

    @Test
    public void testBcPublicKeyParameters()
    {
        RSAKeyParameters bcPublicKeyParameters = this.key.bcPublicKeyParameters();
        String modulus = DatatypeConverter.printBase64Binary(bcPublicKeyParameters.getModulus().toByteArray());
        String publicExponent = DatatypeConverter.printBase64Binary(bcPublicKeyParameters.getExponent().toByteArray());

        Assert.assertEquals(modulus, this.expectedModulus);
        Assert.assertEquals(publicExponent, this.expectedPublicExponent);
    }

    @Test
    public void testBcKeyParameters()
    {
        RSAKeyParameters bcKeyParameters = (RSAKeyParameters) this.key.bcKeyParameters();
        String modulus = DatatypeConverter.printBase64Binary(bcKeyParameters.getModulus().toByteArray());
        String publicExponent = DatatypeConverter.printBase64Binary(bcKeyParameters.getExponent().toByteArray());

        Assert.assertEquals(modulus, this.expectedModulus);
        Assert.assertEquals(publicExponent, this.expectedPublicExponent);
    }

    @Test
    public void testBcPublicKey()
    {
        RSAPublicKey bcPublicKey = this.key.bcPublicKey();
        String modulus = DatatypeConverter.printBase64Binary(bcPublicKey.getModulus().toByteArray());
        String publicExponent = DatatypeConverter.printBase64Binary(bcPublicKey.getPublicExponent().toByteArray());

        Assert.assertEquals(modulus, this.expectedModulus);
        Assert.assertEquals(publicExponent, this.expectedPublicExponent);
    }

    @Test
    public void testBcPublicKeyInfo() throws Throwable
    {
        SubjectPublicKeyInfo bcPublicKeyInfo = this.key.bcPublicKeyInfo();
        AsymmetricKeyParameter bcKeyParameters = PublicKeyFactory.createKey(bcPublicKeyInfo);
        RSAKeyParameters bcPublicKeyParameters = (RSAKeyParameters) bcKeyParameters;
        String modulus = DatatypeConverter.printBase64Binary(bcPublicKeyParameters.getModulus().toByteArray());
        String publicExponent = DatatypeConverter.printBase64Binary(bcPublicKeyParameters.getExponent().toByteArray());

        Assert.assertEquals(modulus, this.expectedModulus);
        Assert.assertEquals(publicExponent, this.expectedPublicExponent);
    }

    @Test(expectedExceptions = RuntimeException.class)
    public void testBcPublicKeyInfoFailure() throws Throwable
    {
        PublicKeyInformationFactory mockFactory = Mockito.mock(PublicKeyInformationFactory.class);
        Mockito.when(mockFactory.create(Mockito.any(RSAKeyParameters.class))).thenThrow(new IOException());

        this.key.bcPublicKeyInfo(mockFactory);
    }

    @Test
    public void testJcePublicKey() throws Throwable
    {
        java.security.PublicKey jcePublicKey = this.key.jcePublicKey();
        StringWriter stringWriter = new StringWriter();
        PEMWriter pemWriter = new PEMWriter(stringWriter);
        pemWriter.writeObject(jcePublicKey);
        pemWriter.close();
        stringWriter.close();

        Assert.assertEquals(stringWriter.toString(), this.keyString);
    }

    @Test(expectedExceptions = RuntimeException.class)
    public void testJcePublicKeyFailure() throws Throwable
    {
        JcaPEMKeyConverter mockConverter = Mockito.mock(JcaPEMKeyConverter.class);
        Mockito.when(mockConverter.getPublicKey(Mockito.any(SubjectPublicKeyInfo.class)))
            .thenThrow(new PEMException(""));

        this.key.jcePublicKey(mockConverter);
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
    private PublicKey key;
    private String expectedModulus;
    private String expectedPublicExponent;
}
