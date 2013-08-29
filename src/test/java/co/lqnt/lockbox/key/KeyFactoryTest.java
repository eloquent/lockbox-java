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
import co.lqnt.lockbox.key.exception.PublicKeyReadException;
import co.lqnt.lockbox.pem.PemParserFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.PublicKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class KeyFactoryTest
{
    @BeforeMethod
    public void setUp()
    {
        BouncyCastleProvider provider = new BouncyCastleProvider();

        this.pemParserFactory = new PemParserFactory();

        this.decryptorProviderBuilder =
            new JcePEMDecryptorProviderBuilder();
        this.decryptorProviderBuilder.setProvider(provider);

        this.keyConverter = new JcaPEMKeyConverter();
        this.keyConverter.setProvider(provider);

        this.factory = new KeyFactory(this.pemParserFactory, this.decryptorProviderBuilder, this.keyConverter);

        this.privateKeyString =
            "-----BEGIN RSA PRIVATE KEY-----\n" +
            "Proc-Type: 4,ENCRYPTED\n" +
            "DEK-Info: DES-EDE3-CBC,C993FE1F47B61753\n" +
            "\n" +
            "YEyAqkV+1qDThx1TYeAEs7eQmT8FkEWv/mnZvebKz3hMweP8/59vGYHzqK6fapGj\n" +
            "WV+UM01IqQQOgsbXdsqn1TyNsOu1QvqLJHQoxkirknAsPfqHHhFCxd0qjY9wW5rp\n" +
            "j29P5SBH+lpizLWa9spjrZuzejI5vDztojy7IJmTu5nsUq1HjyLuhZqBX/JcwDFS\n" +
            "/EGPVPKZcn4bQGUVJ/y1TZIBXkaR8wflVD7ViRh+GrdTjI7biX7LgoY7v0scV25L\n" +
            "NxV/thpxnZEeT5vOeROrPig+aH5VzwimzZ5MSLoCkE0EMJVhrA8xiylIiqw/5xFt\n" +
            "UDWc7DUUGL3OwAEg3EN46vSfgN8tZrFEyoU5//JutZq89few2GbAtyC9sTIxYBxP\n" +
            "1SAc46SM3cHf7MOyuNA4fOceLW3RY6k6GcH9SIBGk49+UWf4TBJg53+Lwj7M57os\n" +
            "o3mg0RtZ1j5snjd8rXKwvTfRMeY70minkPK6RCUwu/aGI9ORGTCOF5FBUXeEEtEC\n" +
            "vgx1mNUjfUK682Q+yjZ3oSMn9pupiGu49XkClxn613be9b/gpKm4Qr62sac/2Y/n\n" +
            "A+zQA4+wevz/zCCoGiktO6AtvIXnuZxGlq4IjzBtYH2D0Z6HatsWWw+LnAeYzSgh\n" +
            "WM/0WjMuiSyYAIQJyqojdIQG+5jwz1WL9mACi8/2r+E1SXcy69ILJn2oWyYLVXD8\n" +
            "vLLK8gV+uKSvmSV2JHYOsuZUGBwyZ75qdY88IaENZTPpZGozh61/mI59seQQqsmZ\n" +
            "T2UD1DiMZZy+/8TW/rpBqiNN8p7Ft/U/OAT2B5j04LIEszMWIJ4ffYF69Xtd/oPU\n" +
            "0p460C1RGxwIhg5bHwfx7w2tEEuM0huBjn9iyaEpJo/YkJpRwGiTi2Xc3Mw5Y2BG\n" +
            "8hdxOvLOpjjGUKjms6QVRqLX2g9hGT5OCKzec4y2Oz9k2aaQ3VCg3fsvlOfP0Yv9\n" +
            "Sh+qJlG66BnrhQ4MMaEbYXpmgp0O4q00+xbInNI83e+Oo3Ia0Oyn6Kbi/4IMaegK\n" +
            "ocH5zr9ONBcUQsibQqu/6b0dSe8Yf2isUtagkFic7ZDsuMmrkmln2PrCBFB2daa8\n" +
            "yWrtZnib9Q2e3QPgFR75kggAmQoN41Y8O2eqw0lHOwBhckE+tSsKkF6dDDyillbB\n" +
            "8XaTllLk2kdC5VGlJtAHGcXDdTgBjyZzbJWt6niJT6KRTWIR6JQk/9t/twmmB9Sr\n" +
            "jXOtCh3/kEDfV+hOFCNNm+mhQdVt8OlevtYnNu3A1sAXpf4Vr3oeaNnvwkqmzlDj\n" +
            "2pbBd7LiJcnP0VvzxSCrErxMBl6s14u2cd5c3r/fiGnaR3u8nxA+GpUPDjD6lNh5\n" +
            "or6BubNGS4NQMrMQ2OL31d5P3qcPZtQoJNdz1MAj5y4qOQBKA384VdIDDF8gJl4k\n" +
            "j5zYqI0tn06/UKWyN3aBknXBKY//LwFBbksSdAeLeHClnbfxpz0hTlj31IT8Td9U\n" +
            "MHgOFCXFKwkUDZH8pou/7Q4eYWwICCcaPp3QA0wv3FNwyBmgamw7quqbk7xiJuz7\n" +
            "1E/yfdAXEjlPRibVjvwpopYitZcGqIS0Mt9bXtwugzdeQh9TF2karA==\n" +
            "-----END RSA PRIVATE KEY-----\n";
        this.publicKeyString =
            "-----BEGIN PUBLIC KEY-----\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwpFuTp1Y+b1JZ9k37aJO\n" +
            "7DT7KT6CE426qbH0SmqUmIFCJOxLTnK/tUV/00VMm16XPeOLQwIGAL5+RpcjIQA8\n" +
            "VEgZKvJQ4bPlRTIm/SKP0goCzUbP7hUbtuaUQvXFrrlcl4YRoF2bwbp3BR3ikUE8\n" +
            "ir6ZtiCTJYSawFZQiSq++M/u4ZZ9rYS9OF7NEKDW7bb9SYsHJv4fPlm7hwIWADdj\n" +
            "OdJSsQRVNOoBBOWG8leIPBdlmKq7PaTJlTlgYpW8IIc37LYj5APl26OLWEYI/VQH\n" +
            "HPIE5o9vqKJL0mC0TCrlJv9Z+Bx1408YwFJf32ubc5c0TtvWC9s+8eu+J5bDbzGd\n" +
            "IQIDAQAB\n" +
            "-----END PUBLIC KEY-----\n";
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
        this.privateKeyStringWrongIv =
            "-----BEGIN RSA PRIVATE KEY-----\n" +
            "Proc-Type: 4,ENCRYPTED\n" +
            "DEK-Info: DES-EDE3-CBC,C993FE1F47B61754\n" +
            "\n" +
            "YEyAqkV+1qDThx1TYeAEs7eQmT8FkEWv/mnZvebKz3hMweP8/59vGYHzqK6fapGj\n" +
            "WV+UM01IqQQOgsbXdsqn1TyNsOu1QvqLJHQoxkirknAsPfqHHhFCxd0qjY9wW5rp\n" +
            "j29P5SBH+lpizLWa9spjrZuzejI5vDztojy7IJmTu5nsUq1HjyLuhZqBX/JcwDFS\n" +
            "/EGPVPKZcn4bQGUVJ/y1TZIBXkaR8wflVD7ViRh+GrdTjI7biX7LgoY7v0scV25L\n" +
            "NxV/thpxnZEeT5vOeROrPig+aH5VzwimzZ5MSLoCkE0EMJVhrA8xiylIiqw/5xFt\n" +
            "UDWc7DUUGL3OwAEg3EN46vSfgN8tZrFEyoU5//JutZq89few2GbAtyC9sTIxYBxP\n" +
            "1SAc46SM3cHf7MOyuNA4fOceLW3RY6k6GcH9SIBGk49+UWf4TBJg53+Lwj7M57os\n" +
            "o3mg0RtZ1j5snjd8rXKwvTfRMeY70minkPK6RCUwu/aGI9ORGTCOF5FBUXeEEtEC\n" +
            "vgx1mNUjfUK682Q+yjZ3oSMn9pupiGu49XkClxn613be9b/gpKm4Qr62sac/2Y/n\n" +
            "A+zQA4+wevz/zCCoGiktO6AtvIXnuZxGlq4IjzBtYH2D0Z6HatsWWw+LnAeYzSgh\n" +
            "WM/0WjMuiSyYAIQJyqojdIQG+5jwz1WL9mACi8/2r+E1SXcy69ILJn2oWyYLVXD8\n" +
            "vLLK8gV+uKSvmSV2JHYOsuZUGBwyZ75qdY88IaENZTPpZGozh61/mI59seQQqsmZ\n" +
            "T2UD1DiMZZy+/8TW/rpBqiNN8p7Ft/U/OAT2B5j04LIEszMWIJ4ffYF69Xtd/oPU\n" +
            "0p460C1RGxwIhg5bHwfx7w2tEEuM0huBjn9iyaEpJo/YkJpRwGiTi2Xc3Mw5Y2BG\n" +
            "8hdxOvLOpjjGUKjms6QVRqLX2g9hGT5OCKzec4y2Oz9k2aaQ3VCg3fsvlOfP0Yv9\n" +
            "Sh+qJlG66BnrhQ4MMaEbYXpmgp0O4q00+xbInNI83e+Oo3Ia0Oyn6Kbi/4IMaegK\n" +
            "ocH5zr9ONBcUQsibQqu/6b0dSe8Yf2isUtagkFic7ZDsuMmrkmln2PrCBFB2daa8\n" +
            "yWrtZnib9Q2e3QPgFR75kggAmQoN41Y8O2eqw0lHOwBhckE+tSsKkF6dDDyillbB\n" +
            "8XaTllLk2kdC5VGlJtAHGcXDdTgBjyZzbJWt6niJT6KRTWIR6JQk/9t/twmmB9Sr\n" +
            "jXOtCh3/kEDfV+hOFCNNm+mhQdVt8OlevtYnNu3A1sAXpf4Vr3oeaNnvwkqmzlDj\n" +
            "2pbBd7LiJcnP0VvzxSCrErxMBl6s14u2cd5c3r/fiGnaR3u8nxA+GpUPDjD6lNh5\n" +
            "or6BubNGS4NQMrMQ2OL31d5P3qcPZtQoJNdz1MAj5y4qOQBKA384VdIDDF8gJl4k\n" +
            "j5zYqI0tn06/UKWyN3aBknXBKY//LwFBbksSdAeLeHClnbfxpz0hTlj31IT8Td9U\n" +
            "MHgOFCXFKwkUDZH8pou/7Q4eYWwICCcaPp3QA0wv3FNwyBmgamw7quqbk7xiJuz7\n" +
            "1E/yfdAXEjlPRibVjvwpopYitZcGqIS0Mt9bXtwugzdeQh9TF2karA==\n" +
            "-----END RSA PRIVATE KEY-----\n";
    }

    @Test
    public void testConstructor()
    {
        Assert.assertSame(this.factory.pemParserFactory(), this.pemParserFactory);
        Assert.assertSame(this.factory.decryptorProviderBuilder(), this.decryptorProviderBuilder);
        Assert.assertSame(this.factory.keyConverter(), this.keyConverter);
    }

    @Test
    public void testConstructorDefaults()
    {
        this.factory = new KeyFactory();

        Assert.assertSame(this.factory.pemParserFactory().getClass(), PemParserFactory.class);
        Assert.assertSame(this.factory.decryptorProviderBuilder().getClass(), JcePEMDecryptorProviderBuilder.class);
        Assert.assertSame(this.factory.keyConverter().getClass(), JcaPEMKeyConverter.class);
    }

    @Test
    public void testCreateKeyPairWithPassword() throws Throwable
    {
        KeyPair keyPair = this.factory.createKeyPair(this.stringToInputStream(this.privateKeyString), "password");

        Assert.assertEquals(this.publicKeyToPemString(keyPair.getPublic()), this.publicKeyString);
    }

    @Test
    public void testCreateKeyPairNoPassword() throws Throwable
    {
        KeyPair keyPair = this.factory.createKeyPair(this.stringToInputStream(this.privateKeyStringNoPassword));

        Assert.assertEquals(this.publicKeyToPemString(keyPair.getPublic()), this.publicKeyStringNoPassword);
    }

    @Test(expectedExceptions = KeyPairReadException.class)
    public void testCreateKeyPairFailureNonPemData() throws Throwable
    {
        this.factory.createKeyPair(this.stringToInputStream(""), "password");
    }

    @Test(expectedExceptions = KeyPairReadException.class)
    public void testCreateKeyPairNoPasswordFailureNonPemData() throws Throwable
    {
        this.factory.createKeyPair(this.stringToInputStream(""));
    }

    @Test(expectedExceptions = KeyPairReadException.class)
    public void testCreateKeyPairFailureNoPemEnd() throws Throwable
    {
        this.factory.createKeyPair(this.stringToInputStream("-----BEGIN RSA PRIVATE KEY-----\n"), "password");
    }

    @Test(expectedExceptions = KeyPairReadException.class)
    public void testCreateKeyPairNoPasswordFailureNoPemEnd() throws Throwable
    {
        this.factory.createKeyPair(this.stringToInputStream("-----BEGIN RSA PRIVATE KEY-----\n"));
    }

    @Test(expectedExceptions = KeyPairReadException.class)
    public void testCreateKeyPairFailureNotPrivateKey() throws Throwable
    {
        this.factory.createKeyPair(this.stringToInputStream(this.publicKeyString), "password");
    }

    @Test(expectedExceptions = KeyPairReadException.class)
    public void testCreateKeyPairNoPasswordFailureNotPrivateKey() throws Throwable
    {
        this.factory.createKeyPair(this.stringToInputStream(this.publicKeyString));
    }

    @Test(expectedExceptions = KeyPairReadException.class)
    public void testCreateKeyPairFailurePemConversion() throws Throwable
    {
        this.keyConverter = Mockito.mock(JcaPEMKeyConverter.class);
        Mockito.when(this.keyConverter.getKeyPair(Mockito.any(PEMKeyPair.class)))
            .thenThrow(new PEMException(""));
        this.factory = new KeyFactory(this.pemParserFactory, this.decryptorProviderBuilder, this.keyConverter);

        this.factory.createKeyPair(this.stringToInputStream(this.privateKeyString), "password");
    }

    @Test(expectedExceptions = KeyPairReadException.class)
    public void testCreateKeyPairNoPasswordFailurePemConversion() throws Throwable
    {
        this.keyConverter = Mockito.mock(JcaPEMKeyConverter.class);
        Mockito.when(this.keyConverter.getKeyPair(Mockito.any(PEMKeyPair.class)))
            .thenThrow(new PEMException(""));
        this.factory = new KeyFactory(this.pemParserFactory, this.decryptorProviderBuilder, this.keyConverter);

        this.factory.createKeyPair(this.stringToInputStream(this.privateKeyStringNoPassword));
    }

    @Test(expectedExceptions = KeyPairReadException.class)
    public void testCreateKeyPairFailureDecryption() throws Throwable
    {
        this.factory.createKeyPair(this.stringToInputStream(this.privateKeyStringWrongIv), "password");
    }

    @Test
    public void testCreatePublicKey() throws Throwable
    {
        PublicKey publicKey = this.factory.createPublicKey(this.stringToInputStream(this.publicKeyString));

        Assert.assertEquals(this.publicKeyToPemString(publicKey), this.publicKeyString);
    }

    @Test(expectedExceptions = PublicKeyReadException.class)
    public void testCreatePublicKeyFailureNonPemData() throws Throwable
    {
        this.factory.createPublicKey(this.stringToInputStream(""));
    }

    @Test(expectedExceptions = PublicKeyReadException.class)
    public void testCreatePublicKeyFailureNoPemEnd() throws Throwable
    {
        this.factory.createPublicKey(this.stringToInputStream("-----BEGIN PUBLIC KEY-----\n"));
    }

    @Test(expectedExceptions = PublicKeyReadException.class)
    public void testCreatePublicKeyFailureNotPublicKey() throws Throwable
    {
        this.factory.createPublicKey(this.stringToInputStream(this.privateKeyStringNoPassword));
    }

    @Test(expectedExceptions = PublicKeyReadException.class)
    public void testCreatePublicKeyFailurePemConversion() throws Throwable
    {
        this.keyConverter = Mockito.mock(JcaPEMKeyConverter.class);
        Mockito.when(this.keyConverter.getPublicKey(Mockito.any(SubjectPublicKeyInfo.class)))
            .thenThrow(new PEMException(""));
        this.factory = new KeyFactory(this.pemParserFactory, this.decryptorProviderBuilder, this.keyConverter);

        this.factory.createPublicKey(this.stringToInputStream(this.publicKeyString));
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
    private PemParserFactory pemParserFactory;
    private JcePEMDecryptorProviderBuilder decryptorProviderBuilder;
    private JcaPEMKeyConverter keyConverter;
    private String privateKeyString;
    private String publicKeyString;
    private String privateKeyStringNoPassword;
    private String publicKeyStringNoPassword;
    private String privateKeyStringWrongIv;
}
