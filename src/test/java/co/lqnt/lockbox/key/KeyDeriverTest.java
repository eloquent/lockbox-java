/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.key;

import co.lqnt.lockbox.key.exception.InvalidAuthSecretSizeException;
import co.lqnt.lockbox.key.exception.InvalidEncryptSecretSizeException;
import co.lqnt.lockbox.key.exception.InvalidIterationsException;
import co.lqnt.lockbox.key.exception.InvalidSaltSizeException;
import co.lqnt.lockbox.random.RandomSourceInterface;
import co.lqnt.lockbox.random.SecureRandom;
import com.google.common.io.BaseEncoding;
import com.google.common.primitives.Bytes;
import com.google.common.primitives.Chars;
import java.nio.charset.Charset;
import java.util.List;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class KeyDeriverTest
{
    public KeyDeriverTest()
    {
        this.pbeParametersGenerator = new PKCS5S2ParametersGenerator(new SHA512Digest());
        this.randomSource = Mockito.mock(RandomSourceInterface.class);

        this.bytes64 = Bytes.asList(
            "1234567890123456789012345678901234567890123456789012345678901234".getBytes(Charset.forName("US-ASCII"))
        );
    }

    @BeforeMethod
    public void setUp()
    {
        this.factory = new KeyFactory();
        this.deriver = new KeyDeriver(this.factory, this.pbeParametersGenerator, this.randomSource);

        Mockito.when(this.randomSource.generate(64)).thenReturn(this.bytes64);
    }

    @Test
    public void testConstructor()
    {
        Assert.assertSame(this.deriver.factory(), this.factory);
        Assert.assertSame(this.deriver.pbeParametersGenerator(), this.pbeParametersGenerator);
        Assert.assertSame(this.deriver.randomSource(), this.randomSource);
    }

    @Test
    public void testConstructorDefaults()
    {
        this.deriver = new KeyDeriver();

        Assert.assertSame(this.deriver.factory(), KeyFactory.instance());
        Assert.assertSame(this.deriver.pbeParametersGenerator().getClass(), PKCS5S2ParametersGenerator.class);
        Assert.assertSame(this.deriver.randomSource(), SecureRandom.instance());
    }

    @DataProvider(name = "keyDerivationData")
    public Object[][] keyDerivationData()
    {
        return new Object[][]{
            {"",                      1000,   this.bytes64, "2k1fkksUHSjVMxOMNkPBihtocgu1ziAI4CVRFfC7ClM", "lNXoGLA83xvvlAUuHCQEw9OcsUloYygz2Oq4PFRMUh4"},
            {"foo",                   1000,   this.bytes64, "9eWWednk0FFnvE_NXA0uElPqBvSRDxTNNfKjj8j-w74", "H8-n0cCupLeoCYckdGFWlwWc8GAl_XvBokZMgWbhB1U"},
            {"foobar",                1000,   this.bytes64, "gvP8UROn7oLyZpbguWlDryCE82uANmVHdp4cV1ZKNik", "shiABRhWtR0nKk6uO_efWMf6yk7iZ8OnD9PjIdYJxVQ"},
            {"foobar",                10000,  this.bytes64, "ZYRW2br9KSzOY4KKpoEGHMXzT4PYa_CP5qPdqSkZKXI", "Bq2Yqmr9iwi89x-DV5MUIMUmvEAXgYNhuLR0dt10jv0"},
            {"foobar",                100000, this.bytes64, "Zbz3tZJjWJDGwMmer1aY1TNBW3uscUCziUpIpAF9sXw", "pS5s8iWZBHwzf_hIIm4SMsR9dTHo2yfl2WHpa1Fp6wc"},
            {"foobar",                1,      this.bytes64, "nrmJyhdG9gAbFrTidwKwg5xeKBFF11wkMkJVbVsWG6A", "cclAcqBRCzX8VMT-DkiNzHiH4emz6GT_iVVpIB84ccw"},
            {"f\u00F6\u00F6b\u00E4r", 1000,   this.bytes64, "kJcrKAvpBNxM5N3uIrBXjwznaAWAWkaqyhd_btIaC1Q", "QKLqZ8Rsrm-WOWxRQwRQ2bSmKkeN00IF_C8MFSYp0Qs"},
        };
    }

    @Test(dataProvider = "keyDerivationData")
    public void testDeriveKeyFromPassword(
        final String password,
        final int iterations,
        final List<Byte> salt,
        final String encryptionSecret,
        final String authenticationSecret
    ) throws Throwable
    {
        List<Character> passwordChars = Chars.asList(password.toCharArray());
        KeyInterface key = this.deriver.deriveKeyFromPassword(passwordChars, iterations, salt, "name", "description");

        Assert.assertEquals(
            BaseEncoding.base64Url().omitPadding().encode(Bytes.toArray(key.encryptSecret())),
            encryptionSecret
        );
        Assert.assertEquals(
            BaseEncoding.base64Url().omitPadding().encode(Bytes.toArray(key.authSecret())),
            authenticationSecret
        );
        Assert.assertEquals(key.name().get(), "name");
        Assert.assertEquals(key.description().get(), "description");
        Assert.assertEquals(passwordChars, Chars.asList(password.toCharArray()));
    }

    @Test
    public void testDeriveKeyFromPasswordWithPasswordIterationsAndSalt() throws Throwable
    {
        List<Character> passwordChars = Chars.asList("foobar".toCharArray());
        KeyInterface key = this.deriver.deriveKeyFromPassword(passwordChars, 10, this.bytes64);

        Assert.assertEquals(
            BaseEncoding.base64Url().omitPadding().encode(Bytes.toArray(key.encryptSecret())),
            "pcVNTpc-PE-kn5dDsuK6UDMQXXJmAQpOygkGavbvTXE"
        );
        Assert.assertEquals(
            BaseEncoding.base64Url().omitPadding().encode(Bytes.toArray(key.authSecret())),
            "1HoCzL6MzfPLCUXIkCdNrQT4v7vpjltxDGbT2qTLqZk"
        );
        Assert.assertFalse(key.name().isPresent());
        Assert.assertFalse(key.description().isPresent());
        Assert.assertEquals(passwordChars, Chars.asList("foobar".toCharArray()));
    }

    @Test
    public void testDeriveKeyFromPasswordWithPasswordAndIterations() throws Throwable
    {
        List<Character> passwordChars = Chars.asList("foobar".toCharArray());
        DerivedKeyDataInterface keyData = this.deriver.deriveKeyFromPassword(passwordChars, 10);

        Assert.assertEquals(
            BaseEncoding.base64Url().omitPadding().encode(Bytes.toArray(keyData.key().encryptSecret())),
            "pcVNTpc-PE-kn5dDsuK6UDMQXXJmAQpOygkGavbvTXE"
        );
        Assert.assertEquals(
            BaseEncoding.base64Url().omitPadding().encode(Bytes.toArray(keyData.key().authSecret())),
            "1HoCzL6MzfPLCUXIkCdNrQT4v7vpjltxDGbT2qTLqZk"
        );
        Assert.assertFalse(keyData.key().name().isPresent());
        Assert.assertFalse(keyData.key().description().isPresent());
        Assert.assertEquals(passwordChars, Chars.asList("foobar".toCharArray()));
    }

    @Test
    public void testDeriveKeyFromPasswordWithPasswordIterationsAndName() throws Throwable
    {
        List<Character> passwordChars = Chars.asList("foobar".toCharArray());
        DerivedKeyDataInterface keyData = this.deriver.deriveKeyFromPassword(passwordChars, 10, "name");

        Assert.assertEquals(
            BaseEncoding.base64Url().omitPadding().encode(Bytes.toArray(keyData.key().encryptSecret())),
            "pcVNTpc-PE-kn5dDsuK6UDMQXXJmAQpOygkGavbvTXE"
        );
        Assert.assertEquals(
            BaseEncoding.base64Url().omitPadding().encode(Bytes.toArray(keyData.key().authSecret())),
            "1HoCzL6MzfPLCUXIkCdNrQT4v7vpjltxDGbT2qTLqZk"
        );
        Assert.assertEquals(keyData.key().name().get(), "name");
        Assert.assertFalse(keyData.key().description().isPresent());
        Assert.assertEquals(passwordChars, Chars.asList("foobar".toCharArray()));
    }

    @Test
    public void testDeriveKeyFromPasswordWithPasswordIterationsNameAndDescription() throws Throwable
    {
        List<Character> passwordChars = Chars.asList("foobar".toCharArray());
        DerivedKeyDataInterface keyData = this.deriver.deriveKeyFromPassword(passwordChars, 10, "name", "description");

        Assert.assertEquals(
            BaseEncoding.base64Url().omitPadding().encode(Bytes.toArray(keyData.key().encryptSecret())),
            "pcVNTpc-PE-kn5dDsuK6UDMQXXJmAQpOygkGavbvTXE"
        );
        Assert.assertEquals(
            BaseEncoding.base64Url().omitPadding().encode(Bytes.toArray(keyData.key().authSecret())),
            "1HoCzL6MzfPLCUXIkCdNrQT4v7vpjltxDGbT2qTLqZk"
        );
        Assert.assertEquals(keyData.key().name().get(), "name");
        Assert.assertEquals(keyData.key().description().get(), "description");
        Assert.assertEquals(passwordChars, Chars.asList("foobar".toCharArray()));
    }

    @Test(expectedExceptions = InvalidIterationsException.class)
    public void testDeriveKeyFromPasswordFailureInvalidIterations() throws Throwable
    {
        this.deriver.deriveKeyFromPassword(Chars.asList("foobar".toCharArray()), 0);
    }

    @Test(expectedExceptions = InvalidSaltSizeException.class)
    public void testDeriveKeyFromPasswordFailureSaltSize() throws Throwable
    {
        this.deriver.deriveKeyFromPassword(
            Chars.asList("foobar".toCharArray()),
            10,
            Bytes.asList("1234567890123456".getBytes(Charset.forName("US-ASCII")))
        );
    }

    @Test(expectedExceptions = RuntimeException.class)
    public void testDeriveKeyFromPasswordFailureGeneratedSaltSize() throws Throwable
    {
        Mockito.when(this.randomSource.generate(64))
            .thenReturn(Bytes.asList("1234567890123456".getBytes(Charset.forName("US-ASCII"))));

        this.deriver.deriveKeyFromPassword(Chars.asList("foobar".toCharArray()), 10);
    }

    @Test(expectedExceptions = RuntimeException.class)
    public void testDeriveKeyFromPasswordFailureEncryptionSecretSize() throws Throwable
    {
        this.factory = Mockito.mock(KeyFactoryInterface.class);
        this.deriver = new KeyDeriver(this.factory, this.pbeParametersGenerator, this.randomSource);
        Mockito
            .when(
                this.factory.createKey(
                    Mockito.anyListOf(Byte.class),
                    Mockito.anyListOf(Byte.class),
                    Mockito.anyString(),
                    Mockito.anyString()
                )
            )
            .thenThrow(new InvalidEncryptSecretSizeException(111));

        this.deriver.deriveKeyFromPassword(Chars.asList("foobar".toCharArray()), 10);
    }

    @Test(expectedExceptions = RuntimeException.class)
    public void testDeriveKeyFromPasswordFailureAuthenticationSecretSize() throws Throwable
    {
        this.factory = Mockito.mock(KeyFactoryInterface.class);
        this.deriver = new KeyDeriver(this.factory, this.pbeParametersGenerator, this.randomSource);
        Mockito
            .when(
                this.factory.createKey(
                    Mockito.anyListOf(Byte.class),
                    Mockito.anyListOf(Byte.class),
                    Mockito.anyString(),
                    Mockito.anyString()
                )
            )
            .thenThrow(new InvalidAuthSecretSizeException(111));

        this.deriver.deriveKeyFromPassword(Chars.asList("foobar".toCharArray()), 10);
    }

    @Test
    public void testInstance()
    {
        KeyDeriver instance = KeyDeriver.instance();

        Assert.assertSame(KeyDeriver.instance(), instance);
    }

    private KeyDeriver deriver;
    private KeyFactoryInterface factory;
    final private PBEParametersGenerator pbeParametersGenerator;
    final private RandomSourceInterface randomSource;
    final private List<Byte> bytes64;
}
