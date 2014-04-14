/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.key;

import co.lqnt.lockbox.random.RandomSourceInterface;
import co.lqnt.lockbox.random.SecureRandom;
import com.google.common.io.BaseEncoding;
import java.nio.charset.Charset;
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

        this.bytes64 = "1234567890123456789012345678901234567890123456789012345678901234"
            .getBytes(Charset.forName("US-ASCII"));

        Mockito.when(this.randomSource.generate(64)).thenReturn(this.bytes64);
    }

    @BeforeMethod
    public void setUp()
    {
        this.factory = new KeyFactory();
        this.deriver = new KeyDeriver(this.factory, this.pbeParametersGenerator, this.randomSource);
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
            {"",       1000,   this.bytes64, "2k1fkksUHSjVMxOMNkPBihtocgu1ziAI4CVRFfC7ClM", "lNXoGLA83xvvlAUuHCQEw9OcsUloYygz2Oq4PFRMUh4"},
            {"foo",    1000,   this.bytes64, "9eWWednk0FFnvE_NXA0uElPqBvSRDxTNNfKjj8j-w74", "H8-n0cCupLeoCYckdGFWlwWc8GAl_XvBokZMgWbhB1U"},
            {"foobar", 1000,   this.bytes64, "gvP8UROn7oLyZpbguWlDryCE82uANmVHdp4cV1ZKNik", "shiABRhWtR0nKk6uO_efWMf6yk7iZ8OnD9PjIdYJxVQ"},
            {"foobar", 10000,  this.bytes64, "ZYRW2br9KSzOY4KKpoEGHMXzT4PYa_CP5qPdqSkZKXI", "Bq2Yqmr9iwi89x-DV5MUIMUmvEAXgYNhuLR0dt10jv0"},
            {"foobar", 100000, this.bytes64, "Zbz3tZJjWJDGwMmer1aY1TNBW3uscUCziUpIpAF9sXw", "pS5s8iWZBHwzf_hIIm4SMsR9dTHo2yfl2WHpa1Fp6wc"},
            {"foobar", 1,      this.bytes64, "nrmJyhdG9gAbFrTidwKwg5xeKBFF11wkMkJVbVsWG6A", "cclAcqBRCzX8VMT-DkiNzHiH4emz6GT_iVVpIB84ccw"},
        };
    }

    @Test(dataProvider = "keyDerivationData")
    public void testDeriveKeyFromPassword(
        String password,
        int iterations,
        byte[] salt,
        String encryptionSecret,
        String authenticationSecret
    ) throws Throwable
    {
        KeyInterface key = this.deriver.deriveKeyFromPassword(
            password.getBytes(Charset.forName("US-ASCII")),
            iterations,
            salt,
            "name",
            "description"
        );

        Assert.assertEquals(
            BaseEncoding.base64Url().omitPadding().encode(key.encryptionSecret()),
            encryptionSecret
        );
        Assert.assertEquals(
            BaseEncoding.base64Url().omitPadding().encode(key.authenticationSecret()),
            authenticationSecret
        );
        Assert.assertEquals(key.name().get(), "name");
        Assert.assertEquals(key.description().get(), "description");
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
    final private byte[] bytes64;
}
