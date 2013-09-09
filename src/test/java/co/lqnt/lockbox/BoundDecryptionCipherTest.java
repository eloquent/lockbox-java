/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox;

import co.lqnt.lockbox.key.KeyFactory;
import co.lqnt.lockbox.key.PrivateKey;
import java.nio.charset.Charset;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class BoundDecryptionCipherTest
{
    public BoundDecryptionCipherTest() throws Throwable
    {
        this.keyFactory = new KeyFactory();
        this.key = this.keyFactory.createPrivateKey(
            this.getClass().getClassLoader().getResourceAsStream("pem/rsa-2048-nopass.private.pem")
        );

        this.decryptionCipher = new DecryptionCipher();
        this.cipher = new BoundDecryptionCipher(this.key, this.decryptionCipher);

        this.encryptionCipher = new EncryptionCipher();
    }

    @Test
    public void testConstructor()
    {
        Assert.assertSame(this.cipher.key(), this.key);
        Assert.assertSame(this.cipher.cipher(), this.decryptionCipher);
    }

    @Test
    public void testConstructorDefaults()
    {
        this.cipher = new BoundDecryptionCipher(this.key);

        Assert.assertSame(this.cipher.cipher().getClass(), DecryptionCipher.class);
    }

    @DataProvider(name = "encryptionData")
    public Object[][] encryptionData()
    {
        StringBuilder longData = new StringBuilder(8192);
        for (int i = 0; i < 8192; ++i) {
            longData.append('A');
        }

        return new Object[][]{
            {""},
            {"foobar"},
            {longData.toString()}
        };
    }

    @Test(dataProvider = "encryptionData")
    public void testEncryptDecrypt(String data) throws Throwable
    {
        byte[] encrypted = this.encryptionCipher.encrypt(this.key, data.getBytes(Charset.forName("US-ASCII")));
        byte[] decrypted = this.cipher.decrypt(encrypted);

        Assert.assertEquals(new String(decrypted, Charset.forName("US-ASCII")), data);
    }

    @Test(dataProvider = "encryptionData")
    public void testEncryptDecryptString(String data) throws Throwable
    {
        String encrypted = this.encryptionCipher.encrypt(this.key, data);
        String decrypted = this.cipher.decrypt(encrypted);

        Assert.assertEquals(decrypted, data);
    }

    private KeyFactory keyFactory;
    private PrivateKey key;
    private DecryptionCipher decryptionCipher;
    private BoundDecryptionCipher cipher;
    private EncryptionCipher encryptionCipher;
}
