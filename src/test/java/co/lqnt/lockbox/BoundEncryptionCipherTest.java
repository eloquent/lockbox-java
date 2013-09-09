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
import co.lqnt.lockbox.key.PublicKey;
import java.nio.charset.Charset;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class BoundEncryptionCipherTest
{
    public BoundEncryptionCipherTest() throws Throwable
    {
        this.keyFactory = new KeyFactory();
        this.privateKey = this.keyFactory.createPrivateKey(
            this.getClass().getClassLoader().getResourceAsStream("pem/rsa-2048-nopass.private.pem")
        );
        this.publicKey = this.privateKey.publicKey();

        this.encryptionCipher = new EncryptionCipher();
        this.cipher = new BoundEncryptionCipher(this.publicKey, this.encryptionCipher);

        this.decryptionCipher = new DecryptionCipher();
    }

    @Test
    public void testConstructor()
    {
        Assert.assertSame(this.cipher.key(), this.publicKey);
        Assert.assertSame(this.cipher.cipher(), this.encryptionCipher);
    }

    @Test
    public void testConstructorDefaultsPublicKey()
    {
        this.cipher = new BoundEncryptionCipher(this.publicKey);

        Assert.assertSame(this.cipher.cipher().getClass(), EncryptionCipher.class);
    }

    @Test
    public void testConstructorDefaultsPrivateKey()
    {
        this.cipher = new BoundEncryptionCipher(this.privateKey);

        Assert.assertEquals(this.cipher.key().toString(), this.publicKey.toString());
        Assert.assertSame(this.cipher.cipher().getClass(), EncryptionCipher.class);
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
        byte[] encrypted = this.cipher.encrypt(data.getBytes(Charset.forName("US-ASCII")));
        byte[] decrypted = this.decryptionCipher.decrypt(this.privateKey, encrypted);

        Assert.assertEquals(new String(decrypted, Charset.forName("US-ASCII")), data);
    }

    @Test(dataProvider = "encryptionData")
    public void testEncryptDecryptString(String data) throws Throwable
    {
        String encrypted = this.cipher.encrypt(data);
        String decrypted = this.decryptionCipher.decrypt(this.privateKey, encrypted);

        Assert.assertEquals(decrypted, data);
    }

    private KeyFactory keyFactory;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private EncryptionCipher encryptionCipher;
    private BoundEncryptionCipher cipher;
    private DecryptionCipher decryptionCipher;
}
