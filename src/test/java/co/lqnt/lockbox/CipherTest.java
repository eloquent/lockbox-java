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

public class CipherTest
{
    public CipherTest() throws Throwable
    {
        this.encryptionCipher = new EncryptionCipher();
        this.decryptionCipher = new DecryptionCipher();

        this.keyFactory = new KeyFactory();
        this.privateKey = this.keyFactory.createPrivateKey(
            this.getClass().getClassLoader().getResourceAsStream("pem/rsa-2048-nopass.private.pem")
        );
        this.publicKey = this.privateKey.publicKey();
    }

    @DataProvider(name = "encryptedData")
    public Object[][] encryptedData()
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

    @Test(dataProvider = "encryptedData")
    public void testEncryptDecrypt(String data) throws Throwable
    {
        byte[] encrypted = this.encryptionCipher.encrypt(this.publicKey, data.getBytes(Charset.forName("US-ASCII")));
        byte[] decrypted = this.decryptionCipher.decrypt(this.privateKey, encrypted);

        Assert.assertEquals(new String(decrypted, Charset.forName("US-ASCII")), data);
    }

    @Test
    public void testDecrypt() throws Throwable
    {
        String encrypted =
            "wdPXCy5amuY7U8tGD0M-nnK5LGc4DC1h" +
            "VwvNWVLCyqOMHgDF3fpsY-8MQkMUuI0T" +
            "eNoutU-TpuGsm6D-KIXeAaWIYuUAaNZ-" +
            "V_5WwmRFT5BEyhQwZ3PFybrs39o4sAlO" +
            "d5IVvLNMMgwRD-FmQc8KU10d3KDd71wW" +
            "r50y7R33xTnyJplx9uqcOrB6ooQLjFcF" +
            "bFU87YPnhkxZK5JryTxAlaDJjfFs-3XM" +
            "zgoJ35rpBgDVywPXbye1C8u5gw81awid" +
            "Xgei_a27MZog1lUvETzMXqqZ4VlhckDV" +
            "m71f4TLMKHTz-CmYinvzj7G_pYmvtHeh" +
            "uxDzjdrT4lbetTuESm-YHKtq9JEj6E2S" +
            "ER4TURlVKf14sPeDgRUo88-zvM7BWpMv";
        byte[] decrypted = this.decryptionCipher.decrypt(
            this.privateKey,
            encrypted.getBytes(Charset.forName("US-ASCII"))
        );

        Assert.assertEquals(new String(decrypted, Charset.forName("US-ASCII")), "1234");
    }

    private EncryptionCipher encryptionCipher;
    private DecryptionCipher decryptionCipher;
    private KeyFactory keyFactory;
    private PrivateKey privateKey;
    private PublicKey publicKey;
}
