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
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.testng.Assert;
import org.testng.annotations.Test;

public class CipherTest
{
    public CipherTest() throws Throwable
    {
        this.cipher = new DecryptionCipher();

        this.keyFactory = new KeyFactory();
        KeyPair keyPair = this.keyFactory.createKeyPair(
            this.getClass().getClassLoader().getResourceAsStream("pem/rsa-2048-nopass.private.pem")
        );
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
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
        byte[] decrypted = this.cipher.decrypt(this.privateKey, encrypted.getBytes(Charset.forName("US-ASCII")));

        Assert.assertEquals(new String(decrypted, Charset.forName("US-ASCII")), "1234");
    }

    private DecryptionCipher cipher;
    private KeyFactory keyFactory;
    private PrivateKey privateKey;
    private PublicKey publicKey;
}
