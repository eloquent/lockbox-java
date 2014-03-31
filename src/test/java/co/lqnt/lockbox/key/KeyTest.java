/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.key;

import java.nio.charset.Charset;
import org.testng.Assert;
import org.testng.annotations.Test;

public class KeyTest
{
    public KeyTest()
    {
        this.encryptionSecret = "1234567890123456".getBytes(Charset.forName("US-ASCII"));
        this.authenticationSecret = "1234567890123456789012345678".getBytes(Charset.forName("US-ASCII"));
        this.key = new Key(this.encryptionSecret, this.authenticationSecret, "name", "description");
    }

    @Test
    public void testConstructor()
    {
        Assert.assertEquals(this.key.encryptionSecret(), this.encryptionSecret);
        Assert.assertEquals(this.key.authenticationSecret(), this.authenticationSecret);
        Assert.assertSame(this.key.name(), "name");
        Assert.assertSame(this.key.description(), "description");
    }

    @Test
    public void testConstructorNoDescription()
    {
        this.key = new Key(this.encryptionSecret, this.authenticationSecret, "name");
        
        Assert.assertEquals(this.key.encryptionSecret(), this.encryptionSecret);
        Assert.assertEquals(this.key.authenticationSecret(), this.authenticationSecret);
        Assert.assertSame(this.key.name(), "name");
        Assert.assertNull(this.key.description());
    }

    @Test
    public void testConstructorNoNameOrDescription()
    {
        this.key = new Key(this.encryptionSecret, this.authenticationSecret);
        
        Assert.assertEquals(this.key.encryptionSecret(), this.encryptionSecret);
        Assert.assertEquals(this.key.authenticationSecret(), this.authenticationSecret);
        Assert.assertNull(this.key.name());
        Assert.assertNull(this.key.description());
    }
    
    private Key key;
    final private byte[] encryptionSecret;
    final private byte[] authenticationSecret;
}
