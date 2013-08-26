/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package eloquent.lockbox;

import org.testng.Assert;
import org.testng.annotations.Test;

public class PlaceholderTest
{
    @Test
    public void testPlaceholder()
    {
        Placeholder placeholder = new Placeholder();

        Assert.assertTrue(placeholder instanceof Placeholder);
    }
}
