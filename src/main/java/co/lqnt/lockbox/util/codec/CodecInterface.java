/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox.util.codec;

import co.lqnt.lockbox.util.codec.exception.DecodingFailedException;

public interface CodecInterface
{
    /**
     * Encode the supplied data packet.
     *
     * @param data The data to encode.
     *
     * @return The encoded data.
     */
    public byte[] encode(final byte[] data);

    /**
     * Encode the supplied data packet.
     *
     * @param data The data to encode.
     *
     * @return The encoded data.
     */
    public byte[] encode(final String data);

    /**
     * Decode the supplied data packet.
     *
     * @param data The data to decode.
     *
     * @return The decoded data.
     * @throws DecodingFailedException If the decoding fails.
     */
    public byte[] decode(final byte[] data) throws DecodingFailedException;

    /**
     * Decode the supplied data packet.
     *
     * @param data The data to decode.
     *
     * @return The decoded data.
     * @throws DecodingFailedException If the decoding fails.
     */
    public byte[] decode(final String data) throws DecodingFailedException;
}
