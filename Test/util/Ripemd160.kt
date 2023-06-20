/* 
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 * 
 * https://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */
package Laeliax.util

import java.util.*

/**
 * Computes the RIPEMD-160 hash of an array of bytes. Not instantiable.
 */
object Ripemd160 {
    private const val BLOCK_LEN = 64 // In bytes
    /*---- Static functions ----*/
    /**
     * Computes and returns a 20-byte (160-bit) hash of the specified binary message.
     * Each call will return a new byte array object instance.
     * @param msg the message to compute the hash of
     * @return a 20-byte array representing the message's RIPEMD-160 hash
     * @throws NullPointerException if the message is `null`
     */
    fun getHash(msg: ByteArray): ByteArray {
        // Compress whole message blocks
        Objects.requireNonNull(msg)
        val state = intArrayOf(0x67452301, -0x10325477, -0x67452302, 0x10325476, -0x3c2d1e10)
        var off = msg.size / BLOCK_LEN * BLOCK_LEN
        compress(state, msg, off)

        // Final blocks, padding, and length
        val block = ByteArray(BLOCK_LEN)
        System.arraycopy(msg, off, block, 0, msg.size - off)
        off = msg.size % block.size
        block[off] = 0x80.toByte()
        off++
        if (off + 8 > block.size) {
            compress(state, block, block.size)
            Arrays.fill(block, 0.toByte())
        }
        val len = msg.size.toLong() shl 3
        for (i in 0..7) block[block.size - 8 + i] = (len ushr i * 8).toByte()
        compress(state, block, block.size)

        // Int32 array to bytes in little endian
        val result = ByteArray(state.size * 4)
        for (i in result.indices) result[i] = (state[i / 4] ushr i % 4 * 8).toByte()
        return result
    }

    /*---- Private functions ----*/
    private fun compress(state: IntArray, blocks: ByteArray, len: Int) {
        require(len % BLOCK_LEN == 0)
        var i = 0
        while (i < len) {


            // Message schedule
            val schedule = IntArray(16)
            for (j in 0 until BLOCK_LEN) schedule[j / 4] =
                schedule[j / 4] or (blocks[i + j].toInt() and 0xFF shl j % 4 * 8)

            // The 80 rounds
            var al = state[0]
            var ar = state[0]
            var bl = state[1]
            var br = state[1]
            var cl = state[2]
            var cr = state[2]
            var dl = state[3]
            var dr = state[3]
            var el = state[4]
            var er = state[4]
            for (j in 0..79) {
                var temp: Int
                temp = Integer.rotateLeft(al + f(j, bl, cl, dl) + schedule[RL[j]] + KL[j / 16], SL[j]) + el
                al = el
                el = dl
                dl = Integer.rotateLeft(cl, 10)
                cl = bl
                bl = temp
                temp = Integer.rotateLeft(ar + f(79 - j, br, cr, dr) + schedule[RR[j]] + KR[j / 16], SR[j]) + er
                ar = er
                er = dr
                dr = Integer.rotateLeft(cr, 10)
                cr = br
                br = temp
            }
            val temp = state[1] + cl + dr
            state[1] = state[2] + dl + er
            state[2] = state[3] + el + ar
            state[3] = state[4] + al + br
            state[4] = state[0] + bl + cr
            state[0] = temp
            i += BLOCK_LEN
        }
    }

    private fun f(i: Int, x: Int, y: Int, z: Int): Int {
        assert(0 <= i && i < 80)
        if (i < 16) return x xor y xor z
        if (i < 32) return x and y or (x.inv() and z)
        if (i < 48) return x or y.inv() xor z
        return if (i < 64) x and z or (y and z.inv()) else x xor (y or z.inv())
    }

    /*---- Class constants ----*/
    private val KL =
        intArrayOf(0x00000000, 0x5A827999, 0x6ED9EBA1, -0x70e44324, -0x56ac02b2) // Round constants for left line
    private val KR =
        intArrayOf(0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000) // Round constants for right line
    private val RL = intArrayOf( // Message schedule for left line
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
        3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
        1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
        4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
    )
    private val RR = intArrayOf( // Message schedule for right line
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
        6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
        15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
        8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
        12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
    )
    private val SL = intArrayOf( // Left-rotation for left line
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
        7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
        11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
        11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
        9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
    )
    private val SR = intArrayOf( // Left-rotation for right line
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
        9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
        9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
        15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
        8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
    )
}
