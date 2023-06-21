package Laeliax.MiniScript

import java.nio.ByteBuffer
import java.nio.ByteOrder

import Laeliax.util.ShiftTo.ByteArrayToHex
import Laeliax.util.ShiftTo.ByteToHex
import Laeliax.util.ShiftTo.HexToByteArray

import Laeliax.util.Address.getP2WSH
import Laeliax.util.Address.segwitP2SH
import Laeliax.util.ShiftTo.DeciToHexByte
import Laeliax.MiniScript.Validator.isMultisig
import Laeliax.util.Address.getP2SH

class ScriptBuilder {

    // * https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki
    fun TimeLock(blockNumber: Int, dataHex: String): String {
        if (blockNumber < 0) {
            throw IllegalArgumentException("Block number must be non-negative")
        }

        /*
         * Block Number: 766910
         * PUSHDATA: คำนวณจากค่าที่เป็นค่า DEC นำไปแปลงเป็น HEX จากนั้นแปลงต่อเป็น LITTLE ENDIAN
         *
         *
         * https://www.save-editor.com/tools/wse_hex.html
         * Block -> [HEX] -> BB3BE -> [LITTLE ENDIAN] -> BEB30B
         *   └── PUSHDATA มาจากขนาด 3 bytes จาก [BE, B3, 0B]
         *          └── PUSHDATA = [03]
         *
         * 697022 -> [HEX] -> AA2BE -> [LITTLE ENDIAN] -> BEA20A
         *   └── PUSHDATA มาจากขนาด 3 bytes จาก [BE, A2, 0A] = 03 หรือ 3 byte
         *          └── PUSHDATA = [03]
         *
         * 7669100 -> [HEX] -> 75056C -> [LITTLE ENDIAN] -> 6C0575
         *   └── PUSHDATA มาจากขนาด 3 bytes จาก [6C, 05, 75] = 03 หรือ 3 byte
         *          └── PUSHDATA = [03]
         *
         * 96385217 -> [HEX] -> 5BEB8C1 -> [LITTLE ENDIAN] -> C1B8BE05
         *   └── PUSHDATA มาจากขนาด 4 bytes จาก [C1, B8, BE, 05] = 04 หรือ 4 byte
         *          └── PUSHDATA = [04]
         *
         * องค์ประกอบ Script
         *   [ < PUSHDATA, LITTLE ENDIAN > ]
         * OP_CHECKLOCKTIMEVERIFY
         * OP_DROP
         *   [ < ขนาดของ Byte Public key พิกัด X >, < Public key > ]
         * OP_CHECKSIG
         * */


        // opPushData กำหนดจำนวนสูงสุด 8 byte เป็นมาตรฐาน ในการเก็บค่า LITTLE ENDIAN
        val opPushData: ByteBuffer = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putInt(blockNumber)

        // ตรวจสอบค่าเพื่อกำกัดใน opPushData ที่มีค่า 0 byte ตั้งแต่ด้านท้ายสุดมา
        var nLockTime: ByteArray = opPushData.array()
        while (nLockTime.isNotEmpty() && nLockTime.last() == 0x00.toByte()) {
            nLockTime = nLockTime.dropLast(1).toByteArray()
        }

        val sizeTime: ByteArray = byteArrayOf(nLockTime.size.toByte())
        val Stack: StringBuilder = StringBuilder()

        val group = dataHex.substring(0, 2)
        if (group in setOf("02", "03")) {
            val PublicKey: ByteArray = dataHex.HexToByteArray()
            for (element: ByteArray in arrayOf(
                sizeTime,
                nLockTime,
                byteArrayOf(OP_.CHECKLOCKTIMEVERIFY),
                byteArrayOf(OP_.DROP),
                byteArrayOf(PublicKey.size.toByte()),
                PublicKey,
                byteArrayOf(OP_.CHECKSIG)
            )) {
                Stack.append(element.ByteArrayToHex())
            }
        } else if (dataHex.isMultisig()) {
            val contract = dataHex.HexToByteArray()
            for (element: ByteArray in arrayOf(
                sizeTime,
                nLockTime,
                byteArrayOf(OP_.CHECKLOCKTIMEVERIFY),
                byteArrayOf(OP_.DROP),
                contract,
                byteArrayOf(OP_.CHECKSIG)
            )) {
                Stack.append(element.ByteArrayToHex())
            }
        } else {
            println("inValid value")
        }

        return Stack.toString()
    }

    // * https://github.com/bitcoin/bips/blob/master/bip-0067.mediawiki
    fun multiSig(M: Int, publicKeys: List<String>): String {
        val N = publicKeys.size
        require(N in M..16) // ! กำหนดจำนวนของ Public Key ไม่ให้เกินระหว่าง M ถึง 16
        require(M in 2..16) // ! จำนวน Public Keys ที่ระบุต้องอยู่ระหว่าง 1 ถึง 16

        /*
         * องค์ประกอบ Script
         * OP_M
         *   [ < ขนาดของ Byte Public key พิกัด X >, < Public key > ]
                    ......
                    ......
         * OP_N
         * OP_CHECKMULTISIG
         */

        val OP_M = OP_.CODE[M]!!.DeciToHexByte()
        val OP_N = OP_.CODE[N]!!.DeciToHexByte()

        val Stack = StringBuilder(OP_M)

        for (pubkey in publicKeys) {
            val dataHex = pubkey.HexToByteArray()
            val pubkeyLength = dataHex.size
            Stack.append(pubkeyLength.toString(16))
            Stack.append(pubkey)
        }

        Stack.append(OP_N)
        Stack.append(OP_.CHECKMULTISIG.ByteToHex())
        return Stack.toString()
    }
}


// * ตัวอย่างการใช้งาน
fun main() {

    val symbol = """ 
         ♡   ∩_∩
          （„• ֊ •„)♡
          ┏━∪∪━━━━┓
        ♡  เสรีภาพ ₿ ♡♤
          ┗━━━━━━━┛
    """.trimIndent()

    println(symbol)

    val Script = ScriptBuilder()

    /**
     * L1c3ZfZu5e8TiQKS9FJ9ioh4GXEjxjob5ZSgqYRCHwrGNNEnyrBk
     * 02aa36a1958e2fc5e5de75d05bcf6f3ccc0799be4905f4e418505dc6ab4422a8db
     * */

    // * MultiSig
    val M = 2
    val keys = listOf(
        // * KyrCxnnGtkM86JspRFeMpJKtEzkpT7dtSz6yUEJno9aMRM6gm2KE
        "0387cb20433e452a106312107c4885c27f209d6ece38055c8bea56bcbc8b1e29af",

        // * L5m1xyLMdVv5S9drKuJUvZmRx5szVoqg4B3nT9YJESFh39qcDzvu
        "02635073d61f689a9dd38be41de286ebb3b7137394164d1e00d4eeb4d7bb9ff48b",

        // * KxczK3NtRk5NMB52iNEyDfmB8o7ErouxfmktMBxdSFmoo5FpzqLh
        "024bc043a0c094c5f2865dad0c494e6e9e76b3d6034e4ce55895b4ea8285274dd7",
    )


    val scriptMultiSig: String = Script.multiSig(M, keys)
    println("MultiSig Script: $scriptMultiSig")
    println("MultiSig P2WSH: ${scriptMultiSig.getP2WSH("main")}")
    println("MultiSig P2SH: ${scriptMultiSig.getP2SH("main")}")
    println("MultiSig Nested SegWit: ${scriptMultiSig.segwitP2SH("main")} \n")


    // * TimeLock
    val blockNumber = 1423787
    //val dataHex = scriptMultiSig
    val dataHex = "02aa36a1958e2fc5e5de75d05bcf6f3ccc0799be4905f4e418505dc6ab4422a8db"

    val scriptTimeLock: String = Script.TimeLock(blockNumber, dataHex)
    println("TimeLock Script: $scriptTimeLock")

    println("TimeLock P2WSH: ${scriptTimeLock.getP2WSH("main")}")
    println("TimeLock P2SH: ${scriptTimeLock.getP2SH("main")}")
    println("TimeLock Nested SegWit: ${scriptTimeLock.segwitP2SH("main")} \n")
}
