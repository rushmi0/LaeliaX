package LaeliaX.MiniScript

import java.nio.ByteBuffer
import java.nio.ByteOrder

import LaeliaX.util.ShiftTo.ByteArrayToHex
import LaeliaX.util.ShiftTo.ByteToHex
import LaeliaX.util.ShiftTo.HexToByteArray

import LaeliaX.util.Address.getP2WSH
import LaeliaX.util.Address.getSegWitP2SH
import LaeliaX.util.ShiftTo.DeciToHexByte
import LaeliaX.MiniScript.Validator.isMultisig
import LaeliaX.util.Address.getP2SH

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
         *
         * องค์ประกอบสคริปต์
         *   [ < PUSHDATA, LITTLE ENDIAN > ]
         * OP_CHECKLOCKTIMEVERIFY
         * OP_DROP
         *   [ < ขนาดของ Byte Public key >, < Public key > ]
         * OP_CHECKSIG
         * */


        // กำหนดค่าเริ่มต้นสำหรับ opPushData เพื่อเก็บค่า blockNumber ในรูปแบบ LITTLE ENDIAN 8 Bytes
        val opPushData: ByteBuffer = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putInt(blockNumber)

        // ตรวจสอบและกำหนดค่าให้กับ nLockTime โดยตัด byte 0x00 ที่อยู่ด้านท้ายออก
        var nLockTime: ByteArray = opPushData.array()
        while (nLockTime.isNotEmpty() && nLockTime.last() == 0x00.toByte()) {
            nLockTime = nLockTime.dropLast(1).toByteArray()
        }

        // * เก็บขนาดของ nLockTime โดยนับผมรวมจำนวณ ByteArray ของ nLockTime
        val sizeTime: ByteArray = byteArrayOf(nLockTime.size.toByte())

        // * Stack โง่ ๆ เก็บค่าต่าง ๆ
        val Stack: StringBuilder = StringBuilder()

        // * ตรวจสอบว่าเป็น Public Key หรือไม่โดยดูจากหมายเลขกลุ่มและขนาดของมัน
        val group = dataHex.substring(0, 2)
        if (group in setOf("02", "03", "04") && dataHex.length == 130 || dataHex.length == 66) {
            val PublicKey: ByteArray = dataHex.HexToByteArray()

            // * กรณีเป็น Public key เรียงลำดับและเก็บค่าต่าง ๆ ใน Stack
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

            // * กรณีเป็น MultiSig เรียงลำดับและเก็บค่าต่าง ๆ ใน Stack
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

            // ! แจ้งเตือนข้อผิดพลาดในกรณีที่ network ไม่ถูกต้อง
            throw IllegalArgumentException("Invalid network")
        }

        return Stack.toString()
    }

    // * https://github.com/bitcoin/bips/blob/master/bip-0067.mediawiki
    fun multiSig(M: Int, publicKeys: List<String>): String {
        val N = publicKeys.size
        require(N in M..16) // ! กำหนดจำนวนของ Public Key ไม่ให้เกินระหว่าง M ถึง 16
        require(M in 2..16) // ! จำนวน Public Keys ที่ระบุต้องอยู่ระหว่าง 1 ถึง 16

        /*
         * องค์ประกอบสคริปต์
         * OP_M
         *   [ < ขนาดของ Byte Public key >, < Public key > ]
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
            Stack.append(pubkeyLength.DeciToHexByte())
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
    println("MultiSig Nested SegWit: ${scriptMultiSig.getSegWitP2SH("main")} \n")


    // * TimeLock
    val blockNumber = 2_440_116
    //val dataHex = scriptMultiSig
    val dataHex = "02aa36a1958e2fc5e5de75d05bcf6f3ccc0799be4905f4e418505dc6ab4422a8db"

    val scriptTimeLock: String = Script.TimeLock(blockNumber, dataHex)
    println("TimeLock Script: $scriptTimeLock")

    println("TimeLock P2WSH: ${scriptTimeLock.getP2WSH("main")}")
    println("TimeLock P2SH: ${scriptTimeLock.getP2SH("main")}")
    println("TimeLock Nested SegWit: ${scriptTimeLock.getSegWitP2SH("main")}\n")

    println("TimeLock P2SH testnet: ${scriptTimeLock.getP2SH("test")}")
    //println("TimeLock SegWit P2SH testnet: ${scriptTimeLock.getSegWitP2SH("test")}")

}
