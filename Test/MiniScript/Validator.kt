package Laeliax.MiniScript


import Laeliax.MiniScript.Validator.readeScript
import Laeliax.util.Hashing.doubleSHA256
import Laeliax.util.ShiftTo.BinaryToByteArray
import Laeliax.util.ShiftTo.ByteArrayToHex
import Laeliax.util.ShiftTo.FlipByteOrder
import Laeliax.util.ShiftTo.HexToBinary
import Laeliax.util.ShiftTo.HexToByteArray
import Laeliax.util.ShiftTo.littleEndianToDeci

object Validator {

    fun String.isMultisig(): Boolean {

        val contractBytes = this.HexToByteArray()

        // * ตัวนำเนินการ OP_CODE
        val operRator = listOf(
            82, // OP_2
            83, // OP_3
            84, // OP_4
            85, // OP_5
            86, // OP_6
            87, // OP_7
            88, // OP_8
            89, // OP_9
            90, // OP_10
            91, // OP_11
            92, // OP_12
            93, // OP_13
            94, // OP_14
            95, // OP_15
            96  // OP_16
        )

        val M = contractBytes[0].toInt()
        val N: Int = contractBytes[contractBytes.size - 2].toInt()

        if (contractBytes.isNotEmpty() && (M in operRator && N in operRator)) {
            // ขนาด Public key
            val pubkeySize: Int = contractBytes[1].toInt()

            // * นับจำนวน Public key ทั้งหมดใน multiSig contract
            val publicKey = contractBytes.count { it == 33.toByte() }
            if (contractBytes.size == (pubkeySize * publicKey) + 3 + publicKey){
                return true
            }
        }
        return false
    }

    fun readeScript(scriptHex: String): List<Any> {
        val decodedScript = mutableListOf<Any>()

        var i = 0
        while (i < scriptHex.length) {
            val opcode = scriptHex.substring(i, i + 2).toInt(16)
            i += 2

            if (opcode < 0x4c) {
                val dataLength = opcode
                val data = scriptHex.substring(i, i + (dataLength * 2))
                i += dataLength * 2
                decodedScript.add(data)
            } else if (opcode == 0x4c) {
                val dataLength = scriptHex.substring(i, i + 2).toInt(16)
                i += 2
                val data = scriptHex.substring(i, i + (dataLength * 2))
                i += dataLength * 2
                decodedScript.add(data)
            } else {
                decodedScript.add(opcode)
            }
        }

        return decodedScript
    }


    fun String.generateTransactionID(): String {
        val binaryTx = this.HexToBinary().BinaryToByteArray()
        val binHash = binaryTx.doubleSHA256().ByteArrayToHex()
        return binHash.FlipByteOrder()
    }


    fun checkValue(value: Any): Boolean {
        return when (value) {
            is String -> {
                val hexRegex = Regex("[0-9a-fA-F]+")
                hexRegex.matches(value) && value.HexToByteArray().size in 3..8
            }
            is Int, is Long, is Short, is Byte -> true
            else -> false
        }
    }



}


fun main() {
    val scriptHex = "03abb915b17552210387cb20433e452a106312107c4885c27f209d6ece38055c8bea56bcbc8b1e29af2102635073d61f689a9dd38be41de286ebb3b7137394164d1e00d4eeb4d7bb9ff48b21024bc043a0c094c5f2865dad0c494e6e9e76b3d6034e4ce55895b4ea8285274dd753aeac"

    val decodedScript = readeScript(scriptHex)
    println(decodedScript)

    val littleEndianValue = "abb915"
    val decimalValue = littleEndianValue.littleEndianToDeci()
    println(decimalValue)
}