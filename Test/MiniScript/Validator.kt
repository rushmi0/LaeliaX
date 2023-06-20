package Laeliax.MiniScript

import Laeliax.MiniScript.Validator.littleEndianToDecimal
import Laeliax.MiniScript.Validator.readeScript
import Laeliax.util.Hashing.doubleSHA256
import Laeliax.util.ShiftTo.BinaryToByteArray
import Laeliax.util.ShiftTo.ByteArrayToHex
import Laeliax.util.ShiftTo.FlipByteOrder
import Laeliax.util.ShiftTo.HexToBinary
import Laeliax.util.ShiftTo.HexToByteArray

object Validator {

    fun String.isMultisig(): Boolean {
        val contractBytes = this.HexToByteArray()

        // ตัวนำเนินการ OP_2 - OP_16
        val operRator = listOf(82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96)

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


    fun littleEndianToDecimal(bytes: ByteArray): Long {
        var result: Long = 0
        var multiplier: Long = 1

        for (i in 0 until bytes.size) {
            val byteValue: Long = bytes[i].toLong() and 0xFF
            result += byteValue * multiplier
            multiplier *= 256
        }

        return result
    }



}


fun main() {
    val scriptHex = "03abb915b17552210387cb20433e452a106312107c4885c27f209d6ece38055c8bea56bcbc8b1e29af2102635073d61f689a9dd38be41de286ebb3b7137394164d1e00d4eeb4d7bb9ff48b21024bc043a0c094c5f2865dad0c494e6e9e76b3d6034e4ce55895b4ea8285274dd753aeac"

    val decodedScript = readeScript(scriptHex)
    println(decodedScript)

    val littleEndianValue = "abb915".HexToByteArray()
    val decimalValue = littleEndianToDecimal(littleEndianValue)
    println(decimalValue)
}