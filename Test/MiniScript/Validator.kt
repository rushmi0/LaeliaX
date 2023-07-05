package LaeliaX.MiniScript


import LaeliaX.MiniScript.Validator.getLockTime
import LaeliaX.MiniScript.Validator.getPublicKeys
import LaeliaX.MiniScript.Validator.viewScript
import LaeliaX.util.Address.getP2WPKH
import LaeliaX.util.Hashing.doubleSHA256
import LaeliaX.util.ShiftTo.BinaryToByteArray
import LaeliaX.util.ShiftTo.ByteArrayToHex
import LaeliaX.util.ShiftTo.FlipByteOrder
import LaeliaX.util.ShiftTo.HexToBinary
import LaeliaX.util.ShiftTo.HexToByteArray
import LaeliaX.util.ShiftTo.littleEndianToDeci

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

    fun viewScript(scriptHex: String): List<Any> {
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

    private fun checkHexValue(value: Any): Boolean {
        return when (value) {
            is String -> {
                val hexRegex = Regex("[0-9a-fA-F]+")
                hexRegex.matches(value) && value.HexToByteArray().size in 1..5
            }
            //is Int, is Long, is Short, is Byte -> true
            else -> false
        }
    }

    private fun checkPublicKey(value: Any): Boolean {
        return when (value) {
            is String -> {
                val hexRegex = Regex("[0-9a-fA-F]+")
                val keyLength = value.HexToByteArray().size
                val byteArray = value.HexToByteArray()
                val group = byteArray.isNotEmpty() && (byteArray[0] == 2.toByte() || byteArray[0] == 3.toByte())
                hexRegex.matches(value) && keyLength == 33 && group
            }
            else -> false
        }
    }

    fun List<Any>.getPublicKeys(): List<String> {
        return this.filter { checkPublicKey(it) }.map { it.toString() }
    }

    fun List<Any>.getLockTime(): Int {
        return this.find { checkHexValue(it) }?.toString()?.littleEndianToDeci()?.toInt() ?: 0
    }


}

fun main() {
    val scriptHex = "03abb915b17552210387cb20433e452a106312107c4885c27f209d6ece38055c8bea56bcbc8b1e29af2102635073d61f689a9dd38be41de286ebb3b7137394164d1e00d4eeb4d7bb9ff48b21024bc043a0c094c5f2865dad0c494e6e9e76b3d6034e4ce55895b4ea8285274dd753aeac"

    val decodedScript = viewScript(scriptHex)
    println("Script: ${decodedScript.size} \n| $decodedScript")

    val publicKey: List<String> = decodedScript.getPublicKeys()
    println("Public Key: ${publicKey.size} \n| $publicKey")

    for (i in 0 until publicKey.size) {
        println("| ${publicKey[i].getP2WPKH("main")}")
    }

    val time = decodedScript.getLockTime()
    println("Time: \n| $time")


    println("5802".littleEndianToDeci())

}