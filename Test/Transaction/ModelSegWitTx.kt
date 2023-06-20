package Laeliax.Transaction

import Laeliax.MiniScript.OP_
import Laeliax.util.ShiftTo.ByteArrayToHex
import Laeliax.util.ShiftTo.ByteToHex
import Laeliax.util.ShiftTo.DeciToHex
import Laeliax.util.ShiftTo.HexToByteArray
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder


class Transaction {
    
    fun _OUT(value: Long, redemmScript: String): ByteArray {
        val sat = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(value).array()
        val scriptSize =  byteArrayOf(redemmScript.HexToByteArray().size.toByte())
        return (sat
                + scriptSize
                + redemmScript.HexToByteArray())
    }
    
}

fun main() {
    val txid = "73c9fec091af7d5fa74650e758b40b4f9895404d1cb95193b6ec059a541dd44f".HexToByteArray().reversedArray()
    val privateKey = BigInteger("96f10efc133110507e9279970c7af13e51b0ccf0e90d4905f2015cb486d82ef7", 16)


    val UTxO = Transaction()
    val version = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(1).array()
    println(version.ByteArrayToHex())

    //val redeemScript = OP_CODE.OP_HASH160.ByteToHex()+ "1487b16bf5c5e43bf1dbd69440556f4f5a1430b5fd" + OP_CODE.OP_EQUAL.ByteToHex()
    val redeemScript = OP_.HASH160.ByteToHex()  + "1487b16bf5c5e43bf1dbd69440556f4f5a1430b5fd" + OP_.EQUAL.ByteToHex()
    println(redeemScript)
    val tx_OUT = UTxO._OUT(130000, redeemScript)
    println(tx_OUT)
    
    val count_txIN = byteArrayOf(1)

    val vout = ByteBuffer.allocate(4).putInt(0).array()
    val sequence = "ffffffff".HexToByteArray()
    val count_txOUT = byteArrayOf(1)
    val lockTime = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(0).array()

    val satAmount = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(20000).array()
    val previous_output = txid + vout

    val rawTx = (
            version
                + count_txIN
                + previous_output
                + "00".HexToByteArray() // sighash
                + sequence
                + count_txOUT
                + tx_OUT
                + lockTime
            )
    println(rawTx.ByteArrayToHex())
    var raw = "01000000014fd41d549a05ecb69351b91c4d4095984f0bb458e75046a75f7daf91c0fec9730000000000ffffffff01d0fb01000000000017a91487b16bf5c5e43bf1dbd69440556f4f5a1430b5fd8700000000"

    val timeLockScript = "03beb30bb17521027de11310f7c996a2d1021276c11759ebb6f26d229dfd0bbc93b7f72fd36e3b8cac"
    val SizeScript = timeLockScript.HexToByteArray().size.DeciToHex()
    println(SizeScript)

}