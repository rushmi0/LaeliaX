package Laeliax.Transaction


import Laeliax.SecureKey.EllipticCurve
import Laeliax.SecureKey.EllipticCurve.ECDSA.Sign
import Laeliax.SecureKey.EllipticCurve.ECDSA.toDERFormat

import Laeliax.util.Bech32
import Laeliax.util.Hashing.doubleSHA256
import Laeliax.util.ShiftTo.ByteArrayToHex
import Laeliax.util.ShiftTo.DeciToHex
import Laeliax.util.ShiftTo.FlipByteOrder
import Laeliax.util.ShiftTo.HexToByteArray

import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder


// * bc1qvtus7nqcuj7n8mwj446zpqjyr8l49e2x76jxpn
fun toSegWit(amountSAT: Long, address: String): String {
    val amountSAT = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(amountSAT).array().ByteArrayToHex()
    val keyHash = Bech32.bech32ToSegwit(address)[2] as ByteArray
    val keyHashLength = keyHash.size.DeciToHex()
    val script = "00${keyHashLength}${keyHash.ByteArrayToHex()}"
    val fieldSizes = "${script}".HexToByteArray().size.DeciToHex()
    return "${amountSAT}${fieldSizes}${script}"
}


fun main() {


    val privateKey = BigInteger("b8f28a772fccbf9b4f58a4f027e07dc2e35e7cd80529975e292ea34f84c4580c", 16)
    println("Private Key: \n> ${privateKey}")

    // compute: Public Key (X point, Y point)
    val curvePoint = EllipticCurve.multiplyPoint(privateKey)

    val scriptTimeLock = "03abb915b1752102aa36a1958e2fc5e5de75d05bcf6f3ccc0799be4905f4e418505dc6ab4422a8dbac"
    val ScriptIN1 = scriptTimeLock

    val version = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(1).array().ByteArrayToHex()

    // * count IN
    val inputCount: String = byteArrayOf(1).ByteArrayToHex()

    // * UTxO Input:
    val txID = "1854c5b5af18d06ec4db1b882ade607ff01fdf367ab3c3b38cea40a0f91b615d".FlipByteOrder()
    val vout = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(0).array().ByteArrayToHex()
    val scriptLength = ScriptIN1.HexToByteArray().size.DeciToHex()
    val script =  ScriptIN1
    val Sequence = "fdffffff"

    // * count OUT
    val outCount: String = byteArrayOf(2).ByteArrayToHex()

    // * UTxO Output
    val output_1 = toSegWit(6_000_000, "bc1qdt43shtcjpug6jlza5yhhmnkd6yks4aarac3yk")
    val output_2 = toSegWit(500_000_000_000, "bc1qrrc5jmelkjtmfjjw5tt8s07nmjhvp82ypnspvu")

    val lockTime = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(766910).array().ByteArrayToHex()

    // * Unsigned Transaction
    val components: List<String> = listOf(
        version,
        inputCount,
        txID,
        vout,
        scriptLength,
        script,
        Sequence,
        outCount,
        output_1,
        output_2,
        lockTime
    )

    val combinedTransaction = StringBuilder()

    for (component in components) {
        combinedTransaction.append(component)
    }

    val unsignedTransaction = combinedTransaction.toString()
    println("\nUnsigned Transaction: \n> ${unsignedTransaction}\n")

    // * Sign Transaction
    val message = BigInteger(unsignedTransaction.HexToByteArray().doubleSHA256().ByteArrayToHex(), 16)
    val signTx = Sign(privateKey, message)

    // * Verify Signature
    val validate = EllipticCurve.ECDSA.Verify(curvePoint, message, signTx)
    if (validate) {
        println("Signature: Valid")
    } else {
        println("Signature: Invalid!!")
    }

    // * compute: ScriptSig components
    val Signature = toDERFormat(signTx) + "01"
    val SignatureLength = Signature.HexToByteArray().size.DeciToHex()

    val RedeemLength = ScriptIN1.HexToByteArray().size.DeciToHex()
    val RedeemScript = ScriptIN1

    // * components unlocking script insert to Unsign Transaction
    val scriptSigLength  = (
            SignatureLength +
            Signature +
            RedeemLength +
            RedeemScript
    ).HexToByteArray().size.DeciToHex()

    // * signed Transaction
    val componentsNEW: List<String> = listOf(
        version,
        inputCount,
        txID,
        vout,
        scriptSigLength,
        SignatureLength,
        Signature,
        RedeemLength,
        RedeemScript,
        Sequence,
        outCount,
        output_1,
        output_2,
        lockTime
    )

    val combinedNewTransaction = StringBuilder()

    for (component in componentsNEW) {
        combinedNewTransaction.append(component)
    }

    val signedTransaction = combinedNewTransaction.toString()
    println("signed Transaction: \n> $signedTransaction")

}

