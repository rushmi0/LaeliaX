package LaeliaX.Transaction


import LaeliaX.MiniScript.Validator
import LaeliaX.MiniScript.Validator.getLockTime
import LaeliaX.SecureKey.EllipticCurve
import LaeliaX.SecureKey.EllipticCurve.ECDSA.SignSignature
import LaeliaX.SecureKey.EllipticCurve.ECDSA.toDERFormat
import LaeliaX.SecureKey.WIF.extractWIF

import LaeliaX.util.Bech32
import LaeliaX.util.Hashing.doubleSHA256
import LaeliaX.util.ShiftTo.ByteArrayToHex
import LaeliaX.util.ShiftTo.DeciToHex
import LaeliaX.util.ShiftTo.FlipByteOrder
import LaeliaX.util.ShiftTo.HexToByteArray

import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder


// * main: bc1qvtus7nqcuj7n8mwj446zpqjyr8l49e2x76jxpn
// * test: tb1qjpvt0f2lt40csen6q87kdh2eudusqt6atkf5ca
fun toSegWit(amountSAT: Long, address: String): String {
    val amountSAT = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(amountSAT).array().ByteArrayToHex()
    val keyHash = Bech32.bech32ToSegwit(address)[2] as ByteArray
    val keyHashLength = keyHash.size.DeciToHex()
    val script = "00${keyHashLength}${keyHash.ByteArrayToHex()}"
    val fieldSizes = script.HexToByteArray().size.DeciToHex()
    return "${amountSAT}${fieldSizes}${script}"
}


fun main() {

    val wif = "L1c3ZfZu5e8TiQKS9FJ9ioh4GXEjxjob5ZSgqYRCHwrGNNEnyrBk"
    val rawKey = wif.extractWIF()

    val privateKey = BigInteger(rawKey, 16)
    println("Private Key: \n| hex = $rawKey \n| dec = $privateKey \n")

    // compute: Public Key (X point, Y point)
    val curvePoint = EllipticCurve.multiplyPoint(privateKey)
    println("Public Key: \n| x = ${curvePoint.x.toByteArray().ByteArrayToHex()}\n| y = ${curvePoint.y.toByteArray().ByteArrayToHex()}")

    val scriptContract = "030c3725b1752102aa36a1958e2fc5e5de75d05bcf6f3ccc0799be4905f4e418505dc6ab4422a8dbac"
    val decodedScript: List<Any> = Validator.readeScript(scriptContract)
    //println(decodedScript)

    val time = decodedScript.getLockTime()
    //println("Lock Time: $time")

    // ──────────────────────────────────────────────────────────────────────────────────────── \\

    // * หมายเลขกับกับชุดกฎที่จะใช้กับ UTxO นี้
    val version = NETWORKS.VERSION[1].toString()

    // * count IN
    val inputCount: String = byteArrayOf(1).ByteArrayToHex()

    // * UTxO Input: 225_433 sat
    val txID = "986bd0687a2c5e2b9f4d95b31ed9a77b77658343b5794439dd45b3a956df3afc".FlipByteOrder()
    val vout = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(0).array().ByteArrayToHex()
    val scriptLength = scriptContract.HexToByteArray().size.DeciToHex()
    val script =  scriptContract
    val Sequence = "fdffffff"

    // * count OUT
    val outCount: String = byteArrayOf(1).ByteArrayToHex()

    // * UTxO Output
    val output_1 = toSegWit(225_235, "tb1qjpvt0f2lt40csen6q87kdh2eudusqt6atkf5ca")

    val lockTime = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(time).array().ByteArrayToHex()


    // ──────────────────────────────────────────────────────────────────────────────────────── \\


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
        lockTime
    )

    val combinedTransaction = StringBuilder()

    for (component in components) {
        combinedTransaction.append(component)
    }

    val unsignedTransaction = combinedTransaction.toString()
    println("\nUnsigned Transaction: \n| ${unsignedTransaction}\n")


    // ──────────────────────────────────────────────────────────────────────────────────────── \\


    val hashTx = unsignedTransaction.HexToByteArray().doubleSHA256()
    println("Message (doubleSHA256): ${hashTx.ByteArrayToHex()}\n")

    // * Sign Transaction
    val message = BigInteger(hashTx.ByteArrayToHex(), 16)
    val signTx: Pair<BigInteger, BigInteger> = SignSignature(privateKey, message)

    println("Signatures: \n| r = ${signTx.first}\n| s = ${signTx.second}\n")

    // * Verify Signature
//    val validate = EllipticCurve.ECDSA.Verify(curvePoint, message, signTx)
//    if (validate) {
//        println("Signature: Valid")
//    } else {
//        println("Signature: Invalid!!")
//    }

    // * compute: ScriptSig components
    val Signature = toDERFormat(signTx) + "01"
    val SignatureLength = Signature.HexToByteArray().size.DeciToHex()

    val RedeemLength = scriptContract.HexToByteArray().size.DeciToHex()
    val RedeemScript = scriptContract

    // * components unlocking script insert to Unsign Transaction
    val scriptSigLength = (
            SignatureLength +
            Signature +
            RedeemLength +
            RedeemScript
    ).HexToByteArray().size.DeciToHex()


    // ──────────────────────────────────────────────────────────────────────────────────────── \\


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
        lockTime
    )

    val combinedNewTransaction = StringBuilder()

    for (component in componentsNEW) {
        combinedNewTransaction.append(component)
    }

    val signedTransaction = combinedNewTransaction.toString()
    println("Signed Transaction: \n| $signedTransaction")

}

