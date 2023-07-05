package LaeliaX.Transaction


import LaeliaX.util.Bech32
import LaeliaX.util.ShiftTo.decodeBase58
import LaeliaX.util.Hashing.doubleSHA256

import LaeliaX.util.ShiftTo.DeciToHex
import LaeliaX.util.ShiftTo.ByteToHex
import LaeliaX.util.ShiftTo.ByteArrayToHex
import LaeliaX.util.ShiftTo.HexToByteArray
import LaeliaX.util.ShiftTo.DeciToHexByte
import LaeliaX.util.ShiftTo.FlipByteOrder

import LaeliaX.MiniScript.OP_
import LaeliaX.MiniScript.Validator.getLockTime
import LaeliaX.MiniScript.Validator.viewScript
import LaeliaX.MiniScript.Validator.generateTransactionID

import LaeliaX.SecureKey.EllipticCurve.ECDSA.SignSignatures
import LaeliaX.SecureKey.EllipticCurve.ECDSA.toDERFormat

import LaeliaX.SecureKey.WIF.extractWIF
import LaeliaX.util.Address.verify.isP2PKH
import LaeliaX.util.Address.verify.isP2WPKH

import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder



class NonsegwitUTxO(private val version: Int, private val privateKey: String) {

    private val inputs: MutableList<UTxOInput> = mutableListOf()
    private val outputs: MutableList<UTxOOutput> = mutableListOf()

    private var scriptCode: String? = null
    private var lockTime: Int? = null

    // * UTxO ขาเข้า
    fun addInput(transactionID: String, outputIndex: Int, scriptCode: String) {
        val input = UTxOInput(transactionID, outputIndex, scriptCode)
        this.inputs.add(input)
        this.scriptCode = scriptCode
        setLockTime(scriptCode)
    }

    // * UTxO ขาออก
    fun addOutput(amounts: Long, address: String) {
        val output = UTxOOutput(amounts, address)
        this.outputs.add(output)
    }

    private fun setLockTime(scriptCode: String) {
        this.lockTime = viewScript(scriptCode).getLockTime()
    }



    // * ประกอบ "ธุรกรรมดิบ" ขึ้นมา
    fun generateUnsignedTransaction(): String {
        val version = NETWORKS.VERSION[this.version].toString()
        val inputCount = inputs.size.DeciToHex().toInt().DeciToHexByte()
        val inputComponents = inputs.joinToString("") { it.generateInputComponents() }

        val outputCount = outputs.size.DeciToHex().toInt().DeciToHexByte()
        val outputComponents = outputs.joinToString("") { it.generateOutputComponents() }
        val lockTime = this.lockTime!!.let { ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(it).array().ByteArrayToHex() }

        return version + inputCount + inputComponents + outputCount + outputComponents + lockTime
    }

    private fun ScriptSigComponents(SignaturePoint: Pair<BigInteger, BigInteger>): String {
        val Signature = toDERFormat(SignaturePoint) + "01"
        val SignatureLength: String = Signature.HexToByteArray().size.DeciToHex()

        val RedeemLength: String = this.scriptCode.toString().HexToByteArray().size.DeciToHex()
        val RedeemScript: String = this.scriptCode.toString()

        val scriptSigLength: String = (
                SignatureLength +
                        Signature +
                        RedeemLength +
                        RedeemScript
                ).HexToByteArray().size.DeciToHex()

        val result = scriptSigLength + SignatureLength + Signature + RedeemLength + RedeemScript
        return result
    }

    private fun Pair<BigInteger, BigInteger>.getScriptSig(): String {
        return ScriptSigComponents(this)
    }


    fun signTransaction(): String {
        val unsignedTransaction = generateUnsignedTransaction()
        val message = BigInteger(unsignedTransaction.HexToByteArray().doubleSHA256().ByteArrayToHex(), 16)
        val signatures = SignSignatures(BigInteger(privateKey, 16), message)
        return mergeSignature(unsignedTransaction, signatures.getScriptSig())
    }


    private fun mergeSignature(UTxO: String, ScriptSig: String): String {
        val pattern = "00000000(.*?)f(.?)ffffff"

        val regex = Regex(pattern)
        val match = regex.find(UTxO)

        if (match != null) {
            val originalData = match.groupValues[1]
            val modifiedData = ScriptSig

            val result = UTxO.replaceFirst(originalData, modifiedData)

            return result
        }
        return UTxO
    }



    // * สร้างองค์ประกอบ UTxO ขาเข้า
    private data class UTxOInput(val txID: String, val vout: Int, val scriptCode: String) {

        // * https://en.bitcoin.it/wiki/Dump_format#CTxIn
        fun generateInputComponents(): String {
            val txIDFlip = txID.FlipByteOrder()
            val voutHex = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(vout).array().ByteArrayToHex()
            val scriptSize = scriptCode.HexToByteArray().size.DeciToHex()

            val time = viewScript(scriptCode).getLockTime()

            // * คุณสมบัติเฉพาะ
            val sequence: List<String> = listOf(
                "ffffffff", // อนุญาตปิดลง block ได้ทันที
                "fdffffff", // ไม่อนุญาตปิดลง block ได้ทันทีจนกว่าจะถึงเวลาที่กำหนด
                //"feffffff"  // ยกเลิกการใช้คุณสมบัติ "replace-by-fee" (RBF)
            )

            return if (time > 0) {
                txIDFlip + voutHex + scriptSize + scriptCode + sequence[1]
            }
            else {
                txIDFlip + voutHex + scriptSize + scriptCode + sequence[0]
            }
        }

    }


    // * สร้างองค์ประกอบ UTxO ขาออก
    private data class UTxOOutput(val amounts: Long, val address: String) {

        // * https://en.bitcoin.it/wiki/Dump_format#CTxOut
        fun generateOutputComponents(): String {

            // * โอนไปที่ P2WPKH
            if (address.isP2WPKH()) {
                val amounts = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(amounts).array().ByteArrayToHex()
                val data = Bech32.bech32ToSegwit(address)[2] as ByteArray
                val size = data.size.DeciToHex()

                val scriptCode = (
                        OP_.FALSE.ByteToHex() +
                        size +
                        data.ByteArrayToHex()
                )

                val scriptSize = scriptCode.HexToByteArray().size.DeciToHex()
                return amounts + scriptSize + scriptCode
            }

            // * โอนไปที่ P2PKH
            if (address.isP2PKH()) {
                val amounts = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(amounts).array().ByteArrayToHex()
                val data = address.decodeBase58().HexToByteArray()
                val keyHash = data.copyOfRange(1, 21)
                val keyHashSize = keyHash.size.DeciToHex()

                // * https://en.bitcoin.it/wiki/Dump_format#CScript
                val scriptCode = (
                        OP_.DUP.ByteToHex() +
                        OP_.HASH160.ByteToHex() +
                        keyHashSize +
                        keyHash.ByteArrayToHex() +
                        OP_.EQUALVERIFY.ByteToHex() +
                        OP_.CHECKSIG.ByteToHex()
                )

                val scriptSize = scriptCode.HexToByteArray().size.DeciToHex()
                return amounts + scriptSize + scriptCode
            }

            throw IllegalArgumentException("Invalid 'address'")
        }

    }

}


fun main() {

    /**
     * L1c3ZfZu5e8TiQKS9FJ9ioh4GXEjxjob5ZSgqYRCHwrGNNEnyrBk
     * 02aa36a1958e2fc5e5de75d05bcf6f3ccc0799be4905f4e418505dc6ab4422a8db
     * */

    val wif = "L1c3ZfZu5e8TiQKS9FJ9ioh4GXEjxjob5ZSgqYRCHwrGNNEnyrBk"
    val privateKey = wif.extractWIF()

    val tx = NonsegwitUTxO(2, privateKey)

    // * UTxO : ขาเข้า
    tx.addInput(
            "de496c29138457073c86de1f6818c8caccb6be3cdfce57254cba5f66f8046bda",
            0,
            "03b43b25b1752102aa36a1958e2fc5e5de75d05bcf6f3ccc0799be4905f4e418505dc6ab4422a8dbac"
    )

    // * UTxO : ขาออก
    tx.addOutput(
        5_800,
        "tb1q7uqrl2tjxj43zunc5aka3fuv2ssn990qhltahj"
    )


    val unsignedTransaction = tx.generateUnsignedTransaction()
    val txUID = unsignedTransaction.generateTransactionID()

    println("Transaction ID: $txUID")
    println("Unsigned Transaction:\n$unsignedTransaction \n")


    val signedTransaction = tx.signTransaction()
    val txSID = signedTransaction.generateTransactionID()

    println("\nTransaction ID: $txSID")
    println("Signed Transaction: \n$signedTransaction")


} // ! Road to Bitcoin developer