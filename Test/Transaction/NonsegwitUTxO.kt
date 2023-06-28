package LaeliaX.Transaction


import LaeliaX.util.Bech32
import LaeliaX.util.ShiftTo.decodeBase58
import LaeliaX.util.Hashing.doubleSHA256

import LaeliaX.util.ShiftTo.ByteArrayToHex
import LaeliaX.util.ShiftTo.DeciToHex
import LaeliaX.util.ShiftTo.HexToByteArray
import LaeliaX.util.ShiftTo.ByteToHex
import LaeliaX.util.ShiftTo.DeciToHexByte
import LaeliaX.util.ShiftTo.FlipByteOrder

import LaeliaX.MiniScript.Validator.generateTransactionID

import LaeliaX.MiniScript.OP_
import LaeliaX.MiniScript.Validator.getLockTime
import LaeliaX.MiniScript.Validator.readeScript

import LaeliaX.SecureKey.EllipticCurve
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
    private var lockTime: Int? = null
    private var scriptCode: String? = null

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
        this.lockTime = readeScript(scriptCode).getLockTime()
    }


    // * ประกอบ "ธุรกรรมดิบ" ขึ้นมา
    fun generateUnsignedTransaction(): String {
        val version = NETWORKS.VERSION[this.version].toString()
        val inputCount = inputs.size.DeciToHex().toInt().DeciToHexByte()
        val inputComponents = inputs.joinToString("") { it.generateInputComponents() }

        val outputCount = outputs.size.DeciToHex().toInt().DeciToHexByte()
        val outputComponents = outputs.joinToString("") { it.generateOutputComponents() }
        val lockTime = this.lockTime?.let { ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(it).array().ByteArrayToHex() }

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

        return scriptSigLength + SignatureLength + Signature + RedeemLength + RedeemScript
    }

    private fun Pair<BigInteger, BigInteger>.getScriptSig(): String {
        return ScriptSigComponents(this)
    }


    fun signTransaction(): String {
        val unsignedTransaction = generateUnsignedTransaction()
        val message = BigInteger(unsignedTransaction.HexToByteArray().doubleSHA256().ByteArrayToHex(), 16)
        val signatures = EllipticCurve.ECDSA.SignSignature(BigInteger(privateKey, 16), message)
        return mergeSignature(unsignedTransaction, signatures.getScriptSig())
    }


    private fun mergeSignature(unignTx: String, ScriptSig: String): String {
        val pattern = "00000000(.*?)f(.?)ffffff"

        val regex = Regex(pattern)
        val match = regex.find(unignTx)

        if (match != null) {
            val originalData = match.groupValues[1]
            val modifiedData = ScriptSig

            val result = unignTx.replaceFirst(originalData, modifiedData)

            return result
        }
        return unignTx
    }



    // * สร้างองค์ประกอบ UTxO ขาเข้า
    private data class UTxOInput(val txID: String, val vout: Int, val scriptCode: String) {

        // * https://en.bitcoin.it/wiki/Dump_format#CTxIn
        fun generateInputComponents(): String {
            val txIDFlip = txID.FlipByteOrder()
            val voutHex = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(vout).array().ByteArrayToHex()
            val scriptSize = scriptCode.HexToByteArray().size.DeciToHex()

            val time = readeScript(scriptCode).getLockTime()

            // * คุณสมบัติเฉพาะ
            val sequence: List<String> = listOf(
                "ffffffff", // อนุญาตปิดลง block ได้ทันที
                "fdffffff", // ไม่อนุญาตปิดลง block ได้ทันทีจนกว่าจะถึงเวลาที่กำหนด
                "feffffff"  // ยกเลิกการใช้คุณสมบัติ "replace-by-fee" (RBF)
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
                val scriptCode = OP_.FALSE.ByteToHex() + size + data.ByteArrayToHex()
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

            return "Invalid 'sat' amount or 'address'"
        }

    }

}


fun main() {

    val wif = "L1c3ZfZu5e8TiQKS9FJ9ioh4GXEjxjob5ZSgqYRCHwrGNNEnyrBk"
    val privateKey = wif.extractWIF()

    val tx = NonsegwitUTxO(2, privateKey)

    /**
     * L1c3ZfZu5e8TiQKS9FJ9ioh4GXEjxjob5ZSgqYRCHwrGNNEnyrBk
     * 02aa36a1958e2fc5e5de75d05bcf6f3ccc0799be4905f4e418505dc6ab4422a8db
     * */

    // * UTxO : ขาเข้า

    /*tx.addInput(
        "a6de7166774a61294d9be0b8e3951c3f81912d800b5e83877a15117754c698a8",
        0,
        // * P2PKH
        "2102aa36a1958e2fc5e5de75d05bcf6f3ccc0799be4905f4e418505dc6ab4422a8db",
        0
    )*/

    tx.addInput(
            "986bd0687a2c5e2b9f4d95b31ed9a77b77658343b5794439dd45b3a956df3afc",
            0,
            // * timeLock 2_438_924: ต้องรอเวลาที่กำหนด จึงจะสามารถปลดล็อคได้
            "030c3725b1752102aa36a1958e2fc5e5de75d05bcf6f3ccc0799be4905f4e418505dc6ab4422a8dbac"
    )

    /*tx.addInput(
        "afbfb2c6e1fad3f8f7dbe16f046961fc0a1469d9401b3a63375da1a10a603956",
        1,
        // * multiSig 2-of-3: ต้องใช้ลายเซ็นขั้นต่ำ 2 ใน 3 ในการปลดล็อค
        "52210387cb20433e452a106312107c4885c27f209d6ece38055c8bea56bcbc8b1e29af2102635073d61f689a9dd38be41de286ebb3b7137394164d1e00d4eeb4d7bb9ff48b21024bc043a0c094c5f2865dad0c494e6e9e76b3d6034e4ce55895b4ea8285274dd753ae",
        0
    )

    tx.addInput(
            "94f3ec09d34b2c150d5790909ab4f657e5467bdfcfd43133b161b8d60449db03",
            2,
            // * timeLock(multiSig 2-of-3)
            "03abb915b17552210387cb20433e452a106312107c4885c27f209d6ece38055c8bea56bcbc8b1e29af2102635073d61f689a9dd38be41de286ebb3b7137394164d1e00d4eeb4d7bb9ff48b21024bc043a0c094c5f2865dad0c494e6e9e76b3d6034e4ce55895b4ea8285274dd753aeac",
            1423787
    )*/

    /*tx.addOutput(
        225_235,
        "tb1qjpvt0f2lt40csen6q87kdh2eudusqt6atkf5ca"
    )*/

    // * UTxO : ขาออก
    tx.addOutput(
        15_000,
        "bc1qxs3jjwpj88f0zq9yyhk02yfpgt5945gwwp2ddx"
    )

   /* tx.addOutput(
        100_000,
        "1EoxGLjv4ZADtRBjTVeXY35czVyDdp7rU4"
    )

    tx.addOutput(
        500_000_000_000,
        "bc1qk2rrmezy90smpnkfrdkz304pexqxuuchjgl2nz"
    )*/


    val unsignedTransaction = tx.generateUnsignedTransaction()
    val txUID = unsignedTransaction.generateTransactionID()

    println("Transaction ID: $txUID")
    println("Unsigned Transaction:\n$unsignedTransaction \n")

    val signedTransaction = tx.signTransaction()
    val txSID = signedTransaction.generateTransactionID()

    println("Transaction ID: $txSID")
    println("Signed Transaction: \n$signedTransaction")


} // ! Road to Bitcoin developer