package Laeliax.Transaction

import Laeliax.SecureKey.EllipticCurve
import Laeliax.util.Bech32
import Laeliax.util.ShiftTo.decodeBase58
import Laeliax.util.Hashing.doubleSHA256

import Laeliax.util.ShiftTo.ByteArrayToHex
import Laeliax.util.ShiftTo.DeciToHex
import Laeliax.util.ShiftTo.HexToByteArray
import Laeliax.util.ShiftTo.ByteToHex
import Laeliax.util.ShiftTo.DeciToHexByte

import Laeliax.util.ShiftTo.FlipByteOrder
import Laeliax.MiniScript.Validator.generateTransactionID

import Laeliax.MiniScript.OP_

import Laeliax.SecureKey.EllipticCurve.ECDSA.toDERFormat

import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder



class LegacyTransaction(private val privateKey: String) {

    private val inputs: MutableList<UTxOInput> = mutableListOf()
    private val outputs: MutableList<UTxOOutput> = mutableListOf()
    private var lockTime: Int = 0

    fun addInput(txID: String, vout: Int, scriptCode: String, lockTime: Int) {
        this.lockTime = lockTime
        val input = UTxOInput(txID, vout, scriptCode, lockTime)
        inputs.add(input)
    }

    fun addOutput(amounts: Long, address: String) {
        val output = UTxOOutput(amounts, address)
        outputs.add(output)
    }

    /*
    fun setLockTime(lockTime: Int) {
        this.lockTime = lockTime
    }*/

    // * ประกอบ "ธุรกรรมดิบ" ขึ้นมา
    fun generateUnsignedTransaction(): String {
        val version = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(1).array().ByteArrayToHex()
        val inputCount = inputs.size.DeciToHex().toInt().DeciToHexByte()
        val inputComponents = inputs.joinToString("") { it.generateInputComponents() }

        val outputCount = outputs.size.DeciToHex().toInt().DeciToHexByte()
        val outputComponents = outputs.joinToString("") { it.generateOutputComponents() }
        val lockTime = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(this.lockTime).array().ByteArrayToHex()

        return version + inputCount + inputComponents + outputCount + outputComponents + lockTime
    }


    // ! ส่วนนี้ยังมีปัญหา
    fun signTransaction(): String {
        val unsignedTransaction = generateUnsignedTransaction()
        val message = BigInteger(unsignedTransaction.HexToByteArray().doubleSHA256().ByteArrayToHex(), 16)
        val signTx = EllipticCurve.ECDSA.SignSignature(BigInteger(privateKey, 16), message)
        return mergeSignature(signTx)
    }

    private fun mergeSignature(signature: Pair<BigInteger, BigInteger>): String {
        //val inputComponents = inputs.joinToString("") { it.generateInputComponents() }
        val scriptSig = toDERFormat(signature)
        val sigSize = scriptSig.HexToByteArray().size.DeciToHex()

        val unlocking = sigSize + scriptSig + "01" + inputs.first().scriptCode.HexToByteArray().size.DeciToHex() + inputs.first().scriptCode
        val unlockingSize = unlocking.HexToByteArray().size.DeciToHex()

        val result = unlockingSize + unlocking
        return result
    }


    // * สร้างองค์ประกอบ UTxO ขาเข้า
    private data class UTxOInput(val txID: String, val vout: Int, val scriptCode: String, val lockTime: Int) {

        // * https://en.bitcoin.it/wiki/Dump_format#CTxIn
        fun generateInputComponents(): String {
            val txIDFlip = txID.FlipByteOrder()
            val voutHex = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(vout).array().ByteArrayToHex()
            val scriptSize = scriptCode.HexToByteArray().size.DeciToHex()

            // * คุณสมบัติเฉพาะ
            val sequence: List<String> = listOf(
                "ffffffff", // อนุญาตปิดลง block ได้ทันที
                "fdffffff", // ไม่อนุญาตปิดลง block ได้ทันทีจนกว่าจะถึงเวลาที่กำหนด
                "feffffff"  // ยกเลิกการใช้คุณสมบัติ "replace-by-fee" (RBF)
            )

            return if (lockTime > 0) {
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
            if (address.substring(0, 3) == "bc1" && address.length == 42) {
                val amounts =ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(amounts).array().ByteArrayToHex()
                val data = Bech32.bech32ToSegwit(address)[2] as ByteArray
                val lockSize = data.size.DeciToHex()
                val lockingScript = "${OP_.FALSE.ByteToHex()}${lockSize}${data.ByteArrayToHex()}"
                val lockingSizes = lockingScript.HexToByteArray().size.DeciToHex()
                return amounts + lockingSizes + lockingScript
            }
            /*else if () {

            }*/

            // * โอนไปที่ P2PKH
            else {
                val amounts = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(amounts).array().ByteArrayToHex()
                val data = address.decodeBase58().HexToByteArray()
                val keyHash = data.copyOfRange(1, 21)
                val keyHashSize = keyHash.size.DeciToHex()

                // * https://en.bitcoin.it/wiki/Dump_format#CScript
                val lockingScript = "${OP_.DUP.ByteToHex()}${OP_.HASH160.ByteToHex()}${keyHashSize}${keyHash.ByteArrayToHex()}${OP_.EQUALVERIFY.ByteToHex()}${OP_.CHECKSIG.ByteToHex()}"

                val lockingSizes = lockingScript.HexToByteArray().size.DeciToHex()
                return amounts + lockingSizes + lockingScript
            }
        }

    }
}


fun main() {

    val privateKey = "f206d54e3383e8efb5f3578403032020c84493b98e12274a40d1663ffa16da44"
    val tx = LegacyTransaction(privateKey)
    //tx.setLockTime(766910)


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
            "c95039b1ce6152a20ecab1759e924c15e25f4d980673bd64c07a43d2fb501acb",
            0,
            // * timeLock 74852: ต้องรอเวลาที่กำหนด จึงจะสามารถปลดล็อคได้
            "03abb915b1752102aa36a1958e2fc5e5de75d05bcf6f3ccc0799be4905f4e418505dc6ab4422a8dbac",
        1423787
    )

    /*tx.addInput(
        "afbfb2c6e1fad3f8f7dbe16f046961fc0a1469d9401b3a63375da1a10a603956",
        1,
        // * multiSig 2-of-3: ต้องใช้ลายเซ็นขั้นต่ำ 2 ใน 3 ในการปลดล็อค
        "52210387cb20433e452a106312107c4885c27f209d6ece38055c8bea56bcbc8b1e29af2102635073d61f689a9dd38be41de286ebb3b7137394164d1e00d4eeb4d7bb9ff48b21024bc043a0c094c5f2865dad0c494e6e9e76b3d6034e4ce55895b4ea8285274dd753ae",
        0
    )*/

    tx.addInput(
            "94f3ec09d34b2c150d5790909ab4f657e5467bdfcfd43133b161b8d60449db03",
            2,
            // * timeLock(multiSig 2-of-3)
            "03abb915b17552210387cb20433e452a106312107c4885c27f209d6ece38055c8bea56bcbc8b1e29af2102635073d61f689a9dd38be41de286ebb3b7137394164d1e00d4eeb4d7bb9ff48b21024bc043a0c094c5f2865dad0c494e6e9e76b3d6034e4ce55895b4ea8285274dd753aeac",
            1423787
    )


    // * UTxO : ขาออก
    tx.addOutput(
        15_000,
        "bc1qxs3jjwpj88f0zq9yyhk02yfpgt5945gwwp2ddx"
    )

    /*tx.addOutput(
        100_000,
        "1EoxGLjv4ZADtRBjTVeXY35czVyDdp7rU4"
    )*/

    tx.addOutput(
        500_000_000_000,
        "bc1qk2rrmezy90smpnkfrdkz304pexqxuuchjgl2nz"
    )



    val unsignedTransaction = tx.generateUnsignedTransaction()
    val txID = unsignedTransaction.generateTransactionID()

    println("Transaction ID:\n${txID}\n")
    println("Unsigned Transaction:\n$unsignedTransaction")


    /*
    Transaction ID:
    f92606b97f2f2c51fee54f3a5325f77b7cb044284052408b9c27711b445a5ddd

    Unsigned Transaction:
    01000000039da47a058bfb24449675d9fe886b7c8d16351fd9007491750bb4553fb346ee4f000000002903beb30bb17521027de11310f7c996a2d1021276c11759ebb6f26d229dfd0bbc93b7f72fd36e3b8cacfdffffff5639600aa1a15d37633a1b40d969140afc6169046fe1dbf7f8d3fae1c6b2bfaf010000006952210387cb20433e452a106312107c4885c27f209d6ece38055c8bea56bcbc8b1e29af2102635073d61f689a9dd38be41de286ebb3b7137394164d1e00d4eeb4d7bb9ff48b21024bc043a0c094c5f2865dad0c494e6e9e76b3d6034e4ce55895b4ea8285274dd753aefdffffff03db4904d6b861b13331d4cfdf7b46e557f6b49a9090570d152c4bd309ecf394020000007103beb30bb1756952210387cb20433e452a106312107c4885c27f209d6ece38055c8bea56bcbc8b1e29af2102635073d61f689a9dd38be41de286ebb3b7137394164d1e00d4eeb4d7bb9ff48b21024bc043a0c094c5f2865dad0c494e6e9e76b3d6034e4ce55895b4ea8285274dd753aeacfdffffff0320a10700000000001600146aeb185d7890788d4be2ed097bee766e896857bda0860100000000001976a914977ae6e32349b99b72196cb62b5ef37329ed81b488ac0088526a74000000160014b2863de4442be1b0cec91b6c28bea1c9806e7317beb30b00
    */

    //val signedTransaction = tx.signTransaction()
    //println("Signed tx:\n$signedTransaction")


} // ! Road to Bitcoin developer