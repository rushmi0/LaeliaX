package Laeliax.util

import Laeliax.util.ShiftTo.DeciToHex
import Laeliax.util.ShiftTo.ByteArrayToHex
import Laeliax.util.ShiftTo.HexToByteArray
import Laeliax.util.ShiftTo.encodeBase58
import Laeliax.util.ShiftTo.decodeBase58

import Laeliax.util.Hashing.RIPEMD160
import Laeliax.util.Hashing.SHA256
import Laeliax.util.Hashing.doubleSHA256

import Laeliax.util.Address.verify.isP2PKH
import Laeliax.util.Address.verify.isP2WPKH
import Laeliax.util.Address.verify.isP2WSH
import Laeliax.util.Address.verify.getChecksum

import Laeliax.util.Address.getP2PKH
import Laeliax.util.Address.getSegWitP2SH

import Laeliax.Transaction.NETWORKS


object Address {

    private val CHAIN = NETWORKS


    private fun P2WSH(network: String, data: String): String {
        val script = data.SHA256()
        val scriptHash = script.HexToByteArray()
        return Bech32.segwitToBech32("bc", 0, scriptHash)
    }

    private fun P2WPKH(network: String, data: String): String {
        val pubkey = data.SHA256()
        val pubkeyHas = pubkey.RIPEMD160().HexToByteArray()
        return Bech32.segwitToBech32("bc", 0, pubkeyHas)
    }

    private fun P2PKH(network: String, data: String): String {

        // * เมื่อตรวจสอบค่า network และสร้าง Locking Script ตาม network นั้น
        return when (network) {

            // * ในกรณีที่ค่า network เป็น "main" หรือ "test"
            "main",
            "test" -> {

                // * คำนวณค่าแฮช SHA256 ของข้อมูล
                val dataHash256: String = data.SHA256()

                // * คำนวณค่าแฮช RIPEMD160 ของแฮชข้อมูล
                val scriptHash: String = dataHash256.RIPEMD160()

                val prefix = when (network) {

                    // * ดึงค่าสคริปต์สำหรับเครือข่าย "main" -> 0x00
                    "main" -> CHAIN.MAIN["p2pkh"]

                    // * ดึงค่าสคริปต์สำหรับเครือข่าย "test" -> 0x6F
                    "test" -> CHAIN.TEST["p2pkh"]

                    // ! แจ้งเตือนข้อผิดพลาดในกรณีที่ network ไม่ถูกต้อง
                    else -> throw IllegalArgumentException("Invalid network")
                }.toString()

                // * รวมสคริปต์และแฮชสคริปต์เข้าด้วยกัน
                val components = prefix + scriptHash

                // * คำนวณเช็คซัม
                val checksum: ByteArray = components.HexToByteArray().getChecksum()

                // * ประกอบสคริปต์ prefix และ dataHash256 เข้าด้วยกัน
                val combine = components + checksum.ByteArrayToHex()

                // * เข้ารหัสและคืนค่าเป็น Base58
                combine.encodeBase58()
            }

            // ! แจ้งเตือนข้อผิดพลาดในกรณีที่ network ไม่ถูกต้อง
            else -> throw IllegalArgumentException("Invalid network")
        }
    }

    private fun P2SH(network: String, data: String): String {

        // * เมื่อตรวจสอบค่า network และสร้าง Locking Script ตาม network นั้น
        return when (network) {

            // * ในกรณีที่ค่า network เป็น "main" หรือ "test"
            "main",
            "test" -> {

                // * คำนวณค่าแฮช SHA256 ของข้อมูล
                val dataHash256: String = data.SHA256()

                // * คำนวณค่าแฮช RIPEMD160 ของแฮชข้อมูล
                val scriptHash: String = dataHash256.RIPEMD160()

                val prefix = when (network) {

                    // * ดึงค่าสคริปต์สำหรับเครือข่าย "main" -> 0x05
                    "main" -> CHAIN.MAIN["p2sh"]

                    // * ดึงค่าสคริปต์สำหรับเครือข่าย "test" -> 0xC4
                    "test" -> CHAIN.TEST["p2sh"]

                    // ! แจ้งเตือนข้อผิดพลาดในกรณีที่ network ไม่ถูกต้อง
                    else -> throw IllegalArgumentException("Invalid network")
                }.toString()

                // * รวมสคริปต์และแฮชสคริปต์เข้าด้วยกัน
                val components = prefix + scriptHash

                // * คำนวณเช็คซัม
                val checksum: ByteArray = components.HexToByteArray().getChecksum()
                
                // * ประกอบสคริปต์ prefix และ dataHash256 เข้าด้วยกัน
                val combine = components + checksum.ByteArrayToHex()

                // * เข้ารหัสและคืนค่าเป็น Base58
                combine.encodeBase58()
            }

            // ! แจ้งเตือนข้อผิดพลาดในกรณีที่ network ไม่ถูกต้อง
            else -> throw IllegalArgumentException("Invalid network")
        }
    }

    private fun NestedSegWit(network: String, data: String): String {

        // * เมื่อตรวจสอบค่า network และสร้าง Locking Script ตาม network นั้น
        return when (network) {

            // * ในกรณีที่ค่า network เป็น "main" หรือ "test"
            "main",
            "test" -> {

                val dataHash: String = if (data.substring(0, 2) in setOf("02", "03") && data.HexToByteArray().size == 33) {

                    // * คำนวณค่าแฮช SHA256 ของข้อมูล -> คำนวณค่าแฮชต่อด้วย RIPEMD160
                    data.SHA256().RIPEMD160()
                } else {

                    // * คำนวณค่าแฮช SHA256 ของข้อมูล
                    data.SHA256()
                }

                /*
                * คำนวณค่า size โดยแปลง dataHash256 ซึ่งเป็นเลขฐานสิบหกให้เป็น Bytes
                * จากนั้นนับจำนวน Bytes ทั้งหมด เอาผมรวมนั้นนำไปแปลงจากเลขฐานสิบ เป็นเลขฐานสิบหก
                */
                val size: String = dataHash.HexToByteArray().size.DeciToHex()

                // * เมื่อตรวจสอบค่า network อีกครั้ง
                val prefix = when (network) {

                    // * ดึงค่าสคริปต์สำหรับเครือข่าย "main" -> 0x00
                    "main" -> CHAIN.MAIN["p2pkh"]

                    // * ดึงค่าสคริปต์สำหรับเครือข่าย "test" -> 0x6F
                    "test" -> CHAIN.TEST["p2pkh"]

                    // ! แจ้งเตือนข้อผิดพลาดในกรณีที่ network ไม่ถูกต้อง
                    else -> throw IllegalArgumentException("Invalid network")

                }.toString()

                // * ประกอบ script โดยรวมค่า prefix, size, และ dataHash256 เข้าด้วยกัน
                val combine = prefix + size + dataHash

                // * ส่งค่าสคริปตไปห่อด้วย P2SH โดยเรียกใช้ getP2SH() -> P2SH( SegWit )
                combine.getP2SH(network)
            }
            
            // ! แจ้งเตือนข้อผิดพลาดในกรณีที่ network ไม่ถูกต้อง
            else -> throw IllegalArgumentException("Invalid network")
        }
    }

    // ──────────────────────────────────────────────────────────────────────────────────────── \\

    // Pay-to-Witness-Script-Hash
    fun String.getP2WSH(network: String): String {
        return P2WSH(network, this)
    }

    // Pay-to-Witness-Public-Key-Hash
    fun String.getP2WPKH(network: String): String {
        return P2WPKH(network, this)
    }

    // Pay-to-Public-Key-Hash
    fun String.getP2PKH(network: String): String {
        return P2PKH(network, this)
    }

    // Nested SegWit (P2SH-P2WPKH)
    fun String.getSegWitP2SH(network: String): String {
        return NestedSegWit(network, this)
    }

    // Pay-to-Script-Hash
    fun String.getP2SH(network: String): String {
        return P2SH(network, this)
    }

    // ──────────────────────────────────────────────────────────────────────────────────────── \\

    /*
    * ในส่วนนี้ ใช้สำหรับการตรวจสอบความถูกต้องของ Locking Script ต่าง ๆ
    */
    object verify {

        private fun findeChecksum(data: ByteArray): ByteArray {
            val hash = data.doubleSHA256()
            return hash.sliceArray(0 until 4)
        }

        private fun P2PKH(address: String): Boolean {
            val decodedAddress = address.decodeBase58().HexToByteArray()
            if (decodedAddress.size != 25) {
                return false
            }

            val checksum = findeChecksum(decodedAddress.sliceArray(0 until 21))
            if (!decodedAddress.sliceArray(21 until 25).contentEquals(checksum)) {
                return false
            }

            val networkPrefix = decodedAddress[0]
            return networkPrefix == 0x00.toByte()
        }

        private fun P2WSH(address: String): Boolean {
            val decodedAddress = Bech32.bech32ToSegwit(address)
            val humanPart = decodedAddress[0] as String
            val witVer = decodedAddress[1] as Int
            val witProg = decodedAddress[2] as ByteArray

            return witVer == 0 || humanPart == "bc" && witProg.size == 32
        }

        private fun P2WPKH(address: String): Boolean {
            val decodedAddress = Bech32.bech32ToSegwit(address)
            val humanPart = decodedAddress[0] as String
            val witVer = decodedAddress[1] as Int
            val witProg = decodedAddress[2] as ByteArray

            return witVer == 0 || humanPart == "bc" && witProg.size == 20
        }

        // ──────────────────────────────────────────────────────────────────────────────────────── \\

        fun ByteArray.getChecksum(): ByteArray {
            return findeChecksum(this)
        }

        fun String.isP2PKH(): Boolean {
            return P2PKH(this)
        }

        fun String.isP2WSH(): Boolean {
            return P2WSH(this)
        }

        fun String.isP2WPKH(): Boolean {
            return P2WPKH(this)
        }

    }
}

fun main() {

    // * สร้าง Locking Script รูปแบบต่าง ๆ
    val isPublicKey = "02aa36a1958e2fc5e5de75d05bcf6f3ccc0799be4905f4e418505dc6ab4422a8db"
    val lockP2PKH = isPublicKey.getP2PKH("main")
    val lockNested = isPublicKey.getSegWitP2SH("main")
    println(lockP2PKH)
    println(lockNested)


    // * ตรวจสอบ Locking Script รูปแบบต่าง ๆ
    val checkP2PKH = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
    val isValidP2PKH = checkP2PKH.isP2PKH()

    if (isValidP2PKH) {
        println("The address is valid.")
    } else {
        println("The address is not valid.")
    }


    val checkP2WSH = "bc1qqsa8rpm5c4etmz394kltr07dtsp9dts3em8el8pljfwsu54747ys0t028e"
    val isValidP2WSH = checkP2WSH.isP2WSH()

    if (isValidP2WSH) {
        println("The address is valid.")
    } else {
        println("The address is not valid.")
    }


    val checkP2WPKH = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    val isValidP2WPKH = checkP2WPKH.isP2WPKH()

    if (isValidP2WPKH) {
        println("The address is valid.")
    } else {
        println("The address is not valid.")
    }

}