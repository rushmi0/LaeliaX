package LaeliaX.SecureKey

import LaeliaX.SecureKey.Virentkey.fromRoot
import LaeliaX.SecureKey.Virentkey.fromSeed
import LaeliaX.SecureKey.Virentkey.toMasterRoot
import LaeliaX.util.Hashing.doubleSHA256
import LaeliaX.util.ShiftTo.ByteArrayToHex
import LaeliaX.util.ShiftTo.HexToByteArray
import LaeliaX.util.ShiftTo.decodeBase58
import LaeliaX.util.ShiftTo.encodeBase58

import javax.crypto.Mac
import javax.crypto.spec.PBEKeySpec
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.SecretKeySpec
import java.nio.charset.StandardCharsets

object Virentkey {
    
    private val MAINNET = "0488ade4"

    fun fromRoot(mnemonic: String, passphrase: String = ""): ByteArray {
        val seed = mnemonic.toCharArray()
        val salt = ("mnemonic$passphrase").toByteArray(Charsets.UTF_8)
        val iterations = 2048
        val keyLength = 64

        val keySpec = PBEKeySpec(seed, salt, iterations, keyLength * 8)
        val secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512")
        val secretKey = secretKeyFactory.generateSecret(keySpec)

        return secretKey.encoded
    }

    fun fromSeed(seed: ByteArray): ByteArray {
        val hmacSha512 = Mac.getInstance("HmacSHA512")
        hmacSha512.init(SecretKeySpec("Bitcoin seed".toByteArray(StandardCharsets.UTF_8), "HmacSHA512"))
        return hmacSha512.doFinal(seed)
    }

    fun toMasterRoot(seed: ByteArray): String {
        val chainCode = seed.copyOfRange(32, seed.size)
        val privateKey = seed.copyOfRange(0, 32)
        
        val xprv = MAINNET.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val depth = ByteArray(9)
        val prefixPrivate = ByteArray(1)

        val xprvBytes = xprv + depth + chainCode + prefixPrivate + privateKey
        val checkSum = xprvBytes.doubleSHA256().copyOfRange(0, 4)
        val master = xprvBytes + checkSum
        return master.ByteArrayToHex().encodeBase58()
    }

}

fun main() {
    val mnemonic = "venture hand impose run history decline kingdom social short thunder firm spend robot love vocal popular lesson rebuild famous write region damp heavy any"
    val passphrase = "กูนึกแล้วมึงต้องอ่าน"
    val seed: ByteArray  = fromRoot(mnemonic, passphrase)
    val privateKey = fromSeed(seed)
    val root = toMasterRoot(privateKey)
    println("Master Private Key: $root")


    val xpub = "xpub6CdMV3MbyaUdLCxVqffsL28bNRjERapsEQbQ9RMcUYup9f7Fj9u1Qd4eC3z4QrxW1AQByzGUNW5DhT8oJ8DxgvWtDJCEF6F1LAcMAGZndd2"
    val rawXpub = xpub.decodeBase58()
    val datasize = rawXpub.HexToByteArray().size
    //println(datasize)
    println(rawXpub)
    println(datasize)

    val depth = rawXpub.HexToByteArray().copyOfRange(4, 5).ByteArrayToHex()
    println("Depth: $depth")

    val fingerPrint = rawXpub.HexToByteArray().copyOfRange(5, 9).ByteArrayToHex()
    println("FingerPrint: $fingerPrint")

    val index = rawXpub.HexToByteArray().copyOfRange(9, 13).ByteArrayToHex()
    println("Index: $index")

    val chainCode = rawXpub.HexToByteArray().copyOfRange(13, 45).ByteArrayToHex()
    println("Chain Code: $chainCode")

    val publicKey = rawXpub.HexToByteArray().copyOfRange(45, 78).ByteArrayToHex()
    println("Public Key: $publicKey")
}
