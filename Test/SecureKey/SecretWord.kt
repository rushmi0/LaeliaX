package Laeliax.SecureKey

import Laeliax.util.Hashing._SHA256
import Laeliax.util.ShiftTo.BinaryToByteArray
import Laeliax.util.ShiftTo.ByteArrayToBinary
import Laeliax.util.ShiftTo.ByteArrayToHex
import Laeliax.util.ShiftTo.HexToBinary
import Laeliax.util.ShiftTo.decodeBase58

import java.io.File
import java.math.BigInteger
import java.nio.file.Paths
import java.security.SecureRandom


class SecretWord(private val Strength: Int) {

    //private val wordlist: List<String> = locationPath()
    private val WORD = BIP39.WORDLIST

    private fun locationPath(): List<String> {
        val wordlistPath = Paths.get("", "SecureKey/english.txt").toString()
        return File(wordlistPath).readLines().map { it.trim() }
    }

    private fun loadWordlist(): List<String> {
        val wordlistPath = File("SecureKey/english.txt")
        return wordlistPath.readLines().map { it.trim() }
    }


    private fun generateEntropy(): ByteArray {
        val entropy = BigInteger(Strength, SecureRandom()).toString(2)
        //val entropy = "10101010111110011011000111010000011111001000100010100100111100100110110001011001010100101011011011000111101010010101101111101101"
        val byteArray: ByteArray = entropy.BinaryToByteArray()

        println("Generated Binary: ${byteArray.ByteArrayToBinary()}")
        println("Entropy Bytes [${byteArray.size}]: ${byteArray.contentToString()}")
        return byteArray
    }


    // * https://www.mathsisfun.com/binary-decimal-hexadecimal-converter.html
    private fun binarySeed(data: ByteArray): String {
        val size = data.size * 8
        println("Entropy Hex: ${data.ByteArrayToHex()}")

        val entropyHash = data._SHA256().ByteArrayToHex()
        println("Entropy hash: $entropyHash")

        val entropy = data.ByteArrayToBinary()
        val checksum = entropyHash.HexToBinary().substring(0, size / 32)

        println("Checksum: $checksum")
        return entropy + checksum
    }

    fun generateMnemonic(): String {
        val entropyBytes = generateEntropy()
        val entropy = binarySeed(entropyBytes)

        val pieces = (0 until entropy.length step 11).map { i -> entropy.substring(i, i + 11) }
        //val mnemonic = pieces.map { piece -> wordlist[piece.toInt(2)] }.joinToString(" ")
        val mnemonic = pieces.map { piece -> WORD[piece.toInt(2)] }.joinToString(" ")

        return mnemonic
    }

}

fun main() {
    val generator = SecretWord(128)
    val mnemonic = generator.generateMnemonic()
    println("\nMnemonic Word [${mnemonic.split(" ").size}]")
    println("> $mnemonic")

    val passphrase = ""
    val seed = Virentkey.fromRoot(mnemonic, passphrase)
    val privateKey = Virentkey.fromSeed(seed)
    val rootKey = Virentkey.toMasterRoot(privateKey)
    println("\nMaster Private key " +
            "\n> $rootKey " +
            "\n> ${rootKey.decodeBase58()}")
}