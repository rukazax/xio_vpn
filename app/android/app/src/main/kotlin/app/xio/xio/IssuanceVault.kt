package app.xio.xio

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.system.Os
import android.system.OsConstants
import java.io.File
import java.security.KeyStore
import java.io.FileInputStream
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.NoSuchFileException
import java.nio.file.attribute.BasicFileAttributes
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Slice B issuance journal storage.
 *
 * Isolated journal namespace: its own AndroidKeyStore alias and its own
 * `xio-issuance-` files directly in filesDir. The legacy credential/account
 * vault alias and filenames are not touched, so no legacy-key migration is
 * required and a generic state write cannot overwrite the journal.
 *
 * A missing key with an existing record fails closed: the read path uses
 * `key(create = false)` and never generates an alias.
 */
class IssuanceVault(private val context: Context) {
    private val alias = "xio.issuance.v1"
    private val prefix = "xio-issuance-"
    private val maxCiphertext = 1024 * 1024
    private val maxPlaintext = 512 * 1024

    fun leasePath(): String = File(context.filesDir, "${prefix}lease").absolutePath

    private fun recordFile(id: String): File {
        require(Regex("^state[a-f0-9]{64}$").matches(id)) { "INVALID_ID" }
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(id.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
        return File(context.filesDir, "$prefix$digest.bin")
    }

    private fun key(create: Boolean): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val existing = store.getKey(alias, null) as? SecretKey
        if (existing != null) return existing
        if (!create) throw IllegalStateException("ISSUANCE_KEY_UNAVAILABLE")
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build(),
        )
        return generator.generateKey()
    }

    fun provision() {
        val files = context.filesDir.listFiles()
            ?: throw IllegalStateException("ISSUANCE_NAMESPACE_UNAVAILABLE")
        val hasRecords = files.any {
            it.name.startsWith(prefix) && it.name.endsWith(".bin")
        }
        // Create only for a fresh journal; an existing record with a missing
        // key must fail closed instead of generating a new alias. A null/error
        // listing is not "fresh".
        key(!hasRecords)
    }

    fun seal(id: String, aad: ByteArray, plaintext: ByteArray): ByteArray {
        require(plaintext.size <= maxPlaintext) { "TOO_LARGE" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key(false))
        cipher.updateAAD(aad)
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(plaintext)
        return byteArrayOf(iv.size.toByte()) + iv + ciphertext
    }

    fun open(id: String, aad: ByteArray, sealed: ByteArray): ByteArray {
        require(sealed.size <= maxCiphertext) { "TOO_LARGE" }
        require(sealed.isNotEmpty()) { "CORRUPT" }
        val size = sealed[0].toInt() and 255
        require(size == 12 && sealed.size > size + 16) { "CORRUPT" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            key(false),
            GCMParameterSpec(128, sealed.copyOfRange(1, size + 1)),
        )
        cipher.updateAAD(aad)
        return cipher.doFinal(sealed.copyOfRange(size + 1, sealed.size))
    }

    fun read(id: String): ByteArray? {
        val file = recordFile(id)
        val attributes = try {
            Files.readAttributes(
                file.toPath(),
                BasicFileAttributes::class.java,
                LinkOption.NOFOLLOW_LINKS,
            )
        } catch (_: NoSuchFileException) {
            return null
        }
        if (!attributes.isRegularFile) throw IllegalStateException("CORRUPT")
        if (attributes.size() > maxCiphertext) throw IllegalArgumentException("TOO_LARGE")
        val expected = attributes.size().toInt()
        val bytes = ByteArray(expected)
        FileInputStream(file).use { input ->
            var offset = 0
            while (offset < expected) {
                val read = input.read(bytes, offset, expected - offset)
                if (read < 0) throw IllegalStateException("CORRUPT")
                offset += read
            }
            if (input.read() != -1) throw IllegalArgumentException("TOO_LARGE")
        }
        return bytes
    }

    fun write(id: String, sealed: ByteArray) {
        require(sealed.size <= maxCiphertext) { "TOO_LARGE" }
        val file = recordFile(id)
        val temp = File(file.path + ".tmp")
        temp.outputStream().use { out ->
            out.write(sealed)
            out.flush()
            out.fd.sync()
        }
        check(temp.renameTo(file)) { "RENAME_FAILED" }
        for (directory in listOfNotNull(file.parentFile, context.filesDir.parentFile)
            .distinctBy { it.absolutePath }
            .filter { it.exists() }) {
            val fd = Os.open(directory.absolutePath, OsConstants.O_RDONLY, 0)
            try {
                Os.fsync(fd)
            } finally {
                Os.close(fd)
            }
        }
    }
}
