package app.xio.xio

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class ConfigVault(private val context: Context) {
    private val noBackupFilesDir get() = context.noBackupFilesDir
    fun contains(id: String) = secretFile(id).exists()
    fun delete(id: String) { secretFile(id).delete() }
    private fun secretFile(id: String): File {
        require(Regex("^((wg|awg|rvh|rvs|xr|ss|ov|ik|ck|ts)[0-9]{1,24}|ssh[a-f0-9]{64}|state[a-f0-9]{64})$").matches(id))
        val directory = File(noBackupFilesDir, "vault").apply { mkdirs() }
        return File(directory, "$id.bin")
    }
    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val existing = store.getKey("xio.vault.v1", null) as? SecretKey
        if (existing != null) return existing
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(KeyGenParameterSpec.Builder("xio.vault.v1", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build())
        return generator.generateKey()
    }
    fun writeSecret(id: String, raw: String) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key())
        cipher.updateAAD(id.toByteArray())
        val file = secretFile(id)
        val temp = File(file.path + ".tmp")
        temp.outputStream().use { out -> out.write(cipher.iv.size); out.write(cipher.iv); out.write(cipher.doFinal(raw.toByteArray())) }
        check(temp.renameTo(file))
    }
    fun readSecret(id: String): String {
        val bytes = secretFile(id).readBytes()
        val size = bytes[0].toInt() and 255
        require(size == 12 && bytes.size > size + 17)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, bytes.copyOfRange(1,size+1)))
        cipher.updateAAD(id.toByteArray())
        return cipher.doFinal(bytes.copyOfRange(size+1,bytes.size)).toString(Charsets.UTF_8)
    }
}
