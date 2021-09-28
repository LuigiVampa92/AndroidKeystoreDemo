package com.luigivampa92.testks

import android.app.KeyguardManager
import android.content.Context
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.AppCompatEditText
import com.google.android.material.switchmaterial.SwitchMaterial
import java.security.*
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.security.spec.InvalidKeySpecException
import javax.security.auth.x500.X500Principal

class MainActivity : AppCompatActivity() {

    companion object {
        const val LOG_TAG = "STRONGBOX"
        const val PREF_FILE = "testks"
        const val PREF_KEY_STORNGBOX = "use_strongbox"
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val KEY_ALIAS = "TEST_KEY"
        const val KEY_CURVE_TYPE = "secp256r1"
        const val KEY_SIGN_ALGO = "SHA256withECDSA"
        const val KEY_HASH_ALGO = KeyProperties.DIGEST_SHA256
    }

    private lateinit var buttonKeyNew: Button
    private lateinit var buttonKeyClear: Button
    private lateinit var switchStrongbox: SwitchMaterial
    private lateinit var containerKeyInfo: View
    private lateinit var textKeyInfo: TextView
    private lateinit var containerSignInfo: View
    private lateinit var textSignInfo: TextView
    private lateinit var editTextSign: AppCompatEditText
    private lateinit var buttonSign: Button

    private lateinit var sharedPreferences: SharedPreferences
    private lateinit var keyguardManager: KeyguardManager
    private lateinit var keystore: KeyStore

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        initObjects()
        initUi()

        buttonKeyNew.setOnClickListener {
            createKeyPair()
            updateKeyInfoUi()
        }
        buttonKeyClear.setOnClickListener {
            cleanKeystore()
            updateKeyInfoUi()
        }
        buttonSign.setOnClickListener {
            updateSignatureInfoUi(editTextSign.text.toString())
        }

        updateKeyInfoUi()
    }

    private fun initUi() {
        buttonKeyNew = findViewById(R.id.button_key_create_new)
        buttonKeyClear = findViewById(R.id.button_key_clear)
        containerKeyInfo = findViewById(R.id.container_key_info)
        textKeyInfo = findViewById(R.id.text_key_ifno)
        containerSignInfo = findViewById(R.id.container_sign_info)
        textSignInfo = findViewById(R.id.text_sign_ifno)
        editTextSign = findViewById(R.id.input_sign)
        buttonSign = findViewById(R.id.button_sign)
        switchStrongbox = findViewById(R.id.switch_strongbox)
        switchStrongbox.setVisible(isStrongBoxAvailable())
        switchStrongbox.isChecked = getPrefIsGeneratedInStrongbox()
    }

    private fun updateKeyInfoUi() {
        if (keystore.aliases().toList().contains(KEY_ALIAS)) {
            val privateKey = keystore.getKey(KEY_ALIAS, null) as PrivateKey
            val certificate = keystore.getCertificate(KEY_ALIAS) as X509Certificate
            val publicKey = certificate.publicKey as PublicKey
            val insideSecureHardware = isPrivateKeyInsideSecureHardware(privateKey)

            val sb = StringBuilder()
            sb.appendLine("alias: $KEY_ALIAS")
            sb.appendLine("key type: ${privateKey.algorithm}")
            sb.appendLine("curve type: $KEY_CURVE_TYPE")
            sb.appendLine("\nPrivate key:")
            sb.appendLine("isInsideSecureHardware(): $insideSecureHardware")
            sb.appendLine("isInsideStrongBox(): ${isStrongBoxAvailable() && getPrefIsGeneratedInStrongbox()}")
            sb.appendLine("\nPublic key:")
            sb.appendLine("format: ${publicKey.format}")
            sb.appendLine("\nHEX:\n\n${cleanPublicKeyValue(publicKey).toHexString()}")
            sb.appendLine("\nCERTIFICATE:\n\n $certificate")
            textKeyInfo.text = sb.toString()

            containerKeyInfo.setVisible(true)
        } else {
            containerKeyInfo.setVisible(false)
        }

        updateSignatureInfoUi(editTextSign.text.toString())
    }

    private fun updateSignatureInfoUi(messageToSign: String) {
        if (keystore.aliases().toList().contains(KEY_ALIAS)) {
            var timeStart = 0L
            var timeStop = 0L
            log("----------")

            val valueString = messageToSign
            val valueHex = valueString.toByteArray()

            val signPrivateKey = keystore.getKey(KEY_ALIAS, null) as PrivateKey
            val signSignature = Signature.getInstance(KEY_SIGN_ALGO) as Signature
            timeStart = System.currentTimeMillis()
            signSignature.initSign(signPrivateKey)
            signSignature.update(valueHex)
            val resultSignature: ByteArray = signSignature.sign()
            timeStop = System.currentTimeMillis()
            log("message signing took ${timeStop - timeStart} ms")

            val verifyPublicKey = keystore.getCertificate(KEY_ALIAS).publicKey as PublicKey
            val verifySignature = Signature.getInstance(KEY_SIGN_ALGO) as Signature
            timeStart = System.currentTimeMillis()
            verifySignature.initVerify(verifyPublicKey)
            verifySignature.update(valueHex)
            val resultVerification: Boolean = verifySignature.verify(resultSignature)
            timeStop = System.currentTimeMillis()
            log("message verification took ${timeStop - timeStart} ms")

            val signature = cleanSignature(resultSignature)
            val publicKey = cleanPublicKeyValue(verifyPublicKey)

            val sb = StringBuilder()
            sb.appendLine("value (str): $valueString")
            sb.appendLine("value (hex): ${valueHex.toHexString()}")
            sb.appendLine("signature: ${signature.cleanSignature.toHexString()}")
            sb.appendLine("verify: ${if (resultVerification) "OK" else "ERROR"}")
            textSignInfo.text = sb.toString()


            log("----------")
            log("key alias: $KEY_ALIAS")
            log("curve type: $KEY_CURVE_TYPE")
            log("sign algo: $KEY_SIGN_ALGO")
            log("input value (str): $valueString")
            log("input value (hex): ${valueHex.toHexStringLowercase()}")
//            log("full asn1 signature: (${resultSignature.size} bytes) : ${resultSignature.toHexStringLowercase()}")
            log("signature r: (${signature.r.size} bytes) : ${signature.r.toHexStringLowercase()}")
            log("signature s: (${signature.s.size} bytes) : ${signature.s.toHexStringLowercase()}")
            log("signature full: (${signature.cleanSignature.size} bytes) : ${signature.cleanSignature.toHexStringLowercase()}")
//            log("full asn1 public key: (${verifyPublicKey.encoded.size} bytes) :${verifyPublicKey.encoded.toHexStringLowercase()}")
            log("public key: (${publicKey.size} bytes) :${publicKey.toHexStringLowercase()}")
            log("verify result: ${if (resultVerification) "OK" else "ERROR"}")

            containerSignInfo.setVisible(true)
        } else {
            containerSignInfo.setVisible(false)
        }
    }

    private fun cleanKeystore() {
        keystore.aliases().toList().forEach {
            keystore.deleteEntry(it)
        }
    }

    private fun createKeyPair() {
        try {
            cleanKeystore()

            val timeStart = System.currentTimeMillis()

            val keyGenParameterSpecBuilder: KeyGenParameterSpec.Builder =
                KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
                )
            keyGenParameterSpecBuilder.setDigests(KEY_HASH_ALGO)
            keyGenParameterSpecBuilder.setAlgorithmParameterSpec(ECGenParameterSpec(KEY_CURVE_TYPE))
            val x500data = X500Principal("CN=CheckAndroidKeystoreTest")
            keyGenParameterSpecBuilder.setCertificateSubject(x500data)
            if (isStrongBoxAvailable() && switchStrongbox.isChecked) {
                keyGenParameterSpecBuilder.setIsStrongBoxBacked(true)
                setPrefIsGeneratedInStrongbox(true)
            } else {
                setPrefIsGeneratedInStrongbox(false)
            }
            val keyGenParameterSpec = keyGenParameterSpecBuilder.build()
            val keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
            keyPairGenerator.initialize(keyGenParameterSpec)
            keyPairGenerator.generateKeyPair()

            val timeStop = System.currentTimeMillis()
            log("----------")
            log("keypair generation took ${timeStop - timeStart} ms")
            log("----------")

        } catch (e: Exception) {
            navigateToError()
        }
    }

    private fun isStrongBoxAvailable() =
        android.os.Build.VERSION.SDK_INT > android.os.Build.VERSION_CODES.P
                && packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    private fun initObjects() {
        sharedPreferences = getSharedPreferences(PREF_FILE, Context.MODE_PRIVATE)
        try {
            keyguardManager = getSystemService(KeyguardManager::class.java) as KeyguardManager
            keystore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keystore.load(null)
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
            Signature.getInstance(KEY_SIGN_ALGO)
        }
        catch (e: KeyStoreException) {
            navigateToError()
        }
        catch (e: NoSuchAlgorithmException) {
            navigateToError()
        }
        catch (e: NoSuchProviderException) {
            navigateToError()
        }
    }

    private fun navigateToError() {
        toast("ERROR")
    }

    private fun isPrivateKeyInsideSecureHardware(key: PrivateKey): Boolean {
        val factory = KeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
        try {
            val keyInfo = factory.getKeySpec(key, KeyInfo::class.java)
            return keyInfo.isInsideSecureHardware
        } catch (e: InvalidKeySpecException) {
            return false
        }
    }

    private fun log(value: String?) {
        value?.let {
            Log.d(LOG_TAG, value)
        }
    }

    private fun concatByteArrays(first: ByteArray, second: ByteArray): ByteArray {
        val fs = first.size
        val ss = second.size
        val result = ByteArray(fs + ss)
        System.arraycopy(first, 0, result, 0, fs)
        System.arraycopy(second, 0, result, fs, ss)
        return result
    }

    private fun getPrefIsGeneratedInStrongbox(): Boolean {
        return sharedPreferences.getBoolean(PREF_KEY_STORNGBOX, false)
    }

    private fun setPrefIsGeneratedInStrongbox(generatedInStrongbox: Boolean) {
        sharedPreferences.edit().putBoolean(PREF_KEY_STORNGBOX, generatedInStrongbox).commit()
    }

    private fun cleanPublicKeyValue(publicKeyObj: PublicKey): ByteArray {
        return publicKeyObj.encoded.copyOfRange(27, publicKeyObj.encoded.size)
    }

    private fun cleanSignature(signature: ByteArray): SignatureResult {
        val cleanSignatureNumbers = ByteArray(signature.size - 2)
        System.arraycopy(signature, 2, cleanSignatureNumbers, 0, signature.size - 2)
        val rBinSize = cleanSignatureNumbers[1].toPositiveInt()
        val sBinSize = cleanSignatureNumbers[2 + rBinSize + 1].toPositiveInt()
        val rBin = ByteArray(rBinSize)
        val sBin = ByteArray(sBinSize)
        System.arraycopy(cleanSignatureNumbers, 2, rBin, 0, rBinSize)
        System.arraycopy(cleanSignatureNumbers, 2 + rBinSize + 2, sBin, 0, sBinSize)
        val rBinClean = ByteArray(32)
        System.arraycopy(rBin, if (rBinSize == 33 && rBin[0] == 0x00.toByte()) 1 else 0, rBinClean, 0, 32)
        val sBinClean = ByteArray(32)
        System.arraycopy(sBin, if (sBinSize == 33 && sBin[0] == 0x00.toByte()) 1 else 0, sBinClean, 0, 32)
        val cleanSignature = concatByteArrays(rBinClean, sBinClean)
        return SignatureResult(rBinClean, sBinClean, cleanSignature)
    }
}

private data class SignatureResult(
    val r: ByteArray,
    val s: ByteArray,
    val cleanSignature: ByteArray
)

fun Context.toast(message: String?) {
    message?.let {
        Toast.makeText(this, it, Toast.LENGTH_LONG).show()
    }
}

fun View.setVisible(visible: Boolean) {
    this.visibility = if (visible) View.VISIBLE else View.GONE
}

fun ByteArray.toHexString(): String {
    val builder = StringBuilder()
    for (i in this.indices) {
        builder.append(String.format("%02X ", this[i]))
    }
    return builder.toString()
}

fun ByteArray.toHexStringLowercase(): String {
    return this.toHexString().lowercase().replace(" ", "")
}

fun Byte.toPositiveInt() = toInt() and 0xFF
