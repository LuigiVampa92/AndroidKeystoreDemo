package com.luigivampa92.testks

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.view.View
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import java.security.*
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.security.spec.InvalidKeySpecException
import java.util.*
import javax.security.auth.x500.X500Principal

class MainActivity : AppCompatActivity() {

    companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val KEY_ALIAS = "TEST_KEY"
        const val KEY_CURVE_TYPE = "secp256r1"
        const val KEY_SIGN_ALGO = "SHA256withECDSA"
    }

    private lateinit var buttonKeyNew: Button
    private lateinit var buttonKeyClear: Button
    private lateinit var containerKeyInfo: View
    private lateinit var textKeyInfo: TextView
    private lateinit var containerSignInfo: View
    private lateinit var textSignInfo: TextView
    private lateinit var buttonTestNew: Button

    private lateinit var keyguardManager: KeyguardManager
    private lateinit var keystore: KeyStore

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        initSecurityObjects()
        initUi()

        buttonKeyNew.setOnClickListener {
            createKeyPair()
            updateKeyInfoUi()
        }
        buttonKeyClear.setOnClickListener {
            cleanKeystore()
            updateKeyInfoUi()
        }
        buttonTestNew.setOnClickListener {
            updateSignatureInfoUi()
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
        buttonTestNew = findViewById(R.id.button_test_new)
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
            sb.appendLine("isInsideStrongBox(): ${isStrongBoxAvailable()}")
            sb.appendLine("\nPublic key:")
            sb.appendLine("format: ${publicKey.format}")
            sb.appendLine("\nHEX:\n\n${publicKey.encoded.toHexString()}")
            sb.appendLine("\nCERTIFICATE:\n\n ${certificate.toString()}")
            textKeyInfo.text = sb.toString()

            containerKeyInfo.setVisible(true)
        } else {
            containerKeyInfo.setVisible(false)
        }

        updateSignatureInfoUi()
    }

    private fun updateSignatureInfoUi() {
        if (keystore.aliases().toList().contains(KEY_ALIAS)) {

            val valueString = "TEST_VALUE_TO_SIGN"
            val valueHex = valueString.toByteArray()

            val signPrivateKey = keystore.getKey(KEY_ALIAS, null) as PrivateKey
            val signSignature = Signature.getInstance(KEY_SIGN_ALGO) as Signature
            signSignature.initSign(signPrivateKey)
            signSignature.update(valueHex)
            val resultSignature: ByteArray = signSignature.sign()

            val verifyPublicKey = keystore.getCertificate(KEY_ALIAS).publicKey as PublicKey
            val verifySignature = Signature.getInstance(KEY_SIGN_ALGO) as Signature
            verifySignature.initVerify(verifyPublicKey)
            verifySignature.update(valueHex)
            val resultVerification: Boolean = verifySignature.verify(resultSignature)

            val sb = StringBuilder()
            sb.appendLine("value (str): $valueString")
            sb.appendLine("value (hex): ${valueHex.toHexString()}")
            sb.appendLine("signature: ${resultSignature.toHexString()}")
            sb.appendLine("verify: ${if (resultVerification) "OK" else "ERROR"}")
            textSignInfo.text = sb.toString()

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

            val keyGenParameterSpecBuilder: KeyGenParameterSpec.Builder =
                KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
                )
            keyGenParameterSpecBuilder.setDigests(KeyProperties.DIGEST_SHA256)
            keyGenParameterSpecBuilder.setAlgorithmParameterSpec(ECGenParameterSpec(KEY_CURVE_TYPE))
            val x500data = X500Principal("CN=CheckAndroidKeystoreTest")
            keyGenParameterSpecBuilder.setCertificateSubject(x500data)
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                if (isStrongBoxAvailable()) {
                    keyGenParameterSpecBuilder.setIsStrongBoxBacked(true)
                }
                keyGenParameterSpecBuilder.setUnlockedDeviceRequired(true)
            }
            val keyGenParameterSpec = keyGenParameterSpecBuilder.build()
            val keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
            keyPairGenerator.initialize(keyGenParameterSpec)
            keyPairGenerator.generateKeyPair()
        } catch (e: Exception) {
            navigateToError()
        }
    }

    private fun isStrongBoxAvailable() =
        android.os.Build.VERSION.SDK_INT > android.os.Build.VERSION_CODES.P
                && packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    private fun getKeyPeriod(): Pair<Date,Date> {
        val cal = Calendar.getInstance()
        cal.add(Calendar.YEAR, 10)
        val dateIssue = Date()
        val dateExpire = cal.time
        return dateIssue to dateExpire
    }

    private fun initSecurityObjects() {
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

    private fun showViews(vararg views: View) {
        views.forEach {
            it.setVisible(true)
        }
    }

    private fun hideViews(vararg views: View) {
        views.forEach {
            it.setVisible(false)
        }
    }
}

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