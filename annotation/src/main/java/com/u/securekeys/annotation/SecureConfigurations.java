package com.u.securekeys.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation for configuring the plugin
 * Created by saguilera on 3/3/17.
 */
@Target({ElementType.TYPE})
@Retention(RetentionPolicy.SOURCE)
public @interface SecureConfigurations {

    String CLASSPATH = "com.u.securekeys.annotation.SecureConfigurations";

    /**
     * 16 bytes length array for the initial vector. If this is specified and has different size, exception will be thrown
     * and will use default.
     * @return Initial vector used for aes with 16 bytes length
     */
    byte[] aesInitialVector() default { 0x01, 0x02 };

    /**
     * 16 bytes length array for the aes key. If this is specified and has different size, exception will be thrown
     * and will use default.
     *
     * @return aes key used for aes with 16 bytes length
     */
    byte[] aesKey() default { 0x01, 0x02 };

    /**
     * Generate a random aes key and initial vector depending of the build. This will make on every build unique
     * hyperparameters for the aes cipher
     * @return boolean if should use a random aes key/iv or not.
     */
    boolean useAesRandomly() default false;

    /**
     * Makes the JNI module return empty strings if the APK is for debugging
     * @return true if should return empty strings if the APK is in debugging mode
     */
    boolean blockIfDebugging() default false;

    /**
     * Makes the JNI module return empty strings if the APK is in a emulated environment
     * @return true if should return empty strings if the APK is in a emulated environment
     */
    boolean blockIfEmluator() default false;

    /**
     * Allowed places to let the APK be installed from.
     * For example if we use:
     * { "com.android.vending" }
     * Then keys will only return if the APK was installed from the playstore. Else it will return
     * empty strings.
     *
     * @return list of allowed places from where the APK should be installed
     */
    String[] permittedInstalledPlaces() default {};

    /**
     * Signing certificate the APK should match, if it doesnt it will return empty strings
     *
     * For getting it you could do something like this:
     PackageInfo packageInfo = context.getPackageManager()
            .getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNATURES);

     for (Signature signature : packageInfo.signatures) {
        byte[] signatureBytes = signature.toByteArray();
        MessageDigest md = MessageDigest.getInstance("SHA");
        md.update(signature.toByteArray());
        final String currentSignature = Base64.encodeToString(md.digest(), Base64.DEFAULT);
     }
     *
     * @return string with the certificate signature that should match
     */
    String signatureCertificate() default "";

}
