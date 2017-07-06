package com.mytrendin.keychainmanagement;

import android.content.Intent;
import android.os.AsyncTask;
import android.os.Environment;
import android.security.KeyChain;
import android.security.KeyChainAliasCallback;
import android.support.annotation.Nullable;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.view.animation.AnimationUtils;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import com.crashlytics.android.Crashlytics;
import io.fabric.sdk.android.Fabric;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends AppCompatActivity {

    private static final int INSTALL_CERT_CODE = 1001;
    private static final String CERT_FILENAME = "MyKeyStore.pfx";
    private static final String CERTIFICATE_NAME = "MyCertificate";
    private static final String TAG = "SigningActivity";
    private static String signedData="";
    private String mAlias ="";
    private Button verifySignedData;
    private TextView textView;
    private Button install_certificate;
    private LinearLayout mContent;
    private EditText mEdittext;
    private String mEncryptedData="";
    private Button mAction;
    private Boolean encrypted=false;
    private String mDecryptedData;
    private TextView mData_display;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Fabric.with(this, new Crashlytics());
        setContentView(R.layout.activity_main);

        install_certificate = (Button) findViewById(R.id.btn_certificate_install);
        install_certificate.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                doInstallCertificate(v);
            }
        });
        textView = (TextView) findViewById(R.id.title);

        mData_display = (TextView) findViewById(R.id.data_display);
        mData_display.setText("Write something");
        mData_display.setVisibility(View.INVISIBLE);

        mContent = (LinearLayout) findViewById(R.id.content);
        mEdittext = (EditText) findViewById(R.id.edittext_text_data);
        mAction = (Button) findViewById(R.id.btn_action_encrypt);

        mAction.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if(!encrypted){
                    final String textData = mEdittext.getText().toString();
                    if(textData.length()!=0 || textData != null){
                        new Thread(new Runnable() {
                            @Override
                            public void run() {
                                mEncryptedData=createSignedNote(textData,mAlias);
                            }
                        }).start();

                        mData_display.setText("Encrypted Data:\n"+mEncryptedData);
                        encrypted=true;
                        mAction.setText(R.string.btn_action_decrypt);
                    }
                }else{
                    new Thread(new Runnable() {
                        @Override
                        public void run() {
                            mDecryptedData=decryptData(mEncryptedData,mAlias);
                        }
                    }).start();
                    mData_display.setText("Decrypted Data :\n"+mDecryptedData);
                    encrypted=false;
                    mAction.setText(R.string.btn_encrypt_text_data);
                }
            }
        });

        verifySignedData = (Button) findViewById(R.id.btn_certificate_install_verify);
        verifySignedData.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new VerifySignatureTask().execute(signedData,mAlias);
            }
        });
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode,
                                    Intent data) {
        if(requestCode == INSTALL_CERT_CODE) {
            if(resultCode == RESULT_OK) {
                // Certificate successfully installed
                Toast.makeText(this,"Certificate installed\n now signing",Toast.LENGTH_SHORT).show();
                doSignNoteData();

            } else {
                // User cancelled certificate installation
                Toast.makeText(this,"Installation Cancelled",Toast.LENGTH_SHORT).show();
            }
        }
    }

    // click-listener for installing certificate
    public void doInstallCertificate(View view) {
        byte[] certData = readFile(CERT_FILENAME);
        Intent installCert = KeyChain.createInstallIntent();
        installCert.putExtra(KeyChain.EXTRA_NAME, CERTIFICATE_NAME);
        installCert.putExtra(KeyChain.EXTRA_PKCS12, certData);
        startActivityForResult(installCert, INSTALL_CERT_CODE);
    }

    private byte[] readFile(String certFilename) {
        // TODO Read the certificate from somewhere...
        File sdcard = Environment.getExternalStorageDirectory();
        //get certficate
        File certi = new File(sdcard,"certificate/"+certFilename);

        Toast.makeText(this,certi.getPath(),Toast.LENGTH_SHORT).show();
        Log.i("checkOut",certi.getPath());

        int size = (int) certi.length();
        byte[] bytes = new byte[size];

        try{
            BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(certi));
            bufferedInputStream.read(bytes,0,bytes.length);
            bufferedInputStream.close();
            return bytes;
        } catch (FileNotFoundException e) {
            Toast.makeText(this,"File Not Found",Toast.LENGTH_SHORT).show();
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public void doSignNoteData() {
        KeyChain.choosePrivateKeyAlias(this, new KeyChainAliasCallback() {
            @Override
            public void alias(String alias) {
                String textToSign = "Pravin Signature text data to be signed";
                mAlias=alias;
                new MySigningTask().execute(textToSign, alias);
            }
        }, null, null, null, -1, null);
    }

    private class MySigningTask extends AsyncTask<String,Void,String> {
        @Override
        protected String doInBackground(String[] data) {
            return createSignedNote(data[0], data[1]);
        }

        @Override
        protected void onPostExecute(String s) {
            super.onPostExecute(s);
            // here s is a encrypted string you can send over network securely
            signedData=s;
            Log.i("checkOut",signedData);
            verifySignedData.setVisibility(View.VISIBLE);
            verifySignedData.setAnimation(AnimationUtils.makeInAnimation(MainActivity.this,true));
            install_certificate.setVisibility(View.GONE);
            textView.setText(R.string.instruction_4);

        }
    }

    private class VerifySignatureTask extends AsyncTask<String,Void,Boolean>{

        @Override
        protected Boolean doInBackground(String[] data) {
            return verifySignature(data[0],data[1]);
        }

        @Override
        protected void onPostExecute(Boolean verified) {
            super.onPostExecute(verified);
            if(verified){
                textView.setText(R.string.instruction_2);
                Thread delay = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            Thread.sleep(3000);
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }
                    }
                });
                delay.start();
                loadContent();
            }else{
                textView.setText(R.string.instruction_3);
            }
        }
    }

    private void loadContent() {
        verifySignedData.setVisibility(View.GONE);
        install_certificate.setVisibility(View.GONE);
        textView.setVisibility(View.GONE);
        mContent.setVisibility(View.VISIBLE);
        mEdittext.setVisibility(View.VISIBLE);
        mAction.setVisibility(View.VISIBLE);
        mData_display.setVisibility(View.VISIBLE);
    }

    public String createSignedNote(String textToSign, String alias) {
        Log.i(TAG,"data: "+textToSign+"\nAlias: "+alias);
        try {
            byte[] textData = textToSign.getBytes("UTF-8");
            PrivateKey privateKey
                    = KeyChain.getPrivateKey(getApplicationContext(), alias);
            Signature signature
                    = Signature.getInstance("SHA1withRSA");
            signature.initSign(privateKey);
            signature.update(textData);
            byte[] signed = signature.sign();
            String signedData = Base64.encodeToString(textData,
                    Base64.NO_WRAP | Base64.NO_PADDING)
                    + "]" + Base64.encodeToString(signed,
                    Base64.NO_WRAP | Base64.NO_PADDING);
            Log.i(TAG,signedData);
            return signedData;
        } catch (Exception e) {
            Log.e(TAG, "Error signing data.", e);
        }
        return null;
    }


    private boolean verifySignature(String dataAndSignature, String alias) {

        try {
            String[] parts = dataAndSignature.split("]");
            byte[] decodedText = Base64.decode(parts[0], Base64.DEFAULT);
            byte[] signed = Base64.decode(parts[1], Base64.DEFAULT);
            X509Certificate[] chain = KeyChain.getCertificateChain(this, alias);
            PublicKey publicKey = chain[0].getPublicKey();
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initVerify(publicKey);
            signature.update(decodedText);
            return signature.verify(signed);
        } catch (Exception e) {
            Log.e(TAG, "Error verifying signature.", e);
        }
        return false;
    }

    private String decryptData(String dataAndSignature,String alias){
        try{
            String[] parts = dataAndSignature.split("]");
            byte[] decodedText = Base64.decode(parts[0], Base64.DEFAULT);
            byte[] signed = Base64.decode(parts[1], Base64.DEFAULT);
            X509Certificate[] chain = KeyChain.getCertificateChain(this, alias);
            PublicKey publicKey = chain[0].getPublicKey();
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initVerify(publicKey);
            signature.update(decodedText);
            return new String(decodedText,"UTF-8");
        }catch (Exception e){
            Log.e(TAG,"Eror decrypting data",e);
        }
        return null;
    }
}
