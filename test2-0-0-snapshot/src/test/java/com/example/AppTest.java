package com.example;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import br.gov.frameworkdemoiselle.certificate.keystore.loader.factory.KeyStoreLoaderFactory;
import br.gov.frameworkdemoiselle.certificate.keystore.loader.implementation.FileSystemKeyStoreLoader;
import br.gov.frameworkdemoiselle.certificate.signer.SignerAlgorithmEnum;
import br.gov.frameworkdemoiselle.certificate.signer.factory.PKCS7Factory;
import br.gov.frameworkdemoiselle.certificate.signer.pkcs7.PKCS7Signer;
import br.gov.frameworkdemoiselle.policy.engine.factory.PolicyFactory.Policies;


/**
 * Unit test for simple App.
 */
public class AppTest 
    extends TestCase
{
    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public AppTest( String testName )
    {
        super( testName );
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite()
    {
        return new TestSuite( AppTest.class );
    }

    /**
     * Rigourous Test :-)
     * @throws NoSuchAlgorithmException 
     * @throws KeyStoreException 
     * @throws UnrecoverableKeyException 
     * @throws IOException 
     */
    public void testApp() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, IOException
    {
		FileSystemKeyStoreLoader loader = (FileSystemKeyStoreLoader) KeyStoreLoaderFactory
				.factoryKeyStoreLoader(new File(
						"cert.p12"));
		KeyStore keystore = loader.getKeyStore("senha");
		
		String alias = "alias";

		PrivateKey pk = (PrivateKey) keystore.getKey(alias, "senha".toCharArray());
		Certificate[] chain = keystore.getCertificateChain(alias);
		
		
		byte[] content = "hello world".getBytes();
		


		PKCS7Signer signer = PKCS7Factory.getInstance().factoryDefault();
		signer.setCertificates(chain);
		signer.setPrivateKey(pk);
		signer.setAttached(true);
		signer.setAlgorithm(SignerAlgorithmEnum.SHA256withRSA);
		

		
		byte[] signed = signer.doSign(content);
		
		signer.check(content, signed);
		
		BufferedOutputStream bos = null;
		FileOutputStream fos = new FileOutputStream(new File("/tmp/result.p7s"));
		bos = new BufferedOutputStream(fos);
		bos.write(signed);
		bos.close();
    }
}
