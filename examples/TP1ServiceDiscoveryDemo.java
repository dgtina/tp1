/* (c)2020 star-trac supply chain solutions GmbH (www.star-trac.de) */
package com.startrac.tp1.demo;

import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.StringTokenizer;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.InitialDirContext;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

public class TP1ServiceDiscoveryDemo {
    private String dnsServiceName = "_tp1._staging.dgtina.org";
    private KeyStore trustStore;
    private SSLSocketFactory sslFactory;
    
    public static void main(String[] args) throws Exception {
        new TP1ServiceDiscoveryDemo().updateValidTrustedPartners();
    }
    
    public TP1ServiceDiscoveryDemo() throws Exception {
        setupSslFactory();
    }
    
    /**
     * @return a list of trusted TP1 host names whose certificates could successfully be stored in our trust store
     * @throws NamingException
     */
    private List<String> updateValidTrustedPartners() throws NamingException {
        String dnsLookup = "dns:"+dnsServiceName;
        ArrayList<String> validHosts = new ArrayList<>();

        Attribute attr = new InitialDirContext().getAttributes(dnsLookup, new String[] {"SRV"}).get("SRV");
        ArrayList<?> tp1entries = Collections.list(attr.getAll());
        
        System.out.println(String.format("DNS query for '%1s' returned %2s",dnsLookup,tp1entries));
        
        for (Object object : tp1entries) {
            try {
                StringTokenizer tk=new StringTokenizer(object.toString()," ");
                tk.nextToken();//skip priority
                tk.nextToken();//skip weight
                Integer port=Integer.parseInt(tk.nextToken());
                String host=tk.nextToken();
                
                addTrustedPartnerCertificate(host, port);
                validHosts.add(host);
                
                System.out.println(String.format("Added %1s on port %2d as new TP1 partner",host,port));
            } catch (Exception e) {
                System.out.println(String.format("Failed to process DNS service entry '%1s' (%2s)",object,e.getMessage()));
                e.printStackTrace();
            }
        }
        
        return validHosts;
    }
    
    private void addTrustedPartnerCertificate(String host, Integer port) throws Exception {
        try (SSLSocket socket = (SSLSocket)sslFactory.createSocket(host, port)){
            socket.startHandshake();
            Certificate[] certs = socket.getSession().getPeerCertificates();
            if (certs != null && certs.length>0) {
                // store remote certificate in our trust store to verify them later
                trustStore.setCertificateEntry(host, certs[0]);
                System.out.println("Saved cert with SN "+((X509Certificate)certs[0]).getSerialNumber());
            }
        } catch (Exception e) {
            throw new Exception("Could not get certificate from TP1 "+host+":"+port,e);
        }
    }
    
    private void setupSslFactory() throws Exception {
        // load my combined keystore / truststore, must contain a private key signed by an official authority or letsencrypt 
        trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(ClassLoader.getSystemResourceAsStream("tp1-example.jks"), "changeit".toCharArray());

        // setup key manager, this sets up my client certificate
        KeyManagerFactory kmfactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmfactory.init(trustStore, "changeit".toCharArray());
        KeyManager[] keymanagers =  kmfactory.getKeyManagers();
        
        // setup trust manager, this sets up any server certificates / ca's we want to trust 
        // should contain letsencrypt ca for testing purposes unless using a very recent Java version which contains it already
        TrustManagerFactory tmf=TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        
        SSLContext sslContext=SSLContext.getInstance("TLSv1.2");
        
        sslContext.init(keymanagers, tmf.getTrustManagers(), new SecureRandom());
        sslFactory = sslContext.getSocketFactory();
    }
    
}
