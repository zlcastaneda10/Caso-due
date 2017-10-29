import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.*;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;



public class Cliente {

	/**
	 * Protocolo de comunicaciones 
	 */
	
	//Datos de conexion
	private final static String DIRSERV = "localhost";
	private final static int PUERTO = 8080;
	//Cadenas de control
	private final static String HOLA = "HOLA";
	private final static String ALGORITMOS = "ALGORITMOS";
	private final static String OK = "OK";
	private final static String CERTIFICADO = "CERTCLNT";
	//Algoritmos
	//Algoritmo simetrico a usar.
	private String ALGS = "AES";
	//Algoritmo asimetrico a usar.
	private String ALGA = "RSA";
	//Algoritmo HASH a usar.
	private String ALGD = "HMACSHA256";
	
	//Separador general de los mensajes.
	private String SP = ":";
	
	//añadir llaves certificados etc
	private KeyPair keyPair;
	
	//Certificado propio.
	private X509Certificate cert;

	//Certificado del servidor.
	private X509Certificate certsrv;
	//Llave de sesion simetrica.
	private SecretKey sessionKey;
	
	//Socket para la comunicacion.
	//*
	private Socket comunicacion;
	//Writer para escritura sobre el socket.
	//OUT
	private PrintWriter writer;
	//Reader para lectura sobre el socket.
	//IN
	private BufferedReader reader;
	
	private int fallo;
	
	private long retoLong;
	

	public static void main(String args[]){
		new Cliente();
	}
	
	public Cliente() {
		inicializar();
		inicioSesion();
		enviarCertificado();
		
		try {
			recibirCertificado();
			//generarReto();
			//verificarReto(reader.readLine());
			//byte[] arr = leerllave();
			//sessionKey = descifrar(arr);
		
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	

	/**
	 * Inicialización de variables, llaves y librerías.
	 * Inicia el socket de comunicación.
	 * Genera las llaves simétricas propias.
	 * Añade el proveedor de seguridad de la librería BouncyCastle.
	 */
	private void inicializar(){
		try{
			Security.addProvider(new BouncyCastleProvider());
			//Inicializacion de las llaves.
			KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGA);
			generator.initialize(1024);
			keyPair = generator.generateKeyPair();
			//Inicializacion de los sockets
			comunicacion = new Socket(DIRSERV, PUERTO);
			writer = new PrintWriter(comunicacion.getOutputStream(), true);
			reader = new BufferedReader(new InputStreamReader(comunicacion.getInputStream()));
		}catch(Exception e){
			System.out.println("Error en la inicializacion del cliente: " + e.getMessage());
			fallo=1;
		}
	}

	private void inicioSesion() {
		try {
			//HOLA
			writer.println(HOLA);
			String s1 = reader.readLine();
			if(!s1.equals(OK)) {fallo =1;}
			writer.println( ALGORITMOS + SP + ALGS + SP + ALGA + SP + ALGD);
			if(reader.ready()) System.out.println(reader.readLine());
			String s2 = reader.readLine();
			if (s2.equals(OK)) {
				fallo=0;
			}else if (s2.equals("ERROR")) {
				fallo=1;
			}
		}catch(Exception e){
			System.out.println("Error en el envio de algoritmos a usar: "+ e.getMessage());
			fallo=1;		
		}
	}
	
	private void enviarCertificado(){
		//CERCLNT
		String s = CERTIFICADO+SP;
		try{
			/*GENERADO DEL CERTIFICADO*/
			//cert  = certGen.generate(keypair.getPrivate(), "BC");
			cert = Certificado.generateV3Certificate(keyPair);
			byte[] certb = cert.getEncoded();
			PemWriter pWrt = new PemWriter(writer);
			PemObject pemObj = new PemObject("CERTIFICATE",Collections.EMPTY_LIST, certb).generate();
			//System.out.println(pemObj.getContent());
			//pWrt.writeObject(pemObj);
			
			StringWriter sw = new StringWriter();
		    try (PemWriter pw = new PemWriter(sw)) {
		        pw.writeObject(pemObj);
		    }
		    String strCert = sw.toString();
		    //System.out.println(strCert);
		    writer.println(s+strCert);
			pWrt.flush();
			
			/*ENVIO DE INFORMACION*/
			//comunicacion.getOutputStream().write(certb);
			//comunicacion.getOutputStream().flush();
		}catch(Exception e){
			System.out.println("Error en la creacion y envio del certificado: " + e.getMessage());
			fallo=1;
		}
	}
	
	/**
	 * Recibe el certificado de identificacion del servidor.
	 * @throws IOException 
	 */
	private void recibirCertificado() throws IOException{
		try{
			
			//String r = reader.readLine();
			//r = reader.readLine();
			
			//System.out.println(r);
			// BufferedInputStream bis = new BufferedInputStream(comunicacion.getInputStream());

			 CertificateFactory cf = CertificateFactory.getInstance("X509");
				certsrv = (X509Certificate) cf.generateCertificate(comunicacion.getInputStream());

			 
			    System.out.println(certsrv.toString());
			
			
		}catch(CertificateException e){
			System.out.println("Error recibiendo el certificado del servidor: "+e.getMessage());
			fallo=1;
		}
	}
	
	private void generarReto(){
		
		Random reto = new Random(System.currentTimeMillis());
		retoLong= reto.nextLong();
		System.out.println(reto);
		System.out.println(retoLong);
		//writer.println(""+number);
		writer.println("6432778618221102025");
		
	}
	
	private void verificarReto(String reto) {
		
		if(retoLong == Long.parseLong(reto)) {
			writer.println(OK);
		}
	}
	
	public byte[] leerllave() throws IOException
	{
		String linea = reader.readLine();
		linea = reader.readLine();
		byte[] llaveSimServidor = decodificarHex(linea);
		return llaveSimServidor;
	}
	
	
	public byte[] decodificarHex(String ss)
	{
		byte[] ret = new byte[ss.length()/2];
		for (int i = 0 ; i < ret.length ; i++) {
			ret[i] = (byte) Integer.parseInt(ss.substring(i*2,(i+1)*2), 16);
		}
		return ret;
	}
	
public SecretKey descifrar(byte [] cipheredText) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		
		
		Cipher decifrador = Cipher.getInstance(ALGA);
		decifrador.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
		byte[] llaveDecifrada = decifrador.doFinal(cipheredText);
		
		SecretKeySpec llaveRecibida = new SecretKeySpec(llaveDecifrada, ALGS);
		return llaveRecibida;
		
	}
	
}
