package crypto;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.util.encoders.Base64;

import registrar.IRegistrar;
import registrar.Registrar;

public class Generator {
	// Generate a 2048-bit RSA key pair.
	public static void main(String[] args){
			RSAKeyPairGenerator generator = new RSAKeyPairGenerator();
			generator.init(new RSAKeyGenerationParameters(
						new BigInteger("10001", 16), new SecureRandom(), 2048,
						80));
			
			AsymmetricCipherKeyPair keys = generator.generateKeyPair();
			RSAKeyParameters publicKey=(RSAKeyParameters) keys.getPublic();
			RSAKeyParameters privateKey=(RSAKeyParameters) keys.getPrivate();
			
			IRegistrar registrar=new Registrar(publicKey.getModulus(), publicKey.getExponent(), privateKey.getModulus(), privateKey.getExponent());
			
			String PublicKeyExponent = Base64.toBase64String(registrar.getPublic().getExponent().toByteArray());

			String PrivateKeyExponent = Base64.toBase64String(registrar.getPrivate().getExponent().toByteArray());

			String Modulus = Base64.toBase64String(registrar.getPrivate().getModulus().toByteArray());
			
			System.out.println(PublicKeyExponent);
			System.out.println(PrivateKeyExponent);
			System.out.println(Modulus);
	}
}
