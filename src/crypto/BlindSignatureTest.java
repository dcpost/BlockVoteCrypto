package crypto;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.util.encoders.Base64;

import registrar.IRegistrar;
import registrar.Registrar;
import tokens.BlindedToken;
import tokens.Token;
import tokens.TokenRequest;

public class BlindSignatureTest {

	public static void main(String[] args) throws CryptoException {
		String publicKeyModulusS = "ALUNsOBF0ziC5rRU3V5ozQtdPeRMZWIFMU6hOC8IWLED2YycfjzNlLNRniv/IhCWYNgaRUDqBPsVwSXQSiOBU2/j4F8eBpsxFHo3YEpiaUGOm920xk8gyJk4aC3QZ+lscTDGuyUWZzT9fy9eGAWp09YZvjv6Z5dMJ/157Eh4UbKorAHG34c5pLH4cPbloRd9ZTZ9CujdYlKpKXwUNjwKj6aqUQkSuCsXwpYC4X60A6O2OsIF9bZXtog/zSJzkzTHtaTaqUCMhfYLNuGfvWdtLzp/Q0TonxlF3PP8Isxn/xafXULBB6UETKkAKYBYKkkOCvvGR9kljGYXGs6CF1xfK9M=";

		String publicKeyExponentS = "AQAB";

		String privateKeyExponentS = "G2jGsbUwbFo41e0RFEVWYVWM1J6SLJwvokE68bfYQXgdO7HHVKokzF7bTLrTq+IwKBcWC+VBusdI1dIqHyTpfkNnyM6RXnY4LOZsP+aVG7UcuJww93K1m6iT8Pefe5GMsz8qvssc9cM4uXGLvnO+26dLCuZ2P0vqs+98y13XtG2eEpmT+RM9IqpidefKcCnCLY8Zrn08LCqmX8OnEmottsgNDpCkgcGfbxZNp/b0U7IvxQbG07X/3suUgiyAgf3gGabxISg1eSwu1WSA5Bz1XTKXy+mA2utqTINPcSdoAfaVK36JIbqqK6Z+uskh8s2oOn5HTBEg2QiEcNhGUFtGVQ==";

        String privateKeyModulusS=publicKeyModulusS;
        BigInteger publicKeyModulus = new BigInteger(Base64.decode(publicKeyModulusS));
        BigInteger publicKeyExponent = new BigInteger(Base64.decode(publicKeyExponentS));
        BigInteger privateKeyModulus = new BigInteger(Base64.decode(privateKeyModulusS));
        BigInteger privateKeyExponent = new BigInteger(Base64.decode(privateKeyExponentS));

		RSAKeyParameters publicKey=new RSAKeyParameters(false, publicKeyModulus, publicKeyExponent);
		RSAKeyParameters privateKey=new RSAKeyParameters(true, privateKeyModulus, privateKeyExponent);
		
		IRegistrar registrar=new Registrar(publicKey.getModulus(), publicKey.getExponent(), privateKey.getModulus(), privateKey.getExponent());
		
		System.out.println("PUBLIC KEY EXPONENT:");
		System.out.println("");
		System.out.println(Base64.toBase64String(registrar.getPublic().getExponent().toByteArray()));
		System.out.println("");
		System.out.println("PUBLIC KEY MODULUS:");
		System.out.println("");
		System.out.println(Base64.toBase64String(registrar.getPublic().getModulus().toByteArray()));
		System.out.println("");
		
		System.out.println("PRIVATE KEY EXPONENT:");
		System.out.println("");
		System.out.println(Base64.toBase64String(registrar.getPrivate().getExponent().toByteArray()));
		System.out.println("");
		System.out.println("PRIVATE KEY MODULUS:");
		System.out.println("");
		System.out.println(Base64.toBase64String(registrar.getPrivate().getModulus().toByteArray()));
		System.out.println("");
		
		// Create a "blinded token" using the bank's public key. The blinded token
		// contains an internal blinding factor that is used to blind the
		// message to be signed by the registrar.
		BlindedToken blindedToken = new BlindedToken(registrar.getPublic());

		// Generate a token request.
		TokenRequest tokenRequest = blindedToken.generateTokenRequest();

		printTokenRequest(tokenRequest);

		// Ask the registrar to sign the token request.

		byte[] signature = registrar.sign(tokenRequest);

		printRegistrarSignature(signature);

		// Create a new token using the registrar's signature.
		Token token = blindedToken.unblindToken(signature);

		printToken(token);

		// The signature on the token is different from the one the bank
		// returned earlier (magic!). Will the registrar accept the token as valid?
		// Let's see ...
		boolean valid = registrar.verify(token);

		assert valid : "Impossible! Registrar rejects its own token!";

		if (valid) {
			// It should always print "OK"
			System.out.println("OK");
		} else {
			System.out.println("Fail!");
		}
	}

	private static void printTokenRequest(TokenRequest tokenRequest) {
		System.out.println("MESSAGE TO BE SIGNED BY THE REGISTRAR:");
		System.out.println("");
		System.out.println(Base64.toBase64String(tokenRequest.getMessage()));
		System.out.println("");
	}

	private static void printRegistrarSignature(byte[] signature) {
		System.out.println("THE REGISTRAR'S SIGNATURE:");
		System.out.println("");
		System.out.println(Base64.toBase64String(signature));
		System.out.println("");
	}

	private static void printToken(Token token) {
		System.out.println("TOKEN:");
		System.out.println("");
		System.out.println(Base64.toBase64String(token.getID()));
		System.out.println("");
		System.out.println(Base64.toBase64String(token.getSignature()));
		System.out.println("");
	}
}
