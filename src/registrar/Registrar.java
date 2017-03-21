package registrar;

import java.math.BigInteger;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;

import tokens.IToken;
import tokens.ITokenRequest;

public class Registrar implements IRegistrar{
	private final AsymmetricCipherKeyPair keys;

	public Registrar(BigInteger publicModulus, BigInteger publicExponent, BigInteger privateModulus, BigInteger privateExponent) {
		RSAKeyParameters publicKey = new RSAKeyParameters(false, publicModulus, publicExponent);
		RSAKeyParameters privateKey = new RSAKeyParameters(true, privateModulus, privateExponent);
		this.keys = new AsymmetricCipherKeyPair(publicKey, privateKey);	
	}

	public RSAKeyParameters getPublic() {
		return (RSAKeyParameters) keys.getPublic();
	}
	
	public RSAKeyParameters getPrivate() {
		return (RSAKeyParameters) keys.getPrivate();
	}

	public byte[] sign(ITokenRequest tokenRequest) {
		// Sign the coin request using our private key.
		byte[] message = tokenRequest.getMessage();

		RSAEngine engine = new RSAEngine();
		engine.init(true, keys.getPrivate());

		return engine.processBlock(message, 0, message.length);
	}

	public boolean verify(IToken coin) {
		// Verify that the coin has a valid signature using our public key.
		byte[] id = coin.getID();
		byte[] signature = coin.getSignature();

		PSSSigner signer = new PSSSigner(new RSAEngine(), new SHA256Digest(), 20);
		signer.init(false, keys.getPublic());

		signer.update(id, 0, id.length);

		return signer.verifySignature(signature);
	}

}
