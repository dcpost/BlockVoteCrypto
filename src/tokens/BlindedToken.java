package tokens;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.RSABlindingEngine;
import org.bouncycastle.crypto.generators.RSABlindingFactorGenerator;
import org.bouncycastle.crypto.params.RSABlindingParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;

public class BlindedToken {
	private final byte[] tokenID;
	private final RSABlindingParameters blindingParams;

	public BlindedToken(RSAKeyParameters pub) {
		// Create a 128-bit globally unique ID for the coin.
		tokenID = getRandomBytes(16);

		// Generate a blinding factor using the bank's public key.
		RSABlindingFactorGenerator blindingFactorGenerator
			= new RSABlindingFactorGenerator();
		blindingFactorGenerator.init(pub);

		BigInteger blindingFactor
			= blindingFactorGenerator.generateBlindingFactor();

		blindingParams = new RSABlindingParameters(pub, blindingFactor);
	}

	public TokenRequest generateTokenRequest() throws CryptoException {
		// "Blind" the coin and generate a coin request to be signed by the
		// bank.
		PSSSigner signer = new PSSSigner(new RSABlindingEngine(),
				new SHA256Digest(), 20);
		signer.init(true, blindingParams);

		signer.update(tokenID, 0, tokenID.length);

		byte[] sig = signer.generateSignature();

		return new TokenRequest(sig);
	}
	
	public Token unblindToken(byte[] signature) {
		// "Unblind" the bank's signature (so to speak) and create a new coin
		// using the ID and the unblinded signature.
		RSABlindingEngine blindingEngine = new RSABlindingEngine();
		blindingEngine.init(false, blindingParams);

		byte[] s = blindingEngine.processBlock(signature, 0, signature.length);

		return new Token(tokenID, s);
	}
	
	private static byte[] getRandomBytes(int count) {
		byte[] bytes = new byte[count];
		new SecureRandom().nextBytes(bytes);
		return bytes;
	}
}
