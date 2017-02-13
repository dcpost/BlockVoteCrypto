package registrar;

import org.bouncycastle.crypto.params.RSAKeyParameters;

import tokens.IToken;
import tokens.ITokenRequest;

public interface IRegistrar {
	// The registrar's RSA public key
	RSAKeyParameters getPublic();
	
	RSAKeyParameters getPrivate();

	// Sign a token request
	byte[] sign(ITokenRequest tokenRequest);

	// Verify a token
	boolean verify(IToken token);

}
