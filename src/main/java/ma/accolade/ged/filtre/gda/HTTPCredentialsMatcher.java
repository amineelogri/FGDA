package ma.accolade.ged.filtre.gda;


import org.apache.log4j.Logger;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.SimpleCredentialsMatcher;
import org.apache.shiro.authz.UnauthorizedException;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.crypto.hash.Sha256Hash;

/**
 * HTTP implementation of Shiro CredentialsMatcher.
 * 
 * @author FR20164
 * 
 */
public class HTTPCredentialsMatcher extends SimpleCredentialsMatcher {

	public static final String UTF8 = "UTF-8";
	public static final String HMAC_SHA256 = "HmacSHA256";
	private static final Logger LOGGER = Logger
			.getLogger(HTTPCredentialsMatcher.class);
	@Override
	public boolean doCredentialsMatch(AuthenticationToken token,
			AuthenticationInfo info) {
		LOGGER.info("Debut de la classe HTTPCredentialsMatcher");

		UsernamePasswordToken usernamePasswordToken = null;
		SimpleAuthenticationInfo simpleAuthenticationInfo = null;

		if (token instanceof UsernamePasswordToken) {
			usernamePasswordToken = (UsernamePasswordToken) token;
		} else {
			System.out.println("");
			return false;
		}

		if (info instanceof SimpleAuthenticationInfo) {
			simpleAuthenticationInfo = (SimpleAuthenticationInfo) info;
		} else {
			System.out.println("");
			return false;
		}
		LOGGER.info(":: login :: "+usernamePasswordToken.getUsername());
		String passwordString = new String(usernamePasswordToken.getPassword());
		System.out.println("pwd String : " + passwordString);
		String PasswordToken = new Sha256Hash(passwordString).toString();
		String passwordBD = new String(
				(char[]) simpleAuthenticationInfo.getCredentials());
		 String userName = (String)
		 simpleAuthenticationInfo.getPrincipals().getPrimaryPrincipal();
		if(!PasswordToken.equals(passwordBD)){
			throw new UnauthorizedException("You are not autho");
		}
		System.out.println(PasswordToken);
		System.out.println(passwordBD);
		return PasswordToken.equals(passwordBD);

	}

}
