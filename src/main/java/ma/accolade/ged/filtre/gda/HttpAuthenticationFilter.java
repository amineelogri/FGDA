package ma.accolade.ged.filtre.gda;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;



import org.apache.log4j.Logger;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter;
import org.apache.shiro.web.util.WebUtils;
import org.springframework.beans.factory.annotation.Autowired;

public class HttpAuthenticationFilter extends BasicHttpAuthenticationFilter {

	private static final Logger LOGGER = Logger.getLogger(HttpAuthenticationFilter.class);
	

	private BasicHttpJdbcRealm basicHttpJdbcRealm;

	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
		LOGGER.info("debut de methode isAccessAllowed");
		HttpServletRequest httpRequest = WebUtils.toHttp(request);
		String headerTest = httpRequest.getHeader("Authorization");
		LOGGER.info(headerTest);
		if ("OPTIONS".equals(httpRequest.getMethod())) {
			return true;
		}
		String header = httpRequest.getHeader("Authorization");
		if (header.contains("Bearer")) {
			boolean resultatSession = false;
			String token = header.split(" ")[1];
			LOGGER.info("Bearer " + token);
			/**
			 * chercher l'existance de token ainsi l'expiration de la session
			 */
			resultatSession = basicHttpJdbcRealm.handleSession(token);
			LOGGER.info(":: rossOriginBasicHttpAuthenticationFilter :: isAccessAllowed :: " + resultatSession);
			return resultatSession;
			// return iuserService.FindUserByToken(token);

		}

		return super.isAccessAllowed(request, response, mappedValue);
	}

	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
		boolean loggedIn = false; // false by default or we wouldn't be in this
									// method
		UsernamePasswordToken usernamePasswordToken = null;
		String login;
		AuthenticationToken token = createToken(request, response);
		usernamePasswordToken = (UsernamePasswordToken) token;
		login = usernamePasswordToken.getUsername();
		if (isLoginAttempt(request, response)) {
			loggedIn = executeLogin(request, response);
		}
		if (!loggedIn) {
			// increment password attempts by 1 et return 401
			basicHttpJdbcRealm.updateWrongPasswordAttempts(login);
			sendChallenge401(request, response);
		} else {

			/** vérifier est ce que le compte est bloqué ou nn **/
			if (basicHttpJdbcRealm.GetEtatCompte(login) == true) {
				/** faire appel a la méthode taitant l'envoi de email **/
				basicHttpJdbcRealm.handleEnvoiMail(login);
				/** return 409 **/
				sendChallenge409(request, response);	
				loggedIn = false;
			} else {
				basicHttpJdbcRealm.resetWrongPasswordAttempts(login);
				sendChallenge200(request, response);
			}
			
		}
		return loggedIn;
	}

	
	protected boolean sendChallenge200(ServletRequest request, ServletResponse response) {

		HttpServletResponse httpResponse = WebUtils.toHttp(response);
		httpResponse.setStatus(HttpServletResponse.SC_OK);
		String authcHeader = getAuthcScheme() + " realm=\"" + getApplicationName() + "\"";
		httpResponse.setHeader(AUTHENTICATE_HEADER, authcHeader);
		return false;
	}
	protected boolean sendChallenge409(ServletRequest request, ServletResponse response) {

		HttpServletResponse httpResponse = WebUtils.toHttp(response);
		httpResponse.setStatus(HttpServletResponse.SC_CONFLICT);
		String authcHeader = getAuthcScheme() + " realm=\"" + getApplicationName() + "\"";
		httpResponse.setHeader(AUTHENTICATE_HEADER, authcHeader);
		return false;
	}
	protected boolean sendChallenge401(ServletRequest request, ServletResponse response) {

		HttpServletResponse httpResponse = WebUtils.toHttp(response);
		httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		String authcHeader = getAuthcScheme() + " realm=\"" + getApplicationName() + "\"";
		httpResponse.setHeader(AUTHENTICATE_HEADER, authcHeader);
		return false;
	}

	public void setBasicHttpJdbcRealm(BasicHttpJdbcRealm basicHttpJdbcRealm) {
		this.basicHttpJdbcRealm = basicHttpJdbcRealm;
	}

}
