package ma.accolade.ged.filtre.gda;

import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;



import org.apache.log4j.Logger;
import org.apache.shiro.authc.AccountException;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.config.ConfigurationException;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.realm.jdbc.JdbcRealm;
import org.apache.shiro.session.ExpiredSessionException;
import org.apache.shiro.session.SessionException;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.apache.shiro.util.JdbcUtils;
import org.apache.shiro.web.util.WebUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.MailSender;
import org.springframework.mail.SimpleMailMessage;

/**
 * This Realm is a copy of the original JdbcRealm with multi-tenant
 * functionnality added.
 * 
 * Realm that allows authentication and authorization via JDBC calls. The
 * default queries suggest a potential schema for retrieving the user's password
 * for authentication, and querying for a user's roles and permissions. The
 * default queries can be overridden by setting the query properties of the
 * realm.
 * <p/>
 * If the default implementation of authentication and authorization cannot
 * handle your schema, this class can be subclassed and the appropriate methods
 * overridden. (usually
 * {@link #doGetAuthenticationInfo(org.apache.shiro.authc.AuthenticationToken)},
 * {@link #getRoleNamesForUser(java.sql.Connection,String)}, and/or
 * {@link #getPermissions(java.sql.Connection,String,java.util.Collection)}
 * <p/>
 * This realm supports caching by extending from
 * {@link org.apache.shiro.realm.AuthorizingRealm}.
 * 
 * @since 0.2
 */
public class BasicHttpJdbcRealm extends AuthorizingRealm  {

	/*--------------------------------------------
	|             C O N S T A N T S             |
	============================================*/
	/**
	 * The default query used to retrieve account data for the user.
	 */
	protected static final String DEFAULT_AUTHENTICATION_QUERY = "select motdepasse from user where login = ?";

	/**
	 * The default query used to retrieve account data for the user when
	 * {@link #saltStyle} is COLUMN.
	 */
	protected static final String DEFAULT_SALTED_AUTHENTICATION_QUERY = "select password, password_salt from users where username = ?";

	/**
	 * The default query used to retrieve the roles that apply to a user.
	 */
	protected static final String DEFAULT_USER_ROLES_QUERY = "select role_name from user_roles where username = ?";

	/**
	 * The default query used to retrieve permissions that apply to a particular
	 * role.
	 */
	protected static final String DEFAULT_PERMISSIONS_QUERY = "select permission from roles_permissions where role_name = ?";

	/**
	 * requette permet de selectionner la date d'expirationToken d'un utilisatuer
	 * selon token
	 */

	protected static final String DEFAULT_DATE_EXPIRATION_QUERRY = "select dateExpirationToken from user where token = ?";
	

	/**
	 * requette permet de mettre à jour  la date d'expirationToken d'un utilisatuer
	 * selon token
	 */
	protected static final String DEFAULT_METTRE_AJOUR_SESSION = "UPDATE user SET dateExpirationToken= ? WHERE token= ?";
	
	
	
	
	
	/**
	 * requette permet de selectionner le nombre de tentative d'une authentification d'un utilisateur
	 * selon login
	 */
	protected static final String DEFAULT_NOMBRE_TENTATIVE="select nombreTentative from user where login= ?";
	
	
	
	/**
	 * requette permet de mettre à jour le nombre de tentative d'une authentification d'un utilisateur
	 * selon login
	 */
	protected static final String DEFAULT_INCREMENT_TENTATIVE="update user SET nombreTentative= ? where login= ?";
	
	
	
	/**
	 * requtte permet de bloquer un compte dans le cas ou l'utilisateur depasse le nombre de tentative 
	 */
	protected static final String DEFAULT_BLOQUER_COMPTE="update user SET compteBloque= ? where login= ?";
	
	/**
	 * requette permet de selectionner l'état du compte, i.e bloqué ou nn
	 */
	protected static final String DEFAULT_ETAT_Compte="select compteBloque from user where login= ?";
	
	/**
	 * requette permettant de savoir est-ce que un email a été envoyé à l'utilisateur ou pas encore
	 */
	protected static final String DEFAULT_MSG_Envoye="select msgEnvoye from user where login= ?";
	
	/**
	 * mettre a jour le code envoyé avec le lien de blockage du compte 
	 */
	protected static final String DEFAULT_METTRE_AJOUR_CODELIEN="update user set codeLien= ? where login= ?";
	
	
	/**
	 * 
	 */
	protected static final String  DEFAULT_NOM_PRENOM_EMAIL="select nom,prenom,email from user where login= ?";
	
	
	protected static final String DEFAULT_CHANGE_ETAT_MSG="update user set msgEnvoye= ? where login= ?";
	
	private static final Logger LOGGER = Logger
			.getLogger(BasicHttpJdbcRealm.class);
	

	static final String AB = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	static SecureRandom rnd = new SecureRandom();

	@Autowired
	private MailSender Envoyermail; // MailSender interface defines a strategy

	/**
	 * Password hash salt configuration.
	 * <ul>
	 * <li>NO_SALT - password hashes are not salted.</li>
	 * <li>CRYPT - password hashes are stored in unix crypt format.</li>
	 * <li>COLUMN - salt is in a separate column in the database.</li>
	 * <li>EXTERNAL - salt is not stored in the database.
	 * {@link #getSaltForUser(String)} will be called to get the salt</li>
	 * </ul>
	 */
	public enum SaltStyle {
		NO_SALT, CRYPT, COLUMN, EXTERNAL
	};
//	•NO_SALT - password hashes are not salted.
//	•CRYPT - password hashes are stored in unix crypt format.
//	•COLUMN - password hashes are stored in unix crypt format.
//	•EXTERNAL - salt is not stored in the database. getSaltForUser(String) will be called to get the salt

	/*--------------------------------------------
	|    I N S T A N C E   V A R I A B L E S    |
	============================================*/
	protected DataSource dataSource;

	 String authenticationQuery = DEFAULT_AUTHENTICATION_QUERY;

	protected String userRolesQuery = DEFAULT_USER_ROLES_QUERY;

	protected String permissionsQuery = DEFAULT_PERMISSIONS_QUERY;

	protected boolean permissionsLookupEnabled = false;

	protected SaltStyle saltStyle = SaltStyle.NO_SALT;

	// requettes personnalisées
	protected String dateExpirationQuery = DEFAULT_DATE_EXPIRATION_QUERRY;
	protected String mettreAjourSessionQuery = DEFAULT_METTRE_AJOUR_SESSION;
	protected String nombreTentativeQuery=DEFAULT_NOMBRE_TENTATIVE;
	protected String metterAjourTentativeQuery=DEFAULT_INCREMENT_TENTATIVE;
	protected String bloquerCompteQuery=DEFAULT_BLOQUER_COMPTE;
	protected String etatCompteQuery=DEFAULT_ETAT_Compte;
	protected String etatMsgEnvoyeQuery=DEFAULT_MSG_Envoye;
	protected String mettreAjourCodeLienQuery=DEFAULT_METTRE_AJOUR_CODELIEN;
	protected String getNomPrenomEmailQuery=DEFAULT_NOM_PRENOM_EMAIL;
	protected String changerEtatMsgEnvoiQuery=DEFAULT_CHANGE_ETAT_MSG;
	/**
	 * Nombre de tentative d'une connexion
	 */
	
	protected long nombreTentativeConnexion;
	/*--------------------------------------------
	|         C O N S T R U C T O R S           |
	============================================*/

	/*--------------------------------------------
	|  A C C E S S O R S / M O D I F I E R S    |
	============================================*/

	/**
	 * Sets the datasource that should be used to retrieve connections used by
	 * this realm.
	 * 
	 * @param dataSource
	 *            the SQL data source.
	 */
	public void setDataSource(DataSource dataSource) {
		this.dataSource = dataSource;
	}

	/**
	 * Overrides the default query used to retrieve a user's password during
	 * authentication. When using the default implementation, this query must
	 * take the user's username as a single parameter and return a single result
	 * with the user's password as the first column. If you require a solution
	 * that does not match this query structure, you can override
	 * {@link #doGetAuthenticationInfo(org.apache.shiro.authc.AuthenticationToken)}
	 * or just {@link #getPasswordForUser(java.sql.Connection,String)}
	 * 
	 * @param authenticationQuery
	 *            the query to use for authentication.
	 * @see #DEFAULT_AUTHENTICATION_QUERY
	 */
	public void setAuthenticationQuery(String authenticationQuery) {
		this.authenticationQuery = authenticationQuery;
	}

	/**
	 * Overrides the default query used to retrieve a user's roles during
	 * authorization. When using the default implementation, this query must
	 * take the user's username as a single parameter and return a row per role
	 * with a single column containing the role name. If you require a solution
	 * that does not match this query structure, you can override
	 * {@link #doGetAuthorizationInfo(PrincipalCollection)} or just
	 * {@link #getRoleNamesForUser(java.sql.Connection,String)}
	 * 
	 * @param userRolesQuery
	 *            the query to use for retrieving a user's roles.
	 * @see #DEFAULT_USER_ROLES_QUERY
	 */
	public void setUserRolesQuery(String userRolesQuery) {
		this.userRolesQuery = userRolesQuery;
	}

	/**
	 * Overrides the default query used to retrieve a user's permissions during
	 * authorization. When using the default implementation, this query must
	 * take a role name as the single parameter and return a row per permission
	 * with three columns containing the fully qualified name of the permission
	 * class, the permission name, and the permission actions (in that order).
	 * If you require a solution that does not match this query structure, you
	 * can override
	 * {@link #doGetAuthorizationInfo(org.apache.shiro.subject.PrincipalCollection)}
	 * or just
	 * {@link #getPermissions(java.sql.Connection,String,java.util.Collection)}
	 * </p>
	 * <p/>
	 * <b>Permissions are only retrieved if you set
	 * {@link #permissionsLookupEnabled} to true. Otherwise, this query is
	 * ignored.</b>
	 * 
	 * @param permissionsQuery
	 *            the query to use for retrieving permissions for a role.
	 * @see #DEFAULT_PERMISSIONS_QUERY
	 * @see #setPermissionsLookupEnabled(boolean)
	 */
	public void setPermissionsQuery(String permissionsQuery) {
		this.permissionsQuery = permissionsQuery;
	}

	/**
	 * Enables lookup of permissions during authorization. The default is
	 * "false" - meaning that only roles are associated with a user. Set this to
	 * true in order to lookup roles <b>and</b> permissions.
	 * 
	 * @param permissionsLookupEnabled
	 *            true if permissions should be looked up during authorization,
	 *            or false if only roles should be looked up.
	 */
	public void setPermissionsLookupEnabled(boolean permissionsLookupEnabled) {
		this.permissionsLookupEnabled = permissionsLookupEnabled;
	}

	/**
	 * Sets the salt style. See {@link #saltStyle}.
	 * 
	 * @param saltStyle
	 *            new SaltStyle to set.
	 */
	public void setSaltStyle(SaltStyle saltStyle) {
		this.saltStyle = saltStyle;
		if (saltStyle == SaltStyle.COLUMN
				&& authenticationQuery.equals(DEFAULT_AUTHENTICATION_QUERY)) {
			authenticationQuery = DEFAULT_SALTED_AUTHENTICATION_QUERY;
		}
	}

	/*--------------------------------------------
	|               M E T H O D S               |
	============================================*/
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(
			AuthenticationToken token) throws AuthenticationException {

		UsernamePasswordToken upToken = (UsernamePasswordToken) token;
		String username = upToken.getUsername();

		// Null username is invalid
		if (username == null) {
			throw new AccountException(
					"Null usernames are not allowed by this realm.");
		}

		Connection conn = null;
		SimpleAuthenticationInfo info = null;
		try {
			conn = getConnection();

			String password = null;
			String salt = null;
			switch (saltStyle) {
			case NO_SALT:
				password = getPasswordForUser(conn, username)[0];
				break;
			case CRYPT:
				// TODO: separate password and hash from getPasswordForUser[0]
				throw new ConfigurationException("Not implemented yet");
				// break;
			case COLUMN:
				String[] queryResults = getPasswordForUser(conn, username);
				password = queryResults[0];
				salt = queryResults[1];
				break;
			case EXTERNAL:
				password = getPasswordForUser(conn, username)[0];
				salt = getSaltForUser(username);
			}

			if (password == null) {
				throw new UnknownAccountException("No account found for user ["
						+ username + "]");
			}

			info = new SimpleAuthenticationInfo(username,
					password.toCharArray(), getName());

			if (salt != null) {
				info.setCredentialsSalt(ByteSource.Util.bytes(salt));
			}

		} catch (SQLException e) {
			final String message = "There was a SQL error while authenticating user ["
					+ username;

			// Rethrow any SQL errors as an authentication exception
			throw new AuthenticationException(message, e);
		} finally {
			JdbcUtils.closeConnection(conn);
		}

		return info;
	}

	private String[] getPasswordForUser(Connection conn, String username)
			throws SQLException {

		String[] result;
		boolean returningSeparatedSalt = false;
		switch (saltStyle) {
		case NO_SALT:
		case CRYPT:
		case EXTERNAL:
			result = new String[1];
			break;
		default:
			result = new String[2];
			returningSeparatedSalt = true;
		}

		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			ps = conn.prepareStatement(authenticationQuery);
			ps.setString(1, username);

			// Execute query
			rs = ps.executeQuery();

			// Loop over results - although we are only expecting one result,
			// since usernames should be unique
			boolean foundResult = false;
			while (rs.next()) {

				// Check to ensure only one row is processed
				if (foundResult) {
					throw new AuthenticationException(
							"More than one user row found for user ["
									+ username + "]. Usernames must be unique.");
				}

				result[0] = rs.getString(1);
				if (returningSeparatedSalt) {
					result[1] = rs.getString(2);
				}

				foundResult = true;
			}
		} finally {
			JdbcUtils.closeResultSet(rs);
			JdbcUtils.closeStatement(ps);
		}

		return result;
	}

	/**
	 * This implementation of the interface expects the principals collection to
	 * return a String username keyed off of this realm's {@link #getName()
	 * name}
	 * 
	 * @see #getAuthorizationInfo(org.apache.shiro.subject.PrincipalCollection)
	 */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(
			PrincipalCollection principals) {

		// null usernames are invalid
		if (principals == null) {
			throw new AuthorizationException(
					"PrincipalCollection method argument cannot be null.");
		}

		String username = (String) getAvailablePrincipal(principals);

		Connection conn = null;
		Set<String> roleNames = null;
		Set<String> permissions = null;
		try {
			conn = getConnection();

			// Retrieve roles and permissions from database
			roleNames = getRoleNamesForUser(conn, username);
			if (permissionsLookupEnabled) {
				permissions = getPermissions(conn, username, roleNames);
			}

		} catch (SQLException e) {
			final String message = "There was a SQL error while authorizing user ["
					+ username + "]";

			// Rethrow any SQL errors as an authorization exception
			throw new AuthorizationException(message, e);
		} finally {
			JdbcUtils.closeConnection(conn);
		}

		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo(roleNames);
		info.setStringPermissions(permissions);
		return info;

	}

	// public boolean FindUserByToken(String token) {
	// List<UserOe> listUsers = new ArrayList<UserOe>();
	//
	// listUsers = userPersistance.findByToken(token);
	//
	// if (listUsers.isEmpty()) {
	// LOGGER.info("la liste FindUserByToken est vide : ");
	// return false;
	// }
	//
	// else {
	// LOGGER.info("la liste FindUserByToken est pleine");
	// // if comparaison sur date systéme et date expiration de token
	// if (System.currentTimeMillis() > listUsers.get(0)
	// .getDateExpirationToken()) {
	// LOGGER.info("session expirée");
	// return false;// session expirée
	// } else {
	// // mettre à jour la date d'expiration de token
	// LOGGER.info(" mettre à jour la date d'expiration de token ");
	// modifierDateExpirationToken(listUsers.get(0));
	// return true;
	// }
	// }
	// }
	/**
	 * Requettes personnalisées
	 * 
	 * @param username
	 * @return
	 */
	public void updateWrongPasswordAttempts(String login){
		Connection conn=null;
		
		long nombreTentative=0;
		try {
			conn=getConnection();
			//methode return nombreTentative
			nombreTentative=NombreTentative(conn,login);
			IncrementNombreTentative(conn,login,nombreTentative);
			nombreTentative=NombreTentative(conn,login);
			LOGGER.info(":: le nouveau nombre de tentative  "+nombreTentative);
			/** si le nombre de tentative egale 3 on bloque le compte cete partie sera parametrable **/
			LOGGER.info(":: nombreTentativeConnexion :: "+nombreTentativeConnexion);
			if(nombreTentative==nombreTentativeConnexion){
				bloqueCompte(conn,login);
			}
			LOGGER.info(":: etat du compte :: "+EtatCompte(conn,login)); 
		}catch(SQLException e){
			LOGGER.error(":: SQLException :: "+e.getMessage());
		}finally{
			JdbcUtils.closeConnection(conn);
		}
	}
	
	public boolean GetEtatCompte(String login){
		boolean etatCompte=false;
		Connection conn=null;
		try{
			conn=getConnection();
			etatCompte=EtatCompte(conn, login);
			
		}catch(SQLException e){
			LOGGER.error(":: SQLException :: "+e.getMessage());
		}finally{
			JdbcUtils.closeConnection(conn);
		}
		LOGGER.info(" :: GetEtatCompte :: "+etatCompte);
		return etatCompte;
	}
	public void handleEnvoiMail(String login){
		boolean etatEnvoiMail=false;
		Connection conn=null;
		PreparedStatement ps=null;
		ResultSet rs=null;
		String codeLien=null,nom=null,prenom = null,email=null;
		try{
			conn=getConnection();
			etatEnvoiMail=EtatEnvoiMail(conn, login);
			/** if etatEnvoeMail egal false ==> faut l'envoyer **/
			if(etatEnvoiMail==false){
			/** faire appel à la method qui génére codeLien  **/	
			codeLien=randomStringCode(8);
			
			/** mettre à jour codeLien **/
			mettreAjourCodeLien(conn,login,codeLien);
			
			/** select nom, prenom et l'email de l'utilisateur **/
			ps=conn.prepareStatement(getNomPrenomEmailQuery);
			ps.setString(1, login);
			rs=ps.executeQuery();
			while(rs.next()){
			nom=rs.getString(1);
			prenom=rs.getString(2);
			email=rs.getString(3);
			}
			EmailBloqueCompte(login,nom,prenom,email,codeLien);
			
			/** apres l'envoi de msg faut changer son etat  à true **/
			ChangerEtatMsgEnvoi(conn,login);	
			}
			
		}catch(SQLException e){
			LOGGER.error(":: SQLException :: "+e.getMessage());
		}finally{
			JdbcUtils.closeConnection(conn);
			JdbcUtils.closeStatement(ps);
			JdbcUtils.closeResultSet(rs);
		}
	
		
	}
	
	public void mettreAjourCodeLien(Connection conn,String login,String codeLien) throws SQLException{
		PreparedStatement ps=null;
		try{
			ps=conn.prepareStatement(mettreAjourCodeLienQuery);
			ps.setString(1, codeLien);
			ps.setString(2, login);
			ps.executeUpdate();
			
		}finally{
			JdbcUtils.closeStatement(ps);
		}
	}
	
	
	public void ChangerEtatMsgEnvoi(Connection conn,String login)throws SQLException {
		PreparedStatement ps=null;
		try{
			ps=conn.prepareStatement(changerEtatMsgEnvoiQuery);
			ps.setBoolean(1, true);
			ps.setString(2, login);
			ps.executeUpdate();
		}finally{
			JdbcUtils.closeStatement(ps);
		}
	}
	
	public boolean EtatEnvoiMail(Connection conn,String login)throws SQLException {
		PreparedStatement ps=null;
		ResultSet rs=null;
		boolean etatEnvoiMail=false;
		try{
			ps=conn.prepareStatement(etatMsgEnvoyeQuery);
			ps.setString(1, login);
			rs=ps.executeQuery();
			while(rs.next()){
				etatEnvoiMail=rs.getBoolean(1);
			}
		}finally{
			JdbcUtils.closeStatement(ps);
		    JdbcUtils.closeResultSet(rs);
			LOGGER.info(" :: EtatEnvoiMail ::"+etatEnvoiMail);
			
		}
		return etatEnvoiMail;
	}
	public long NombreTentative(Connection conn,String login)throws SQLException {
		PreparedStatement ps=null;
		long nombreTentative=0;
		ResultSet rs=null;
		try{
			ps=conn.prepareStatement(nombreTentativeQuery);
			ps.setString(1, login);
			rs=ps.executeQuery();
			while(rs.next()){
				nombreTentative=rs.getLong(1);
			}
		}finally{
			JdbcUtils.closeResultSet(rs);
			JdbcUtils.closeStatement(ps);
		}
		return nombreTentative;
	}
	public void IncrementNombreTentative(Connection conn,String login,long nombreTentative) throws SQLException{
		PreparedStatement ps =null;
		nombreTentative=nombreTentative+1;
		try{
			ps=conn.prepareStatement(metterAjourTentativeQuery);
			ps.setLong(1, nombreTentative);
			ps.setString(2,login);
			ps.executeUpdate();
		}finally{
			JdbcUtils.closeStatement(ps);
		}
	}
	public void bloqueCompte(Connection conn,String login) throws SQLException{
		PreparedStatement ps=null;
		try{
			ps=conn.prepareStatement(bloquerCompteQuery);
			ps.setBoolean(1, true);
			ps.setString(2, login);
			ps.executeUpdate();
		}finally{
			JdbcUtils.closeStatement(ps);
		}
	}
	public boolean EtatCompte(Connection conn,String login) throws SQLException{
		PreparedStatement ps=null;
		ResultSet rs=null;
		boolean etatCompte = false;
		try{
			ps=conn.prepareStatement(etatCompteQuery);
			ps.setString(1, login);
			rs=ps.executeQuery();
			while(rs.next()){
				etatCompte=rs.getBoolean(1);
			}
		}finally{
			JdbcUtils.closeResultSet(rs);
			JdbcUtils.closeStatement(ps);
		}
		return etatCompte;
	}
	public void resetWrongPasswordAttempts(String login) throws SQLException{
		Connection conn=null;
		PreparedStatement ps=null;
		try{
			conn=getConnection();
			ps=conn.prepareStatement(metterAjourTentativeQuery);
			ps.setLong(1, 0);
			ps.setString(2, login);
			ps.executeUpdate();
		}catch(SQLException e){
			LOGGER.error(":: SQLException :: "+e.getMessage());
		}finally{
			JdbcUtils.closeConnection(conn);
			JdbcUtils.closeStatement(ps);
		}
	}
	public boolean handleSession(String token) {
		Connection conn = null;
		long dateExpirationToken;
		boolean handle = false;
		try {
			conn = getConnection();
			dateExpirationToken = getDateExpiration(conn, token);
			if (dateExpirationToken != 0) {
				LOGGER.info(" ::BasicHttpAppAuthJdbcRealm:: handleSession:: Tester la session ");
				if (System.currentTimeMillis() > dateExpirationToken) {
					LOGGER.info("::BasicHttpAppAuthJdbcRealm:: handleSession:: session expirée");
					//throw new ExpiredSessionException("Session expirée");
				} else {
					LOGGER.info("::BasicHttpAppAuthJdbcRealm:: handleSession:: mettre à jour la session");
					mettreAjourSession(conn, token);
					handle = true;
				}
			}
		} catch (SQLException e) {

			LOGGER.error(":: SQLException :: " + e.getMessage());
			// Rethrow any SQL errors as an authorization exception
			// throw new AuthorizationException(message, e);
		} finally {
			JdbcUtils.closeConnection(conn);
		}
		return handle;

	}

	/**
	 * getDateExpiration
	 * 
	 * @param conn
	 *            , token
	 * @return long dateExpirationToken
	 * @throws SQLException
	 */
	public long getDateExpiration(Connection conn, String token)
			throws SQLException {
		long dateExpirationToken2 = 0;
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			ps = conn.prepareStatement(dateExpirationQuery);
			ps.setString(1, token);

			// Execute query
			rs = ps.executeQuery();

			// Loop over results and add each returned dateExpiration to a set
			while (rs.next()) {
				dateExpirationToken2 = rs.getLong(1);
			}
		} finally {
			JdbcUtils.closeResultSet(rs);
			JdbcUtils.closeStatement(ps);
		}
		return dateExpirationToken2;
	}

	public void mettreAjourSession(Connection conn, String token)
			throws SQLException {
		PreparedStatement ps = null;
		long dateExpirationTokenSession = System.currentTimeMillis() + 3600000;
		SimpleDateFormat sdf = new SimpleDateFormat("MMM dd,yyyy HH:mm");
		Date resultdate = new Date(dateExpirationTokenSession);
		LOGGER.info("************ date d'expiration de token : "
				+ sdf.format(resultdate));
		try {
			ps = conn.prepareStatement(mettreAjourSessionQuery);
			ps.setLong(1, dateExpirationTokenSession);
			ps.setString(2, token);
			// Execute query
			ps.executeUpdate();
		} finally {
			JdbcUtils.closeStatement(ps);
		}
	}

	protected Set<String> getRoleNamesForUser(Connection conn, String username)
			throws SQLException {
		PreparedStatement ps = null;
		ResultSet rs = null;
		Set<String> roleNames = new LinkedHashSet<String>();
		try {
			ps = conn.prepareStatement(userRolesQuery);
			ps.setString(1, username);

			// Execute query
			rs = ps.executeQuery();

			// Loop over results and add each returned role to a set
			while (rs.next()) {

				String roleName = rs.getString(1);

				// Add the role to the list of names if it isn't null
				if (roleName != null) {
					roleNames.add(roleName);
				} else {

				}
			}
		} finally {
			JdbcUtils.closeResultSet(rs);
			JdbcUtils.closeStatement(ps);
		}
		return roleNames;
	}

	protected Set<String> getPermissions(Connection conn, String username,
			Collection<String> roleNames) throws SQLException {
		PreparedStatement ps = null;
		Set<String> permissions = new LinkedHashSet<String>();
		try {
			ps = conn.prepareStatement(permissionsQuery);
			for (String roleName : roleNames) {

				ps.setString(1, roleName);

				ResultSet rs = null;

				try {
					// Execute query
					rs = ps.executeQuery();

					// Loop over results and add each returned role to a set
					while (rs.next()) {

						String permissionString = rs.getString(1);

						// Add the permission to the set of permissions
						permissions.add(permissionString);
					}
				} finally {
					JdbcUtils.closeResultSet(rs);
				}

			}
		} finally {
			JdbcUtils.closeStatement(ps);
		}

		return permissions;
	}

	protected String getSaltForUser(String username) {
		return username;
	}

	protected Connection getConnection() throws SQLException {
		Statement statement = null;

		final Connection connection = dataSource.getConnection();
		try {
			String tenantIdentifier = "acc_ged";
			if (tenantIdentifier != null) {
				statement = connection.createStatement();
				statement.execute("USE " + tenantIdentifier);
			}
		} finally {
			JdbcUtils.closeStatement(statement);
		}
		return connection;
	}
/** fct qui génére une chaine aléatoire  **/
	public  String randomStringCode( int len ){
		   StringBuilder sb = new StringBuilder( len );
		   for( int i = 0; i < len; i++ ) 
		      sb.append( AB.charAt( rnd.nextInt(AB.length()) ) );
		   return sb.toString();
		}
	/**
	 * partie d'envoi d'un email
	 */
	public void EmailBloqueCompte(String login,String nom,String prenom,String email,String codeLien){
		String toAddr=email;
		String fromAddr="aaithamou@accolade.co.ma";
		String subject="Débloquer le compte";
		String url="http://localhost:9000/ged/Debloque/"+ login+"/"+codeLien;
		String body="Bonjour M(Mme) "+nom.toUpperCase()+" "+prenom+",\n\n votre compte a été bloqué pour le débloquer veuillez cliquer sur le lien ci-dessous\n\n"+url;		
		accoladeReadyToSendEmail(toAddr, fromAddr, subject, body);
	}
	
	public boolean accoladeReadyToSendEmail(String toAddress,
			String fromAddress, String subject, String msgBody) {

		SimpleMailMessage AccoladeMsg = new SimpleMailMessage();
		AccoladeMsg.setFrom(fromAddress);
		AccoladeMsg.setTo(toAddress);
		AccoladeMsg.setSubject(subject);
		AccoladeMsg.setText(msgBody);
		Envoyermail.send(AccoladeMsg);
		return true;
	}

	public String getDateExpirationQuery() {
		return dateExpirationQuery;
	}

	public void setDateExpirationQuery(String dateExpirationQuery) {
		this.dateExpirationQuery = dateExpirationQuery;
	}

	public String getMettreAjourSessionQuery() {
		return mettreAjourSessionQuery;
	}

	public void setMettreAjourSessionQuery(String mettreAjourSessionQuery) {
		this.mettreAjourSessionQuery = mettreAjourSessionQuery;
	}

	public String getNombreTentativeQuery() {
		return nombreTentativeQuery;
	}

	public void setNombreTentativeQuery(String nombreTentativeQuery) {
		this.nombreTentativeQuery = nombreTentativeQuery;
	}

	public String getMetterAjourTentativeQuery() {
		return metterAjourTentativeQuery;
	}

	public void setMetterAjourTentativeQuery(String metterAjourTentativeQuery) {
		this.metterAjourTentativeQuery = metterAjourTentativeQuery;
	}

	public String getBloquerCompteQuery() {
		return bloquerCompteQuery;
	}

	public void setBloquerCompteQuery(String bloquerCompteQuery) {
		this.bloquerCompteQuery = bloquerCompteQuery;
	}

	public String getEtatCompteQuery() {
		return etatCompteQuery;
	}

	public void setEtatCompteQuery(String etatCompteQuery) {
		this.etatCompteQuery = etatCompteQuery;
	}

	public String getEtatMsgEnvoyeQuery() {
		return etatMsgEnvoyeQuery;
	}

	public void setEtatMsgEnvoyeQuery(String etatMsgEnvoyeQuery) {
		this.etatMsgEnvoyeQuery = etatMsgEnvoyeQuery;
	}

	public String getMettreAjourCodeLienQuery() {
		return mettreAjourCodeLienQuery;
	}

	public void setMettreAjourCodeLienQuery(String mettreAjourCodeLienQuery) {
		this.mettreAjourCodeLienQuery = mettreAjourCodeLienQuery;
	}

	public String getGetNomPrenomEmailQuery() {
		return getNomPrenomEmailQuery;
	}

	public void setGetNomPrenomEmailQuery(String getNomPrenomEmailQuery) {
		this.getNomPrenomEmailQuery = getNomPrenomEmailQuery;
	}

	public String getChangerEtatMsgEnvoiQuery() {
		return changerEtatMsgEnvoiQuery;
	}

	public void setChangerEtatMsgEnvoiQuery(String changerEtatMsgEnvoiQuery) {
		this.changerEtatMsgEnvoiQuery = changerEtatMsgEnvoiQuery;
	}

	public long getNombreTentativeConnexion() {
		return nombreTentativeConnexion;
	}

	public void setNombreTentativeConnexion(long nombreTentativeConnexion) {
		this.nombreTentativeConnexion = nombreTentativeConnexion;
	}

	public String getAuthenticationQuery() {
		return authenticationQuery;
	}
	
	
}

