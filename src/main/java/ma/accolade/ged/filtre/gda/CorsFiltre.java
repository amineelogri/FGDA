package ma.accolade.ged.filtre.gda;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.HttpHeaders;

/**
 * The Class CorsFiltre.
 */
public class CorsFiltre implements Filter {

	/** The Constant OPTIONS_HTTP_METHOD. */
	public static final String OPTIONS_HTTP_METHOD = "OPTIONS";

	/** The Constant REQUEST_ORIGIN. */
	public static final String REQUEST_ORIGIN = "Origin";

	/** The Constant ALLOW_ORIGIN. */
	public static final String ALLOW_ORIGIN = "Access-Control-Allow-Origin";

	/** The Constant ALL. */
	public static final String ALL = "*";

	/** The Constant ALLOW_CREDENTIALS. */
	public static final String ALLOW_CREDENTIALS = "Access-Control-Allow-Credentials";

	/** The Constant REQUEST_METHOD. */
	public static final String REQUEST_METHOD = "Access-Control-Request-Method";

	/** The Constant ALLOW_METHODS. */
	public static final String ALLOW_METHODS = "Access-Control-Allow-Methods";

	/** The Constant EXPOSE_HEADERS. */
	public static final String EXPOSE_HEADERS = "Access-Control-Expose-Headers";

	/** The Constant REQUEST_HEADERS. */
	public static final String REQUEST_HEADERS = "Access-Control-Request-Headers";

	/** The Constant ALLOW_HEADERS. */
	public static final String ALLOW_HEADERS = "Access-Control-Allow-Headers";

	/** The Constant AUTH_ALLOWED_HEADERS. */
	public static final String AUTH_ALLOWED_HEADERS = "locale,sign,Cache-Control,Pragma,If-Modified-Since,client,Authorization,"
			+ HttpHeaders.CONTENT_TYPE;

	/** The Constant AUTH_ALLOWED_METHODS. */
	public static final String AUTH_ALLOWED_METHODS = "GET";

	/** The Constant BUNDLE_ORIGINS_KEY. */
	public static final String BUNDLE_ORIGINS_KEY = "origins";

	/** The Constant BUNDLE_METHODS_KEY. */
	public static final String BUNDLE_METHODS_KEY = "methods";

	/** The origins. */
	private static List<String> origins = null;

	/** The methods. */
	private static List<String> methods = null;

	static {
		try {
			origins = Arrays.asList("*");
			methods = Arrays.asList("POST", "GET", "DELETE", "OPTIONS","PUT");
		} catch (Exception e) {
			System.out
					.println("Can't find cors configuration! All cross-domain requests will be rejected!"
							+ e);
			System.out.println("INIT CorsFilter" + CorsFiltre.class + ""
					+ "Can't find cors configuration! All cross-domain requests will be rejected!");
		}
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		String method = null;

		HttpServletRequest httpRequest = null;

		if (request instanceof HttpServletRequest) {
			httpRequest = (HttpServletRequest) request;

			String origin = httpRequest.getHeader(REQUEST_ORIGIN);
			method = httpRequest.getMethod();

			if (origin != null) {

				if (response instanceof HttpServletResponse) {
					HttpServletResponse httpResponse = (HttpServletResponse) response;

					if (OPTIONS_HTTP_METHOD.equals(method)
							&& httpRequest.getHeader(REQUEST_METHOD) != null) {
						String accessMethod = httpRequest.getHeader(REQUEST_METHOD);
						if (methods.contains(accessMethod)) {
							httpResponse.addHeader(ALLOW_METHODS, accessMethod);
						}
						httpResponse.addHeader(ALLOW_HEADERS, AUTH_ALLOWED_HEADERS);
					} else {
						httpResponse.addHeader(EXPOSE_HEADERS, AUTH_ALLOWED_HEADERS);
					}

					// set allowed origins
					// cors will be browser rejected if no origins configured
					if (origins != null) {
						if (origins.contains(origin)) {
							httpResponse.addHeader(ALLOW_ORIGIN, origin);
						} else if (origins.contains(ALL)) {
							httpResponse.addHeader(ALLOW_ORIGIN, ALL);
						}
					}
				}
			}
		}

		if (method != null && method.equals(OPTIONS_HTTP_METHOD)) {
			// no need to launch other filters
			return;
		} else {
			chain.doFilter(request, response);
		}
	}

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
	}

	@Override
	public void destroy() {
	}
}
