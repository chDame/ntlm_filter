package org.bonitasoft.auth;

import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.bonitasoft.auth.utils.JsonUtils;
import org.bonitasoft.console.common.server.login.LoginFailedException;
import org.bonitasoft.console.common.server.utils.PermissionsBuilder;
import org.bonitasoft.console.common.server.utils.PermissionsBuilderAccessor;
import org.bonitasoft.console.common.server.utils.SessionUtil;
import org.bonitasoft.engine.api.LoginAPI;
import org.bonitasoft.engine.api.TenantAPIAccessor;
import org.bonitasoft.engine.exception.BonitaHomeNotSetException;
import org.bonitasoft.engine.exception.ServerAPIException;
import org.bonitasoft.engine.exception.UnknownAPITypeException;
import org.bonitasoft.engine.platform.LoginException;
import org.bonitasoft.engine.session.APISession;

public class NtlmSsoFilter implements Filter {

	private static final Logger LOGGER = Logger.getLogger(NtlmSsoFilter.class.getName());

	@Override
	public void destroy() {
		// TODO Auto-generated method stub

	}

	public void ntlm_unset_auth(HttpSession session) {
		if (session.getAttribute("_ntlm_auth")!= null)
		{
			session.setAttribute("_ntlm_auth",null);
		}
	}

	/**
	 * R�cup�re le type de navigateur de l'utilisateur avec sa version, son 
	 * @return array Tableau contenant des informations sur le navigateur de l'utilisateur
	 */
	public Map<String,String> getBrowser(HttpServletRequest request) {
		String uAgent = ((String) request.getHeader("user-agent")).toLowerCase();
		String platform = "unknown";
		String bname = "unknown";

		if (uAgent.contains("linux")) {
			platform = "linux";
		} else if (uAgent.contains("macintosh") || uAgent.contains("mac os")) {
			platform = "mac";
		} else if (uAgent.contains("windows") || uAgent.contains("win32")) {
			platform = "windows";
		}

		// Next get the name of the useragent yes seperately and for good reason
		if (uAgent.contains("firefox")) {
			bname = "Mozilla Firefox";
		} else if (uAgent.contains("chrome")) {
			bname = "Google Chrome";
		} else if (uAgent.contains("safari")) {
			bname = "Apple Safari";
		} else if (uAgent.contains("opera")) {
			bname = "Opera";
		} else if (uAgent.contains("netscape")) {
			bname = "Netscape";
		} else if ( uAgent.contains("msie") ||uAgent.contains("windows") || uAgent.contains("trident") ) {
			bname = "Internet Explorer";
		}

		Map<String, String> result = new HashMap<>();
		result.put("name",bname);
		result.put("platform",platform);

		return result;
	}


	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
			throws IOException, ServletException {


		HttpServletRequest httpRequest = (HttpServletRequest) request;
		HttpServletResponse httpResponse = ((HttpServletResponse) response);
		HttpSession httpSession = httpRequest.getSession();
		String host = httpRequest.getRequestURL().toString();
		host = host.substring(0, host.length()-9);//this is executed only on login.jsp
		//host = host.substring(0, host.indexOf("/", 9));//after https
		String redirect = httpRequest.getParameter("redirectUrl");
		if (redirect==null) {
			redirect = host;
		} else {
			//it can happen that redirect contains the base URL
			String baseRedirect = redirect.substring(0, redirect.indexOf("/",1)+1);
			if (host.endsWith(baseRedirect)) {
				redirect = redirect.substring(baseRedirect.length());
			}
			redirect = host + redirect;
		}


		/**
		 * if session exists, we redirect directly to the target page
		 */
		APISession apiSession = (APISession) httpSession.getAttribute(SessionUtil.API_SESSION_PARAM_KEY);
		if (apiSession != null) {
			httpResponse.sendRedirect(redirect);
			filterChain.doFilter(httpRequest, response);
			return;
		}


		ntlm_unset_auth(httpSession);

		Map<String, String> browser = getBrowser(httpRequest);
		Map<String, String> authInconnu = new HashMap<>();
		authInconnu.put("user","INCONNU");
		authInconnu.put("domain","INCONNU");
		authInconnu.put("workstation","INCONNU");
		authInconnu.put("error","INCONNU");

		// Si l'utilisateur n'utilise pas windows, ou si le navigateur n'est pas chrome ni IE ni FF, �choue
		if (!browser.get("platform").equals("windows") || ( !browser.get("name").equals("Google Chrome") && !browser.get("name").equals("Internet Explorer") && !browser.get("name").equals("Mozilla Firefox"))) {
			authInconnu.put("error","Probleme de navigateur : "+browser.get("name")+" ; plateforme : "+browser.get("platform"));
			OutputStream os = response.getOutputStream();
			OutputStreamWriter osw = new OutputStreamWriter(os, "UTF-8");
			osw.write(JsonUtils.toJSON(authInconnu));
			osw.close();
			os.close();
			filterChain.doFilter(request, response);
			LOGGER.info("l'utilisateur n'utilise pas windows, ou le navigateur n'est pas chrome ni IE ni FF");
			return ;
		}

		if (httpRequest.getHeader("Authorization") == null || !httpRequest.getHeader("Authorization").substring(0, 5).equals("NTLM ")) {
			httpResponse.setStatus(401);//envoi au client le mode d'identification
			httpResponse.setHeader("Connection","Keep-Alive");
			httpResponse.setHeader("WWW-Authenticate", "Negotiate");
			httpResponse.setHeader("WWW-Authenticate","NTLM");//dans notre cas le NTLM
			filterChain.doFilter(request, response);
			return ;
		}

		String chaine = httpRequest.getHeader("Authorization");
		chaine = chaine.substring(5); // recuperation du base64-encoded type1 message    
		byte[] chained64 = Base64.getDecoder().decode(chaine); // decodage base64 dans $chained64
		if (chained64[8] == 1) {          
			byte z = 0;
			byte[] chained641 = {(byte) 'N', (byte) 'T', (byte) 'L', (byte) 'M', (byte) 'S',
					(byte) 'S', (byte) 'P', z,
					(byte) 2, z, z, z, z, z, z, z,
					(byte) 40, z, z, z, (byte) 1, (byte) 130, z, z,
					z, (byte) 2, (byte) 2, (byte) 2, z, z, z, z,
					z, z, z, z, z, z, z, z};

			// send ntlm type2 chained64
			httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			httpResponse.setHeader("WWW-Authenticate", "NTLM " + new String(Base64.getEncoder().encode(chained641)).trim());
			filterChain.doFilter(request, response);
			return ;
		} else if (chained64[8] == 3) {

			int off = 30;

			//username
			int length = chained64[off + 9] * 256 + chained64[off + 8];
			int offset = chained64[off + 11] * 256 + chained64[off + 10];
			String username = "";
			
			for(int i = offset; i< (offset+length); i++) {
				String x = new String(Arrays.copyOfRange(chained64, i, i+1));
				if(x.getBytes()[0] >0) {
					username+=x;
				}
			}
			LoginAPI loginAPI;
			try {
				loginAPI = TenantAPIAccessor.getLoginAPI();

			} catch (BonitaHomeNotSetException | ServerAPIException | UnknownAPITypeException e) {
				filterChain.doFilter(request, response);
				LOGGER.info("Probleme de chargement loginAPI");
				return;
			}



			APISession userApiSession;
			Set<String> permissions = null;
			try {
				userApiSession = loginAPI.login(username, "bpm");
				PermissionsBuilder permissionsBuilder = PermissionsBuilderAccessor.createPermissionBuilder(userApiSession);
				permissions = permissionsBuilder.getPermissions();
			} catch (LoginException | LoginFailedException e) {
				filterChain.doFilter(request, response);
				LOGGER.info("Probleme pour logger l'utilisateur "+username);
				return;
			}
			httpSession.setAttribute(SessionUtil.API_SESSION_PARAM_KEY, userApiSession);
			httpSession.setAttribute(SessionUtil.PERMISSIONS_SESSION_PARAM_KEY, permissions);
			httpResponse.sendRedirect(redirect);
			filterChain.doFilter(httpRequest, response);
			return;
		}

		filterChain.doFilter(request, response);
		return;

	}

	@Override
	public void init(FilterConfig arg0) throws ServletException {
		// TODO Auto-generated method stub

	}




}


