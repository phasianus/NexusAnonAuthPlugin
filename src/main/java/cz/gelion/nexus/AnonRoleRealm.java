package cz.gelion.nexus;

import java.util.HashSet;
import java.util.List;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.eclipse.sisu.Description;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonatype.nexus.security.SecuritySystem;
import org.sonatype.nexus.security.anonymous.AnonymousPrincipalCollection;
import org.sonatype.nexus.security.authz.AuthorizationManager;
import org.sonatype.nexus.security.realm.RealmConfiguration;
import org.sonatype.nexus.security.user.User;
import org.sonatype.nexus.security.user.UserManager;
import org.sonatype.nexus.security.user.UserNotFoundException;



@Named(AnonRoleRealm.NAME)
@Singleton
@Description("Anonymous Role")
public class AnonRoleRealm extends AuthorizingRealm {

	private static final Logger log = LoggerFactory.getLogger(AnonRoleRealm.class);
	
	String UNKNOWN_USER = "anonymous";
	String UNKNOWN_USER_ROLE = "sa-anonymous";
	
	static final String
		UNKNOWN_USER_ROLE_PROPERTY_NAME = "AnonRoleRealm.unkonwnUserRole",
		UNKNOWN_USER_PROPERTY_NAME = "AnonRoleRealm.unkonwnUser";
		
	
	List<UserManager> userManagers;
	SecuritySystem securitySystem;
	RealmConfiguration realmConfiguration;
	AuthorizationManager authorizationManager;
	

	@Inject
	public AnonRoleRealm(final SecuritySystem securitySystem, final List<UserManager> userManagers, RealmConfiguration realmConfiguration, AuthorizationManager authorizationManager) {
		log.trace("^this(" + securitySystem + "," +  userManagers + ")");
		
		this.securitySystem = securitySystem;
		this.userManagers = userManagers;
		this.realmConfiguration = realmConfiguration;
		this.authorizationManager = authorizationManager;
	}
	
	
	public static final String NAME = "AnonRoleRealm";
	
	@Override
	protected void onInit() {
		log.info("Initializing {} realm", NAME);
		super.onInit();
	}

	
	
	@Override
	public String getName() {
		return NAME;
	}
	
	
	
	@Override
	public boolean supports(AuthenticationToken token) {
		log.trace("supprots(" + token+ ")");
		return true;
	}
	
	
	SimpleAuthorizationInfo ANON_AUTH_INFO = new SimpleAuthorizationInfo(new HashSet<String>() {
		private static final long serialVersionUID = 1L;

		{
			add(System.getProperty(UNKNOWN_USER_ROLE_PROPERTY_NAME, UNKNOWN_USER_ROLE));
		}
	});
	
	
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		log.trace(String.format("doGetAuthorizationInfo(%s)", principals));
		if (principals instanceof AnonymousPrincipalCollection) {
			return ANON_AUTH_INFO;
		}
	
		return null;
	}
	
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		log.trace(String.format("doGetAuthenticationInfo(%s)", token));
		String rutUserId = token.getPrincipal().toString();
	    SimplePrincipalCollection principals = new SimplePrincipalCollection();

		 List<String> r = realmConfiguration.getRealmNames();
		 try {
			 User u = securitySystem.getUser(rutUserId);

			  log.trace(String.format("trying find user %s in %s" , u, u.getSource()));
			 principals.add(u.getUserId(), u.getSource());
		 } catch (UserNotFoundException e) {
			 
		 }
		
		 if (!principals.isEmpty()) {
	            log.debug("Found principals for user '{}': '{}' from realms '{}'", rutUserId, principals, principals.getRealmNames());
	           
	            final SimplePrincipalCollection principalCollection = new SimplePrincipalCollection(token.getPrincipal(), getName());
	            principalCollection.addAll(principals);
	            return new SimpleAuthenticationInfo(principalCollection, null);
	     }
		 String unknownUser = System.getProperty(UNKNOWN_USER_PROPERTY_NAME, UNKNOWN_USER);
		 log.trace(String.format("Unknown user, substituting to '%s'...", unknownUser));
		 for(UserManager m: userManagers) {
			 if (! r.contains(m.getAuthenticationRealmName())) continue;
             try {
                 User u = m.getUser(unknownUser);
                 
                 log.trace(String.format("found user '%s' in %s, roles: %s", u, m, u.getRoles()));
                 principals.add(u.getUserId(), m.getAuthenticationRealmName());
                 
                 AnonymousPrincipalCollection ac = new AnonymousPrincipalCollection(u.getUserId(), m.getAuthenticationRealmName());
                 return new SimpleAuthenticationInfo(ac, null);                 
                 
             } catch (UserNotFoundException ex) {
                 log.trace(String.format("Cannot get user substituion on '%s'", unknownUser));
             }    
         };
     
     
     log.debug("No found principals for SA user '{}'", rutUserId);
     return null;	 
	}
	
	
	@Override
	public CredentialsMatcher getCredentialsMatcher() {
		return MATCHER;
	}

	
	CredentialsMatcher MATCHER  = new CredentialsMatcher() {
		
		@Override
		public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
		
			return true;
		}
	};
	
}
