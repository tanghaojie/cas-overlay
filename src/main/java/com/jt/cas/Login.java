package com.jt.cas;

import org.apereo.cas.authentication.AuthenticationHandlerExecutionResult;
import org.apereo.cas.authentication.Credential;
import org.apereo.cas.authentication.PreventedException;
import org.apereo.cas.authentication.UsernamePasswordCredential;
import org.apereo.cas.authentication.handler.support.AbstractPreAndPostProcessingAuthenticationHandler;
import org.apereo.cas.authentication.handler.support.AbstractUsernamePasswordAuthenticationHandler;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.services.ServicesManager;

import javax.security.auth.login.FailedLoginException;
import java.security.GeneralSecurityException;

public class Login extends AbstractUsernamePasswordAuthenticationHandler {

    public Login(String name, ServicesManager servicesManager, PrincipalFactory principalFactory, Integer order) {
        super(name, servicesManager, principalFactory, order);
    }

    @Override
    protected AuthenticationHandlerExecutionResult authenticateUsernamePasswordInternal
            (
                    UsernamePasswordCredential credential,
                    String originalPassword
            )
            throws GeneralSecurityException, PreventedException {
        String username = credential.getUsername();
        String password = credential.getPassword();
        if(username.equals("Admin") && password.equals("admin")){
            return createHandlerResult(credential, principalFactory.createPrincipal(username));
        }
        throw new FailedLoginException("必须是admin用户才允许通过");
    }

    @Override
    public boolean supports(Credential credential) {
        return super.supports(credential);
    }
}
