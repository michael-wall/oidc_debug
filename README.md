Modules:

custom.portal.security.sso.openid.connect.impl.fragment-1.0.0.jar
custom.portal.security.sso.openid.connect.impl-1.0.0.jar

The fragment module exports some internal Liferay packages as well as exporting some com.nimbusds packages.

The other module provides a custom OSGi component implementation of OpenIdConnectAuthenticationHandler and a custom version of non-OSGi class OpenIdConnectTokenRequestUtil, both have additional DEBUG logging.

The logging level of package custom.openid.connect should be set to DEBUG to see the additional logging.



