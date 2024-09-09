**Introduction**

The fragment module exports some internal Liferay OIDC packages as well as exporting some com.nimbusds packages.

The other module provides a custom OSGi component implementation of OpenIdConnectAuthenticationHandler interface and a custom version of non-OSGi class OpenIdConnectTokenRequestUtil. Both of these classes have additional DEBUG logging.

Both custom classes are based on the DXP 7.4 U92 versions and have been tested locally with JDK 8.

**Modules**

1. custom.portal.security.sso.openid.connect.impl.fragment-1.0.0.jar
2. custom.portal.security.sso.openid.connect.impl-1.0.0.jar

**Configuration**
1. Blacklist the following component: com.liferay.portal.security.sso.openid.connect.internal.OpenIdConnectAuthenticationHandlerImpl
2. Change the logging level of package custom.openid.connect to DEBUG to see the additional logging.



