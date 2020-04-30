# NTLM SSO Filter

This repository contains a project that should be compiled as a jar and used as a servlet filter for NTLM SSO 


## How to use this jar

1. Get it from the repo.
1. Build it with Gradle : gradlew.bat build
1. Put the jar in the libs folder
1. Modify the web.xml of Bonita with the filter definition
1. Restart the server and check that you can connect



## web.xml
``` xml
    <filter>
        <filter-name>ntlmSsoFilter</filter-name>
		<filter-class>org.bonitasoft.auth.NtlmSsoFilter</filter-class>
    </filter>
    <filter-mapping>
        <filter-name>ntlmSsoFilter</filter-name>
        <url-pattern>/login.jsp</url-pattern>
    </filter-mapping>
```
