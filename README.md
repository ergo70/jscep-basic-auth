# jscep-basic-auth
Transports for jscep with HTTP Basic-Authentication.

## Requirements

This needs a working [JSCEP](https://github.com/jscep/jscep) installation.

## Installation

Just put the classes into the JSCEP source directory besides the original JSCEP code and compile.

## Usage

```java
import org.theplateisbad.jscep.transport.auth.basic.UrlConnectionBasicAuthTransportFactory;

Client client = new Client(url, handler);

client.setTransportFactory(new UrlConnectionBasicAuthTransportFactory());
```

The user credentials must be passed via the URL, like so `https://<user>:<password>@someserver.example.org`, and that is all.

## SSL / TLS

These classes do not enforce the use of SSL / TLS, because there are other means of secure transport, e.g. a VPN. However some sort of transport layer security is strongly advised when using HTTP Basic authentication, since the credentials are transferred as plain text. So, if these classes do not detect the use of HTTPS, they will issue a warning to the logging facility. If you use something other than HTTPS to secure the connection, you can safely ignore this.