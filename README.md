# jscep-basic-auth
Transports for [jscep](https://github.com/jscep/jscep) with HTTP Basic authentication.

## Requirements

This needs a working [jscep](https://github.com/jscep/jscep) installation.

## Installation

Just put the classes into the jscep source directory alongside the original code and compile.

## Usage

```java
import org.theplateisbad.jscep.transport.auth.basic.UrlConnectionBasicAuthTransportFactory;

Client client = new Client(url, handler);

client.setTransportFactory(new UrlConnectionBasicAuthTransportFactory());
```

The user credentials must be passed via the URL, like so `https://<user>:<password>@someserver.example.org`, and that is all. Seriously, do not pass such an URL from the outside, but rather construct it at runtime.

## SSL / TLS

These classes do not enforce the use of SSL / TLS, because there are other means of secure transport, e.g. a VPN. However some sort of transport layer security is strongly advised when using HTTP Basic authentication, since the credentials are transferred as plain text. So, if these classes do not detect the use of HTTPS, they will issue a warning to the logging facility. If you use something other than HTTPS to secure the connection, you can safely ignore this.
