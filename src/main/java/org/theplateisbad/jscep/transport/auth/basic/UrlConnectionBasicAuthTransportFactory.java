package org.theplateisbad.jscep.transport.auth.basic;

import java.net.URL;

import javax.net.ssl.SSLSocketFactory;

import org.jscep.transport.Transport;
import org.jscep.transport.TransportFactory;
import org.jscep.transport.UrlConnectionTransportFactory;

public class UrlConnectionBasicAuthTransportFactory extends UrlConnectionTransportFactory implements TransportFactory {

  private SSLSocketFactory sslSocketFactory;

  public UrlConnectionBasicAuthTransportFactory() {
  }

  public UrlConnectionBasicAuthTransportFactory(SSLSocketFactory sslSocketFactory) {
    this.sslSocketFactory = sslSocketFactory;
  }

  @Override
  public Transport forMethod(Method method, URL url) {
      if (method == Method.GET) {
          return new UrlConnectionGetBasicAuthTransport(url, sslSocketFactory);
      } else {
          return new UrlConnectionPostBasicAuthTransport(url, sslSocketFactory);
      }
  }
}
