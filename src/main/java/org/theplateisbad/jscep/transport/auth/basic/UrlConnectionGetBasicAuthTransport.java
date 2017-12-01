package org.theplateisbad.jscep.transport.auth.basic;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;

import org.apache.commons.io.Charsets;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.util.encoders.Base64;
import org.jscep.transport.AbstractTransport;
import org.jscep.transport.TransportException;
import org.jscep.transport.request.Operation;
import org.jscep.transport.request.Request;
import org.jscep.transport.response.ScepResponseHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

final class UrlConnectionGetBasicAuthTransport extends AbstractTransport {

  private static final Logger LOGGER = LoggerFactory.getLogger(UrlConnectionGetBasicAuthTransport.class);

  private SSLSocketFactory sslSocketFactory;
  private String userInfo;

  /**
   * Creates a new <tt>HttpGetTransport</tt> with Basic authentication for the given <tt>URL</tt>.
   *
   * @param url
   *          the <tt>URL</tt> with <tt>credentials</tt> to send <tt>GET</tt> requests to.
   */
  public UrlConnectionGetBasicAuthTransport(final URL url) {
    super(url);
    this.userInfo = url.getUserInfo();

    checkForTLS(url);
  }

  /**
   * Creates a new <tt>HttpGetTransport</tt> with Basic authentication for the given <tt>URL</tt>.
   *
   * @param url
   *          the <tt>URL</tt> with <tt>credentials</tt> to send <tt>GET</tt> requests to.
   * @param sslSocketFactory
   *          the sslSocketFactory to be passed along https requests
   */
  public UrlConnectionGetBasicAuthTransport(final URL url, final SSLSocketFactory sslSocketFactory) {
    super(url);

    this.sslSocketFactory = sslSocketFactory;
    this.userInfo = url.getUserInfo();

    checkForTLS(url);
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public <T> T sendRequest(final Request msg, final ScepResponseHandler<T> handler) throws TransportException {
    URL url = getUrl(msg.getOperation(), msg.getMessage());
    if (LOGGER.isDebugEnabled()) {
      LOGGER.debug("Sending {} to {}", msg, url);
    }
    HttpURLConnection conn;
    try {
      conn = (HttpURLConnection) url.openConnection();
      String encoded = new String(Base64.encode(userInfo.getBytes(Charsets.US_ASCII.name())), Charsets.US_ASCII.name());
      conn.setRequestProperty("Authorization", "Basic " + encoded);
      if (conn instanceof HttpsURLConnection && sslSocketFactory != null) {
        ((HttpsURLConnection) conn).setSSLSocketFactory(sslSocketFactory);
      }
    } catch (IOException e) {
      throw new TransportException(e);
    }

    try {
      int responseCode = conn.getResponseCode();
      String responseMessage = conn.getResponseMessage();

      LOGGER.debug("Received '{} {}' when sending {} to {}", varargs(responseCode, responseMessage, msg, url));
      if (responseCode != HttpURLConnection.HTTP_OK) {
        throw new TransportException(responseCode + " " + responseMessage);
      }
    } catch (IOException e) {
      throw new TransportException("Error connecting to server", e);
    }

    byte[] response;
    try {
      response = IOUtils.toByteArray(conn.getInputStream());
    } catch (IOException e) {
      throw new TransportException("Error reading response stream", e);
    }

    return handler.getResponse(response, conn.getContentType());
  }

  private URL getUrl(final Operation op, final String message) throws TransportException {
    try {
      return new URL(getUrl(op).toExternalForm() + "&message=" + URLEncoder.encode(message, "UTF-8"));
    } catch (MalformedURLException e) {
      throw new TransportException(e);
    } catch (UnsupportedEncodingException e) {
      throw new TransportException(e);
    }
  }

  private void checkForTLS(URL url) {
    if ("http".equalsIgnoreCase(url.getProtocol())) {
      LOGGER.warn("HTTP Basic authentication is used without SSL/TLS! Are you using a secure transport layer?");
    }
  }
}
