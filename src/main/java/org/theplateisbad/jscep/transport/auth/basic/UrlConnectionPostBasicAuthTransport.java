package org.theplateisbad.jscep.transport.auth.basic;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;

import org.apache.commons.io.Charsets;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.util.encoders.Base64;
import org.jscep.transport.AbstractTransport;
import org.jscep.transport.TransportException;
import org.jscep.transport.request.PkiOperationRequest;
import org.jscep.transport.request.Request;
import org.jscep.transport.response.ScepResponseHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

final class UrlConnectionPostBasicAuthTransport extends AbstractTransport {

  private static final Logger LOGGER = LoggerFactory.getLogger(UrlConnectionPostBasicAuthTransport.class);

  private SSLSocketFactory sslSocketFactory;
  private String userInfo;

  /**
   * Creates a new <tt>HttpGetTransport</tt> with Basic authentication for the
   * given <tt>URL</tt>.
   *
   * @param url
   *          the <tt>URL</tt> with <tt>credentials</tt> to send <tt>GET</tt>
   *          requests to.
   */
  public UrlConnectionPostBasicAuthTransport(final URL url) {
    super(url);
    this.userInfo = url.getUserInfo();

    checkForTLS(url);
  }

  /**
   * Creates a new <tt>HttpGetTransport</tt> with Basic authentication for the
   * given <tt>URL</tt>.
   *
   * @param url
   *          the <tt>URL</tt> with <tt>credentials</tt> to send <tt>GET</tt>
   *          requests to.
   * @param sslSocketFactory
   *          the sslSocketFactory to be passed along https requests
   */
  public UrlConnectionPostBasicAuthTransport(final URL url, final SSLSocketFactory sslSocketFactory) {
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
    if (!PkiOperationRequest.class.isAssignableFrom(msg.getClass())) {
      throw new IllegalArgumentException("POST transport may not be used for " + msg.getOperation() + " messages.");
    }

    URL url = getUrl(msg.getOperation());
    HttpURLConnection conn;
    try {
      conn = (HttpURLConnection) url.openConnection();
      conn.setRequestMethod("POST");
      conn.setRequestProperty("Content-Type", "application/octet-stream");
      if (conn instanceof HttpsURLConnection && sslSocketFactory != null) {
        ((HttpsURLConnection) conn).setSSLSocketFactory(sslSocketFactory);
      }
      String encoded = new String(Base64.encode(userInfo.getBytes(Charsets.US_ASCII.name())), Charsets.US_ASCII.name());
      conn.setRequestProperty("Authorization", "Basic " + encoded);
    } catch (IOException e) {
      throw new TransportException(e);
    }
    conn.setDoOutput(true);

    byte[] message;
    try {
      message = Base64.decode(msg.getMessage().getBytes(Charsets.US_ASCII.name()));
    } catch (UnsupportedEncodingException e) {
      throw new RuntimeException(e);
    }

    OutputStream stream = null;
    try {
      stream = new BufferedOutputStream(conn.getOutputStream());
      stream.write(message);
    } catch (IOException e) {
      throw new TransportException(e);
    } finally {
      if (stream != null) {
        try {
          stream.close();
        } catch (IOException e) {
          LOGGER.error("Failed to close output stream", e);
        }
      }
    }

    try {
      int responseCode = conn.getResponseCode();
      String responseMessage = conn.getResponseMessage();

      LOGGER.debug("Received '{} {}' when sending {} to {}", varargs(responseCode, responseMessage, msg, url));
      if (responseCode != HttpURLConnection.HTTP_OK) {
        throw new TransportException(responseCode + " " + responseMessage);
      }
    } catch (IOException e) {
      throw new TransportException("Error connecting to server.", e);
    }

    byte[] response;
    try {
      response = IOUtils.toByteArray(conn.getInputStream());
    } catch (IOException e) {
      throw new TransportException("Error reading response stream", e);
    }

    return handler.getResponse(response, conn.getContentType());
  }

  private void checkForTLS(URL url) {
    if ("http".equalsIgnoreCase(url.getProtocol())) {
      LOGGER.warn("HTTP Basic authentication is used without SSL/TLS! Are you using a secure transport layer?");
    }
  }
}
