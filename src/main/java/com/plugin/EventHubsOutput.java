package com.plugin;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import okhttp3.*;
import okio.BufferedSink;
import okio.GzipSink;
import okio.Okio;
import org.apache.commons.collections.FastArrayList;
import org.apache.commons.collections4.ListUtils;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.configuration.ConfigurationRequest;
import org.graylog2.plugin.configuration.fields.BooleanField;
import org.graylog2.plugin.configuration.fields.ConfigurationField;
import org.graylog2.plugin.configuration.fields.TextField;
import org.graylog2.plugin.outputs.MessageOutput;
import org.graylog2.plugin.streams.Stream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.google.inject.Inject;
import com.google.inject.assistedinject.Assisted;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * This is the plugin. Your class should implement one of the existing plugin
 * interfaces. (i.e. AlarmCallback, MessageInput, MessageOutput)
 */
public class EventHubsOutput implements MessageOutput {

    public static final int HTTP_BATCH_SIZE = 500;
    private final OkHttpClient httpClient;
    private final Gson gson = new Gson();
    private boolean shutdown;
    private String url;
    private String sasKey;
    private String sasValue;
    private static final String CK_OUTPUT_API = "output_api";
    private static final String CK_SAS_KEY = "sas_key";
    private static final String CK_SAS_VALUE = "sas_value";
    private static final String CK_GZIP_REQUEST = "gzip_request";
    private static final Logger LOG = LoggerFactory.getLogger(EventHubsOutput.class);
    private static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");

    /**
     * This interceptor compresses the HTTP request body. Many webservers can't
     * handle this!
     * <p>
     * taken from https://square.github.io/okhttp/interceptors/
     */
    final class GzipRequestInterceptor implements Interceptor {
        @Override
        public Response intercept(Interceptor.Chain chain) throws IOException {
            Request originalRequest = chain.request();
            if (originalRequest.body() == null || originalRequest.header("Content-Encoding") != null) {
                return chain.proceed(originalRequest);
            }

            Request compressedRequest = originalRequest.newBuilder().header("Content-Encoding", "gzip")
                    .method(originalRequest.method(), gzip(originalRequest.body())).build();
            return chain.proceed(compressedRequest);
        }

        private RequestBody gzip(final RequestBody body) {
            return new RequestBody() {
                @Override
                public MediaType contentType() {
                    return body.contentType();
                }

                @Override
                public long contentLength() {
                    return -1; // We don't know the compressed length in advance!
                }

                @Override
                public void writeTo(BufferedSink sink) throws IOException {
                    BufferedSink gzipSink = Okio.buffer(new GzipSink(sink));
                    body.writeTo(gzipSink);
                    gzipSink.close();
                }
            };
        }
    }

    @Inject
    public EventHubsOutput(@Assisted Stream stream, @Assisted Configuration conf) throws EventHubsOutputException {

        this.url = conf.getString(CK_OUTPUT_API);
        this.sasKey = conf.getString(CK_SAS_KEY);
        this.sasValue = conf.getString(CK_SAS_VALUE);

        this.shutdown = false;
        LOG.info(" Azure EventHubs Output Plugin has been configured with the following parameters:");
        LOG.info(CK_OUTPUT_API + " : " + this.url);
        LOG.info(CK_GZIP_REQUEST + " : " + conf.getBoolean(CK_GZIP_REQUEST));

        try {
            new URL(this.url);
        } catch (MalformedURLException e) {
            LOG.info("Error in the given API", e);
            throw new EventHubsOutputException("Error while constructing the API.", e);
        }

        OkHttpClient.Builder clientBuilder = new OkHttpClient.Builder().connectTimeout(10, TimeUnit.SECONDS)
                .writeTimeout(10, TimeUnit.SECONDS).readTimeout(5, TimeUnit.SECONDS);

        if (conf.getBoolean(CK_GZIP_REQUEST)) {
            clientBuilder.addInterceptor(new GzipRequestInterceptor());
        }
        this.httpClient = clientBuilder.build();
    }

    @Override
    public boolean isRunning() {
        return !this.shutdown;
    }

    @Override
    public void stop() {
        this.shutdown = true;

    }

    @Override
    public void write(List<Message> msgs) throws Exception {

        for (List<Message> partition : ListUtils.partition(msgs, HTTP_BATCH_SIZE)) {
            List<Map<String, Object>> payload = new FastArrayList();
            for (Message msg : partition) {
                payload.add(msg.getFields());
            }
            this.executeRequest(RequestBody.create(JSON, this.gson.toJson(payload)));
        }

    }

    @Override
    public void write(Message msg) throws Exception {

        this.executeRequest(RequestBody.create(JSON, this.gson.toJson(msg.getFields())));
    }

    private void executeRequest(RequestBody requestBody) throws EventHubsOutputException, IOException {
        if (this.shutdown) {
            return;
        }

        Request request = new Request.Builder().url(this.url)
                .addHeader("Authorization", this.getSASToken(this.url, this.sasKey, this.sasValue)).post(requestBody)
                .build();

        // ensure the response (and underlying response body) is closed
        try (Response response = this.httpClient.newCall(request).execute()) {
            if (response.code() < 200 || response.code() >= 300) {
                LOG.info("Unexpected HTTP response status " + response.code());
                throw new EventHubsOutputException("Unexpected HTTP response status " + response.code());
            }
        }
    }

    private String getSASToken(String resourceUri, String keyName, String key) {
        long epoch = System.currentTimeMillis() / 1000L;
        int week = 60 * 60 * 24 * 7;
        String expiry = Long.toString(epoch + week);

        String sasToken = null;
        try {
            String stringToSign = URLEncoder.encode(resourceUri, "UTF-8") + "\n" + expiry;
            String signature = getHMAC256(key, stringToSign);
            sasToken = "SharedAccessSignature sr=" + URLEncoder.encode(resourceUri, "UTF-8") + "&sig="
                    + URLEncoder.encode(signature, "UTF-8") + "&se=" + expiry + "&skn=" + keyName;
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        return sasToken;
    }

    public String getHMAC256(String key, String input) {
        Mac sha256_HMAC = null;
        String hash = null;
        try {
            sha256_HMAC = Mac.getInstance("HmacSHA256");
            SecretKeySpec secret_key = new SecretKeySpec(key.getBytes(), "HmacSHA256");
            sha256_HMAC.init(secret_key);
            Base64.Encoder encoder = Base64.getEncoder();

            hash = new String(encoder.encode(sha256_HMAC.doFinal(input.getBytes("UTF-8"))));

        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IllegalStateException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        return hash;
    }

    public interface Factory extends MessageOutput.Factory<EventHubsOutput> {
        @Override
        EventHubsOutput create(Stream stream, Configuration configuration);

        @Override
        Config getConfig();

        @Override
        Descriptor getDescriptor();
    }

    public static class Descriptor extends MessageOutput.Descriptor {
        public Descriptor() {
            super("EventHubsOutput Output", false, "", "Forwards stream to Azure EventHubs.");
        }
    }

    public static class Config extends MessageOutput.Config {
        @Override
        public ConfigurationRequest getRequestedConfiguration() {
            final ConfigurationRequest configurationRequest = new ConfigurationRequest();

            configurationRequest.addField(new TextField(CK_OUTPUT_API, "API to forward the stream data.", "/",
                    "HTTP address where the stream data to be sent.", ConfigurationField.Optional.NOT_OPTIONAL));

            configurationRequest.addField(
                    new TextField(CK_SAS_KEY, "SAS key name. (skn)", "", "", ConfigurationField.Optional.NOT_OPTIONAL));

            configurationRequest.addField(new TextField(CK_SAS_VALUE, "SAS key.", "", "Primary or secondary key",
                    ConfigurationField.Optional.NOT_OPTIONAL));

            configurationRequest.addField(new BooleanField(CK_GZIP_REQUEST, "GZIP request", false,
                    "Enable GZIP compression for HTTP requests."));

            return configurationRequest;
        }
    }

    public class EventHubsOutputException extends Exception {

        private static final long serialVersionUID = -5301266791901423492L;

        public EventHubsOutputException(String msg) {
            super(msg);
        }

        public EventHubsOutputException(String msg, Throwable cause) {
            super(msg, cause);
        }

    }
}
