package com.example.summaries;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/**
 * Known gap: the destination is assembled at runtime.
 *
 * The scanner sees a variable where the endpoint should be. The host comes from
 * the environment and the path is concatenated onto it, so no literal in this
 * file names a provider. Reporting it anyway would be a claim the evidence does
 * not support, so it is not reported at all.
 *
 * Catalogued as KG-002 in the known gaps list.
 */
public final class RuntimeBuiltUrl {

    private final HttpClient http = HttpClient.newHttpClient();

    public String summarize(String record) throws Exception {
        String endpoint = System.getenv("MODEL_HOST") + "/v1/chat/completions";

        HttpRequest request = HttpRequest.newBuilder()
                .uri(new URI(endpoint))
                .POST(HttpRequest.BodyPublishers.ofString(record))
                .build();

        return http.send(request, HttpResponse.BodyHandlers.ofString()).body();
    }
}
