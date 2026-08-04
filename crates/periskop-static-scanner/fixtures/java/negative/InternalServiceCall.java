package com.example.enrichment;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/**
 * Looks like an egress call and is not one.
 *
 * The destination is an internal service. A rule that fired here would report
 * every HTTP call in a codebase, and a report full of those trains the reader to
 * skim.
 */
public final class InternalServiceCall {

    private final HttpClient http = HttpClient.newHttpClient();

    public String enrich(String record) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://billing.internal.example/v1/enrich"))
                .POST(HttpRequest.BodyPublishers.ofString(record))
                .build();

        return http.send(request, HttpResponse.BodyHandlers.ofString()).body();
    }
}
