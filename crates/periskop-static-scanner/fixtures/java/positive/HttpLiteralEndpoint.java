package com.example.summaries;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/** No SDK anywhere: a plain stdlib POST straight at a provider endpoint. */
public final class HttpLiteralEndpoint {

    private final HttpClient http = HttpClient.newHttpClient();

    public String summarize(String record, String token) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://api.openai.com/v1/chat/completions"))
                .header("Authorization", "Bearer " + token)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(record))
                .build();

        return http.send(request, HttpResponse.BodyHandlers.ofString()).body();
    }
}
