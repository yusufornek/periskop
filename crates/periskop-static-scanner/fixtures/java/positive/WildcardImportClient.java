package com.example.summaries;

import java.util.*;

import com.openai.client.*;
import com.openai.client.okhttp.OpenAIOkHttpClient;
import com.openai.models.chat.completions.ChatCompletionCreateParams;

/**
 * The client type arrives through a wildcard import.
 *
 * The platform wildcard next to it is the reason this case is worth a fixture:
 * `java.util.*` sits in a large share of Java files, and a resolver that counted
 * it as a candidate would call the package of `OpenAIClient` ambiguous and give
 * up on the one import that carries meaning.
 */
public final class WildcardImportClient {

    private final OpenAIClient client = OpenAIOkHttpClient.fromEnv();

    public String summarize(List<String> records) {
        ChatCompletionCreateParams params = ChatCompletionCreateParams.builder()
                .model("gpt-4o-mini")
                .addUserMessage(String.join("\n", records))
                .build();

        return client.chat().completions().create(params).toString();
    }
}
