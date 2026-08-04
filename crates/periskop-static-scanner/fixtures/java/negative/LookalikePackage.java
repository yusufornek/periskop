package com.example.summaries;

import com.openaimock.client.OpenAIClient;

/**
 * The right class name from the wrong package.
 *
 * A vendored test double, imported from `com.openaimock`. Comparing package
 * prefixes as plain text would accept it, because `com.openaimock` starts with
 * the characters of `com.openai`; comparing them segment by segment does not.
 */
public final class LookalikePackage {

    private final OpenAIClient client = new OpenAIClient();

    public String summarize(Object params) {
        return client.chat().completions().create(params).toString();
    }
}
