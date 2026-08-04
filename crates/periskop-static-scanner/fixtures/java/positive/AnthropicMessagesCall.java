package com.example.summaries;

import com.anthropic.client.AnthropicClient;
import com.anthropic.models.messages.Message;
import com.anthropic.models.messages.MessageCreateParams;
import com.anthropic.models.messages.Model;

/**
 * The official Anthropic Java SDK, with the client arriving as a parameter.
 *
 * Written this way on purpose: an injected client is the shape enterprise Java
 * takes, and the type in the signature is what makes it resolvable.
 */
public final class AnthropicMessagesCall {

    public Message summarize(AnthropicClient client, String record) {
        MessageCreateParams params = MessageCreateParams.builder()
                .model(Model.CLAUDE_SONNET_4_20250514)
                .maxTokens(1024L)
                .addUserMessage(record)
                .build();

        return client.messages().create(params);
    }
}
