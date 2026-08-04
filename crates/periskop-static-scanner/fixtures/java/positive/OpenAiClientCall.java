package com.example.summaries;

import com.openai.client.OpenAIClient;
import com.openai.client.okhttp.OpenAIOkHttpClient;
import com.openai.models.ChatModel;
import com.openai.models.chat.completions.ChatCompletion;
import com.openai.models.chat.completions.ChatCompletionCreateParams;

/** The official OpenAI Java SDK, held in a field and called through the accessor chain. */
public final class OpenAiClientCall {

    private final OpenAIClient client = OpenAIOkHttpClient.fromEnv();

    public String summarize(String record) {
        ChatCompletionCreateParams params = ChatCompletionCreateParams.builder()
                .model(ChatModel.GPT_4O)
                .addUserMessage(record)
                .build();

        ChatCompletion completion = client.chat().completions().create(params);
        return completion.choices().get(0).message().content().orElse("");
    }
}
