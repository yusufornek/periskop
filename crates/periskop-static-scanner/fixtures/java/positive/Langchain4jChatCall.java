package com.example.summaries;

import dev.langchain4j.model.chat.ChatModel;
import dev.langchain4j.model.openai.OpenAiChatModel;

/** langchain4j, built with a builder and called through the framework interface. */
public final class Langchain4jChatCall {

    private final ChatModel model = OpenAiChatModel.builder()
            .apiKey(System.getenv("OPENAI_API_KEY"))
            .modelName("gpt-4o-mini")
            .build();

    public String summarize(String record) {
        return model.chat(record);
    }
}
