package com.example.summaries;

import java.lang.reflect.Method;

/**
 * Known gap: neither the class nor the method is written in the syntax tree.
 *
 * `Class.forName` takes the type as a string and `Method.invoke` takes the
 * method name as a value, so the only thing the scanner can see is a call to
 * `invoke` on something. Nothing in this source says a provider is reached, and
 * a rule that guessed from the string literal would be doing text matching with
 * a confirmed finding attached to it.
 *
 * The JVM instrumentation agent is the answer to this one: bytecode level
 * interception sees the real call regardless of how the name got there.
 *
 * Catalogued as KG-001 in the known gaps list.
 */
public final class ReflectionInvoke {

    public Object summarize(Object params, String action) throws Exception {
        Class<?> type = Class.forName("com.openai.client.OpenAIClient");
        Object client = type.getMethod("fromEnv").invoke(null);
        Method target = client.getClass().getMethod(action, params.getClass());
        return target.invoke(client, params);
    }
}
