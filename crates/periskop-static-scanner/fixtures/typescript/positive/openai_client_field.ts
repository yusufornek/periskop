// The client kept in a class field rather than a module level const.
//
// Both spellings appear here on purpose: the field written as a class property
// and the field written as an assignment to `this` in the constructor are
// different nodes in the tree and the same value at the call site, so a resolver
// that saw only one of them would still walk past half of this shape.
import OpenAI from "openai";

export class Summariser {
  private client = new OpenAI();

  async summarise(record: string) {
    return this.client.chat.completions.create({
      model: "gpt-4",
      messages: [{ role: "user", content: record }],
    });
  }
}

export class Translator {
  private client: OpenAI;

  constructor() {
    this.client = new OpenAI();
  }

  async translate(record: string) {
    return this.client.chat.completions.create({
      model: "gpt-4",
      messages: [{ role: "user", content: record }],
    });
  }
}
