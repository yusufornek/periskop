// A create method on something unrelated to any provider SDK.
class RecordStore {
  create(fields: Record<string, unknown>) {
    return fields;
  }
}

const store = new RecordStore();

export function save(record: Record<string, unknown>) {
  return store.create(record);
}
