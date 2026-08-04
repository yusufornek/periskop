package com.example.records;

import java.util.Map;

/** A create() call on something unrelated to any provider SDK. */
public final class LocalCreateMethod {

    private final RecordStore store = new RecordStore();

    public Map<String, String> save(Map<String, String> record) {
        return store.create(record);
    }
}

class RecordStore {

    Map<String, String> create(Map<String, String> fields) {
        return fields;
    }
}
