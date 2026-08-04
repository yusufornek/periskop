"""A create() call on something unrelated to any provider SDK."""


class RecordStore:
    def create(self, **fields):
        return fields


store = RecordStore()


def save(record):
    return store.create(payload=record)
