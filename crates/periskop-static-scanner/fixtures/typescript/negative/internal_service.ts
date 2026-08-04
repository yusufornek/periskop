// Looks like egress and is not. The destination is an internal service.
export async function enrich(record: unknown) {
  return fetch("https://billing.internal.example/v1/enrich", {
    method: "POST",
    body: JSON.stringify(record),
  });
}
