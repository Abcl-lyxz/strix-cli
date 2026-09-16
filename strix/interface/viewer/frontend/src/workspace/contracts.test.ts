import { describe, expect, test } from "vitest";

import fixture from "../../../../../../tests/fixtures/protocol_v7_contract.json";
import { parseWorkspaceStream } from "./contracts";

describe("shared protocol v7 golden fixture", () => {
  test("normalizes the same workspace snapshot used by Python and Go", () => {
    expect(fixture.version).toBe(7);
    const stream = parseWorkspaceStream(fixture.workspace_stream);
    expect(stream?.state?.run_name).toBe("fixture-run");
    expect(stream?.agents?.[0].id).toBe("root");
    expect(stream?.events?.[0].agent_id).toBe("root");
    expect(stream?.events?.[0].data.content).toBe("checkpoint");
  });
});
