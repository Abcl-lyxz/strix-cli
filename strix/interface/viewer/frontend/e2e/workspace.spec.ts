import { test, expect } from "@playwright/test";
test("multiline draft, offline retry, forms, and narrow viewport", async ({
  page,
}) => {
  const sends: any[] = [];
  await page.addInitScript(() => {
    class Stream {
      onopen: any;
      onmessage: any;
      onerror: any;
      constructor() {
        setTimeout(() => {
          this.onopen?.();
          this.onmessage?.({
            data: JSON.stringify({
              reset: true,
              state: { setup_mode: true },
              events: [],
              agents: [],
              findings: [],
              attachments: [],
            }),
          });
        }, 40);
      }
      close() {}
    }
    (window as any).EventSource = Stream;
  });
  await page.route("**/api/**", async (route) => {
    const body = route.request().postDataJSON() || {};
    if (body.command === "scan.submit") {
      sends.push(body);
      if (sends.length === 1)
        return route.fulfill({
          status: 503,
          json: { error: "Synthetic disconnect" },
        });
    }
    return route.fulfill({
      json:
        body.command === "providers.list"
          ? { providers: [{ id: "custom", name: "Custom gateway" }] }
          : { sent: true },
    });
  });
  await page.goto("/");
  const prompt = page.getByRole("textbox", { name: "Prompt" });
  await prompt.fill("/baseurl pasted content\n  Unicode ไทย 🧪\n\nlast line");
  await prompt.press("End");
  await prompt.press("Enter");
  expect(sends).toHaveLength(0);
  await prompt.press("Control+s");
  await expect(page.getByRole("alert")).toContainText("Synthetic disconnect");
  await expect(prompt).toHaveValue(/last line/);
  await prompt.press("Control+s");
  await expect(prompt).toHaveValue("");
  expect(sends[0].request_id).toBe(sends[1].request_id);
  await page.getByRole("button", { name: "Connect provider" }).click();
  await page.getByRole("button", { name: "Custom gateway" }).click();
  await expect(page.getByLabel("API key")).toHaveAttribute("type", "password");
  await page.setViewportSize({ width: 500, height: 750 });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  await page.screenshot({
    path: "../../../../build/workspace-provider-mobile.png",
    fullPage: true,
  });
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await page.setViewportSize({ width: 1400, height: 920 });
  await page.screenshot({
    path: "../../../../build/workspace-desktop.png",
    fullPage: true,
  });
});
