/*
const { chromium } = require("playwright");


async function fillForm(url, fields, values, button)
{
    console.log("hi");
    const browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    await page.goto(url);

    for(let i = 0; i < fields.length; i++)
    {
        const [tag, name] = fields[i];

        const value = values[i];
        const selector = `${tag}[name="${name}"]`;
        try
        {
            console.log(`selector=${selector}, value=${value}`)
            await page.fill(selector, value);
        }
        catch (e)
        {
            console.error('could not fill selector')
        }
    }

    const [resp] = await Promise.all([
  page.waitForResponse(r => {
      const req = r.request;
      if (req.method !== "POST") return false;

      try
      {
          const reqUrl = new URL(req.url());
          return reqUrl.origin === new URL(url).origin;
      }
      catch{
          return false;
      }
    }
  , { timeout: 5000 }),

  page.click(button)
]);
    /*
    const [response] = await Promise.all([
    page.waitForNavigation(),
    page.click(button)
  ]);

    const result = {
        status: resp?.status?.() ?? null,
        finalUrl: page.url(),
        content: await page.content()
    };

    await browser.close();
    console.log(JSON.stringify(result));
}

async function main(){
    const [, , url, fieldsJson, valuesJson, buttonSelector] = process.argv;

  if (!url || !fieldsJson || !valuesJson || !buttonSelector) {
    console.error("Usage: node fillForm.js <url> <fieldsJson> <valuesJson> <buttonSelector>");
    process.exit(1);
  }

  let fields, values;
  try {
    fields = JSON.parse(fieldsJson);
    values = JSON.parse(valuesJson);
  } catch (e) {
    console.error("Invalid JSON input:", e.message);
    process.exit(1);
  }

  await fillForm(url, fields, values, buttonSelector);
}

main().catch(err => {
  console.error("Fatal error in main():", err);
  process.exit(1);
});
*/

const { chromium } = require("playwright");

/**
 * Fills the given fields, clicks the button, and returns the server’s reply.
 *
 * @param {string} url
 * @param {Array<[string, string]>} fields    e.g. [["input","name"],["textarea","comment"]]
 * @param {string[]} values                   e.g. ["alice", "hello there"]
 * @param {string} buttonSelector             e.g. 'button[type="submit"]'
 */
async function fillForm(url, fields, values, buttonSelector) {
  console.log("▶️ fillForm called for", url);

  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();

  // 1) Navigate to the page
  await page.goto(url, { waitUntil: "domcontentloaded" });

  // 2) Fill all fields
  for (let i = 0; i < fields.length; i++) {
    const [tag, name] = fields[i];
    const selector = `${tag}[name="${name}"]`;
    const value = values[i] || "";

    try {
      console.log(`  → Filling ${selector} with "${value}"`);
      await page.fill(selector, value);
    } catch (err) {
      console.error(`  ⚠️ could not fill ${selector}: ${err.message}`);
    }
  }

  // 3) Click the button and catch any same-origin POST response
  let resp = null;
  try {
    [resp] = await Promise.all([
      page.waitForResponse(r => {
        const req = r.request();
        if (req.method() !== "POST") return false;
        try {
          const reqUrl = new URL(req.url());
          return reqUrl.origin === new URL(url).origin;
        } catch {
          return false;
        }
      }, { timeout: 5000 }),
      page.click(buttonSelector),
    ]);
    console.log("  ✅ Captured a POST response:", resp.request().url());
  } catch {
    console.log("  ℹ️ No matching POST detected within 5s; falling back to networkidle.");
    await page.click(buttonSelector);
    await page.waitForLoadState("networkidle", { timeout: 10000 });
  }

  // 4) Build and log the result
  const result = {
    status:   resp ? resp.status() : null,
    finalUrl: page.url(),
    content:  await page.content()
  };

  await browser.close();
  console.log("▶️ Result:", JSON.stringify(result));
  return result;
}

async function main() {
  const [, , url, fieldsJson, valuesJson, buttonSelector] = process.argv;

  if (!url || !fieldsJson || !valuesJson || !buttonSelector) {
    console.error("Usage: node submitForm.js <url> <fieldsJson> <valuesJson> <buttonSelector>");
    process.exit(1);
  }

  let fields, values;
  try {
    fields = JSON.parse(fieldsJson);
    values = JSON.parse(valuesJson);
  } catch (e) {
    console.error("Invalid JSON input:", e.message);
    process.exit(1);
  }

  await fillForm(url, fields, values, buttonSelector);
}

main().catch(err => {
  console.error("Fatal error in main():", err);
  process.exit(1);
});
