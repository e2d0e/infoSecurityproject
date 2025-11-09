const { chromium } = require("playwright");

(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();

  // Navigate (invisibly) to the form page
  await page.goto("https://0a82000c03a5a7248161163700f60062.web-security-academy.net/post?postId=5");

  // Auto‑fill every field
  await page.fill('textarea[name="comment"]', 'stam');
  await page.fill('input[name = "name"]', 'eden')
  await page.fill('input[name="email"]', 'e2d0e0n4@gmail.com')
  await page.fill('input[name="website"]', '');

  // Submit and wait for the result

  const [response] = await Promise.all([
    page.waitForNavigation(),
    page.click('button[type="submit"]')
  ]);


  console.log("Status:", response.status());
  console.log("Redirected to:", page.url());

  await browser.close();
})();
