import asyncio
from playwright.async_api import async_playwright

def test_alert(url):
    async def detect_xss():
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()

            # to detect an alert event - we need to listen to "dialog" in the page
            saw_alert = False
            async def on_dialog(dialog):
                nonlocal saw_alert
                if dialog.type == "alert" and dialog.message == "1":
                    saw_alert = True
                await dialog.dismiss() #close the popup

            page.on("dialog", on_dialog)

            await page.goto(url)

            # 3) Wait up to `timeout_ms` for any "alert"
            #    If an alert shows immediately on page load, on_dialog() flips saw_alert.
            try:
                # Wait for either a dialog event or just a timeout
                await page.wait_for_timeout(5000)
            except TimeoutError:
                # If wait_for_timeout ever throws (rare), ignore it.
                pass
            await browser.close()

            return saw_alert

    return asyncio.run(detect_xss())
