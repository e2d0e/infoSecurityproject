import asyncio
from playwright.async_api import async_playwright

def test_reflected(url):
    async def detect_reflected_xss():
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

            values = ['<script>alert(1)</script>', '<img src=1 onerror=alert(1)>', r'\"-alert(1)}//']
            for value in values:
                await page.goto(url)
                await page.fill('input[name="search"]', value)
                await page.press('input[name="search"]', 'Enter')

                await page.wait_for_timeout(2000)

                if saw_alert:
                    print(f'got alert, exposed to reflected xss using {value}')
                    break
                else:
                    print(f'didnt get alert, not exposed to reflected xss using {value}')

            await browser.close()

    asyncio.run(detect_reflected_xss())
