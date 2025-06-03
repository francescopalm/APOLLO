from email import policy
from email.parser import BytesParser
import re
import quopri
from bs4 import BeautifulSoup
import base64


def preprocess_email(email_content):
    parser = BytesParser(policy=policy.default)
    email_message = parser.parsebytes(email_content)

    # 1. Extract subject
    subject = email_message.get('subject', "NO SUBJECT")

    # 2. Extract headers
    headers = dict(email_message.items())

    # 3. Extract body
    raw_body, content_type = extract_body(email_message)
    if raw_body.find("Content-Transfer-Encoding: quoted-printable") != -1:
        print("Quoted-printable content")
        body = quopri.decodestring(raw_body).decode("utf-8", errors="ignore")
    else: 
        body = raw_body

    # 4. Process URLs and tags
    body, urls_list = preprocessHTMLtags(body)

    # 5. Final cleaning
    body = re.sub(r" {2,}", " ", body)
    body = re.sub(r"\n{2,}", "\n", body)
    body = re.sub(r"[\u00A0\u200B\u202F]+", " ", body)  # remove common invisible Unicode characters

    return {
        "headers": headers,
        "subject": subject,
        "body": body.strip(),
        "urls": urls_list
    }

def extract_body(email_message):
    # Extract only the first text/html or text/plain body part (prefer HTML if available)
    html_body = None
    plain_body = None

    if email_message.is_multipart():
        for part in email_message.walk():
            content_type = part.get_content_type()
            if content_type == 'text/html' and html_body is None:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or 'utf-8'
                    try:
                        html_body = payload.decode(charset, errors='replace')
                    except:
                        continue
            elif content_type == 'text/plain' and plain_body is None:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or 'utf-8'
                    try:
                        plain_body = payload.decode(charset, errors='replace')
                    except:
                        continue
    else:
        payload = email_message.get_payload(decode=True)
        if payload:
            charset = email_message.get_content_charset() or 'utf-8'
            content_type = email_message.get_content_type()
            try:
                if content_type == 'text/html':
                    html_body = payload.decode(charset, errors='replace')
                elif content_type == 'text/plain':
                    plain_body = payload.decode(charset, errors='replace')
            except:
                pass

    return html_body or plain_body or "", ('text/html' if html_body else 'text/plain')


def preprocessHTMLtags(body):
    soup = BeautifulSoup(body, 'html.parser')
    urls_list = []

    for tag in soup.find_all(True):
        tag_name = tag.name.lower()
        href = tag.get("href")
        src = tag.get("src")

        if tag_name == "script":
            tag.replace_with("[SCRIPT]")
            continue

        if tag_name == "img":
            if src:
                urls_list.append(src)
                tag.replace_with(f"[IMG SRC=\"{src}\"]")
            else:
                tag.replace_with("[IMG]")
            continue

        if tag_name == "button":
            if href:
                urls_list.append(href)
                visible_string = tag.string or ""
                tag.replace_with(f"[BTN HREF=\"{href}\"] {visible_string} [/BTN]")
            else:
                tag.replace_with("[BTN]")
            continue

        if tag_name == "a":
            if href:
                if href.startswith('tel'):
                    metatag = "PHONE"
                    clean_href = re.sub(r'^tel:', '', href)
                elif href.startswith('sms'):
                    metatag = "PHONE"
                    clean_href = re.sub(r'^sms:', '', href)
                elif href.startswith('mailto'):
                    metatag = "EMAIL"
                    clean_href = re.sub(r'^mailto:', '', href)
                else:
                    metatag = "URL"
                    clean_href = href
                urls_list.append(clean_href)
                visible_string = tag.string or ""
                tag.replace_with(f'[{metatag} HREF="{clean_href}"] {visible_string} [/{metatag}]')
            continue

        # Remove all other tags except the allowed ones
        if tag_name not in ['a', 'img', 'button', 'script']:
            tag.unwrap()

    body = soup.get_text()

    # Normalize URLs to only show scheme+FQDN
    body = re.sub(
        r"(https?:\/\/|www\.)" +
        r"([-a-zA-Z0-9@:%._\-\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6})" +
        r"\b[-a-zA-Z0-9()@:%_+.~#?&\/=\-]*",
        r"\g<1>\g<2>", body)

    return body, list(set(urls_list))


def preprocess_email_body_from_string(body_string):
    decoded_bytes = base64.urlsafe_b64decode(body_string.encode("ASCII"))
    decoded_body = decoded_bytes.decode("utf-8", errors="replace")

    try:
        decoded_body = quopri.decodestring(decoded_body)
    except:
        print("already quoted-printable decoded")
    body = decoded_body.decode("utf-8", errors="ignore")
    body, urls_list = preprocessHTMLtags(body)

    # Final cleaning
    body = re.sub(r" {2,}", " ", body)
    body = re.sub(r"\n{2,}", "\n", body)
    body = body.strip()

    return {
        "body": body,
        "urls": urls_list
    }


"""
from email import parser as email_parser


def preprocess_email(email_content):
    # Parse the email content
    parser = email_parser.BytesParser()
    email_message = parser.parsebytes(email_content)

    ## Extract the subject
    subject = email_message['subject'] or "NO SUBJECT"

    ## Extract the email headers
    headers = email_message.items()
    # Convert the headers to a string
    header_string = "\n".join([f"{key}: {value}" for key, value in headers])

    ## Extract the email body
    body = ""
    if email_message.is_multipart():
        # If the email has multiple parts (e.g., text and HTML), we iterate through them
        for part in email_message.walk():
            content_type = part.get_content_type()
            if content_type == 'text/plain' or content_type == 'text/html':
              body += part.get_payload(decode=True).decode()
    else:
        # If the email is not multipart, it's a single plain text message
        body = email_message.get_payload(decode=True).decode()

    urls_list = []
    # Body pre-processing
    if body.find("Content-Transfer-Encoding: quoted-printable") != -1:
        print("Quoted-printable content")
        decoded_bytes_object = quopri.decodestring(body)
        body = decoded_bytes_object.decode("utf-8", errors="ignore")  # TODO: get the right charset

        body, urls_list = preprocessURLS(body)  # preprocesses the anchor tags in the body

        body = re.sub(r" {2,}", " ", body)  # remove duplicate blanks
        body = re.sub(r"\n{2,}", "\n", body) # remove duplicate \n chars
        # body = urllib.parse.parseqsl(body)
        # body = body.replace(r'=[0-9A-F]{2}', '')

    return {
      "headers": headers,
      "subject": subject,
      "body": body,
      "urls": urls_list
    }


def preprocessURLS(body):
    soup = BeautifulSoup(body, 'html.parser')

    urls_list = []
    # we try to find URLS in the href attribute of a, img, and div tags
    for a_tag in soup.find_all(re.compile('a|img|div', re.I)):
        href = a_tag.get("href")
        if href is not None:
            if href.startswith('tel') or href.startswith('sms'):
                metatag = "PHONE"
                href = href.replace(r'(tel|sms):', '')
            elif href.startswith('mailto'):
                metatag = "EMAIL"
                href = href.replace('mailto:', '')
            else:
                metatag = "URL"
                urls_list.append(href)
            visible_string = a_tag.string or ""
            a_tag.replace_with(f'[{metatag} HREF="{href}"] {visible_string} [/{metatag}]')

    body = soup.get_text()
    # get the initial URL part only [protocol+FQDN(fully qualified domain name)] \g<1> = protocol (+ www.), \g<2> = FQDN
    body = re.sub(
        r"(https?:\/\/|www\.)([-a-zA-Z0-9@:%._\-\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6})\b[-a-zA-Z0-9()@:%_+.~#?&\/=\-]*",
        r"\g<1>\g<2>", body)
    return body, urls_list


def preprocessURLsPlainText(body, truncate_URLs=True):
    urls_list = []
    # if needed truncate the URLs to [protocol+FQDN(fully qualified domain name)] \g<1> = protocol (+ www.), \g<2> = FQDN
    if truncate_URLs:
        body = re.sub(
            r"(https?:\/\/|www\.)([-a-zA-Z0-9@:%._\-\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6})\b[-a-zA-Z0-9()@:%_+.~#?&\/=\-]*",
            r"[URL]\g<1>\g<2>[/URL]", body)
    else:
        body = re.sub(
            r"(https?:\/\/|www\.)([-a-zA-Z0-9@:%._\-\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6})\b([-a-zA-Z0-9()@:%_+.~#?&\/=\-]*)",
            r"[URL]\g<1>\g<2>\g<3>[/URL]", body)
    for m in re.finditer(r"\[URL\]([^\[]*)\[/URL\]", body):
        url = m.group(1)
        # clean the URL if something weird happened
        url = url.removeprefix("[/RL]")
        url = url.removesuffix("[/URL]")
        # append the string to the list of strings
        urls_list.append(url)
    return body, urls_list
"""
