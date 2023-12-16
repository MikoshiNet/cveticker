"""interfaces to sources"""
import feedparser
from bs4 import BeautifulSoup
import re
import asyncio
import aiohttp

from modules.data import Dataset, Data

# pylint: disable=missing-docstring

def deduce_cve(html):
    pattern = r'(CVE-\d{4}-\d{4,7})'
    return [cve for cve in re.findall(pattern, html)] if re.search(pattern, html) else [None]


def strip_html_tags(html):
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text(separator=' ')
    return text


def pretty_for_llm(text):
    return re.sub(r'\n\s*\n', '\n', text)


async def process_entry(session, dataset, entry):
    content_html = await fetch_entry(session, entry)
    if content_html is not None:
        cves = deduce_cve(content_html)
        content_raw = strip_html_tags(content_html)
        print(Data(entry.link, pretty_for_llm(content_raw), mentioned_cves=cves))
        dataset.add(Data(entry.link, pretty_for_llm(content_raw), mentioned_cves=cves))


async def fetch_entry(session, entry) -> str:
    try:
        async with session.get(entry.link) as response:
            response.raise_for_status()
            return await response.text()
    except aiohttp.ClientError as e:
        print(f"Client error occurred: {e}")
        return None
    except aiohttp.HttpProcessingError as e:
        print(f"HTTP processing error occurred: {e}")
        return None
    except Exception as e: # pylint: disable=broad-exception-caught
        print(f"An unexpected error occurred: {e}")
        return None


async def fetch_feed(url) -> feedparser.FeedParserDict:
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            content = await response.text()
            feed = feedparser.parse(content)
            return feed


async def fetch_and_process_feed(session, url, dataset:Dataset):
    feed:feedparser.FeedParserDict = await fetch_feed(url)
    for entry in feed.entries:
        if entry.link not in dataset:
            await process_entry(session, dataset, entry)
        else:
            continue
