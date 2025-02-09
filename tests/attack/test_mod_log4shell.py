import asyncio
import os
import random
from asyncio import Event
from typing import Dict
from unittest import mock
from unittest.mock import MagicMock, mock_open, patch

import pytest
import respx
from dns.resolver import Resolver
from tests import AsyncMock
from wapitiCore.attack.attack import VULN
from wapitiCore.attack.mod_log4shell import ModuleLog4Shell
from wapitiCore.definitions.log4shell import NAME
from wapitiCore.language.vulnerability import CRITICAL_LEVEL, _
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.net.web import Request


def get_mock_open(files: Dict[str, str]):
    def open_mock(filename, *_args, **_kwargs):
        for expected_filename, content in files.items():
            if filename == expected_filename:
                return mock_open(read_data=content).return_value
        raise FileNotFoundError('(mock) Unable to open {filename}')
    return MagicMock(side_effect=open_mock)

@pytest.mark.asyncio
@respx.mock
async def test_read_headers():
    files = {
        "headers.txt": "Header1\nHeader2\n",
        "empty.txt": ""
    }

    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE")
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler = AsyncCrawler(Request("http://perdu.com/"))
    options = {"timeout": 10, "level": 2}

    module = ModuleLog4Shell(crawler, persister, options, Event())
    module.DATA_DIR = ""

    with mock.patch("builtins.open", get_mock_open(files)) as mock_open_headers:
        module.HEADERS_FILE = "headers.txt"

        headers = await module.read_headers()

        mock_open_headers.assert_called_once()

        assert len(headers) == 2
        assert headers[0] == "Header1"
        assert headers[1] == "Header2"

        module.HEADERS_FILE = "empty.txt"
        headers = await module.read_headers()

        assert len(headers) == 1


def test_get_batch_malicious_headers():
    persister = AsyncMock()
    persister.get_root_url.return_value = "http://perdu.com"
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE")
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler = AsyncCrawler(Request("http://perdu.com/"))
    options = {"timeout": 10, "level": 2}

    module = ModuleLog4Shell(crawler, persister, options, Event())

    headers = random.sample(range(0, 100), 100)
    malicious_headers, headers_uuid_record = module._get_batch_malicious_headers(headers)

    assert len(malicious_headers) == 10

    for batch_headers in malicious_headers:
        for header, payload in batch_headers.items():
            assert "${jndi:dns://" + module.dns_endpoint in payload
            assert header in headers
            assert header in headers_uuid_record
            assert str(headers_uuid_record.get(header)) in payload

@pytest.mark.asyncio
@respx.mock
async def test_verify_dns():
    class MockAnswer():
        def __init__(self, response: bool) -> None:
            self.strings = [str(response).lower().encode("utf-8")]


    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE")
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler = AsyncCrawler(Request("http://perdu.com/"))
    options = {"timeout": 10, "level": 2}

    module = ModuleLog4Shell(crawler, persister, options, Event())
    module._dns_host = ""

    with mock.patch.object(Resolver, "resolve", return_value=(MockAnswer(True),)):
        assert await module._verify_dns("foobar") is True

    with mock.patch.object(Resolver, "resolve", return_value=(MockAnswer(False),)):
        assert await module._verify_dns("foobar") is False

@pytest.mark.asyncio
@respx.mock
async def test_is_valid_dns():
    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE")
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler = AsyncCrawler(Request("http://perdu.com/"))
    options = {"timeout": 10, "level": 2}

    module = ModuleLog4Shell(crawler, persister, options, Event())

    good_dns = "foobar"
    bad_dns = "wrongdns"

    # Good DNS
    with patch("socket.gethostbyname", autospec=True) as mock_gethostbyname:
        status = module._is_valid_dns(good_dns)
        assert status
        mock_gethostbyname.assert_called_once_with(good_dns)

    # Bad DNS
    with patch("socket.gethostbyname", side_effect=OSError("error")) as mock_gethostbyname:
        status = module._is_valid_dns(bad_dns)
        assert not status

@pytest.mark.asyncio
@respx.mock
async def test_verify_headers_vuln_found():

    async def mock_verify_dns(_header_uuid: str):
        return True

    # When a vuln has been found
    with patch.object(Request, "http_repr", autospec=True) as mock_http_repr:
        persister = AsyncMock()
        home_dir = os.getenv("HOME") or os.getenv("USERPROFILE")
        base_dir = os.path.join(home_dir, ".wapiti")
        persister.CONFIG_DIR = os.path.join(base_dir, "config")

        request = Request("http://perdu.com/")
        request.path_id = 1

        crawler = AsyncCrawler(Request("http://perdu.com/"))
        options = {"timeout": 10, "level": 2}

        module = ModuleLog4Shell(crawler, persister, options, Event())

        module._verify_dns = mock_verify_dns

        modified_request = Request("http://perdu.com/")
        malicious_headers = {"Header": "payload"}
        headers_uuid_record = {"Header": "unique_id"}

        await module._verify_headers_vulnerability(modified_request, malicious_headers, headers_uuid_record)
        mock_http_repr.assert_called_once()
        persister.add_payload.assert_called_once_with(
            request_id=-1,
            payload_type=VULN,
            module="log4shell",
            category=NAME,
            level=CRITICAL_LEVEL,
            request=request,
            parameter="Header: payload",
            info=_("URL {0} seems vulnerable to Log4Shell attack by using the header {1}") \
                        .format(modified_request.url, "Header"),
            wstg=["WSTG-INPV-11"]
        )


@pytest.mark.asyncio
@respx.mock
async def test_verify_headers_vuln_not_found():

    async def mock_verify_dns(_header_uuid: str):
        return False

    #  When no vuln have been found
    with patch.object(Request, "http_repr", autospec=True) as mock_http_repr:

        persister = AsyncMock()
        home_dir = os.getenv("HOME") or os.getenv("USERPROFILE")
        base_dir = os.path.join(home_dir, ".wapiti")
        persister.CONFIG_DIR = os.path.join(base_dir, "config")

        request = Request("http://perdu.com/")
        request.path_id = 1

        crawler = AsyncCrawler(Request("http://perdu.com/"))
        options = {"timeout": 10, "level": 2}

        module = ModuleLog4Shell(crawler, persister, options, Event())

        module._verify_dns = mock_verify_dns

        modified_request = Request("http://perdu.com/")
        malicious_headers = {"Header": "payload"}
        headers_uuid_record = {"Header": "unique_id"}

        await module._verify_headers_vulnerability(modified_request, malicious_headers, headers_uuid_record)
        mock_http_repr.assert_not_called()
        persister.add_payload.assert_not_called()

@pytest.mark.asyncio
@respx.mock
async def test_must_attack():
    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE")
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler = AsyncCrawler(Request("http://perdu.com/"))
    options = {"timeout": 10, "level": 2}

    module = ModuleLog4Shell(crawler, persister, options, Event())

    module.finished = False

    assert await module.must_attack(Request("foobar"))

    module.finished = True

    assert not await module.must_attack(Request("foobar"))

@pytest.mark.asyncio
@respx.mock
async def test_attack():
    files = {
        "headers.txt": '\n'.join([str(nbr) for nbr in random.sample(range(0, 100), 100)]),
    }

    persister = AsyncMock()
    persister.get_root_url.return_value = "http://perdu.com/"
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE")
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler = AsyncMock()
    options = {"timeout": 10, "level": 2}

    request_to_attack = Request("http://perdu.com/", "GET")

    future_verify_dns = asyncio.Future()
    future_verify_dns.set_result(True)

    with mock.patch("builtins.open", get_mock_open(files)) as mock_open_headers, \
        patch.object(ModuleLog4Shell, "_verify_dns", return_value=future_verify_dns) as mock_verify_dns:
        module = ModuleLog4Shell(crawler, persister, options, Event())

        module.DATA_DIR = ""
        module.HEADERS_FILE = "headers.txt"
        await module.attack(request_to_attack)

        mock_open_headers.assert_called_once()

        # vsphere case (2) + each header batch (10) + url case (1) + druid case (1) + solr case (1)
        assert crawler.async_send.call_count == 15
        assert mock_verify_dns.call_count == 105

def test_init():
    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE")
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler = AsyncMock()
    options = {"timeout": 10, "level": 2, "dns_endpoint": None}

    # When the dns_endpoint is valid
    with patch.object(ModuleLog4Shell, "_is_valid_dns", return_value=True), \
        patch("socket.gethostbyname", autospec=True) as mock_gethostbyname:
        module = ModuleLog4Shell(crawler, persister, options, Event())

        assert mock_gethostbyname.assert_called_once
        assert not module.finished

    # When the dns_endpoint is not valid
    with patch.object(ModuleLog4Shell, "_is_valid_dns", return_value=False):
        module = ModuleLog4Shell(crawler, persister, options, Event())

        assert module.finished

    # When the dns_endpoint is None
    with patch("socket.gethostbyname", autospec=True) as mock_gethostbyname:
        module = ModuleLog4Shell(crawler, persister, options, Event())

        assert module.finished

@pytest.mark.asyncio
@respx.mock
async def test_attack_apache_struts():
    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE")
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler = AsyncMock()
    options = {"timeout": 10, "level": 2, "dns_endpoint": None}

    future_url_vulnerability = asyncio.Future()
    future_url_vulnerability.set_result(None)

    with patch.object(ModuleLog4Shell, "_verify_url_vulnerability", return_value=future_url_vulnerability) as mock_verify_url:
        module = ModuleLog4Shell(crawler, persister, options, Event())

        await module._attack_apache_struts("http://perdu.com/")

        assert crawler.async_send.assert_called_once
        assert mock_verify_url.assert_called_once

@pytest.mark.asyncio
@respx.mock
async def test_attack_apache_druid():
    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE")
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler = AsyncMock()
    options = {"timeout": 10, "level": 2, "dns_endpoint": None}

    future_url_vulnerability = asyncio.Future()
    future_url_vulnerability.set_result(None)

    with patch.object(ModuleLog4Shell, "_verify_url_vulnerability", return_value=future_url_vulnerability) as mock_verify_url:
        module = ModuleLog4Shell(crawler, persister, options, Event())

        await module._attack_apache_druid_url("http://perdu.com/")

        assert crawler.async_send.assert_called_once
        assert mock_verify_url.assert_called_once
