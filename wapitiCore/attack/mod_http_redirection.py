#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti.sourceforge.io)
# Copyright (C) 2009-2021 Nicolas Surribas
#
# Original authors :
# Anthony DUBOCAGE
# Guillaume TRANCHANT
# Gregory FONTAINE
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
from os.path import splitext
from urllib.parse import urljoin

from httpx import RequestError

from wapitiCore.main.log import log_red
from wapitiCore.attack.attack import Attack
from wapitiCore.language.vulnerability import _
from wapitiCore.definitions.http_redirection import NAME
from wapitiCore.net.web import Request
from wapitiCore.net.crawler import AsyncCrawler


class ModuleHttpRedirection(Attack):
    """
    Check if credentials are transported on an encrypted channel.
    """

    name = "http_redirection"

    do_get = False
    do_post = False

    def __init__(self, crawler: AsyncCrawler, persister, attack_options, stop_event):
        super().__init__(crawler, persister, attack_options, stop_event)
        self.root_url = None

    # vérifier la location et pas le code http (301)
    # vérifier l'https
    #

    async def must_attack(self, request: Request):
        if self.root_url is None:
            self.root_url = await self.persister.get_root_url()

        if self.finished:
            return False

        if request.method == "POST":
            return False

        return True
        # return "https" not in request.url and request.url == await self.persister.get_root_url()

    async def attack(self, request: Request):
        self.finished = True
        self.crawler: AsyncCrawler = self.crawler

        try:
            response = await self.crawler.async_send(request, follow_redirects=False)
        except RequestError:
            self.network_errors += 1
            return
        if not request.url.startswith(self.root_url) or \
            len(self.crawler.auth_credentials) != 2 or \
            request.url.startswith("https://"):
        # if response.status == 301 or len(self.crawler.auth_credentials) != 2:
            return

        await self.add_vuln_medium(
            request_id=request.path_id,
            category=NAME,
            request=request,
            info=_("Credentials are transported over an Unencrypted Channel")
        )

        log_red("---")
        log_red(_("Credentials are transported over an Unencrypted Channel"))
        log_red(request.http_repr())
        log_red("---")
