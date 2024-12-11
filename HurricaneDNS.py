"""
Hurricane Electric DNS library module

Inspired by EveryDNS Python library by Scott Yang:
    http://svn.fucoder.com/fucoder/pyeverydns/everydnslib.py
"""

from http.cookiejar import CookieJar

from urllib.parse import urlencode
from urllib.request import HTTPCookieProcessor, build_opener

import re
import warnings
from importlib.metadata import version
import logging
from typing import Dict, Optional, Union, List

from lxml import etree

try:
    __version__ = version("hurricanedns")
except:
    __version__ = "1.0.3"
__author__ = "Brian Hartvigsen <brian.andrew@brianandjenny.com>"
__copyright__ = "Copyright 2015, Brian Hartvigsen"
__credits__ = ["Scott Yang", "Brian Hartvigsen"]
__license__ = "MIT"

HTTP_USER_AGENT = "PyHurriceDNS/%s" % __version__
HTTP_REQUEST_PATH = "https://dns.he.net/index.cgi"

logger = logging.getLogger(__name__)


class HurricaneError(Exception):
    pass


class HurricaneAuthenticationError(HurricaneError):
    pass


class HurricaneBadArgumentError(HurricaneError):
    pass


class HurricaneDNS:
    def __init__(self, username: str, password: str, totp: Optional[str] = None):
        """
        Initialize HurricaneDNS object with username and password.

        Args:
            username (str): DNS account username
            password (str): DNS account password
            totp (str | None, optional): Two-factor authentication code. Defaults to None.
        """
        self.__account = None
        self.__cookie = CookieJar()
        self.__opener = build_opener(HTTPCookieProcessor(self.__cookie))
        self.__opener.addheaders = [("User-Agent", HTTP_USER_AGENT)]
        self.__cachedict = {}

        self.login(username, password, totp)

    def __submit(self, postdata: Optional[Union[dict, list]] = None) -> etree._Element:
        """
        Submit a request to the Hurricane DNS web interface.

        Args:
            postdata (dict | list | None, optional): Data to be posted to the web interface. Defaults to None.

        Returns:
            etree._Element: The HTML response from the web interface.
        """
        if isinstance(postdata, dict) or isinstance(postdata, list):
            postdata = urlencode(postdata).encode("UTF-8")
            # print(postdata) # debug

        response = self.__opener.open(HTTP_REQUEST_PATH, postdata)

        element = etree.HTML(response.read().decode("utf-8"))
        info = element.find('.//div[@id="dns_status"]')
        error = element.find('.//div[@id="dns_err"]')

        if info is not None:
            logger.info(info.text)

        if error is not None:
            # This is not a real error...
            if "properly delegated" in error.text:
                pass
            # elif "record already exists" in error.text.lower():
            #     pass
            else:
                raise HurricaneError(error.text)

        return element

    def __build_cache(
        self, element: Optional[etree._Element] = None
    ) -> Dict[str, Dict[str, Optional[Union[str, list]]]]:
        """
        Build a dictionary of domain information from the web interface.

        Args:
            element (etree._Element | None, optional): The HTML response from the web interface. Defaults to None.

        Returns:
            dict[str, dict[str, str | list | None]]: A dictionary of domain information, where each key is a domain name and the value is a dictionary with keys "domain", "id", "type", and "records".
        """
        if element is not None:
            logger.debug("Reading domain list from last response")
        else:
            logger.debug("Pulling domain list from remote, please wait")

            element = self.__submit()

        domain_info_dict = {}
        _list = element.findall('.//img[@alt="edit"]')
        _list += element.findall('.//img[@alt="information"]')
        for each in _list:
            info = each.findall("./../../td")
            info = info[len(info) - 1].find("img")
            domain_type = "zone"
            if each.get("menu") is not None:
                domain_type = re.match(r"edit_(.*)", each.get("menu")).group(1)
            else:
                domain_type = re.search(r"menu=edit_([a-z]+)", each.get("onclick")).group(1)

            domain_info_dict[info.get("name")] = {
                "domain": info.get("name"),
                "id": info.get("value"),
                "type": domain_type,
                "records": None,
            }

        return domain_info_dict

    def __update_domain_cache(
        self, element: Optional[etree._Element] = None
    ) -> None:
        """
        Update the domain cache dictionary with the latest information from the web interface.

        Args:
            element (etree._Element | None, optional): The HTML response from the web interface. Defaults to None.

        Returns:
            None
        """
        old = self.__cachedict
        new = self.__build_cache(element)

        for key in new:
            if key in old:
                new[key] = old[key]

        self.__cachedict = new

    def login(
        self, username: str, password: str, totp: Optional[str] = None
    ) -> bool:
        """
        Log in to the Hurricane Electric DNS web interface.

        Args:
            username (str): DNS account username
            password (str): DNS account password
            totp (str | None, optional): Two-factor authentication code. Defaults to None.

        Returns:
            bool: True if login is successful, False if not.
        """
        # check if already logged in
        if self.__account is not None:
            return True

        # Checking for a CGI session ID first?
        self.__submit()

        # Login
        try:
            element = self.__submit(
                {"email": username, "pass": password, "submit": "Login!"}
            )
        except HurricaneError:
            raise HurricaneAuthenticationError("Invalid Username/Password")

        # If two-step validation is required, perform two-step validation
        if element.find('.//input[@type="text"][@name="tfacode"]') is not None:
            try:
                element = self.__submit({"tfacode": totp, "submit": "Submit"})
            except HurricaneError:
                raise HurricaneAuthenticationError("Invalid 2FA code")

        account = element.find('.//input[@type="hidden"][@name="account"]').get("value")
        if account:
            # Getting Account Information
            self.__account = account
            # List of resolved domains
            self.__cachedict = self.__build_cache(element)
        else:
            raise HurricaneAuthenticationError("Login failure")

        return True

    @property
    def domain_list(self) -> list[str]:
        """
        List of domains associated with the account. Requires login.

        Returns:
            list[str]: List of domains associated with the account.
        """
        if not self.__cachedict:
            self.__build_cache()
        return list(self.__cachedict.keys())

    def add_domain(self, domain: str, master: Optional[Union[str, list, tuple]] = None, method: Optional[str] = None) -> None:
        """
        Add a domain to the account.

        Args:
            domain (str): The domain to add.
            master (str | list | tuple | None, optional): The master DNS server(s) for a slave zone. Defaults to None.
            method (str | None, optional): The method to use for adding a reverse zone. Defaults to None.

        Raises:
            HurricaneBadArgumentError: If the domain is a slave zone and a method is given, or vice versa.
        """
        domain = domain.lower()
        postdata = {
            "retmain": "0",
            "submit": "1",
        }

        if master and method:
            raise HurricaneBadArgumentError(
                'Domain "%s" can not be both slave and reverse' % domain
            )

        if master:
            if isinstance(master, list) or isinstance(master, tuple):
                i = 1
                for ns in master:
                    postdata["master%s" % i] = ns
                    i += 1
                    if i == 4:
                        break
            else:
                postdata["master1"] = master
            postdata["add_slave"] = domain
            postdata["action"] = "add_slave"
        elif method:
            postdata["add_reverse"] = domain
            postdata["method"] = method
            postdata["action"] = "add_reverse"
        else:
            postdata["add_domain"] = domain
            postdata["action"] = "add_zone"

        try:
            element = self.__submit(postdata)
            # Update Domain Cache
            self.__update_domain_cache(element)
        except HurricaneError as e:
            raise HurricaneBadArgumentError(e)

    def get_domain_info(self, key: str) -> Dict[str, Dict[str, Optional[Union[str, list]]]]:
        """
        Get domain information from the cache.

        Args:
            key (str): The domain name or "all" to get the entire cache.

        Returns:
            dict[str, dict[str, str | list | None]]: The domain information as a dictionary.
        """
        key = key.lower()

        if key == "all":
            # return cache dict
            return self.__cachedict
        elif key in self.__cachedict:
            # return domain info list
            return self.__cachedict[key]

        raise HurricaneBadArgumentError(f'Domain "{key}" does not exist')

    def del_domain(self, domain: str) -> None:
        """
        Delete a domain from the account.

        Args:
            domain (str): The domain to delete.

        Raises:
            HurricaneBadArgumentError: If the domain does not exist.
        """
        domain = domain.lower()
        try:
            element = self.__submit(
                {
                    "delete_id": self.get_domain_info(domain)["id"],
                    "account": self.__account,
                    "remove_domain": 1,
                }
            )
            # Update Domain Cache
            self.__update_domain_cache(element)
        except HurricaneError as e:
            raise HurricaneBadArgumentError(e)

    def cache_records(
        self,
        domain: Optional[str] = None,
        element: Optional[etree._Element] = None
    ) -> None:
        """
        Cache the records for a domain.

        Args:
            domain (str | None, optional): The domain to read records from. Defaults to None.
            element (etree._Element | None, optional): The element to read records from. Defaults to None.

        Returns:
            None
        """
        # domain and element are provided at least one
        if element is not None:
            # Find the domain name from the response
            try:
                logger.debug("--Reading records from last response--")
                d = element.find(r'.//*[@id="content"]/div/div[2]')
                domain = re.match(r"Managing zone: (.*)", d.text).group(1)
            except Exception as e:
                logger.exception(e)
                element = None
                raise HurricaneError("--Failed to read record from last response, domain is needed for cache_records--")

        domain_info = self.get_domain_info(domain)

        records = []

        if domain_info["type"] == "zone":
            if element is None:
                logger.debug("--Pulling domain record data from remote, please wait--")
                element = self.__submit(
                    {
                        "hosted_dns_zoneid": domain_info["id"],
                        "menu": "edit_zone",
                        "hosted_dns_editzone": "",
                    }
                )

            # Drop the first row as it's actually headers...
            rows = element.findall(r'.//div[@id="dns_main_content"]/table//tr')[1:]
            for r in rows:
                data = r.findall("td")
                status = re.search(r"dns_tr_(.*)", r.get("class"))
                if status:
                    status = status.group(1)

                records.append(
                    {
                        "id": data[1].text,
                        "status": status,
                        "host": data[2].text,
                        "type": data[3].find("span").get("data"),
                        "ttl": data[4].text,
                        "mx": data[5].text,
                        "value": data[6].text,
                        "extended": data[6].get("data"),
                        "ddns": data[7].text,
                    }
                )
        elif domain_info["type"] == "slave":
            if element is None:
                logger.debug("--Pulling domain record data from remote, please wait--")
                element = self.__submit(
                    {"domid": domain_info["id"], "menu": "edit_slave", "action": "edit"}
                )

            rows = element.findall(r'.//tr[@class="dns_tr"]')
            records = [
                {
                    "id": r.get("id"),
                    "status": "locked",
                    "host": r.findall("td")[0].text,
                    "type": r.findall("td")[1].text,
                    "ttl": r.findall("td")[2].text,
                    "mx": r.findall("td")[3].text,
                    "value": r.findall("td")[4].text,
                }
                for r in rows
            ]

        logger.debug("Domain %s has %s records", domain, len(records))
        self.__cachedict[domain]["records"] = records

    def get_domain_records(self, domain: str) -> List[Dict[str, Optional[str]]]:
        """
        Get a list of records for a domain.

        Args:
            domain (str): The domain name.

        Returns:
            list[dict[str, str | None]]: A list of record dictionaries, each with keys "id", "status", "host", "type", "ttl", "mx", "value", and "ddns".
        """
        domain_info = self.get_domain_info(domain)
        if domain_info["records"] is None:
            self.cache_records(domain=domain)
            domain_info = self.get_domain_info(domain)
        return domain_info["records"]

    def get_record_by_id(
        self, domain: str, record_id: str
    ) -> Dict[str, Optional[str]]:
        """
        Get a record by its ID.

        Args:
            domain (str): The domain name.
            record_id (str): The record ID.

        Returns:
            dict[str, str | None]: The record dictionary with keys "id", "status", "host", "type", "ttl", "mx", "value", and "ddns".
        """
        records = self.get_domain_records(domain)
        for r in records:
            if r["id"] == record_id:
                return r
        raise HurricaneBadArgumentError(
            f'Record {record_id} does not exist for domain "{domain}"'
        )

    def filter_records(
        self,
        domain: str,
        host: str,
        rtype: Optional[str] = None,
        value: Optional[str] = None,
        mx: Optional[str] = None,
        ttl: Optional[int] = None,
    ) -> list[dict[str, Optional[str]]]:
        """
        Filter records by criteria.

        Args:
            domain (str): The domain name.
            host (str): The host name.
            rtype (str | None, optional): The record type. Defaults to None.
            value (str | None, optional): The record value. Defaults to None.
            mx (str | None, optional): The record MX value. Defaults to None.
            ttl (int | None, optional): The record TTL value. Defaults to None.

        Returns:
            list[dict[str, str | None]]: A list of record dictionaries that match the criteria, each with keys "id", "status", "host", "type", "ttl", "mx", "value", and "ddns".
        """
        rtype = rtype.lower() if rtype else rtype
        records = self.get_domain_records(domain)
        results = []
        for r in records:
            if (
                r["host"] == host.lower()
                and (rtype is None or r["type"].lower() == rtype)
                and (value is None or r["value"] == value)
                and (mx is None or r["mx"] == mx)
                and (ttl is None or r["ttl"] == str(ttl))
            ):
                results.append(r)
        return results

    def __fullhost(self, domain: str, host: str) -> str:
        """
        Construct a fully qualified domain name from a host and a domain.

        Args:
            domain (str): The domain name.
            host (str): The host name.

        Returns:
            str: The fully qualified domain name.
        """
        if host.endswith(domain):
            h = host.lower()
        else:
            h = host + "." + domain
            h = h.lower()
        return h

    def __add_or_edit_record(
        self,
        domain: str,
        host: str,
        record_id: Optional[int] = None,
        rtype: Optional[str] = None,
        value: Optional[str] = None,
        mx: Optional[str] = None,
        ttl: Optional[int] = None,
        DDNS_key: Optional[str] = None,
    ) -> None:
        """
        Add or edit a record for a domain.

        Args:
            domain (str): The domain name.
            host (str): The host name.
            record_id (int | None): The record ID to edit. If None, a new record is created.
            rtype (str | None): The record type. Defaults to None.
            value (str | None): The record value. Defaults to None.
            mx (str | None): The record MX value. Defaults to None.
            ttl (int | None): The record TTL value. Defaults to None.
            DDNS_key (str | None): The DDNS key to use. Defaults to None.

        Returns:
            None
        """
        domain = domain.lower()
        domain_info = self.get_domain_info(domain)

        if domain_info["type"] == "slave":
            raise HurricaneBadArgumentError(
                'Domain "%s" is a slave zone, this is a bad idea!' % domain
            )

        # Create records
        try:
            element = self.__submit(
                {
                    "account": "",  # self.__account,
                    "menu": "edit_zone",
                    "hosted_dns_zoneid": domain_info["id"],
                    "hosted_dns_recordid": str(record_id) or "",
                    "hosted_dns_editzone": 1,
                    "hosted_dns_editrecord": "Update" if record_id else "Submit",
                    "Name": host.lower(),
                    "Type": rtype,
                    "Priority": mx or "",
                    "Content": value,
                    "TTL": str(ttl),
                    "dynamic": 1 if DDNS_key else 0,
                }
            )
        except HurricaneError as e:
            logger.error('Record "%s" (%s) not added or modified for domain "%s"', host, rtype, domain)

        # Submit DDNS_key
        if DDNS_key:
            try:
                element = self.__submit(
                    {
                        "account": "",  # self.__account,
                        "menu": "edit_zone",
                        "hosted_dns_zoneid": domain_info["id"],
                        "hosted_dns_recordid": str(record_id) or "",
                        "hosted_dns_editzone": 1,
                        "Name": self.__fullhost(domain, host),
                        "Key": DDNS_key,
                        "Key2": DDNS_key,
                        "generate_key": "Submit",
                    }
                )
            except HurricaneError as e:
                logger.error('Record "%s" (%s) DDNS key not modified for domain "%s"', host, rtype, domain)
                raise HurricaneBadArgumentError(e)

        # Updating the record cache
        self.cache_records(element=element)

    def add_record(
        self,
        domain: str,
        host: str,
        rtype: str,
        value: str,
        mx: Optional[str] = None,
        ttl: int = 86400,
        DDNS_key: Optional[str] = None,
    ) -> None:
        """
        Add a record for a domain.

        Args:
            domain (str): The domain name.
            host (str): The host name.
            rtype (str): The record type.
            value (str): The record value.
            mx (str | None, optional): The record MX value. Defaults to None.
            ttl (int, optional): The record TTL value. Defaults to 86400.
            DDNS_key (str | None, optional): The DDNS key to use. Defaults to None.

        Returns:
            None
        """
        self.__add_or_edit_record(domain, host, None, rtype, value, mx, ttl, DDNS_key)

    def edit_record(
        self,
        domain: str,
        host: str,
        rtype: str,
        old_value: Optional[str] = None,
        old_mx: Optional[str] = None,
        old_ttl: Optional[int] = None,
        value: Optional[str] = None,
        mx: Optional[str] = None,
        ttl: Optional[int] = None,
    ) -> None:
        """
        Edit a record for a domain.

        Args:
            domain (str): The domain name.
            host (str): The host name.
            rtype (str): The record type.
            old_value (str | None, optional): The old record value. Defaults to None.
            old_mx (str | None, optional): The old record MX value. Defaults to None.
            old_ttl (int | None, optional): The old record TTL value. Defaults to None.
            value (str | None, optional): The new record value. Defaults to None.
            mx (str | None, optional): The new record MX value. Defaults to None.
            ttl (int | None, optional): The new record TTL value. Defaults to None.

        Returns:
            None
        """
        if value is None and ttl is None and not (rtype == "MX" and mx is not None):
            raise HurricaneError(
                "You must specify one or more of value, ttl or mx priority"
            )

        record = list(
            self.filter_records(domain, host, rtype, old_value, old_mx, old_ttl)
        )
        if len(record) > 1:
            raise HurricaneBadArgumentError(
                "Criteria matches multiple records, please be more specific"
            )
        else:
            record = record[0]

        if not value:
            value = record["value"]
        if (not mx) and rtype == "MX":
            mx = record["mx"]
        if not ttl:
            ttl = int(record["ttl"])

        self.__add_or_edit_record(
            domain, host, int(record["id"]), rtype, value, mx, ttl, record["ddns"]
        )

    def del_record_by_id(self, domain: str, record_id: int) -> None:
        """
        Delete a record by its ID from a domain.

        Args:
            domain (str): The domain name.
            record_id (int): The record ID.

        Returns:
            None
        """
        domain_info = self.get_domain_info(domain.lower())
        if domain_info["type"] == "slave":
            raise HurricaneBadArgumentError(
                'Domain "%s" is a slave zone, this is a bad idea!' % domain
            )

        element = self.__submit(
            {
                "hosted_dns_zoneid": domain_info["id"],
                "hosted_dns_recordid": str(record_id),
                "menu": "edit_zone",
                "hosted_dns_delconfirm": "delete",
                "hosted_dns_editzone": 1,
                "hosted_dns_delrecord": 1,
            }
        )

        # Updating the record cache
        self.cache_records(element=element)

    def del_records(
        self,
        domain: str,
        host: str,
        rtype: Optional[str] = None,
        value: Optional[str] = None,
        mx: Optional[str] = None,
        ttl: Optional[int] = None,
    ) -> None:
        """
        Delete a record(s) from a domain.

        Args:
            domain (str): The domain name.
            host (str): The host name.
            rtype (str | None, optional): The record type. Defaults to None.
            value (str | None, optional): The record value. Defaults to None.
            mx (str | None, optional): The record MX value. Defaults to None.
            ttl (int | None, optional): The record TTL value. Defaults to None.

        Returns:
            None
        """
        domain = domain.lower()
        domain_info = self.get_domain_info(domain)
        if domain_info["type"] == "slave":
            raise HurricaneBadArgumentError(
                'Domain "%s" is a slave zone, this is a bad idea!' % domain
            )

        records = self.filter_records(domain, host, rtype, value, mx, ttl)
        logger.debug("Deleting %s record(s) from domain %s...", len(records), domain)
        for r in records:
            if r["status"] == "locked":
                logger.info("Record %s is locked, skipping...", r)
                continue
            self.del_record_by_id(domain, int(r["id"]))
