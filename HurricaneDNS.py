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


class HurricaneError(Exception):
    pass


class HurricaneAuthenticationError(HurricaneError):
    pass


class HurricaneBadArgumentError(HurricaneError):
    pass


class HurricaneDNS:
    def __init__(self, username, password, totp=None):
        self.__account = None
        self.__cookie = CookieJar()
        self.__opener = build_opener(HTTPCookieProcessor(self.__cookie))
        self.__opener.addheaders = [("User-Agent", HTTP_USER_AGENT)]

        self.__cachedict = {}
        """
        __cachedb = {
            "domain": domain name,
            "id": domain ID,
            "type": domain type,
            "records": ...,
        }
        """

        self.login(username, password, totp)

    def __submit(self, data=None):
        if isinstance(data, dict) or isinstance(data, list):
            data = urlencode(data).encode("UTF-8")

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            response = self.__opener.open(HTTP_REQUEST_PATH, data)
            element = etree.HTML(response.read().decode("utf-8"))

        error = element.find('.//div[@id="content"]/div/div[@id="dns_err"]')

        if error is not None:
            # This is not a real error...
            if "properly delegated" in error.text:
                pass
            elif "record already exists" in error.text.lower():
                pass
            else:
                raise HurricaneError(error.text)

        return element

    def login(self, username, password, totp=None):
        # 检查是否已登录
        if self.__account is not None:
            return True

        # 先喊一声拿个 CGI Session ID
        self.__submit()

        # 提交登录表单
        try:
            element = self.__submit(
                {"email": username, "pass": password, "submit": "Login!"}
            )
        except HurricaneError:
            raise HurricaneAuthenticationError("Invalid Username/Password")

        # 如果需要两步验证，则进行两步验证
        if element.find('.//input[@type="text"][@name="tfacode"]') is not None:
            try:
                element = self.__submit({"tfacode": totp, "submit": "Submit"})
            except HurricaneError:
                raise HurricaneAuthenticationError("Invalid 2FA code")

        account = element.find('.//input[@type="hidden"][@name="account"]').get("value")
        if account:
            # 获取账户信息
            self.__account = account
            # 解析域名列表
            self.__reset_cache(element)
        else:
            raise HurricaneAuthenticationError("Login failure")

        return True

    def __reset_cache(self, element=None):
        if element is not None:
            print("Will set cache from last response.")
        else:
            element = self.__submit()

        domains = {}
        _list = element.findall('.//img[@alt="edit"]')
        _list += element.findall('.//img[@alt="information"]')
        for each in _list:
            info = each.findall("./../../td")
            info = info[len(info) - 1].find("img")
            domain_type = "zone"
            if each.get("menu") is not None:
                domain_type = re.match(r"edit_(.*)", each.get("menu")).group(1)
            else:
                domain_type = re.search(
                    r"menu=edit_([a-z]+)", each.get("onclick")
                ).group(1)

            domains[info.get("name")] = {
                "domain": info.get("name"),
                "id": info.get("value"),
                "type": domain_type,
                "records": None,
            }

        self.__cachedict = domains
        # return domains

    @property
    def domain_list(self):
        if not self.__cachedict:
            self.__reset_cache()
        return self.__cachedict

    def get_domain(self, domain):
        domain = domain.lower()
        if domain in self.domain_list:
            return self.domain_list[domain]
        else:
            raise HurricaneBadArgumentError('Domain "%s" does not exist' % domain)

    def add_domain(self, domain, master=None, method=None):
        domain = domain.lower()
        data = {"retmain": 0, "submit": 1}

        if master and method:
            raise HurricaneBadArgumentError(
                'Domain "%s" can not be both slave and reverse' % domain
            )

        if master:
            if isinstance(master, list) or isinstance(master, tuple):
                i = 1
                for ns in master:
                    data["master%s" % i] = ns
                    i += 1
                    if i == 4:
                        break
            else:
                data["master1"] = master
            data["add_slave"] = domain
            data["action"] = "add_slave"
        elif method:
            data["add_reverse"] = domain
            data["method"] = method
            data["action"] = "add_reverse"
        else:
            data["add_domain"] = domain
            data["action"] = "add_zone"

        try:
            element = self.__submit(data)
            # 更新域名缓存
            self.__reset_cache(element)
        except HurricaneError as e:
            raise HurricaneBadArgumentError(e)

    def del_domain(self, domain):
        domain = domain.lower()
        try:
            element = self.__submit(
                {
                    "delete_id": self.get_domain(domain)["id"],
                    "account": self.__account,
                    "remove_domain": 1,
                }
            )
            # 更新域名缓存
            self.__reset_cache(element)
        except HurricaneError as e:
            raise HurricaneBadArgumentError(e)

    def cache_records(self, domain=None, element=None):
        # domain 和 element 至少提供一个
        if element is not None:
            try:
                d = element.find('.//*[@id="content"]/div/div[2]')
                domain = re.match(r"Managing zone: (.*)", d.text).group(1)
                print("Will cache records from last response.")
            except Exception as e:
                print(e)
                element = None
        domain_info = self.get_domain(domain)
        records = []

        if domain_info["type"] == "zone":
            if element is not None:
                element = self.__submit(
                    {
                        "hosted_dns_zoneid": domain_info["id"],
                        "menu": "edit_zone",
                        "hosted_dns_editzone": "",
                    }
                )

            # Drop the first row as it's actually headers...
            rows = element.findall('.//div[@id="dns_main_content"]/table//tr')[1:]
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
                    }
                )
        elif domain_info["type"] == "slave":
            if element is not None:
                element = self.__submit(
                    {"domid": domain_info["id"], "menu": "edit_slave", "action": "edit"}
                )

            rows = element.findall('.//tr[@class="dns_tr"]')
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

        self.__cachedict[domain]["records"] = records

    def get_records_by_domain(self, domain):
        domain_info = self.get_domain(domain)
        if not domain_info["records"]:
            self.cache_records(domain=domain)
            domain_info = self.get_domain(domain)
        return domain_info["records"]

    def get_record_by_id(self, domain, record_id):
        # no use yet
        records = self.get_records_by_domain(domain)
        for r in records:
            if r["id"] == record_id:
                return r
        raise HurricaneBadArgumentError(
            f'Record {record_id} does not exist for domain "{domain}"'
        )

    def filter_records(self, domain, host, rtype=None, value=None, mx=None, ttl=None):
        rtype = rtype.lower() if rtype else rtype
        records = self.get_records_by_domain(domain)
        results = []
        for r in records:
            if (
                r["host"] == host
                and (rtype is None or r["type"].lower() == rtype)
                and (value is None or r["value"] == value)
                and (mx is None or r["mx"] == mx)
                and (ttl is None or r["ttl"] == ttl)
            ):
                results.append(r)
        return results

    def __add_or_edit_record(self, domain, record_id, host, rtype, value, mx, ttl):
        domain = domain.lower()
        d = self.get_domain(domain)

        if d["type"] == "slave":
            raise HurricaneBadArgumentError(
                'Domain "%s" is a slave zone, this is a bad idea!' % domain
            )

        try:
            element = self.__submit(
                {
                    "account": "",  # self.__account,
                    "menu": "edit_zone",
                    "hosted_dns_zoneid": d["id"],
                    "hosted_dns_recordid": record_id or "",
                    "hosted_dns_editzone": 1,
                    "hosted_dns_editrecord": "Update" if record_id else "Submit",
                    "Name": host.lower(),
                    "Type": rtype,
                    "Priority": mx or "",
                    "Content": value,
                    "TTL": ttl,
                    "dynamic": 1,
                }
            )
        except HurricaneError as e:
            raise HurricaneBadArgumentError(e)

        if element.find('.//div[@id="dns_err"]') is not None:
            # this should mean duplicate records
            pass
        elif element.find('.//div[@id="dns_status"]') is None:
            raise HurricaneBadArgumentError(
                f'Record "{host}" ({rtype}) not added or modified for domain "{domain}"'
            )

        # 更新记录缓存
        self.cache_records(element=element)

    def add_record(self, domain, host, rtype, value, mx=None, ttl=86400):
        self.__add_or_edit_record(domain, None, host, rtype, value, mx, ttl)

    def edit_record(
        self,
        domain,
        host,
        rtype,
        old_value=None,
        old_mx=None,
        old_ttl=None,
        value=None,
        mx=None,
        ttl=None,
    ):
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
            ttl = record["ttl"]

        self.__add_or_edit_record(domain, record["id"], host, rtype, value, mx, ttl)

    def del_record(self, domain, record_id):
        d = self.get_domain(domain.lower())
        if d["type"] == "slave":
            raise HurricaneBadArgumentError(
                'Domain "%s" is a slave zone, this is a bad idea!' % domain
            )

        self.__submit(
            {
                "hosted_dns_zoneid": d["id"],
                "hosted_dns_recordid": record_id,
                "menu": "edit_zone",
                "hosted_dns_delconfirm": "delete",
                "hosted_dns_editzone": 1,
                "hosted_dns_delrecord": 1,
            }
        )

        # 更新记录缓存
        self.cache_records(element=element)

    def del_records(self, domain, host, rtype=None, value=None, mx=None, ttl=None):
        domain = domain.lower()
        d = self.get_domain(domain)
        if d["type"] == "slave":
            raise HurricaneBadArgumentError(
                'Domain "%s" is a slave zone, this is a bad idea!' % domain
            )

        for r in self.filter_records(domain, host, rtype, value, mx, ttl):
            if r["status"] == "locked":
                continue
            self.del_record(domain, r["id"])
