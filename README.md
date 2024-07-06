# HurricaneDNS

## Requirements
 * python3
 * python-lxml
 * dnspython (optional - for importing BIND zones)

## Install

```
git clone https://github.com/1-1-2/pyHurricaneDNS

cd pyHurricaneDNS
python3 setup.py build
pip install .
# Using pipx
# pipx install .
```

## What works?

- add (domain, record)
- del (domain, record). Using filter, delete all match records, **please handle with caution**.
- ls (domain, record)
- import (BIND zone files)
- cp (records from one domain to another)

## TODO

- edit (you may del and add now)

## Usage

Get the party started by logging in:

```
hurricanedns <he.net username> <he.net password>
```

You'll get dropped to a `hurricanedns` command prompt:

```
[<username>@dns.he.net]
```

Start with `help`.

You can always get specific help for a command by doing `help [command]`, for example `help ls`

To quit, use `exit`, `EOF`, or CTRL-D.
