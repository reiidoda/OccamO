import re


def find_tokens(text):
    pattern = re.compile(r"ab+c")
    return pattern.findall(text)
