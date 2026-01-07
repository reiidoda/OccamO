def quad(xs):
    s = 0
    for x in xs:
        for y in xs:
            s += x*y
    return s
