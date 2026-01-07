
def transform(df):
    out = df.apply(lambda row: row, axis=1)
    total = 0
    for _row in out:
        total += 1
    return total
