def get_above_avg(pObject : DCC_CSV) -> list:
    counts = pObject.ReturnField('Count')
    totalize = 0
    for c in counts:
        totalize += int(c)
    averagecount = totalize / len(counts)
    baddudes = []
    for x,c in enumerate(counts):
        if int(c) > averagecount:
            baddudes.append(pObject.dictionaryList[x])
    return baddudes

def get_below_avg(pObject : DCC_CSV) -> list:
    counts = pObject.ReturnField('Count')
    totalize = 0
    for c in counts:
        totalize += int(c)
    averagecount = totalize / len(counts)
    baddudes = []
    for x,c in enumerate(counts):
        if int(c) < averagecount:
            baddudes.append(pObject.dictionaryList[x])
    return baddudes