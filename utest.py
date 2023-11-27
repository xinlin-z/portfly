from portfly import cx, dx
import random
random.seed()


for i in range(1000):
    bmsg = bytes(random.randint(0,255) for _ in range(i))
    # print('##', i, bmsg)
    # print(1, cx(bmsg))
    # print(2, dx(cx(bmsg)))
    assert dx(cx(bmsg)) == bmsg

