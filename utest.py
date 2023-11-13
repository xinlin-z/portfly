from portfly import cx, dx
import random
random.seed()


for i in range(1000):
    bmsg = bytes(random.randint(0,255) for _ in range(i))
    assert dx(cx(bmsg)) == bmsg

