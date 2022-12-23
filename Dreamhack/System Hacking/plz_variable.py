from pwn import *
from z3 import *

p = remote("host3.dreamhack.games", 24083)
s = Solver()

for i in range(0,30):
    print("\n")
    print("=================================")
    print("Calculating......................")
    p.recvuntil(b'th...\n')
    print("=================================\n")
    
    equation = p.recvuntil(b'Answer ->').decode('utf-8')
    equation = equation.split("\n")[:-1]
    equation = [i.replace("=", "==") for i in equation]
    
    variables = list(set(re.findall(r"[a-z]", "".join(equation))))
    variables.sort()
    print("Variable is =", variables)
    print("") 
    print("=================================")
    print("")
    
    for var in variables:
        exec("%c = z3.Int('%c')"%(var, var))
        s.add(eval("%s >= 100"%var))
        s.add(eval("%s <= 1000"%var))
        
    for eq in equation:
        s.add(eval(eq))
        print(eq)
    
    print("=================================")
    s.check()
    ans = s.model()
    
    payload = []
    for var in variables:
        payload.append(str(ans.evaluate(eval(var)).as_long()))
    print("Answer is =", payload)
    
    p.sendline(','.join(payload))
    s.reset()

p.interactive()
