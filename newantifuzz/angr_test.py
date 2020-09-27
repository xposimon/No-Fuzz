import angr
import claripy

p = angr.Project("./symbol_test", auto_load_libs=False)

flag = claripy.BVS('cons', 48)

st = p.factory.full_init_state(
            args=['./symbol_test'],
            add_options=angr.options.unicorn,
            stdin=flag
           )

sm = p.factory.simulation_manager(st)
sm.run()

y = []
for x in sm.deadended:
    if b"branch" in x.posix.dumps(1):
        y.append(x)

if len(y) > 0:
    print(y[0].posix.dumps(0))
    
