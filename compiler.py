from __future__ import annotations

from . import ast_nodes as A
from .bytecode import Instr, Proto, BINOP_TO_OP

_ONE_OPERAND = {
    "LOADK", "GETLOCAL", "SETLOCAL", "NEWLOCAL", "GETUPVAL", "SETUPVAL",
    "GETGLOBAL", "SETGLOBAL", "SETARRAYIDX", "APPENDLIST", "EXPAND",
    "JMP", "JMPIFFALSE", "JMPIFTRUE", "JMPIFNIL", "CLOSURE",
}

class CompileError(Exception):
    pass

class FuncState:
    def __init__(self, proto: Proto, parent: "FuncState | None"):
        self.proto = proto
        self.parent = parent
        self.scopes: list[dict] = [{}]
        self.nslots = proto.numparams
        self.upval_names: dict[str, int] = {}
        self.loops: list[dict] = []
        self.labels: dict[str, int] = {}           # name → instruction index
        self.pending_gotos: list[dict] = []        # {name, jump_idx, line}

    def new_slot(self) -> int:
        self.nslots += 1
        return self.nslots

    def declare(self, name: str) -> int:
        slot = self.new_slot()
        self.scopes[-1][name] = slot
        return slot

    def push_scope(self):
        self.scopes.append({})

    def pop_scope(self):
        self.scopes.pop()

    def find_local(self, name: str):
        for scope in reversed(self.scopes):
            if name in scope:
                return scope[name]
        return None

class Compiler:
    def __init__(self):
        self.fs: FuncState | None = None

    @property
    def code(self) -> list:
        return self.fs.proto.code

    def emit(self, op: str, a: int = 0, b: int = 0) -> int:
        nargs = 1 if op in _ONE_OPERAND else 0
        self.code.append(Instr(op, a, b, nargs))
        return len(self.code) - 1

    def here(self) -> int:
        return len(self.code)

    def patch(self, idx: int, target: int):
        self.code[idx].a = target

    def const(self, value) -> int:
        return self.fs.proto.const_index(value)

    def resolve(self, name: str):
        slot = self.fs.find_local(name)
        if slot is not None:
            return ("local", slot)
        up = self._resolve_upvalue(self.fs, name)
        if up is not None:
            return ("upval", up)
        return ("global", name)

    def _resolve_upvalue(self, fs: FuncState, name: str):
        if fs.parent is None:
            return None
        if name in fs.upval_names:
            return fs.upval_names[name]
        parent = fs.parent
        pslot = parent.find_local(name)
        if pslot is not None:
            return self._add_upvalue(fs, name, (1, pslot))
        pup = self._resolve_upvalue(parent, name)
        if pup is not None:
            return self._add_upvalue(fs, name, (2, pup))
        return None

    def _add_upvalue(self, fs: FuncState, name: str, desc) -> int:
        fs.proto.upvals.append(desc)
        idx = len(fs.proto.upvals)
        fs.upval_names[name] = idx
        return idx

    def compile_main(self, chunk: A.Chunk) -> Proto:
        proto = Proto(numparams=0, is_vararg=True, name="main")
        self.fs = FuncState(proto, None)
        self.compile_block(chunk.body)
        self._check_unresolved_gotos()
        self.emit("NEWARR")
        self.emit("RETURN")
        return proto

    def compile_function(self, func: A.Function) -> int:
        parent = self.fs
        proto = Proto(numparams=len(func.params), is_vararg=func.is_vararg,
                      name=func.name or "?")
        fs = FuncState(proto, parent)
        for i, p in enumerate(func.params, start=1):
            fs.scopes[-1][p] = i
        self.fs = fs
        self.compile_block(func.body)
        self._check_unresolved_gotos()
        self.emit("NEWARR")
        self.emit("RETURN")
        self.fs = parent
        parent.proto.protos.append(proto)
        return len(parent.proto.protos)

    def compile_block(self, stmts: list):
        self.fs.push_scope()
        for s in stmts:
            self.compile_stat(s)
        self.fs.pop_scope()

    def compile_block_noscope(self, stmts: list):
        for s in stmts:
            self.compile_stat(s)

    @staticmethod
    def is_multi(e) -> bool:
        return isinstance(e, (A.Call, A.MethodCall, A.Vararg))

    def build_args_array(self, args: list):
        self.emit("NEWARR")
        n = len(args)
        for idx, a in enumerate(args):
            if idx == n - 1 and self.is_multi(a):
                self.compile_expr_multi(a)
                self.emit("ARREXTEND")
            else:
                self.compile_expr_single(a)
                self.emit("ARRPUSH")

    def compile_exprlist(self, exprs: list, want: int):
        n = len(exprs)
        if n == 0:
            for _ in range(want):
                self.emit("LOADNIL")
            return
        for e in exprs[:-1]:
            self.compile_expr_single(e)
        last = exprs[-1]
        head = n - 1
        if self.is_multi(last):
            remaining = want - head
            if remaining <= 0:
                self.compile_expr_single(last)
                for _ in range(n - want):
                    self.emit("POP")
            else:
                self.compile_expr_multi(last)
                self.emit("EXPAND", remaining)
        else:
            self.compile_expr_single(last)
            if n < want:
                for _ in range(want - n):
                    self.emit("LOADNIL")
            elif n > want:
                for _ in range(n - want):
                    self.emit("POP")

    def emit_call(self, node, multi: bool, void: bool):
        if isinstance(node, A.MethodCall):
            self.compile_expr_single(node.obj)
            self.emit("DUP")
            self.emit("LOADK", self.const(node.method))
            self.emit("GETINDEX")
            self.emit("SWAP")
            self.emit("NEWARR")
            self.emit("SWAP")
            self.emit("ARRPUSH")
            args = node.args
            m = len(args)
            for idx, a in enumerate(args):
                if idx == m - 1 and self.is_multi(a):
                    self.compile_expr_multi(a); self.emit("ARREXTEND")
                else:
                    self.compile_expr_single(a); self.emit("ARRPUSH")
        else:
            self.compile_expr_single(node.func)
            self.build_args_array(node.args)
        self.emit("CALLVOID" if void else ("CALLM" if multi else "CALL"))

    def compile_expr_single(self, e):
        t = type(e)
        if t is A.Number:
            self.emit("LOADK", self.const(e.value))
        elif t is A.Str:
            self.emit("LOADK", self.const(e.value))
        elif t is A.Nil:
            self.emit("LOADNIL")
        elif t is A.TrueLit:
            self.emit("LOADTRUE")
        elif t is A.FalseLit:
            self.emit("LOADFALSE")
        elif t is A.Vararg:
            self.emit("VARARG1")
        elif t is A.Name:
            kind, ref = self.resolve(e.name)
            if kind == "local":
                self.emit("GETLOCAL", ref)
            elif kind == "upval":
                self.emit("GETUPVAL", ref)
            else:
                self.emit("GETGLOBAL", self.const(ref))
        elif t is A.Index:
            self.compile_expr_single(e.obj)
            self.compile_expr_single(e.key)
            self.emit("GETINDEX")
        elif t is A.Call or t is A.MethodCall:
            self.emit_call(e, multi=False, void=False)
        elif t is A.Table:
            self.compile_table(e)
        elif t is A.Function:
            idx = self.compile_function(e)
            self.emit("CLOSURE", idx)
        elif t is A.BinOp:
            self.compile_binop(e)
        elif t is A.UnOp:
            self.compile_unop(e)
        elif t is A.InterpStr:
            self.compile_interp(e)
        elif t is A.IfExpr:
            self.compile_ifexpr(e)
        else:
            raise CompileError(f"cannot compile expr {t.__name__}")

    def compile_expr_multi(self, e):
        if isinstance(e, (A.Call, A.MethodCall)):
            self.emit_call(e, multi=True, void=False)
        elif isinstance(e, A.Vararg):
            self.emit("VARARGM")
        else:
            self.compile_expr_single(e)

    def compile_table(self, e: A.Table):
        self.emit("NEWTABLE")
        items = e.array_items
        n = len(items)
        for idx, item in enumerate(items, start=1):
            if idx == n and self.is_multi(item):
                self.compile_expr_multi(item)
                self.emit("APPENDLIST", idx)
            else:
                self.compile_expr_single(item)
                self.emit("SETARRAYIDX", idx)
        for key, val in e.hash_items:
            self.compile_expr_single(key)
            self.compile_expr_single(val)
            self.emit("SETFIELD")

    def _fold_numbers(self, op: str, l: float, r: float):
        """Fold a pure numeric binary op at compile time. Returns result or None."""
        try:
            if op == "+":  return l + r
            if op == "-":  return l - r
            if op == "*":  return l * r
            if op == "/" and r != 0:  return l / r
            if op == "//" and r != 0: return float(int(l // r))
            if op == "%" and r != 0:  return l % r
            if op == "^":  return l ** r
            if op == "&":  return float(int(l) & int(r))
            if op == "|":  return float(int(l) | int(r))
            if op == "~":  return float(int(l) ^ int(r))
            if op == "<<": return float((int(l) << (int(r) & 31)) & 0xFFFFFFFF)
            if op == ">>": return float((int(l) & 0xFFFFFFFF) >> (int(r) & 31))
        except Exception:
            pass
        return None

    def compile_binop(self, e: A.BinOp):
        if e.op == "and":
            self.compile_expr_single(e.left)
            self.emit("DUP")
            j = self.emit("JMPIFFALSE")
            self.emit("POP")
            self.compile_expr_single(e.right)
            self.patch(j, self.here())
            return
        if e.op == "or":
            self.compile_expr_single(e.left)
            self.emit("DUP")
            j = self.emit("JMPIFTRUE")
            self.emit("POP")
            self.compile_expr_single(e.right)
            self.patch(j, self.here())
            return
        # Constant folding: both operands are compile-time literals
        if isinstance(e.left, A.Number) and isinstance(e.right, A.Number):
            result = self._fold_numbers(e.op, e.left.value, e.right.value)
            if result is not None:
                self.emit("LOADK", self.const(result))
                return
        # String concat folding: "a" .. "b" → "ab"
        if e.op == ".." and isinstance(e.left, A.Str) and isinstance(e.right, A.Str):
            self.emit("LOADK", self.const(e.left.value + e.right.value))
            return
        self.compile_expr_single(e.left)
        self.compile_expr_single(e.right)
        self.emit(BINOP_TO_OP[e.op])

    def compile_unop(self, e: A.UnOp):
        if e.op == "paren":
            self.compile_expr_single(e.operand)
            return
        self.compile_expr_single(e.operand)
        self.emit({"-": "UNM", "not": "NOT", "#": "LEN", "~": "BNOT"}[e.op])

    def compile_interp(self, e: A.InterpStr):
        # Luau string interpolation: `a{x}b` desugars to  "a" .. tostring(x) .. "b"
        # (interpolation always applies tostring, unlike raw `..`, which errors
        # on non-string/number operands).
        nodes = []
        for kind, val in e.parts:
            if kind == "str":
                if val == "":
                    continue
                nodes.append(A.Str(val))
            else:
                nodes.append(A.Call(A.Name("tostring"), [val]))
        if not nodes:
            self.emit("LOADK", self.const(""))
            return
        expr = nodes[0]
        for n in nodes[1:]:
            expr = A.BinOp("..", expr, n)
        self.compile_expr_single(expr)

    def compile_ifexpr(self, e: A.IfExpr):
        # Luau if-expression: `if c1 then v1 elseif c2 then v2 else v3`.
        # Each arm pushes exactly one value, so the stack stays balanced
        # regardless of which branch is taken.
        end_jumps = []
        for cond, val in e.clauses:
            self.compile_expr_single(cond)
            skip = self.emit("JMPIFFALSE")
            self.compile_expr_single(val)
            end_jumps.append(self.emit("JMP"))
            self.patch(skip, self.here())
        self.compile_expr_single(e.orelse)
        for j in end_jumps:
            self.patch(j, self.here())

    def compile_stat(self, s):
        t = type(s)
        getattr(self, "_st_" + t.__name__)(s)

    def _st_LocalAssign(self, s: A.LocalAssign):
        self.compile_exprlist(s.values, len(s.names))
        slots = [self.fs.declare(n) for n in s.names]
        for slot in reversed(slots):
            self.emit("NEWLOCAL", slot)

    def _st_Assign(self, s: A.Assign):
        if len(s.targets) == 1:
            self._assign_single(s.targets[0], s.values)
            return
        self.compile_exprlist(s.values, len(s.targets))
        for tgt in reversed(s.targets):
            if isinstance(tgt, A.Name):
                self._store_name(tgt.name)
            elif isinstance(tgt, A.Index):
                self.compile_expr_single(tgt.obj)
                self.compile_expr_single(tgt.key)
                self.emit("ROT3")
                self.emit("SETINDEX")
            else:
                raise CompileError("invalid assignment target")

    def _assign_single(self, tgt, values):
        if isinstance(tgt, A.Name):
            self.compile_exprlist(values, 1)
            self._store_name(tgt.name)
        elif isinstance(tgt, A.Index):
            self.compile_expr_single(tgt.obj)
            self.compile_expr_single(tgt.key)
            self.compile_exprlist(values, 1)
            self.emit("SETINDEX")
        else:
            raise CompileError("invalid assignment target")

    def _store_name(self, name: str):
        kind, ref = self.resolve(name)
        if kind == "local":
            self.emit("SETLOCAL", ref)
        elif kind == "upval":
            self.emit("SETUPVAL", ref)
        else:
            self.emit("SETGLOBAL", self.const(ref))

    def _st_CallStat(self, s: A.CallStat):
        self.emit_call(s.call, multi=False, void=True)

    def _st_Do(self, s: A.Do):
        self.compile_block(s.body)

    def _st_Return(self, s: A.Return):
        self.build_args_array(s.values)
        self.emit("RETURN")

    def _st_Break(self, s: A.Break):
        if not self.fs.loops:
            raise CompileError("break outside loop")
        self.fs.loops[-1]["breaks"].append(self.emit("JMP"))

    def _st_Continue(self, s: A.Continue):
        if not self.fs.loops:
            raise CompileError("continue outside loop")
        self.fs.loops[-1]["continues"].append(self.emit("JMP"))

    def _st_If(self, s: A.If):
        end_jumps = []
        clauses = s.clauses
        for i, (cond, body) in enumerate(clauses):
            if cond is None:
                # else branch
                self.compile_block(body)
                break
            # Dead code elimination: always-false condition — skip entire clause
            if isinstance(cond, (A.FalseLit, A.Nil)):
                continue
            # Dead code elimination: always-true condition — compile body, done
            if isinstance(cond, A.TrueLit):
                self.compile_block(body)
                break
            self.compile_expr_single(cond)
            skip = self.emit("JMPIFFALSE")
            self.compile_block(body)
            is_last = i == len(clauses) - 1
            if not is_last:
                end_jumps.append(self.emit("JMP"))
            self.patch(skip, self.here())
        for j in end_jumps:
            self.patch(j, self.here())

    def _st_While(self, s: A.While):
        start = self.here()
        self.compile_expr_single(s.cond)
        exit_j = self.emit("JMPIFFALSE")
        loop = {"breaks": [], "continues": []}
        self.fs.loops.append(loop)
        self.compile_block(s.body)
        self.emit("JMP", start)
        self.patch(exit_j, self.here())
        self.fs.loops.pop()
        for j in loop["breaks"]:
            self.patch(j, self.here())
        for j in loop["continues"]:
            self.patch(j, start)

    def _st_Repeat(self, s: A.Repeat):
        start = self.here()
        loop = {"breaks": [], "continues": []}
        self.fs.loops.append(loop)
        self.fs.push_scope()
        self.compile_block_noscope(s.body)
        cont_target = self.here()
        self.compile_expr_single(s.cond)
        self.emit("JMPIFFALSE", start)
        self.fs.pop_scope()
        self.fs.loops.pop()
        end = self.here()
        for j in loop["breaks"]:
            self.patch(j, end)
        for j in loop["continues"]:
            self.patch(j, cont_target)

    def _st_NumericFor(self, s: A.NumericFor):
        i_slot = self.fs.new_slot()
        limit_slot = self.fs.new_slot()
        step_slot = self.fs.new_slot()
        self.compile_expr_single(s.start); self.emit("NEWLOCAL", i_slot)
        self.compile_expr_single(s.stop); self.emit("NEWLOCAL", limit_slot)
        if s.step is not None:
            self.compile_expr_single(s.step)
        else:
            self.emit("LOADK", self.const(1.0))
        self.emit("NEWLOCAL", step_slot)

        start = self.here()
        self.emit("GETLOCAL", i_slot)
        self.emit("GETLOCAL", limit_slot)
        self.emit("GETLOCAL", step_slot)
        self.emit("FORTEST")
        exit_j = self.emit("JMPIFFALSE")

        loop = {"breaks": [], "continues": []}
        self.fs.loops.append(loop)
        self.fs.push_scope()
        var_slot = self.fs.declare(s.var)
        self.emit("GETLOCAL", i_slot)
        self.emit("NEWLOCAL", var_slot)
        self.compile_block_noscope(s.body)
        self.fs.pop_scope()

        cont_target = self.here()
        self.emit("GETLOCAL", i_slot)
        self.emit("GETLOCAL", step_slot)
        self.emit("ADD")
        self.emit("SETLOCAL", i_slot)
        self.emit("JMP", start)
        self.patch(exit_j, self.here())
        self.fs.loops.pop()
        for j in loop["breaks"]:
            self.patch(j, self.here())
        for j in loop["continues"]:
            self.patch(j, cont_target)

    def _st_GenericFor(self, s: A.GenericFor):
        f_slot = self.fs.new_slot()
        s_slot = self.fs.new_slot()
        ctrl_slot = self.fs.new_slot()
        self.compile_exprlist(s.exprs, 3)
        self.emit("NEWLOCAL", ctrl_slot)
        self.emit("NEWLOCAL", s_slot)
        self.emit("NEWLOCAL", f_slot)

        start = self.here()
        self.emit("GETLOCAL", f_slot)
        self.emit("NEWARR")
        self.emit("GETLOCAL", s_slot); self.emit("ARRPUSH")
        self.emit("GETLOCAL", ctrl_slot); self.emit("ARRPUSH")
        self.emit("CALLM")
        self.emit("EXPAND", len(s.names))

        loop = {"breaks": [], "continues": []}
        self.fs.loops.append(loop)
        self.fs.push_scope()
        name_slots = [self.fs.declare(n) for n in s.names]
        for slot in reversed(name_slots):
            self.emit("NEWLOCAL", slot)
        self.emit("GETLOCAL", name_slots[0])
        self.emit("ISNIL")
        exit_j = self.emit("JMPIFTRUE")
        self.emit("GETLOCAL", name_slots[0])
        self.emit("SETLOCAL", ctrl_slot)
        self.compile_block_noscope(s.body)
        self.fs.pop_scope()

        cont_target = self.here()
        self.emit("JMP", start)
        self.patch(exit_j, self.here())
        self.fs.loops.pop()
        for j in loop["breaks"]:
            self.patch(j, self.here())
        for j in loop["continues"]:
            self.patch(j, cont_target)

    def _st_Goto(self, s: A.Goto):
        j = self.emit("JMP")
        known = self.fs.labels.get(s.target)
        if known is not None:
            self.patch(j, known)
        else:
            self.fs.pending_gotos.append({"name": s.target, "jump_idx": j})

    def _st_Label(self, s: A.Label):
        if s.name in self.fs.labels:
            raise CompileError(f"duplicate label '{s.name}'")
        addr = self.here()
        self.fs.labels[s.name] = addr
        # patch any forward gotos that were waiting for this label
        still_pending = []
        for g in self.fs.pending_gotos:
            if g["name"] == s.name:
                self.patch(g["jump_idx"], addr)
            else:
                still_pending.append(g)
        self.fs.pending_gotos = still_pending

    def _check_unresolved_gotos(self):
        if self.fs.pending_gotos:
            g = self.fs.pending_gotos[0]
            raise CompileError(f"no visible label '{g['name']}' for goto")

    def _st_FunctionStat(self, s: A.FunctionStat):
        if s.is_local:
            slot = self.fs.declare(s.target.name)
            self.emit("LOADNIL")
            self.emit("NEWLOCAL", slot)
            idx = self.compile_function(s.func)
            self.emit("CLOSURE", idx)
            self.emit("SETLOCAL", slot)
        else:
            target = s.target
            if isinstance(target, A.Name):
                idx = self.compile_function(s.func)
                self.emit("CLOSURE", idx)
                self._store_name(target.name)
            else:
                self.compile_expr_single(target.obj)
                self.compile_expr_single(target.key)
                idx = self.compile_function(s.func)
                self.emit("CLOSURE", idx)
                self.emit("SETINDEX")

def compile_source_to_proto(chunk: A.Chunk) -> Proto:
    return Compiler().compile_main(chunk)

_JUMP_OPS = {"JMP", "JMPIFFALSE", "JMPIFTRUE", "JMPIFNIL"}

def apply_fusions(proto: Proto, fusion_map: dict) -> None:
    for sub in proto.protos:
        apply_fusions(sub, fusion_map)

    code = proto.code
    m = len(code)
    targets = {ins.a for ins in code if ins.op in _JUMP_OPS}

    new: list[Instr] = []
    old_to_new: dict[int, int] = {}
    i = 0
    while i < m:
        old_to_new[i] = len(new)
        fname = None
        if i + 1 < m and (i + 1) not in targets:
            fname = fusion_map.get((code[i].op, code[i + 1].op))
        if fname is not None:
            # Pack two operands for fusions that need both (F_KSETG, F_LMOV).
            # Encoding: a = (second.a << 16) | first.a   (16-bit each; indices are small)
            # F_KSETG: first=LOADK(value), second=SETGLOBAL(name) → ENV[K[name]]=K[value]
            # F_LMOV:  first=GETLOCAL(src), second=SETLOCAL(dst) → L[dst]=L[src]
            if fname in ("F_KSETG", "F_LMOV"):
                packed = ((code[i + 1].a & 0xFFFF) << 16) | (code[i].a & 0xFFFF)
                new.append(Instr(fname, a=packed, nargs=1))
            else:
                new.append(Instr(fname, a=code[i].a, nargs=1))
            old_to_new[i + 1] = len(new) - 1
            i += 2
        else:
            new.append(code[i])
            i += 1
    old_to_new[m] = len(new)

    for ins in new:
        if ins.op in _JUMP_OPS:
            ins.a = old_to_new[ins.a]
    proto.code = new

_CONST_OPS = {"LOADK", "GETGLOBAL", "SETGLOBAL"}

def shuffle_constants(proto: Proto, rng) -> None:
    for sub in proto.protos:
        shuffle_constants(sub, rng)

    n = len(proto.consts)
    if n <= 1:
        return
    order = list(range(n))
    rng.shuffle(order)
    old_to_new = {order[new0] + 1: new0 + 1 for new0 in range(n)}
    proto.consts = [proto.consts[order[new0]] for new0 in range(n)]
    for ins in proto.code:
        if ins.op in _CONST_OPS:
            ins.a = old_to_new[ins.a]

_COND_JUMPS = {"JMPIFFALSE", "JMPIFTRUE", "JMPIFNIL"}

def _bogus_block(rng, real_ids: list[int]) -> dict:
    filler = Instr(rng.choice(["NEWARR", "LOADNIL", "LOADTRUE"]), nargs=0)
    jmp = Instr("JMP", a=rng.choice(real_ids), nargs=1)
    return {"instrs": [filler, jmp], "bogus": True}

def scramble_cfg(proto: Proto, rng) -> None:
    for sub in proto.protos:
        scramble_cfg(sub, rng)

    code = proto.code
    m = len(code)
    if m < 2:
        return

    leaders = {0}
    for i, ins in enumerate(code):
        if ins.op in _JUMP_OPS:
            leaders.add(ins.a)
            if i + 1 < m:
                leaders.add(i + 1)
        elif ins.op == "RETURN":
            if i + 1 < m:
                leaders.add(i + 1)
    starts = sorted(l for l in leaders if l < m)

    blocks = []
    start_to_id = {}
    for bi, s in enumerate(starts):
        e = starts[bi + 1] if bi + 1 < len(starts) else m
        start_to_id[s] = len(blocks)
        blocks.append({"instrs": code[s:e], "bogus": False})

    end_id = None

    def target_id(t: int) -> int:
        nonlocal end_id
        if t == m:
            if end_id is None:
                blocks.append({"instrs": [Instr("NEWARR", nargs=0),
                                          Instr("RETURN", nargs=0)], "bogus": False})
                end_id = len(blocks) - 1
            return end_id
        return start_to_id[t]

    n_real = len(starts)
    for bi in range(n_real):
        instrs = blocks[bi]["instrs"]
        last = instrs[-1]
        ft = target_id(starts[bi + 1]) if bi + 1 < n_real else target_id(m)
        if last.op == "RETURN":
            pass
        elif last.op == "JMP":
            last.a = target_id(last.a)
        elif last.op in _COND_JUMPS:
            last.a = target_id(last.a)
            instrs.append(Instr("JMP", a=ft, nargs=1))
        else:
            instrs.append(Instr("JMP", a=ft, nargs=1))

    real_ids = list(range(n_real))
    rest_ids = list(range(1, len(blocks)))
    rng.shuffle(rest_ids)
    for _ in range(rng.randint(1, 3)):
        blocks.append(_bogus_block(rng, real_ids))
        rest_ids.append(len(blocks) - 1)
        rest_ids.insert(rng.randrange(len(rest_ids)), rest_ids.pop())
    layout = [0] + rest_ids

    new_start = {}
    pos = 0
    for bid in layout:
        new_start[bid] = pos
        pos += len(blocks[bid]["instrs"])
    new_code = []
    for bid in layout:
        new_code.extend(blocks[bid]["instrs"])
    for ins in new_code:
        if ins.op in _JUMP_OPS:
            ins.a = new_start[ins.a]
    proto.code = new_code


# ── Junk proto injection ──────────────────────────────────────────────────────
# Inspired by nxtzy item 10: inject N dummy sub-protos at random positions among
# real sub-protos of every Proto.  Junk protos have a valid but unreachable body
# (LOADNIL + RETURN) and are never referenced by any CLOSURE instruction —
# they exist purely to confuse decompilers and inflate the proto table.
# After injection every CLOSURE operand (1-based index into proto.protos) is
# remapped to the new shuffled position so real code still calls the right child.

def _make_junk_proto(rng) -> Proto:
    """Return a syntactically valid but dead Proto with 0–2 no-op instructions."""
    p = Proto(numparams=0, is_vararg=False, name="_J")
    # Random filler from instructions that don't corrupt state if ever reached
    filler_choices = [
        [Instr("LOADNIL", nargs=0), Instr("NEWARR", nargs=0)],
        [Instr("LOADTRUE", nargs=0)],
        [Instr("LOADNIL", nargs=0)],
        [],
    ]
    for ins in rng.choice(filler_choices):
        p.code.append(ins)
    p.code.append(Instr("NEWARR", nargs=0))
    p.code.append(Instr("RETURN", nargs=0))
    return p


def inject_junk_protos(proto: Proto, rng) -> None:
    """
    Recursively inject junk sub-protos into every Proto node.
    Remaps all CLOSURE operands (1-based) to match the new shuffled layout.
    """
    # Recurse into real children first (before we shuffle them)
    for sub in proto.protos:
        inject_junk_protos(sub, rng)

    n_real = len(proto.protos)
    if n_real == 0:
        return   # leaf proto — nothing to shuffle

    # Number of junk protos to inject: ~40% of real count, minimum 1
    n_junk = max(1, int(n_real * 0.4))
    junk_protos = [_make_junk_proto(rng) for _ in range(n_junk)]

    # Build merged list: real entries tagged with original 0-based index,
    # junk entries tagged with -1.
    items = [{"p": p, "orig": i} for i, p in enumerate(proto.protos)]
    items += [{"p": p, "orig": -1} for p in junk_protos]
    rng.shuffle(items)

    # Build orig_0based → new_1based map for real protos
    orig_to_new: dict[int, int] = {}
    for new_i, item in enumerate(items):
        if item["orig"] >= 0:
            orig_to_new[item["orig"]] = new_i + 1   # CLOSURE uses 1-based index

    # Remap CLOSURE operands in this proto's code
    for ins in proto.code:
        if ins.op == "CLOSURE":
            orig_0based = ins.a - 1   # convert from 1-based to 0-based
            new_1based = orig_to_new.get(orig_0based)
            if new_1based is not None:
                ins.a = new_1based

    proto.protos = [item["p"] for item in items]
