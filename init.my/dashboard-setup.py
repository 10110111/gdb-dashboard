class x86gpr(Dashboard.Module):
    "x86 general-purpose registers view"

    def __init__(self):
        self.table={}

    def label(self):
        return 'GPRs'

    @staticmethod
    def formatReg(name,value,changed):
        return ansi(name,R.style_low)+' '+ansi(value,R.style_selected_1 if changed else '')

    def linesGPR(self,termWidth,styleChanged):
        try:
            if self.bits==32:
                regNames=["EAX","ECX","EDX","EBX","ESP","EBP","ESI","EDI"]
                regValues=run('printf "%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x",'+
                              '$eax,$ecx,$edx,$ebx,$esp,$ebp,$esi,$edi').split(',')
                if len(regValues)!=8:
                    raise Exception("Registers unavailable")
            else:
                regNames=["RAX","RCX","RDX","RBX","RSP","RBP","RSI","RDI",
                          "R8 ","R9 ","R10","R11","R12","R13","R14","R15"]
                regValues=run('printf "%016lx,%016lx,%016lx,%016lx,%016lx,%016lx,%016lx,%016lx,'+
                              '%016lx,%016lx,%016lx,%016lx,%016lx,%016lx,%016lx,%016lx",'+
                              '$rax,$rcx,$rdx,$rbx,$rsp,$rbp,$rsi,$rdi,'+
                              '$r8,$r9,$r10,$r11,$r12,$r13,$r14,$r15').split(',')
                if len(regValues)!=16:
                    raise Exception("Registers unavailable")

            regs=dict(zip(regNames,regValues))
            registers=[]
            for name in regNames:
                value=regs[name]
                changed=self.table and self.table.get(name,'')!=value
                self.table[name]=value
                registers.append(self.formatReg(name,value,changed))
            return registers
        except Exception,e:
            return [str(e)]

    def linesPC(self,termWidth,styleChanged):
        if self.bits==32:
            name="EIP"
            value=run(r'printf "%08x", $pc')
        else:
            name="RIP"
            value=run(r'printf "%016lx", $pc')
        changed=self.table and self.table.get(name,'')!=value
        self.table[name]=value
        return [self.formatReg(name,value,changed)]

    def lines(self,termWidth,styleChanged):
        self.bits=32
        return self.linesGPR(termWidth,styleChanged)+['']+self.linesPC(termWidth,styleChanged)
