class x86gpr(Dashboard.Module):
    "x86 general-purpose registers view"

    def __init__(self):
        self.table={}

    def label(self):
        return 'GPRs'

    @staticmethod
    def formatReg(name,value,changed):
        return ansi(name,R.style_low)+' '+ansi(value,R.style_selected_1 if changed else '')
    @staticmethod
    def getSymbolicPos(addrStr):
        addrWithSymPos=run("x/i $pc").split('\t')[0]
        if not addrWithSymPos.startswith("=> ") or not addrWithSymPos.endswith(":"):
            raise Exception("bad symbolic pos: \""+addrWithSymPos+"\"")
        else:
            return re.sub("=> [^ ]+ ?(.*):","\\1",addrWithSymPos)

    def formatAndUpdateFlag(self,name,value):
        key='flag'+name
        changed=self.table and self.table.get(key,'')!=value
        self.table[key]=value
        return self.formatReg(name[0],value,changed)

    def linesGPR(self,termWidth,styleChanged):
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

    def linesPC(self,termWidth,styleChanged):
        if self.bits==32:
            name="EIP"
            value=run(r'printf "%08x", $pc')
        else:
            name="RIP"
            value=run(r'printf "%016lx", $pc')
        changed=self.table and self.table.get(name,'')!=value
        self.table[name]=value
        comment=self.getSymbolicPos("$pc")
        return [self.formatReg(name,value,changed)+' '+comment]

    def linesEFL(self,termWidth,styleChanged):
        name="EFL"
        value=run(r'printf "%08x", $eflags')
        efl=int(value,16);
        CFbit=1
        PFbit=4
        AFbit=0x10
        ZFbit=0x40
        SFbit=0x80
        TFbit=0x100
        DFbit=0x400
        OFbit=0x800
        CF = int((efl&CFbit)!=0)
        PF = int((efl&PFbit)!=0)
        AF = int((efl&AFbit)!=0)
        ZF = int((efl&ZFbit)!=0)
        SF = int((efl&SFbit)!=0)
        TF = int((efl&TFbit)!=0)
        DF = int((efl&DFbit)!=0)
        OF = int((efl&OFbit)!=0)
        result=[]
        result.append(self.formatAndUpdateFlag("CF",CF))
        result.append(self.formatAndUpdateFlag("PF",PF))
        result.append(self.formatAndUpdateFlag("AF",AF))
        result.append(self.formatAndUpdateFlag("ZF",ZF))
        result.append(self.formatAndUpdateFlag("SF",SF))
        result.append(self.formatAndUpdateFlag("TF",TF))
        result.append(self.formatAndUpdateFlag("DF",DF))
        result.append(self.formatAndUpdateFlag("OF",OF))
        result.append('')
        changed=self.table and self.table.get(name,'')!=value
        self.table[name]=value
        eflStr=self.formatReg(name,value,changed)
        eflStr += " ("
        eflStr += "O,"  if OF           else "NO,"
        eflStr += "B,"  if CF           else "AE,"
        eflStr += "E,"  if ZF           else "NE,"
        eflStr += "BE," if ZF or CF     else "A,"
        eflStr += "S,"  if SF           else "NS,"
        eflStr += "P,"  if PF           else "NP,"
        eflStr += "L,"  if SF!=OF       else "GE,"
        eflStr += "LE"  if SF!=OF or ZF else "G"
        eflStr += ")"
        result.append(eflStr)
        return result

    def lines(self,termWidth,styleChanged):
        arch=run("show arch")
        if " i386:x64-32" in arch or " i386:x86-64" in arch:
            self.bits=64
        else:
            self.bits=32
        try:
            return (self.linesGPR(termWidth,styleChanged)+['']+
                   self.linesPC(termWidth,styleChanged)+['']+
                   self.linesEFL(termWidth,styleChanged))
        except Exception,e:
            return [str(e)]
