class x86regs(Dashboard.Module):
    "x86 general-purpose registers view"

    def __init__(self):
        self.table={}

    def label(self):
        return 'GPRs'

    @staticmethod
    def formatRegValue(value,changed):
        return ansi(value,R.style_selected_1 if changed else '')
    @staticmethod
    def formatReg(name,value,changed):
        return ansi(name,R.style_low)+' '+x86regs.formatRegValue(value,changed)
    @staticmethod
    def getSymbolicPos(addrStr):
        addrWithSymPos=run("x/i $pc").split('\t')[0]
        if not addrWithSymPos.startswith("=> ") or not addrWithSymPos.endswith(":"):
            raise Exception("bad symbolic pos: \""+addrWithSymPos+"\"")
        else:
            return re.sub("=> [^ ]+ ?(.*):","\\1",addrWithSymPos)

    @staticmethod
    def x87RoundingModeString(mode):
        return { 0: "NEAR",
                 1: "DOWN",
                 2: "  UP",
                 3: "ZERO" }[mode]
    @staticmethod
    def x87PrecisionString(mode):
        return {0:"24",1:"??",2:"53",3:"64"}[mode]

    @staticmethod
    def fpuStackFaultDetail(statusWord):
        invalidOperationException=statusWord & 0x01
        C1=statusWord&(1<<9)
        stackFault=statusWord&0x40
        if invalidOperationException and stackFault:
            return "Stack overflow" if C1 else "Stack underflow"
        return ""
    @staticmethod
    def fpuComparExplain(statusWord):
        C0=int((statusWord&(1<<8))!=0)
        C2=int((statusWord&(1<<10))!=0)
        C3=int((statusWord&(1<<14))!=0)
        if C3==0 and C2==0 and C0==0: return "GT"
        if C3==0 and C2==0 and C0==1: return "LT"
        if C3==1 and C2==0 and C0==0: return "EQ"
        if C3==1 and C2==1 and C0==1: return "Unordered"
        return ""
    @staticmethod
    def fpuExplainPE(statusWord):
        if statusWord&(1<<5):
            C1=statusWord&(1<<9)
            return "Rounded UP" if C1 else "Rounded DOWN"
        return ""
    @classmethod
    def fsrComment(self,statusWord):
        stackFaultDetail=self.fpuStackFaultDetail(statusWord)
        comparisonResult=self.fpuComparExplain(statusWord)
        comparComment="" if not comparisonResult else '('+comparisonResult+')'
        peExplanation=self.fpuExplainPE(statusWord)

        comment=comparComment
        if len(comment) and len(stackFaultDetail): comment+=", "
        comment+=stackFaultDetail
        if len(comment) and len(peExplanation): comment+=", "
        comment+=peExplanation
        return comment.rstrip()

    def checkAndUpdateChanged(self,key,value):
        changed=self.table and self.table.get(key,'')!=value
        self.table[key]=value
        return changed
    def formatAndUpdateReg(self,name,value,prefix=''):
        changed=self.checkAndUpdateChanged(prefix+name,value)
        return self.formatReg(name,value,changed)
    def formatAndUpdateRegValue(self,name,value):
        changed=self.checkAndUpdateChanged(name,value)
        return x86regs.formatRegValue(value,changed)
    def formatAndUpdateFlag(self,name,value):
        changed=self.checkAndUpdateChanged('flag'+name,value)
        return self.formatReg(name[0],value,changed)

    def linesGPR(self,termWidth,styleChanged):
        if self.bits==32:
            regNames=["EAX","ECX","EDX","EBX","ESP","EBP","ESI","EDI"]
            regValues=run('printf "%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x",'+
                          '$eax,$ecx,$edx,$ebx,$esp,$ebp,$esi,$edi').split(',')
            if len(regValues)!=8:
                raise Exception("32-bit general-purpose registers unavailable")
        else:
            regNames=["RAX","RCX","RDX","RBX","RSP","RBP","RSI","RDI",
                      "R8 ","R9 ","R10","R11","R12","R13","R14","R15"]
            regValues=run('printf "%016lx,%016lx,%016lx,%016lx,%016lx,%016lx,%016lx,%016lx,'+
                          '%016lx,%016lx,%016lx,%016lx,%016lx,%016lx,%016lx,%016lx",'+
                          '$rax,$rcx,$rdx,$rbx,$rsp,$rbp,$rsi,$rdi,'+
                          '$r8,$r9,$r10,$r11,$r12,$r13,$r14,$r15').split(',')
            if len(regValues)!=16:
                raise Exception("64-bit general-purpose registers unavailable")

        regs=dict(zip(regNames,regValues))
        registers=[]
        for name in regNames:
            value=regs[name]
            registers.append(self.formatAndUpdateReg(name,value))
        return registers

    def linesPC(self,termWidth,styleChanged):
        if self.bits==32:
            name="EIP"
            value=run(r'printf "%08x", $pc')
        else:
            name="RIP"
            value=run(r'printf "%016lx", $pc')
        comment=self.getSymbolicPos("$pc")
        return [self.formatAndUpdateReg(name,value)+' '+comment]

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
        eflStr=self.formatAndUpdateReg(name,value)
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

    def linesSegReg(self,termWidth,styleChanged):
        regNames=["ES","CS","SS","DS","FS","GS"]
        regValues=run('printf "%04x,%04x,%04x,%04x,%04x,%04x",'+
                      '$es,$cs,$ss,$ds,$fs,$gs').split(',')
        if len(regValues)!=6:
            raise Exception("Segment registers unavailable")
        regs=dict(zip(regNames,regValues))
        registers=[]
        for name in regNames:
            value=regs[name]
            registers.append(self.formatAndUpdateReg(name,value))
        return registers

    def linesMXCSR(self,termWidth,styleChanged):
#                                 P U O Z D I
# MXCSR 00001f80  FZ 0 DZ 0  Err  0 0 0 0 0 0
#                 Rnd NEAR   Mask 1 1 1 1 1 1
        name="MXCSR"
        value=run('printf "%08x", $mxcsr')
        try: mxcsr=int(value,16)
        except: return [] # MXCSR may be unavailable if SSE isn't supported
        mxcsrLines=[]
        mxcsrLines.append("                                P U O Z D I")

        mainLine=(self.formatAndUpdateReg(name,value)+
                  "  "+self.formatAndUpdateReg("FZ",int((mxcsr&0x8000)!=0))+
                  " "+self.formatAndUpdateReg("DZ",int((mxcsr&0x40)!=0))+
                  "  Err  "+
                  self.formatAndUpdateRegValue("mxcsr-PE",int((mxcsr&0x20)!=0))+" "+
                  self.formatAndUpdateRegValue("mxcsr-UE",int((mxcsr&0x10)!=0))+" "+
                  self.formatAndUpdateRegValue("mxcsr-OE",int((mxcsr&0x08)!=0))+" "+
                  self.formatAndUpdateRegValue("mxcsr-ZE",int((mxcsr&0x04)!=0))+" "+
                  self.formatAndUpdateRegValue("mxcsr-DE",int((mxcsr&0x02)!=0))+" "+
                  self.formatAndUpdateRegValue("mxcsr-IE",int((mxcsr&0x01)!=0))
                 )
        secondLine=("                "+
                    self.formatAndUpdateReg("Rnd",self.x87RoundingModeString((mxcsr>>13)&3),"SSE-")+
                    "   Mask "+
                    self.formatAndUpdateRegValue("mxcsr-PM",int((mxcsr&0x1000)!=0))+" "+
                    self.formatAndUpdateRegValue("mxcsr-UM",int((mxcsr&0x0800)!=0))+" "+
                    self.formatAndUpdateRegValue("mxcsr-OM",int((mxcsr&0x0400)!=0))+" "+
                    self.formatAndUpdateRegValue("mxcsr-ZM",int((mxcsr&0x0200)!=0))+" "+
                    self.formatAndUpdateRegValue("mxcsr-DM",int((mxcsr&0x0100)!=0))+" "+
                    self.formatAndUpdateRegValue("mxcsr-IM",int((mxcsr&0x0080)!=0))
                 )

        mxcsrLines.append(mainLine)
        mxcsrLines.append(secondLine)
        return mxcsrLines

    def linesFPUStatusAndControl(self,termWidth,styleChanged):
        regs=run('printf "%04x,%04x,%04x",$ftag,$fstat,$fctrl').split(',')
        if(len(regs)!=3):
            raise Exception("FTR, FSR or FCR unavailable")
        ftr=regs[0]
        fsr=regs[1]
        fcr=regs[2]
        lines=[]
        lines.append(self.formatAndUpdateReg("FTR",ftr)+
                     "       3 2 1 0      E S P U O Z D I")
        fsrLine=self.formatAndUpdateReg("FSR",fsr);
        fsr=int(fsr,16)
        fsrLine+=("  Cond "+
                  self.formatAndUpdateRegValue("fpu-C3",int((fsr&0x4000)!=0))+' '+
                  self.formatAndUpdateRegValue("fpu-C2",int((fsr&0x0400)!=0))+' '+
                  self.formatAndUpdateRegValue("fpu-C1",int((fsr&0x0200)!=0))+' '+
                  self.formatAndUpdateRegValue("fpu-C0",int((fsr&0x0100)!=0))+"  Err "+
                  self.formatAndUpdateRegValue("fpu-ES",int((fsr&0x0080)!=0))+' '+
                  self.formatAndUpdateRegValue("fpu-SF",int((fsr&0x0040)!=0))+' '+
                  self.formatAndUpdateRegValue("fpu-PE",int((fsr&0x0020)!=0))+' '+
                  self.formatAndUpdateRegValue("fpu-UE",int((fsr&0x0010)!=0))+' '+
                  self.formatAndUpdateRegValue("fpu-OE",int((fsr&0x0008)!=0))+' '+
                  self.formatAndUpdateRegValue("fpu-ZE",int((fsr&0x0004)!=0))+' '+
                  self.formatAndUpdateRegValue("fpu-DE",int((fsr&0x0002)!=0))+' '+
                  self.formatAndUpdateRegValue("fpu-IE",int((fsr&0x0001)!=0))
                 )
        lines.append(fsrLine+' '+self.fsrComment(fsr))

        fcrLine=self.formatAndUpdateReg("FCR",fcr)
        fcr=int(fcr,16)
        fcrLine+=("  "+
                  self.formatAndUpdateReg("Prec",self.x87RoundingModeString((fcr>>10)&3),"fpu-")+
                  ','+
                  self.formatAndUpdateRegValue("fpu-RC",self.x87PrecisionString((fcr>>8)&3))
                  )
        fcrLine+=("  Mask    "+
                  self.formatAndUpdateRegValue("fpu-PM",int((fcr&0x0020)!=0))+' '+
                  self.formatAndUpdateRegValue("fpu-UM",int((fcr&0x0010)!=0))+' '+
                  self.formatAndUpdateRegValue("fpu-OM",int((fcr&0x0008)!=0))+' '+
                  self.formatAndUpdateRegValue("fpu-ZM",int((fcr&0x0004)!=0))+' '+
                  self.formatAndUpdateRegValue("fpu-DM",int((fcr&0x0002)!=0))+' '+
                  self.formatAndUpdateRegValue("fpu-IM",int((fcr&0x0001)!=0))
                 )
        lines.append(fcrLine)
        return lines

    def linesLastFPUOp(self,termWidth,styleChanged):
        offsetFormat = "%016lx" if self.bits==64 else "%08x"
        regs=run('printf "%04x,%04x,%04x,'+offsetFormat+','+offsetFormat+'",$fop,$fiseg,$foseg,$fioff,$fooff').split(',')
        if len(regs)!=5:
            raise Exception("Failed to get FPU last operation info")
        fop=regs[0]
        fiseg=regs[1]
        foseg=regs[2]
        fioff=regs[3]
        fooff=regs[4]
        lines=[]
        lines.append(self.formatAndUpdateReg("Last insn",fiseg,"seg-")+":"+
                     self.formatAndUpdateRegValue("off-Last insn",fioff))
        lines.append(self.formatAndUpdateReg("Last data",foseg,"seg-")+":"+
                     self.formatAndUpdateRegValue("off-Last data",fooff))
        fop=int(fop,16)
        fop1=(fop>>8)|0xd8
        fop2=fop&0xff
        fopStr = "%02x %02x" % (fop1,fop2) if fop!=0 else "00 00"
        lines.append(self.formatAndUpdateReg("Last opcode",fopStr,"fpu-"))
        return lines

    def lines(self,termWidth,styleChanged):
        arch=run("show arch")
        if " i386:x64-32" in arch or " i386:x86-64" in arch:
            self.bits=64
        else:
            self.bits=32
        try:
            theLines=(self.linesGPR(termWidth,styleChanged)+['']+
                      self.linesPC(termWidth,styleChanged)+[''])
            efl=self.linesEFL(termWidth,styleChanged)
            seg=self.linesSegReg(termWidth,styleChanged)
            if len(efl)<len(seg):
                raise Exception("BUG: EFL has fewer lines than segReg")
            for i in range(len(efl)):
                if i<len(seg):
                    theLines.append(efl[i]+'  '+seg[i])
                else:
                    theLines.append(efl[i])
            theLines+=['']+self.linesFPUStatusAndControl(termWidth,styleChanged)
            theLines+=['']+self.linesLastFPUOp(termWidth,styleChanged)
            theLines+=['']+self.linesMXCSR(termWidth,styleChanged)
            return theLines
        except Exception,e:
            return [str(e)]
